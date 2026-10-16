// Package hostname contains an isolated, diagnostic OpenSSL correlation experiment.
// No records are pinned or made available to Mihomo.
package hostname

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Offsets were checked against the getters and BIO_s_socket in these exact
// x86-64 ELF files. A version string alone does not establish layout identity.
const (
	sslSHA256       = "2dead83fbc10ddfbc6240921ebe691995df7753e1a11319de923534e4c992064"
	cryptoSHA256    = "f1b2c9b4070ea2724480a3f0d65e0f80b5d5665782e0de18e7190a0348f33c0b"
	libcSHA256      = "090f858814642a3f28e5f4ae6499667e7901e47902ca3e72fb9c8a1967a3b8df"
	socketMethodRVA = 0x654620
)

type observation struct {
	Cookie   uint64
	BootNS   uint64
	TGID     uint32
	FD       int32
	Len      int32
	Pad      uint32
	Hostname [256]byte
}

type probe struct {
	collection  *ebpf.Collection
	uprobe      link.Link
	cgroup      link.Link
	send        link.Link
	egress      link.Link
	publication *ebpf.Map // owned by collection, always read afresh
}

func checkBinary(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		return fmt.Errorf("unsupported binary %s: SHA256 %s", path, got)
	}
	return nil
}

// mappingBase requires a file-backed offset-zero mapping of the verified
// library. The fixture loads its libraries before it waits for attachment.
func mappingBase(maps, path string) (uint64, error) {
	for _, line := range strings.Split(maps, "\n") {
		f := strings.Fields(line)
		if len(f) != 6 || f[5] != path || f[2] != "00000000" {
			continue
		}
		start, _, ok := strings.Cut(f[0], "-")
		if !ok {
			continue
		}
		base, err := strconv.ParseUint(start, 16, 64)
		if err != nil {
			return 0, err
		}
		return base, nil
	}
	return 0, fmt.Errorf("verified library %s has no offset-zero mapping", path)
}

// attach is deliberately private to the experiment. Target PID and exact
// binaries are mandatory; there is no system-wide discovery or attachment.
func attach(object, cgroup, sslPath, cryptoPath string, pid int) (_ *probe, err error) {
	return attachMode(object, cgroup, sslPath, cryptoPath, pid, false)
}

func attachMode(object, cgroup, sslPath, cryptoPath string, pid int, liveSend bool) (_ *probe, err error) {
	if pid <= 0 {
		return nil, fmt.Errorf("target PID must be positive")
	}
	if err := checkBinary(sslPath, sslSHA256); err != nil {
		return nil, err
	}
	if err := checkBinary(cryptoPath, cryptoSHA256); err != nil {
		return nil, err
	}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	sslBase, err := mappingBase(string(maps), sslPath)
	if err != nil {
		return nil, err
	}
	base, err := mappingBase(string(maps), cryptoPath)
	if err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		return nil, err
	}
	constants := map[string]interface{}{
		"target_tgid": uint32(pid), "socket_method": base + socketMethodRVA,
	}
	if liveSend {
		if err := validatePublicationMap(spec.Maps["publication_state"]); err != nil {
			return nil, err
		}
		const libcPath = "/usr/lib64/libc.so.6"
		if err := checkBinary(libcPath, libcSHA256); err != nil {
			return nil, err
		}
		libcBase, err := mappingBase(string(maps), libcPath)
		if err != nil {
			return nil, err
		}
		constants["ssl_base"] = sslBase
		constants["crypto_base"] = base
		constants["libc_base"] = libcBase
	}
	for name, value := range constants {
		v := spec.Variables[name]
		if v == nil {
			return nil, fmt.Errorf("missing BPF constant %s", name)
		}
		if err := v.Set(value); err != nil {
			return nil, err
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load snapshot experiment: %w", err)
	}
	p := &probe{collection: coll}
	if liveSend {
		p.publication = coll.Maps["publication_state"]
	}
	defer func() {
		if err != nil {
			p.close()
		}
	}()
	seed := "seed_cookie"
	if liveSend {
		seed = "seed_send"
	}
	p.cgroup, err = link.AttachCgroup(link.CgroupOptions{
		Path: cgroup, Attach: ebpf.AttachCGroupInetSockCreate, Program: coll.Programs[seed],
	})
	if err != nil {
		return nil, err
	}
	exe, err := link.OpenExecutable(sslPath)
	if err != nil {
		return nil, err
	}
	p.uprobe, err = exe.Uprobe("SSL_do_handshake", coll.Programs["snapshot"], &link.UprobeOptions{PID: pid})
	if err != nil {
		return nil, err
	}
	if liveSend {
		p.send, err = link.AttachLSM(link.LSMOptions{Program: coll.Programs["observe_send"]})
		if err != nil {
			return nil, err
		}
		p.egress, err = link.AttachCgroup(link.CgroupOptions{Path: cgroup, Attach: ebpf.AttachCGroupInetEgress, Program: coll.Programs["observe_flow"]})
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *probe) close() {
	if p.egress != nil {
		p.egress.Close()
	}
	if p.send != nil {
		p.send.Close()
	}
	if p.uprobe != nil {
		p.uprobe.Close()
	}
	if p.cgroup != nil {
		p.cgroup.Close()
	}
	if p.collection != nil {
		p.collection.Close()
	}
}

// hostname validates only conservative ASCII DNS names. It rejects ambiguity,
// truncated strings and IP literals; IDNA conversion is outside the experiment.
func (o observation) hostname() (string, error) {
	if o.Len < 2 || o.Len >= int32(len(o.Hostname)) || o.Hostname[o.Len-1] != 0 {
		return "", fmt.Errorf("missing or truncated hostname")
	}
	name := string(o.Hostname[:o.Len-1])
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return "", fmt.Errorf("invalid hostname length")
	}
	// IPs are not DNS routing names, including numeric IPv4 input.
	numeric := true
	for _, c := range name {
		if c != '.' && (c < '0' || c > '9') {
			numeric = false
		}
	}
	if numeric {
		return "", fmt.Errorf("numeric hostname")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("invalid hostname character")
			}
		}
	}
	// Validate the original characters before case folding: Unicode case
	// folding can otherwise turn an unsupported character into ASCII.
	return strings.ToLower(name), nil
}
