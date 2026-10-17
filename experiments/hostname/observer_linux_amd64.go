package hostname

// Resident observer for the experimental first-send profile. It performs the
// same initialization as the VM helpers for one explicit target process and
// serves the authenticated v1/profile-1 bootstrap until stopped. Raw diagnostic
// maps alone are never routing authority.

//go:generate sh -c "clang -O2 -g -Wall -Werror -D__TARGET_ARCH_x86 -target bpfel -mcpu=v3 -c bpf/send.c -o observer_bpfel.o && llvm-strip -g observer_bpfel.o"

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// The ordinary send object. Fault-injection builds are rejected below, so a
// resident observer can never load them.
//
//go:embed observer_bpfel.o
var observerObject []byte

// ObserverProfile names the only verified library and layout profile.
const ObserverProfile = "openssl-3.5.3-x86-64-v3"

// ObserverConfig identifies everything the observer attaches to. Paths must be
// absolute and canonical; the libraries are the files the target has mapped.
type ObserverConfig struct {
	Runtime   string // the endpoint is Runtime/bootstrap.sock
	Pins      string // private directory on bpffs
	Cgroup    string // cgroup v2 directory containing the target
	Profile   string
	TargetPID int
	SSL       string
	Crypto    string
	C         string
	ReaderUID uint32
	ReaderGID uint32
}

// ObserverEndpoint is the reader endpoint inside a runtime directory.
func ObserverEndpoint(runtime string) string { return filepath.Join(runtime, "bootstrap.sock") }

func canonicalPath(name, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s must be an absolute canonical path: %q", name, path)
	}
	return nil
}

func (c ObserverConfig) validate() error {
	if c.Profile != ObserverProfile {
		return fmt.Errorf("unsupported observer profile %q; only %s is verified", c.Profile, ObserverProfile)
	}
	if c.TargetPID <= 0 {
		return errors.New("a target PID is required")
	}
	if c.ReaderUID == 0 {
		return errors.New("the reader must not be root")
	}
	for _, p := range []struct{ name, path string }{
		{"runtime", c.Runtime}, {"pin", c.Pins}, {"cgroup", c.Cgroup},
		{"libssl", c.SSL}, {"libcrypto", c.Crypto}, {"libc", c.C},
	} {
		if err := canonicalPath(p.name, p.path); err != nil {
			return err
		}
	}
	if len(ObserverEndpoint(c.Runtime)) >= 108 {
		return errors.New("runtime directory is too long for a Unix socket path")
	}
	return nil
}

func observerSpec() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(observerObject))
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"publication_faults", "publication_error", "packet_test_evidence", "reclaim_test_state"} {
		if spec.Maps[name] != nil {
			return nil, errors.New("embedded observer object is a fault-injection build")
		}
	}
	for _, name := range []string{"test_publication", "test_packet", "test_reclaim"} {
		if spec.Programs[name] != nil {
			return nil, errors.New("embedded observer object is a fault-injection build")
		}
	}
	for _, name := range []string{"seed_send", "release_send", "lifetime_send", "observe_send", "observe_flow"} {
		if spec.Programs[name] == nil {
			return nil, fmt.Errorf("embedded observer object lacks %s", name)
		}
	}
	return spec, nil
}

// targetInCgroup requires the target's cgroup v2 path to lie within the
// attachment cgroup; otherwise none of its sockets would be observed.
func targetInCgroup(pid int, cgroup string) error {
	var fs unix.Statfs_t
	if err := unix.Statfs(cgroup, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return fmt.Errorf("%s is not a cgroup v2 directory", cgroup)
	}
	var want unix.Stat_t
	if err := unix.Stat(cgroup, &want); err != nil {
		return err
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return err
	}
	rel, ok := strings.CutPrefix(strings.TrimSuffix(string(data), "\n"), "0::")
	if !ok || strings.Contains(rel, "\n") || !strings.HasPrefix(rel, "/") || filepath.Clean(rel) != rel || strings.Contains(rel, "/..") {
		return errors.New("target is not in a cgroup v2 hierarchy visible to the observer")
	}
	for dir := filepath.Join("/sys/fs/cgroup", rel); ; dir = filepath.Dir(dir) {
		var stat unix.Stat_t
		if err := unix.Stat(dir, &stat); err != nil {
			return err
		}
		if stat.Dev == want.Dev && stat.Ino == want.Ino {
			return nil
		}
		if dir == "/sys/fs/cgroup" {
			return fmt.Errorf("target is not inside %s", cgroup)
		}
	}
}

// pinAuthorityMaps creates the authority gate and pins and freezes the four
// maps a reader receives. Nothing is active until activateObserver.
func pinAuthorityMaps(p *probe, directory string) (_ *ebpf.Map, manifest authorityManifest, err error) {
	gate, err := ebpf.NewMap(&ebpf.MapSpec{Name: "authority", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1, Flags: unix.BPF_F_RDONLY})
	if err != nil {
		return nil, manifest, err
	}
	defer func() {
		if err != nil {
			gate.Close()
		}
	}()
	for i, name := range authorityMapNames {
		m := gate
		if i != 0 {
			m = p.collection.Maps[name]
		}
		path := filepath.Join(directory, name)
		if err := m.Pin(path); err != nil {
			return nil, manifest, err
		}
		// RDONLY restricts the original FD, not the map globally. Freeze
		// through a temporary writable FD before issuing reader capabilities.
		writable, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			return nil, manifest, err
		}
		err = writable.Freeze()
		writable.Close()
		if err != nil {
			return nil, manifest, err
		}
		if manifest.Maps[i], err = mapIdentity(m); err != nil {
			return nil, manifest, err
		}
	}
	return gate, manifest, nil
}

// activateObserver pins every required link, then switches the fresh gate on.
// afterLink is a test hook run after each pin; its error stops setup there.
func activateObserver(p *probe, gate *ebpf.Map, directory string, afterLink func() error) error {
	for _, l := range p.session.links {
		if err := l.get().Pin(filepath.Join(directory, "link_"+l.name)); err != nil {
			return err
		}
		if afterLink != nil {
			if err := afterLink(); err != nil {
				return err
			}
		}
	}
	state, err := changeAuthority(gate, true)
	if err != nil || state != 1 {
		return fmt.Errorf("failed to activate fresh authority: %d, %v", state, err)
	}
	return nil
}

// ownAuthorityReader opens the pinned maps read-only, bound to this process.
// The bootstrap server issues its descriptors to authenticated readers.
func ownAuthorityReader(directory string, manifest authorityManifest) (*authorityReader, error) {
	var maps [4]*ebpf.Map
	defer func() {
		for _, m := range maps {
			if m != nil {
				m.Close()
			}
		}
	}()
	for i, name := range authorityMapNames {
		var err error
		maps[i], err = ebpf.LoadPinnedMap(filepath.Join(directory, name), &ebpf.LoadPinOptions{ReadOnly: true})
		if err != nil {
			return nil, err
		}
	}
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pidfd)
	return newAuthorityReader(manifest, maps, pidfd)
}

type residentObserver struct {
	owner  *bootstrapOwner
	probe  *probe
	gate   *ebpf.Map
	reader *authorityReader
}

// close revokes authority before anything is detached or unpinned, including
// after a failed setup, then removes this instance's endpoint and pins.
func (o *residentObserver) close() error {
	var err error
	if o.gate != nil {
		if state, e := changeAuthority(o.gate, false); e != nil || state&2 == 0 {
			err = fmt.Errorf("hostname revocation failed: %d, %v", state, e)
		}
		o.gate.Close()
	}
	if err != nil {
		// Leave the pins for recovery rather than detaching unrevoked authority.
		return err
	}
	return o.owner.finish(o.probe, o.reader)
}

func (o *residentObserver) healthy() error {
	select {
	case <-o.owner.done:
		return errors.New("bootstrap endpoint stopped")
	default:
	}
	if err := o.probe.session.healthy(); err != nil {
		return err
	}
	o.reader.mu.RLock()
	defer o.reader.mu.RUnlock()
	if err := o.reader.healthy(); err != nil {
		return err
	}
	var word uint64
	if err := o.reader.maps[1].Lookup(uint32(0), &word); err != nil {
		return err
	}
	if word&publicationFailed != 0 {
		// Includes an exhausted send-guard table. Readers already return
		// unknown; a restart gives a fresh instance.
		return errPublicationFailed
	}
	return nil
}

// RunObserver attaches to the target, publishes the reader endpoint and serves
// it until ctx ends, the target exits or the instance stops being usable. ready
// runs once readers can connect. Any remains of a crashed instance are
// recovered first. Shutdown revokes readers before detaching; a nil result
// means the stop was requested or the target exited.
func RunObserver(ctx context.Context, c ObserverConfig, ready func()) error {
	return runObserver(ctx, c, nil, ready)
}

func runObserver(ctx context.Context, c ObserverConfig, expected *registeredTarget, ready func()) (err error) {
	if err := c.validate(); err != nil {
		return err
	}
	spec, err := observerSpec()
	if err != nil {
		return err
	}
	target, err := unix.PidfdOpen(c.TargetPID, 0)
	if err != nil {
		return fmt.Errorf("open target: %w", err)
	}
	defer unix.Close(target)
	if expected != nil {
		got, err := targetIdentity(target)
		if err != nil || got != *expected {
			return errors.New("registered target identity changed; prepare the target again")
		}
	}
	if err := targetInCgroup(c.TargetPID, c.Cgroup); err != nil {
		return err
	}
	if err := rootDirectory(c.Pins, 0700); err != nil {
		return err
	}
	owner, err := newBootstrapOwner(c.Runtime, c.Pins, time.Now().Add(time.Second))
	if err != nil {
		return err
	}
	o := &residentObserver{owner: owner}
	defer func() { err = errors.Join(err, o.close()) }()
	directory, err := owner.begin()
	if err != nil {
		return err
	}
	o.probe, err = attachSpec(spec, c.Cgroup, libraries{c.SSL, c.Crypto, c.C}, c.TargetPID, true, false)
	if err != nil {
		return err
	}
	// The maps read during attachment belonged to this target only if it
	// is still alive now; a reused PID would be a different process.
	if err := pidfdAlive(target); err != nil {
		return errors.New("target exited during attachment")
	}
	var manifest authorityManifest
	if o.gate, manifest, err = pinAuthorityMaps(o.probe, directory); err != nil {
		return err
	}
	if err := activateObserver(o.probe, o.gate, directory, nil); err != nil {
		return err
	}
	if o.reader, err = ownAuthorityReader(directory, manifest); err != nil {
		return err
	}
	if err := owner.publish(o.probe, o.reader, c.ReaderUID, c.ReaderGID); err != nil {
		return err
	}
	if ready != nil {
		ready()
	}
	for {
		poll := []unix.PollFd{{Fd: int32(target), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, 250)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if n != 0 {
			if poll[0].Revents&unix.POLLIN == 0 {
				return errors.New("cannot watch the target process")
			}
			return nil // target exited; its sockets are retired
		}
		if ctx.Err() != nil {
			return nil
		}
		if err := o.healthy(); err != nil {
			return fmt.Errorf("hostname observer stopped: %w", err)
		}
	}
}

// CleanupObserver removes a stopped or crashed observer's endpoint, pins and
// journal. It refuses while the original observer lives or when the recorded
// state is not its own.
func CleanupObserver(runtime, pins string) error {
	if err := canonicalPath("runtime", runtime); err != nil {
		return err
	}
	if err := canonicalPath("pin", pins); err != nil {
		return err
	}
	owner, err := newBootstrapOwner(runtime, pins, time.Now())
	if err != nil {
		return err
	}
	return owner.finish(nil, nil)
}
