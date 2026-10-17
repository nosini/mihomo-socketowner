//go:build linux && amd64 && hostname_vm

package hostname

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

// Exercise the production BIO/filter validator with unreadable and mismatched
// user objects. Real curl/syscall/packet attribution is tested by the service
// matrix; these cases deliberately break links without changing curl itself.
func TestVMCurlBIOBindings(t *testing.T) {
	object := os.Getenv("HOSTNAME_VM_CURL_OBJECT")
	if object == "" {
		t.Skip("needs curl validation BPF test object")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	const base = uint64(0x10000000)
	if err := spec.Variables["curl_base"].Set(base); err != nil {
		t.Fatal(err)
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{"test_curl": spec.Programs["test_curl"]}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	type params struct {
		SSL, BIO, Socket uint64
		FD               int32
		Pad              uint32
	}
	pointer := func(b []byte) uint64 { return uint64(uintptr(unsafe.Pointer(&b[0]))) }
	type mutation struct {
		object string
		offset int
		value  uint64
	}
	cases := map[string]mutation{
		"control": {}, "unreadable BIO": {"params", 8, 1}, "unreadable method": {"bio", 8, 1},
		"wrong BIO type": {"method", 0, 1}, "wrong callback": {"method", 0x18, base + 0xc20f1},
		"unreadable filter": {"bio", 0x40, 1}, "wrong TLS filter": {"tls", 0, base + 0x11c801},
		"unreadable happy filter": {"tls", 8, 1}, "wrong happy filter": {"happy", 0, base + 0x11c0a1},
		"different live socket": {"happy", 8, 1}, "wrong TCP filter": {"socket", 0, base + 0x11c5e1},
		"extra TCP filter": {"socket", 8, 1}, "TLS socket index": {"tls", 0x20, 1},
		"happy socket index": {"happy", 0x20, 1}, "TCP socket index": {"socket", 0x20, 1},
		"missing owner": {"tls", 0x18, 0}, "different happy owner": {"happy", 0x18, 1},
		"different socket owner": {"socket", 0x18, 1}, "unreadable TLS context": {"tls", 0x10, 1},
		"unreadable backend": {"connssl", 0x38, 1}, "different SSL": {"backend", 8, 1},
		"different BIO method": {"backend", 0x10, 1}, "unreadable TCP context": {"socket", 0x10, 1},
		"different descriptor": {"sockctx", 0x98, 8}, "negative descriptor": {"params", 24, ^uint64(0)},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			objects := map[string][]byte{}
			for _, key := range []string{"ssl", "bio", "method", "tls", "happy", "socket", "connssl", "backend", "sockctx", "owner", "params"} {
				objects[key] = make([]byte, 256)
			}
			put := func(obj string, off int, value uint64) { binary.LittleEndian.PutUint64(objects[obj][off:], value) }
			ptr := func(key string) uint64 { return pointer(objects[key]) }
			put("bio", 8, ptr("method"))
			put("bio", 0x40, ptr("tls"))
			put("method", 0, 0x401)
			put("method", 0x18, base+0xc20f0)
			put("tls", 0, base+0x11c800)
			put("tls", 8, ptr("happy"))
			put("tls", 0x10, ptr("connssl"))
			put("tls", 0x18, ptr("owner"))
			put("happy", 0, base+0x11c0a0)
			put("happy", 8, ptr("socket"))
			put("happy", 0x18, ptr("owner"))
			put("socket", 0, base+0x11c5e0)
			put("socket", 0x10, ptr("sockctx"))
			put("socket", 0x18, ptr("owner"))
			put("connssl", 0x38, ptr("backend"))
			put("backend", 8, ptr("ssl"))
			put("backend", 0x10, ptr("method"))
			put("sockctx", 0x98, 7)
			put("params", 0, ptr("ssl"))
			put("params", 8, ptr("bio"))
			put("params", 16, ptr("socket"))
			put("params", 24, 7)
			if change.object != "" {
				put(change.object, change.offset, change.value)
			}
			data := objects["params"]
			input := params{binary.LittleEndian.Uint64(data), binary.LittleEndian.Uint64(data[8:]), binary.LittleEndian.Uint64(data[16:]), int32(binary.LittleEndian.Uint32(data[24:])), 0}
			if err := coll.Maps["curl_test_input"].Put(uint32(0), input); err != nil {
				t.Fatal(err)
			}
			got, _, err := coll.Programs["test_curl"].Test(make([]byte, 64))
			runtime.KeepAlive(objects)
			want := uint32(0)
			if name == "control" {
				want = 1
			}
			if err != nil || got != want {
				t.Fatalf("validator=%d want=%d: %v", got, want, err)
			}
		})
	}
}

// Preparation must establish all four mapped file identities before publishing
// any registration. This catches configuration and binary-selection failures
// independently of the live routing tests.
func TestVMCurlRegistration(t *testing.T) {
	root, _ := bootstrapVMRoot(t)
	cmd := exec.Command("curl", "-q", "--config", "-")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	cgroup := filepath.Join("/sys/fs/cgroup", "hostname-experiment-curl-"+strconv.Itoa(cmd.Process.Pid))
	if err := os.Mkdir(cgroup, 0700); err != nil {
		in.Close()
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal(err)
	}
	// Reap before removing the task's cgroup, including a failed assertion.
	defer func() {
		in.Close()
		cmd.Process.Kill()
		cmd.Wait()
		if err := os.Remove(cgroup); err != nil {
			t.Error(err)
		}
	}()
	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	resolve := func(path string) string {
		p, err := filepath.EvalSymlinks(path)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	config := ObserverConfig{Runtime: root + "/runtime", Pins: root + "/pins", Cgroup: cgroup,
		Profile: CurlObserverProfile, TargetPID: cmd.Process.Pid, ReaderUID: 1000, ReaderGID: 1000,
		SSL:    resolve("/usr/lib64/glibc-hwcaps/x86-64-v3/libssl.so.3"),
		Crypto: resolve("/usr/lib64/glibc-hwcaps/x86-64-v3/libcrypto.so.3"), C: profileLibc, Curl: resolve("/usr/lib64/libcurl.so.4")}
	deadline := time.Now().Add(3 * time.Second)
	for {
		maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", cmd.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(maps), config.Curl) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("curl did not load libcurl")
		}
		time.Sleep(time.Millisecond)
	}
	registration := root + "/registration/target.json"
	if err := os.Mkdir(root+"/registration", 0700); err != nil {
		t.Fatal(err)
	}
	copyPath := root + "/libcurl-copy.so"
	bytes, err := os.ReadFile(config.Curl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"missing": "", "wrong hash": config.SSL,
		"symlink": "/usr/lib64/libcurl.so.4", "unmapped identical bytes": copyPath} {
		t.Run(name, func(t *testing.T) {
			c := config
			c.Curl = path
			if err := PrepareObserver(registration, c); err == nil {
				t.Fatal("accepted unsupported curl library")
			}
			if _, err := os.Lstat(registration); !os.IsNotExist(err) {
				t.Fatalf("failed prepare published registration: %v", err)
			}
		})
	}
	if err := PrepareObserver(registration, config); err != nil {
		t.Fatal(err)
	}
	reg, err := loadRegistration(registration)
	if err != nil || reg.Config.Curl != config.Curl || reg.Config.Profile != CurlObserverProfile {
		t.Fatalf("registration mismatch: %+v %v", reg, err)
	}
}
