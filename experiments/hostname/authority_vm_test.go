//go:build linux && amd64 && hostname_vm

package hostname

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type authorityVMConfig struct {
	Object, Cgroup, SSL, Crypto, Directory string
	PID                                    int
	Manifest                               authorityManifest
	Unpinned                               bool // deliberately unsafe pidfd-only counterexample
	Runtime, Endpoint, Pause, Attack       string
}

type authorityVMRequest struct {
	Command string
	Key     flowKey
}

type authorityVMReply struct {
	Manifest                   authorityManifest
	Name, Error                string
	Cookie                     uint64
	Unknown, NoFlow            bool
	Copied                     bool
	State                      uint64
	Directory, Endpoint, Phase string
}

type authorityVMProcess struct {
	conn net.Conn
	enc  *json.Encoder
	dec  *json.Decoder
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	log  bytes.Buffer
}

func startAuthorityVMProcess(t *testing.T, role string, files []*os.File) *authorityVMProcess {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := os.NewFile(uintptr(fds[0]), "authority-parent"), os.NewFile(uintptr(fds[1]), "authority-child")
	conn, err := net.FileConn(parent)
	parent.Close()
	if err != nil {
		child.Close()
		t.Fatal(err)
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	h := &authorityVMProcess{conn: conn, enc: json.NewEncoder(conn), dec: json.NewDecoder(conn), done: make(chan struct{})}
	h.cmd = exec.CommandContext(ctx, path, "-test.run", "^TestVMHostnameAuthorityHelper$", "-test.timeout", "23s")
	h.cmd.Env = append(os.Environ(), "HOSTNAME_VM_AUTHORITY_ROLE="+role)
	h.cmd.ExtraFiles = append([]*os.File{child}, files...)
	h.cmd.Stdout, h.cmd.Stderr = &h.log, &h.log
	if role == "reader" || role == "contract-reader" || role == "bootstrap-attacker" {
		h.cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	}
	err = h.cmd.Start()
	child.Close()
	if err != nil {
		conn.Close()
		cancel()
		t.Fatal(err)
	}
	go func() { h.err = h.cmd.Wait(); close(h.done) }()
	t.Cleanup(func() {
		conn.Close()
		cancel()
		<-h.done
		if t.Failed() {
			t.Logf("%s: %s", role, h.log.String())
		}
	})
	return h
}

func (h *authorityVMProcess) exchange(t *testing.T, request any) authorityVMReply {
	t.Helper()
	h.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := h.enc.Encode(request); err != nil {
		t.Fatal(err)
	}
	var reply authorityVMReply
	if err := h.dec.Decode(&reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestVMHostnameAuthorityHelper(t *testing.T) {
	role := os.Getenv("HOSTNAME_VM_AUTHORITY_ROLE")
	if role == "" {
		t.Skip("private independent-process experiment helper")
	}
	file := os.NewFile(3, "authority-control")
	conn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	dec, enc := json.NewDecoder(conn), json.NewEncoder(conn)
	var config authorityVMConfig
	if err := dec.Decode(&config); err != nil {
		t.Fatal(err)
	}
	if role == "observer" {
		runAuthorityVMObserver(t, config, dec, enc)
	} else if role == "reader" {
		runAuthorityVMReader(t, config, dec, enc)
	} else if role == "contract-reader" {
		runContractVMReader(t, config, dec, enc)
	} else if role == "bootstrap-attacker" {
		runBootstrapVMAttacker(t, config, enc)
	} else if role == "bootstrap-fake" {
		runBootstrapVMFake(t, config, enc)
	} else {
		t.Fatal("invalid helper role")
	}
}

func runAuthorityVMObserver(t *testing.T, config authorityVMConfig, dec *json.Decoder, enc *json.Encoder) {
	var owner *bootstrapOwner
	var ownedReader *authorityReader
	if config.Runtime != "" {
		var err error
		owner, err = newBootstrapOwner(config.Runtime, config.Directory, time.Now().Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		defer owner.lock.Close()
		config.Directory, err = owner.begin()
		if err != nil {
			t.Fatal(err)
		}
		if config.Pause == "intent" {
			pauseBootstrapVM(t, enc, dec, "intent", config.Directory)
			return
		}
	}
	spec, err := ebpf.LoadCollectionSpec(config.Object)
	if err != nil {
		t.Fatal(err)
	}
	// The baseline handshake observer is not part of this authority contract.
	p, err := attachSpec(spec, config.Cgroup, libraries{config.SSL, config.Crypto, profileLibc}, config.PID, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	gate, manifest, err := pinAuthorityMaps(p, config.Directory)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err := p.collection.Maps["last_seeded"].Pin(filepath.Join(config.Directory, "last_seeded")); err != nil {
		t.Fatal(err)
	}
	// Pins must exist for every required link, not only for records/programs.
	if !config.Unpinned {
		paused := errors.New("paused after a partial link pin")
		err := activateObserver(p, gate, config.Directory, func() error {
			if owner != nil && config.Pause == "partial" {
				pauseBootstrapVM(t, enc, dec, "partial", config.Directory)
				return paused
			}
			return nil
		})
		if errors.Is(err, paused) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	reply := authorityVMReply{Manifest: manifest, Directory: config.Directory}
	if owner != nil {
		ownedReader, err = ownAuthorityReader(config.Directory, manifest)
		if err != nil {
			t.Fatal(err)
		}
		defer ownedReader.close()
		if err := owner.publish(p, ownedReader, 1000, 1000); err != nil {
			t.Fatal(err)
		}
		reply.Endpoint = owner.socketPath()
	}
	if err := enc.Encode(reply); err != nil {
		t.Fatal(err)
	}
	for {
		var request authorityVMRequest
		if err := dec.Decode(&request); err != nil {
			return
		}
		reply := authorityVMReply{}
		switch request.Command {
		case "stop":
			if owner == nil {
				t.Fatal("no cleanup owner")
			}
			if err := owner.finish(p, ownedReader); err != nil {
				t.Fatal(err)
			}
		case "drop-lock":
			if owner == nil {
				t.Fatal("no cleanup owner")
			}
			if err := owner.lock.Close(); err != nil {
				t.Fatal(err)
			}
		case "drop-fds":
			// Deterministically model descriptor teardown before pidfd readiness.
			p.close()
		case "revoke":
			if state := setAuthorityVM(t, gate, false); state != 3 {
				t.Fatalf("failed to revoke authority: %d", state)
			}
			// Deliberate detach, not just closing an FD while pins stay alive.
			for _, l := range p.session.links {
				path := filepath.Join(config.Directory, "link_"+l.name)
				pinned, err := link.LoadPinnedLink(path, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := pinned.Unpin(); err != nil {
					t.Fatal(err)
				}
				pinned.Close()
			}
			p.stop()
		case "reactivate":
			reply.State = setAuthorityVM(t, gate, true)
		case "exit":
			return // crash-like cleanup: authority stays active, pins remain
		default:
			t.Fatalf("unknown observer command %q", request.Command)
		}
		if err := enc.Encode(reply); err != nil {
			t.Fatal(err)
		}
	}
}

// Even the privileged owner cannot update the gate through a map syscall. Only
// this private BPF program writes it; no program/link FD is sent to the reader.
// Repinning a read-only map FD cannot create userspace write access to the gate.
func setAuthorityVM(t *testing.T, gate *ebpf.Map, activate bool) uint64 {
	t.Helper()
	value, err := changeAuthority(gate, activate)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func runAuthorityVMReader(t *testing.T, config authorityVMConfig, dec *json.Decoder, enc *json.Encoder) {
	if os.Geteuid() != 1000 {
		t.Fatal("reader did not drop root")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !bytes.Contains(status, []byte("CapEff:\t0000000000000000")) {
		t.Fatal("reader has capabilities")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	var maps [4]*ebpf.Map
	var r *authorityReader
	pidfd := 8
	var fdCount int
	if config.Endpoint != "" {
		files, e := os.ReadDir("/proc/self/fd")
		if e != nil {
			t.Fatal(e)
		}
		fdCount = len(files)
		r, _, err = dialAuthority(config.Endpoint, time.Now().Add(time.Second))
		if err == nil {
			maps, pidfd = r.maps, r.pidfd
		}
	} else {
		for i := range maps {
			maps[i], err = ebpf.NewMapFromFD(4 + i)
			if err != nil {
				t.Fatal(err)
			}
			defer maps[i].Close()
		}
		defer unix.Close(8)
		r, err = newAuthorityReader(config.Manifest, maps, 8)
	}

	if err != nil {
		if config.Endpoint != "" {
			files, e := os.ReadDir("/proc/self/fd")
			if e != nil || len(files) != fdCount {
				t.Fatalf("bootstrap failure leaked FDs: %d -> %d (%v)", fdCount, len(files), e)
			}
		}
		if err := enc.Encode(authorityVMReply{Unknown: true, Error: err.Error()}); err != nil {
			t.Fatal(err)
		}
		return
	}
	defer r.close()
	// Possessing data FDs must not grant publication or observer authority.
	for _, m := range maps {
		info, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		key, value := make([]byte, info.KeySize), make([]byte, info.ValueSize)
		if err := m.Update(key, value, ebpf.UpdateAny); !errors.Is(err, unix.EPERM) {
			t.Fatalf("reader wrote map: %v", err)
		}
		if err := m.Delete(key); !errors.Is(err, unix.EPERM) {
			t.Fatalf("reader deleted map entry: %v", err)
		}
		// Avoid a library feature probe that itself creates a map and
		// mistakes lack of reader privilege for an unsupported kernel.
		fd := uint32(m.FD())
		if _, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_FREEZE, uintptr(unsafe.Pointer(&fd)), unsafe.Sizeof(fd)); errno != unix.EPERM {
			t.Fatalf("reader freeze syscall: %v", errno)
		}
	}
	if _, err := ebpf.LoadPinnedMap(filepath.Join(config.Directory, "authority"), nil); !errors.Is(err, unix.EACCES) {
		t.Fatalf("reader reopened private pin for writing: %v", err)
	}
	if err := unix.PidfdSendSignal(pidfd, unix.SIGSTOP, nil, 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("reader can signal privileged observer: %v", err)
	}
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SocketFilter, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}})
	if err == nil {
		program.Close()
		t.Fatal("reader can load BPF programs")
	}
	if !errors.Is(err, unix.EPERM) {
		t.Fatal(err)
	}
	if err := enc.Encode(authorityVMReply{}); err != nil {
		t.Fatal(err)
	}
	for {
		var request authorityVMRequest
		if err := dec.Decode(&request); err != nil {
			return
		}
		if request.Command != "lookup" && request.Command != "lookup-pause" {
			t.Fatalf("unknown reader command %q", request.Command)
		}
		var value flowObservation
		if request.Command == "lookup-pause" {
			value, err = r.read(func(value *flowObservation) error {
				if err := r.maps[3].Lookup(request.Key, value); err != nil {
					return err
				}
				if err := enc.Encode(authorityVMReply{Copied: true, Cookie: value.Cookie}); err != nil {
					return err
				}
				var resume authorityVMRequest
				return dec.Decode(&resume)
			})
		} else {
			value, err = r.lookup(request.Key)
		}
		reply := authorityVMReply{Cookie: value.Cookie}
		if err != nil {
			reply.Unknown, reply.Error = true, err.Error()
			if value != (flowObservation{}) {
				t.Fatal("failed read exposed nonzero record")
			}
		} else {
			reply.Name, err = value.Observation.hostname()
			if err != nil {
				reply.Unknown = true
			}
		}
		if err := enc.Encode(reply); err != nil {
			t.Fatal(err)
		}
	}
}

type authorityVMFixture struct {
	f        *fixture
	observer *authorityVMProcess
	reader   *authorityVMProcess
	path     string
	manifest authorityManifest
	maps     [4]*ebpf.Map
	pidfd    int
}

func newAuthorityVMFixture(t *testing.T, network string, unpinned bool) *authorityVMFixture {
	t.Helper()
	root := os.Getenv("HOSTNAME_VM_PIN_ROOT")
	if root == "" {
		t.Skip("set HOSTNAME_VM_PIN_ROOT to a private bpffs mount in the VM mount namespace")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil || fs.Type != unix.BPF_FS_MAGIC {
		t.Fatalf("private bpffs required: %v", err)
	}
	f := newFixtureSetup(t, network, true, "", false)
	return newAuthorityVMEpoch(t, f, root, unpinned)
}

func newAuthorityVMEpoch(t *testing.T, f *fixture, root string, unpinned bool) *authorityVMFixture {
	t.Helper()
	a := &authorityVMFixture{f: f, pidfd: -1}
	var err error
	a.path, err = os.MkdirTemp(root, "authority-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(a.path) }) // only this test's private pins
	a.observer = startAuthorityVMProcess(t, "observer", nil)
	a.pidfd, err = unix.PidfdOpen(a.observer.cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(a.pidfd) })
	a.manifest = a.observer.exchange(t, authorityVMConfig{Object: f.object, Cgroup: f.cgroup, SSL: f.sslPath, Crypto: f.cryptoPath, PID: int(f.pid), Directory: a.path, Unpinned: unpinned}).Manifest
	for i, name := range authorityMapNames {
		a.maps[i], err = ebpf.LoadPinnedMap(filepath.Join(a.path, name), &ebpf.LoadPinOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.maps[i].Close() })
	}
	seed, err := ebpf.LoadPinnedMap(filepath.Join(a.path, "last_seeded"), &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { seed.Close() })
	// Only used by fixture.socket's independent sock_create assertion. No
	// parent-held link refs or in-process lookup session keep observation alive.
	f.probe = &probe{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{"last_seeded": seed}}}
	if !unpinned {
		a.reader = a.newReader(t)
	}
	return a
}

func (a *authorityVMFixture) newReader(t *testing.T) *authorityVMProcess {
	t.Helper()
	h, reply := a.startReader(t)
	if reply.Unknown || reply.Error != "" {
		t.Fatalf("reader bootstrap: %+v", reply)
	}
	return h
}

func (a *authorityVMFixture) startReader(t *testing.T) (*authorityVMProcess, authorityVMReply) {
	t.Helper()
	var files []*os.File
	for _, fd := range []int{a.maps[0].FD(), a.maps[1].FD(), a.maps[2].FD(), a.maps[3].FD(), a.pidfd} {
		dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(dup), "readonly-authority")
		defer file.Close()
		files = append(files, file)
	}
	h := startAuthorityVMProcess(t, "reader", files)
	return h, h.exchange(t, authorityVMConfig{Manifest: a.manifest, Directory: a.path})
}

func (a *authorityVMFixture) named(t *testing.T) (connection, flowKey) {
	t.Helper()
	c := a.f.accepted(a.f.command("open authority.test name-first fd"))
	a.f.command("handshake %d", c.slot)
	key := a.f.flowKey(c)
	a.assertName(t, a.reader, key, c.cookie)
	return c, key
}

func (a *authorityVMFixture) assertName(t *testing.T, reader *authorityVMProcess, key flowKey, cookie uint64) {
	t.Helper()
	deadline := time.Now().Add(100 * time.Millisecond)
	for {
		reply := reader.exchange(t, authorityVMRequest{Command: "lookup", Key: key})
		if !reply.Unknown && reply.Name == "authority.test" && reply.Cookie == cookie {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected live application name: %+v", reply)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertAuthorityUnknown(t *testing.T, reader *authorityVMProcess, key flowKey) {
	t.Helper()
	reply := reader.exchange(t, authorityVMRequest{Command: "lookup", Key: key})
	if !reply.Unknown || reply.Name != "" || reply.Cookie != 0 || !strings.Contains(reply.Error, errObserverUnavailable.Error()) {
		t.Fatalf("dead authority exposed record: %+v", reply)
	}
}

func (a *authorityVMFixture) retained(t *testing.T, key flowKey, cookie uint64) {
	t.Helper()
	var raw flowObservation
	if err := a.maps[3].Lookup(key, &raw); err != nil || raw.Cookie != cookie || raw.Observation.Len == 0 {
		t.Fatalf("did not retain positive data: %+v, %v", raw, err)
	}
}

func TestVMObserverCrashAuthority(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, mode := range []string{"kill", "exit", "drop-fds-then-kill", "revoke"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				a := newAuthorityVMFixture(t, network, false)
				c, key := a.named(t)
				pending := a.f.accepted(a.f.command("open authority.test name-first fd"))
				pendingKey := a.f.flowKey(pending)
				// Independent readers can reconnect to a still-active epoch.
				reconnected := a.newReader(t)
				a.assertName(t, reconnected, key, c.cookie)
				if mode == "drop-fds-then-kill" {
					a.observer.exchange(t, authorityVMRequest{Command: "drop-fds"})
					if err := pidfdAlive(a.pidfd); err != nil {
						t.Fatal("did not hold the pre-exit interval open")
					}
					// All observer FDs are closed, but pins must preserve live
					// observation, including new sockets and retirement callbacks.
					a.assertName(t, a.reader, key, c.cookie)
					a.f.command("close %d", c.slot)
					var guard uint64
					if err := a.maps[2].Lookup(c.cookie, &guard); !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("lost retirement during descriptor teardown: %d, %v", guard, err)
					}
					c, key = a.named(t)
				}
				if mode == "revoke" {
					a.observer.exchange(t, authorityVMRequest{Command: "revoke"})
					if err := pidfdAlive(a.pidfd); err != nil {
						t.Fatal("revocation test requires a still-live observer")
					}
				} else {
					if mode == "exit" {
						if err := a.observer.enc.Encode(authorityVMRequest{Command: "exit"}); err != nil {
							t.Fatal(err)
						}
					} else if err := a.observer.cmd.Process.Kill(); err != nil {
						t.Fatal(err)
					}
					<-a.observer.done
					if mode == "exit" && a.observer.err != nil {
						t.Fatalf("normal observer exit failed: %v", a.observer.err)
					}
					if err := pidfdAlive(a.pidfd); err == nil {
						t.Fatal("observer pidfd did not report exit")
					}
				}
				// The raw positive data survives; it must not authorize either
				// the original or reconnected reader after death/revocation.
				a.retained(t, key, c.cookie)
				assertAuthorityUnknown(t, a.reader, key)
				assertAuthorityUnknown(t, reconnected, key)
				if mode == "revoke" {
					if reply := a.observer.exchange(t, authorityVMRequest{Command: "reactivate"}); reply.State != 3 {
						t.Fatalf("revoked authority healed: %+v", reply)
					}
					if _, reply := a.startReader(t); !reply.Unknown {
						t.Fatal("new reader accepted a revoked epoch")
					}
				}
				if got := wireName(t, c); got != "authority.test" {
					t.Fatal(got)
				}
				// This sending operation begins only after authority is gone.
				a.f.command("handshake %d", pending.slot)
				assertAuthorityUnknown(t, a.reader, pendingKey)
				if got := wireName(t, pending); got != "authority.test" {
					t.Fatal(got)
				}
			})
		}
	}
}

func TestVMPidfdWithoutPinsCounterexample(t *testing.T) {
	a := newAuthorityVMFixture(t, "tcp4", true)
	c := a.f.accepted(a.f.command("open authority.test name-first fd"))
	a.f.command("handshake %d", c.slot)
	key := a.f.flowKey(c)
	a.observer.exchange(t, authorityVMRequest{Command: "drop-fds"})
	a.f.command("close %d", c.slot)
	if err := pidfdAlive(a.pidfd); err != nil {
		t.Fatal(err)
	}
	a.retained(t, key, c.cookie)
	var guard uint64
	if err := a.maps[2].Lookup(c.cookie, &guard); err != nil || guard != 1 {
		t.Fatalf("counterexample did not miss retirement: %d, %v", guard, err)
	}
	// A pidfd-only reader would still accept this stale positive. A valid
	// bootstrap must leave authority zero when required links are not pinned.
	var active uint64
	if err := a.maps[0].Lookup(uint32(0), &active); err != nil || active != 0 {
		t.Fatalf("unprotected observer advertised authority: %d, %v", active, err)
	}
	if r, err := newAuthorityReader(a.manifest, a.maps, a.pidfd); err == nil {
		r.close()
		t.Fatal("unprotected observer was accepted")
	}
	t.Log(fmt.Sprintf("pidfd remains live with stale cookie %d and guard 1; inactive epoch rejects it", c.cookie))
}

func TestVMObserverFreshEpoch(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			a := newAuthorityVMFixture(t, network, false)
			c, oldKey := a.named(t)
			pending := a.f.accepted(a.f.command("open authority.test name-first fd"))
			pendingKey := a.f.flowKey(pending)
			if err := a.observer.cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			<-a.observer.done
			a.retained(t, oldKey, c.cookie)
			assertAuthorityUnknown(t, a.reader, oldKey)
			if _, reply := a.startReader(t); !reply.Unknown || !strings.Contains(reply.Error, errObserverUnavailable.Error()) {
				t.Fatalf("reconnect authorized a dead epoch: %+v", reply)
			}
			// The trusted cleaner may unpin only after the original pidfd is
			// ready. Retain data pins/FDs to test stale reader rejection.
			if err := pidfdAlive(a.pidfd); err == nil {
				t.Fatal("attempted cleanup before observer exit")
			}
			for _, name := range []string{"create", "release", "state", "send", "egress"} {
				if err := os.Remove(filepath.Join(a.path, "link_"+name)); err != nil {
					t.Fatal(err)
				}
			}
			b := newAuthorityVMEpoch(t, a.f, filepath.Dir(a.path), false)
			for i, id := range a.manifest.Maps {
				if id == b.manifest.Maps[i] {
					t.Fatal("restart reused an old authority/data map")
				}
			}
			// Existing sockets are not adopted, even if their first ClientHello
			// is sent only after restart. New sockets get the fresh scope.
			a.f.command("handshake %d", pending.slot)
			for _, key := range []flowKey{oldKey, pendingKey} {
				reply := b.reader.exchange(t, authorityVMRequest{Command: "lookup", Key: key})
				if !reply.Unknown || reply.Name != "" || reply.Cookie != 0 {
					t.Fatalf("restart adopted existing socket: %+v", reply)
				}
			}
			b.named(t)
			assertAuthorityUnknown(t, a.reader, oldKey)
			a.retained(t, oldKey, c.cookie)
			if got := wireName(t, pending); got != "authority.test" {
				t.Fatal(got)
			}
		})
	}
}

func TestVMObserverBootstrapValidation(t *testing.T) {
	a := newAuthorityVMFixture(t, "tcp4", false)
	wrong := a.manifest
	wrong.Maps[3]++
	if r, err := newAuthorityReader(wrong, a.maps, a.pidfd); err == nil {
		r.close()
		t.Fatal("bootstrap accepted a foreign map identity")
	}
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if r, err := newAuthorityReader(a.manifest, a.maps, int(file.Fd())); err == nil {
		r.close()
		t.Fatal("bootstrap accepted a non-pidfd")
	}
	// A layout-compatible writable descriptor is still not a reader capability.
	writable, err := ebpf.LoadPinnedMap(filepath.Join(a.path, "authority"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writable.Close()
	if err := writable.Update(uint32(0), uint64(0), ebpf.UpdateAny); !errors.Is(err, unix.EPERM) {
		t.Fatalf("even a writable FD must not permit userspace authority changes: %v", err)
	}
	maps := a.maps
	maps[0] = writable
	if r, err := newAuthorityReader(a.manifest, maps, a.pidfd); err == nil {
		r.close()
		t.Fatal("bootstrap accepted a writable map descriptor")
	}
}

func TestVMObserverDiesDuringRead(t *testing.T) {
	for _, mode := range []string{"kill", "revoke"} {
		t.Run(mode, func(t *testing.T) {
			a := newAuthorityVMFixture(t, "tcp4", false)
			c, key := a.named(t)
			copied := a.reader.exchange(t, authorityVMRequest{Command: "lookup-pause", Key: key})
			if !copied.Copied || copied.Cookie != c.cookie {
				t.Fatalf("did not pause after copying positive data: %+v", copied)
			}
			if mode == "kill" {
				if err := a.observer.cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				<-a.observer.done
			} else {
				a.observer.exchange(t, authorityVMRequest{Command: "revoke"})
			}
			a.retained(t, key, c.cookie)
			// Resume inside the original lookup. Its final authority check
			// must reject the record already copied into the reader process.
			reply := a.reader.exchange(t, authorityVMRequest{Command: "resume"})
			if !reply.Unknown || reply.Cookie != 0 || reply.Name != "" || !strings.Contains(reply.Error, errObserverUnavailable.Error()) {
				t.Fatalf("interrupted read exposed positive data: %+v", reply)
			}
			assertAuthorityUnknown(t, a.reader, key)
		})
	}
}
