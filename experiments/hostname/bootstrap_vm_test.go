//go:build linux && amd64 && hostname_vm

package hostname

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func pauseBootstrapVM(t *testing.T, enc *json.Encoder, dec *json.Decoder, phase, directory string) {
	t.Helper()
	if err := enc.Encode(authorityVMReply{Phase: phase, Directory: directory}); err != nil {
		t.Fatal(err)
	}
	var wait authorityVMRequest
	_ = dec.Decode(&wait)
}

func runBootstrapVMAttacker(t *testing.T, config authorityVMConfig, enc *json.Encoder) {
	c, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: config.Endpoint, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	h := bootstrapHeader{Kind: 1, Profile: 3, Nonce: [16]byte{1}}
	data, rights := h.encode(), []byte(nil)
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	switch config.Attack {
	case "version":
		data[8] = 2
	case "profile":
		data[64] = 4
	case "legacy-profile":
		data[64] = 1
	case "profile-2":
		data[64] = 2
	case "kind":
		data[10] = 2
	case "zero-nonce":
		data[16] = 0
	case "instance":
		data[32] = 1
	case "map":
		data[48] = 1
	case "count":
		data[14] = 4
	case "extra":
		data = append(data, 0)
	case "rights":
		rights = unix.UnixRights(int(file.Fd()))
	case "stall":
	default:
		t.Fatal("unknown bootstrap attack")
	}
	if config.Attack != "stall" {
		if _, _, err := c.WriteMsgUnix(data, rights, nil); err != nil {
			t.Fatal(err)
		}
	}
	_, fds, err := receiveBootstrap(c)
	defer closeBootstrapFDs(fds)
	if err == nil || len(fds) != 0 {
		t.Fatal("malformed client obtained map FDs")
	}
	if err := enc.Encode(authorityVMReply{}); err != nil {
		t.Fatal(err)
	}
}

func runBootstrapVMFake(t *testing.T, config authorityVMConfig, enc *json.Encoder) {
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: config.Endpoint, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.Chown(config.Endpoint, 0, 1000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config.Endpoint, 0660); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(authorityVMReply{}); err != nil {
		t.Fatal(err)
	}
	c, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	data, fds, err := receiveBootstrap(c)
	defer closeBootstrapFDs(fds)
	if err != nil {
		t.Fatal(err)
	}
	h, err := decodeBootstrap(data)
	if err != nil {
		t.Fatal(err)
	}
	if config.Attack == "stall-context" {
		if err := enc.Encode(authorityVMReply{Phase: "request"}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("canceled bootstrap did not close socket: %v", err)
		}
		return
	}
	h.Kind, h.Count, h.Instance = 2, 4, [16]byte{1}
	h.Manifest.Maps = [4]ebpf.MapID{1, 2, 3, 4}
	data = h.encode()
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fds = []int{int(file.Fd()), int(file.Fd()), int(file.Fd()), int(file.Fd())}
	switch config.Attack {
	case "nonce":
		data[16] ^= 1
	case "version":
		data[8] = 2
	case "profile":
		data[64] = 4
	case "legacy-profile":
		data[64] = 1
	case "profile-2":
		data[64] = 2
	case "missing":
		fds = fds[:3]
	case "extra":
		fds = append(fds, int(file.Fd()))
	case "truncated-rights":
		for len(fds) < 32 {
			fds = append(fds, int(file.Fd()))
		}
	case "wrong-type":
	default:
		t.Fatal("unknown fake response")
	}
	if _, _, err := c.WriteMsgUnix(data, unix.UnixRights(fds...), nil); err != nil {
		t.Fatal(err)
	}
}

func bootstrapVMRoot(t *testing.T) (string, string) {
	t.Helper()
	if os.Getenv("HOSTNAME_VM_PIN_ROOT") == "" {
		t.Skip("run the bootstrap tests in the privileged authority VM suite")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires VM root")
	}
	self, err := os.Readlink("/proc/self/ns/mnt")
	init, initErr := os.Readlink("/proc/1/ns/mnt")
	if err != nil || initErr != nil || self == init {
		t.Fatal("requires unshare --mount in the VM")
	}
	root, err := os.MkdirTemp("/run", "mihomo-hn-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	pins := filepath.Join(root, "pins")
	if err := os.Mkdir(pins, 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("bpf", pins, "bpf", 0, "mode=0700"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(pins, 0); err != nil {
			t.Error(err)
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	return root, pins
}

func bootstrapVMReader(t *testing.T, a *authorityVMFixture, endpoint string) (*authorityVMProcess, authorityVMReply) {
	t.Helper()
	h := startAuthorityVMProcess(t, "reader", nil) // only test-control FD; no inherited maps/pidfd
	return h, h.exchange(t, authorityVMConfig{Directory: a.path, Endpoint: endpoint})
}

func bootstrapVMEpoch(t *testing.T, f *fixture, runtime, pins, pause string) (*authorityVMFixture, authorityVMReply) {
	t.Helper()
	a := &authorityVMFixture{f: f, observer: startAuthorityVMProcess(t, "observer", nil)}
	reply := a.observer.exchange(t, authorityVMConfig{Object: f.object, Cgroup: f.cgroup, SSL: f.sslPath, Crypto: f.cryptoPath, PID: int(f.pid), Directory: pins, Runtime: runtime, Pause: pause})
	a.path, a.manifest = reply.Directory, reply.Manifest
	if pause != "" {
		return a, reply
	}
	var err error
	a.pidfd, err = unix.PidfdOpen(a.observer.cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(a.pidfd) })
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
	f.probe = &probe{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{"last_seeded": seed}}}
	a.reader, reply = bootstrapVMReader(t, a, reply.Endpoint)
	if reply.Unknown || reply.Error != "" {
		t.Fatalf("authenticated bootstrap failed: %+v", reply)
	}
	return a, authorityVMReply{Endpoint: filepath.Join(runtime, "bootstrap.sock"), Directory: a.path}
}

func TestVMBootstrapTransferAndStop(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			root, pins := bootstrapVMRoot(t)
			f := newFixtureSetup(t, network, true, "", false)
			a, ready := bootstrapVMEpoch(t, f, root, pins, "")
			c, key := a.named(t)
			second, reply := bootstrapVMReader(t, a, ready.Endpoint)
			if reply.Unknown {
				t.Fatal(reply)
			}
			a.assertName(t, second, key, c.cookie)
			// Root can connect through file permissions, but is not the configured reader UID.
			if r, _, err := dialAuthority(ready.Endpoint, time.Now().Add(time.Second)); err == nil {
				r.close()
				t.Fatal("unauthorized UID received a session")
			}
			if _, err := newBootstrapOwner(root, pins, time.Now().Add(30*time.Millisecond)); err == nil {
				t.Fatal("second owner acquired the held lock")
			}
			a.observer.exchange(t, authorityVMRequest{Command: "stop"})
			if err := pidfdAlive(a.pidfd); err != nil {
				t.Fatal("graceful stop must be tested while owner remains alive")
			}
			a.retained(t, key, c.cookie)
			assertAuthorityUnknown(t, a.reader, key)
			assertAuthorityUnknown(t, second, key)
			entries, err := os.ReadDir(pins)
			if err != nil || len(entries) != 0 {
				t.Fatalf("stop left pins: %v %v", entries, err)
			}
			if _, err := os.Stat(filepath.Join(root, "state", "journal")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("stop left journal")
			}
			o, err := newBootstrapOwner(root, pins, time.Now().Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if err := o.finish(nil, nil); err != nil {
				t.Fatal(err)
			}
			if err := o.finish(nil, nil); err != nil {
				t.Fatal("cleanup was not idempotent", err)
			}
		})
	}
}

func TestVMBootstrapContextCancellation(t *testing.T) {
	root, _ := bootstrapVMRoot(t)
	endpoint := filepath.Join(root, "canceled.sock")
	fake := startAuthorityVMProcess(t, "bootstrap-fake", nil)
	fake.exchange(t, authorityVMConfig{Endpoint: endpoint, Attack: "stall-context"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		r, err := DialReaderContext(ctx, endpoint, time.Now().Add(5*time.Second))
		if r != nil {
			r.Close()
		}
		done <- err
	}()
	var phase authorityVMReply
	fake.conn.SetReadDeadline(time.Now().Add(time.Second))
	if err := fake.dec.Decode(&phase); err != nil || phase.Phase != "request" {
		t.Fatalf("bootstrap did not reach reply wait: %+v, %v", phase, err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled bootstrap granted a reader")
		}
	case <-time.After(time.Second):
		t.Fatal("bootstrap ignored cancellation")
	}
	<-fake.done
	if fake.err != nil {
		t.Fatal(fake.err)
	}
}

func TestVMBootstrapProtocolDenials(t *testing.T) {
	root, pins := bootstrapVMRoot(t)
	f := newFixtureSetup(t, "tcp4", true, "", false)
	a, ready := bootstrapVMEpoch(t, f, root, pins, "")
	for _, attack := range []string{"version", "profile", "legacy-profile", "profile-2", "kind", "zero-nonce", "instance", "map", "count", "extra", "rights", "stall"} {
		t.Run(attack, func(t *testing.T) {
			h := startAuthorityVMProcess(t, "bootstrap-attacker", nil)
			h.exchange(t, authorityVMConfig{Endpoint: ready.Endpoint, Attack: attack})
		})
	}
	a.named(t) // bad clients must not poison a good instance
	a.observer.exchange(t, authorityVMRequest{Command: "stop"})
}

func TestVMBootstrapRejectsBadPublisher(t *testing.T) {
	for _, attack := range []string{"nonce", "version", "profile", "legacy-profile", "profile-2", "missing", "extra", "truncated-rights", "wrong-type"} {
		t.Run(attack, func(t *testing.T) {
			root, _ := bootstrapVMRoot(t)
			endpoint := filepath.Join(root, "bootstrap.sock")
			h := startAuthorityVMProcess(t, "bootstrap-fake", nil)
			h.exchange(t, authorityVMConfig{Endpoint: endpoint, Attack: attack})
			_, reply := bootstrapVMReader(t, &authorityVMFixture{}, endpoint)
			if !reply.Unknown || reply.Error == "" {
				t.Fatalf("bad publisher accepted: %+v", reply)
			}
		})
	}
}

func TestVMBootstrapCrashRecovery(t *testing.T) {
	for _, phase := range []string{"intent", "partial", "ready", "lock-released", "reused-pid"} {
		t.Run(phase, func(t *testing.T) {
			root, pins := bootstrapVMRoot(t)
			f := newFixtureSetup(t, "tcp4", true, "", false)
			pause := ""
			if phase == "intent" || phase == "partial" {
				pause = phase
			}
			a, _ := bootstrapVMEpoch(t, f, root, pins, pause)
			var old connection
			var oldKey flowKey
			if phase == "ready" {
				old, oldKey = a.named(t)
			}
			if phase == "lock-released" {
				a.observer.exchange(t, authorityVMRequest{Command: "drop-lock"})
				if o, err := newBootstrapOwner(root, pins, time.Now().Add(30*time.Millisecond)); err == nil {
					o.finish(nil, nil)
					t.Fatal("recovery cleaned a live original owner")
				}
				if _, err := os.Stat(a.path); err != nil {
					t.Fatal("live owner pins disappeared", err)
				}
			}
			if err := a.observer.cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			<-a.observer.done
			if phase == "ready" {
				a.retained(t, oldKey, old.cookie)
				assertAuthorityUnknown(t, a.reader, oldKey)
			}
			if phase == "reused-pid" {
				path := filepath.Join(root, "state", "journal")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var j bootstrapJournal
				if err := json.Unmarshal(data, &j); err != nil {
					t.Fatal(err)
				}
				j.PID = os.Getpid() // live unrelated process, different pidfs identity
				data, _ = json.Marshal(j)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			other := filepath.Join(pins, "unrelated")
			if err := os.Mkdir(other, 0700); err != nil {
				t.Fatal(err)
			}
			o, err := newBootstrapOwner(root, pins, time.Now().Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(a.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("crash pins remain", err)
			}
			if _, err := os.Stat(other); err != nil {
				t.Fatal("recovery touched unrelated work", err)
			}
			if err := o.finish(nil, nil); err != nil {
				t.Fatal(err)
			}
			if phase == "ready" {
				b, _ := bootstrapVMEpoch(t, f, root, pins, "")
				if a.manifest == b.manifest {
					t.Fatal("restart reused maps")
				}
				unknown := b.reader.exchange(t, authorityVMRequest{Command: "lookup", Key: oldKey})
				if !unknown.Unknown || unknown.Cookie != 0 || unknown.Name != "" {
					t.Fatal("new bootstrap adopted an old socket", unknown)
				}
				b.named(t)
				assertAuthorityUnknown(t, a.reader, oldKey)
				b.observer.exchange(t, authorityVMRequest{Command: "stop"})
			}
		})
	}
}

func TestVMBootstrapRecoveryRefusesForeignState(t *testing.T) {
	root, pins := bootstrapVMRoot(t)
	f := newFixtureSetup(t, "tcp4", true, "", false)
	a, _ := bootstrapVMEpoch(t, f, root, pins, "")
	if err := a.observer.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-a.observer.done
	journal := filepath.Join(root, "state", "journal")
	original, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var record bootstrapJournal
	if err := json.Unmarshal(original, &record); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"truncated", "version", "path", "pid-range", "boot", "namespace", "pin-root", "oversized", "symlink", "unexpected-pin"} {
		t.Run(mode, func(t *testing.T) {
			copy := record
			var data []byte
			switch mode {
			case "truncated":
				data = []byte("{")
			case "version":
				copy.Version++
			case "path":
				copy.Pin = "../unrelated"
			case "pid-range":
				copy.PID = 1<<32 + 1
			case "boot":
				copy.Boot = "other"
			case "namespace":
				copy.PIDNS++
			case "pin-root":
				copy.PinRoot += "-other"
			case "oversized":
				data = append(bytes.Clone(original), bytes.Repeat([]byte(" "), 16385)...)
			case "symlink":
				if err := os.Rename(journal, journal+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(journal+".saved", journal); err != nil {
					t.Fatal(err)
				}
			case "unexpected-pin":
				if err := os.Mkdir(filepath.Join(a.path, "unknown"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if data == nil {
				data, _ = json.Marshal(copy)
			}
			if mode != "symlink" {
				if err := os.WriteFile(journal, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if o, err := newBootstrapOwner(root, pins, time.Now().Add(30*time.Millisecond)); err == nil {
				o.finish(nil, nil)
				t.Fatal("unsafe recovery state was accepted")
			}
			if _, err := os.Stat(filepath.Join(a.path, "authority")); err != nil {
				t.Fatal("failed recovery deleted valid retained pins", err)
			}
			if mode == "symlink" {
				if err := os.Remove(journal); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(journal+".saved", journal); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unexpected-pin" {
				if err := os.Remove(filepath.Join(a.path, "unknown")); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(journal, original, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	o, err := newBootstrapOwner(root, pins, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.finish(nil, nil); err != nil {
		t.Fatal(err)
	}
}
