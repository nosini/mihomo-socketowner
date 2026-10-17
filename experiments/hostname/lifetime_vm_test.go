//go:build linux && amd64 && hostname_vm

package hostname

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

func assertObserverUnavailable(t *testing.T, p *probe, c connection, key flowKey) {
	t.Helper()
	if value, err := lookupPublished[observation](p, "send_snapshots", c.cookie); !errors.Is(err, errObserverUnavailable) || value != (observation{}) {
		t.Fatalf("unavailable observer exposed snapshot: %+v, %v", value, err)
	}
	if value, err := lookupPublished[flowObservation](p, "send_flows", key); !errors.Is(err, errObserverUnavailable) || value != (flowObservation{}) {
		t.Fatalf("unavailable observer exposed flow: %+v, %v", value, err)
	}
}

func assertRetired(t *testing.T, p *probe, c connection, key flowKey) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		var state uint64
		err := p.collection.Maps["send_guards"].Lookup(c.cookie, &state)
		if (err == nil && state == 3) || errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil || time.Now().After(deadline) {
			t.Fatalf("socket not retired: %d, %v", state, err)
		}
		time.Sleep(time.Millisecond)
	}
	if value, err := stableLookupFor[observation](p, "send_snapshots", c.cookie); (!errors.Is(err, errSendAmbiguous) && !errors.Is(err, ebpf.ErrKeyNotExist)) || value != (observation{}) {
		t.Fatalf("retired snapshot exposed: %+v, %v", value, err)
	}
	if value, err := stableLookupFor[flowObservation](p, "send_flows", key); (!errors.Is(err, errSendAmbiguous) && !errors.Is(err, ebpf.ErrKeyNotExist)) || value != (flowObservation{}) {
		t.Fatalf("retired flow exposed: %+v, %v", value, err)
	}
}

func stableLookupFor[T sendRecord](p *probe, name string, key interface{}) (T, error) {
	deadline := time.Now().Add(100 * time.Millisecond)
	for {
		value, err := lookupPublished[T](p, name, key)
		if (!errors.Is(err, errPublicationBusy) && !errors.Is(err, errPublicationChanged)) || time.Now().After(deadline) {
			return value, err
		}
		time.Sleep(time.Millisecond)
	}
}

func namedLifetimeSocket(t *testing.T, f *fixture) (connection, flowKey) {
	t.Helper()
	c := f.open("lifetime.test", "fd-first", "fd")
	f.command("handshake %d", c.slot)
	if name, err := f.flow(c).Observation.hostname(); err != nil || name != "lifetime.test" {
		t.Fatalf("initial flow %q, %v", name, err)
	}
	return c, f.flowKey(c)
}

func assertRetainedName(t *testing.T, p *probe, key flowKey, cookie uint64) {
	t.Helper()
	var raw flowObservation
	if err := p.collection.Maps["send_flows"].Lookup(key, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Cookie != cookie || raw.Observation.Len == 0 {
		t.Fatalf("test lost old positive flow: %+v", raw)
	}
}

func TestVMLifetimeCloseAndDuplicate(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newPublicationFixture(t, network)
			c, key := namedLifetimeSocket(t, f)
			alias := f.alias(c, "unused.test")
			f.command("close %d", alias.slot)
			if name, err := f.flow(c).Observation.hostname(); err != nil || name != "lifetime.test" {
				t.Fatalf("closing one duplicate retired a live socket: %q, %v", name, err)
			}
			f.fault(publicationFault{Mask: 64})
			f.command("close %d", c.slot)
			assertRetainedName(t, f.probe, key, c.cookie)
			assertRetired(t, f.probe, c, key)
		})
	}
}

func TestVMLifetimePeerClose(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, reset := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reset=%t", network, reset), func(t *testing.T) {
				f := newPublicationFixture(t, network)
				c, key := namedLifetimeSocket(t, f)
				f.fault(publicationFault{Mask: 64})
				if reset {
					if err := c.server.SetLinger(0); err != nil {
						t.Fatal(err)
					}
					c.server.Close()
				} else if err := c.server.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				// The client has not closed its descriptor. TCP state changes
				// must retire it without waiting for socket release or timeouts.
				assertRetired(t, f.probe, c, key)
				assertRetainedName(t, f.probe, key, c.cookie)
			})
		}
	}
}

func TestVMLifetimeClientExit(t *testing.T) {
	f := newPublicationFixture(t, "tcp4")
	c, key := namedLifetimeSocket(t, f)
	f.fault(publicationFault{Mask: 64})
	if err := unix.Kill(int(f.pid), unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	assertRetired(t, f.probe, c, key)
	assertRetainedName(t, f.probe, key, c.cookie)
}

func TestVMLifetimeTupleReuse(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newPublicationFixture(t, network)
			old, key := namedLifetimeSocket(t, f)
			f.fault(publicationFault{Mask: 64})
			old.server.SetLinger(0)
			old.server.Close()
			assertRetired(t, f.probe, old, key)
			f.command("source %d", old.localPort)
			c := f.open("reused.test", "fd-first", "fd")
			if c.cookie == old.cookie || f.flowKey(c) != key {
				t.Fatal("test did not reuse the exact flow tuple with a new socket")
			}
			assertRetainedName(t, f.probe, key, old.cookie)
			if value, err := lookupPublished[flowObservation](f.probe, "send_flows", key); !errors.Is(err, errSendAmbiguous) || value != (flowObservation{}) {
				t.Fatalf("reused tuple exposed old name: %+v, %v", value, err)
			}
			f.fault(publicationFault{})
			f.command("handshake %d", c.slot)
			if name, err := f.flow(c).Observation.hostname(); err != nil || name != "reused.test" || wireName(t, c) != name {
				t.Fatalf("reused flow %q, %v", name, err)
			}
		})
	}
}

func TestVMLifetimeCallbackFailure(t *testing.T) {
	f := newPublicationFixture(t, "tcp4")
	f.fault(publicationFault{Mask: 128})
	c := f.accepted(f.command("open flags.test fd-first fd"))
	f.command("handshake %d", c.slot)
	f.assertPublicationFailed()
	f.assertRejected(c)
	if wireName(t, c) != "flags.test" {
		t.Fatal("callback setup failure blocked TLS")
	}
}

func TestVMObserverClosedLinks(t *testing.T) {
	for _, target := range []string{"create", "release", "state", "send", "egress"} {
		t.Run(target, func(t *testing.T) {
			f := newFixtureMode(t, "tcp4", true)
			disableHandshakeProbe(t, f)
			c, key := namedLifetimeSocket(t, f)
			for _, l := range f.probe.session.links {
				if l.name == target {
					if err := l.get().Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			assertRetainedName(t, f.probe, key, c.cookie)
			assertObserverUnavailable(t, f.probe, c, key)
			if wireName(t, c) != "lifetime.test" {
				t.Fatal("detached observation blocked already-sent TLS")
			}
		})
	}
}

func TestVMObserverDetachedLiveFD(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	disableHandshakeProbe(t, f)
	c, key := namedLifetimeSocket(t, f)
	l := f.probe.egress.(interface{ Detach() error })
	if err := l.Detach(); err != nil {
		t.Fatal(err)
	}
	info, err := f.probe.egress.Info()
	if err != nil || info.Cgroup() == nil || info.Cgroup().CgroupId != 0 {
		t.Fatalf("detached link did not retain an inspectable FD: %+v, %v", info, err)
	}
	assertRetainedName(t, f.probe, key, c.cookie)
	assertObserverUnavailable(t, f.probe, c, key)
}

func TestVMObserverProgramReplacement(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	disableHandshakeProbe(t, f)
	c, key := namedLifetimeSocket(t, f)
	replacement, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "no_observation", Type: ebpf.CGroupSKB, AttachType: ebpf.AttachCGroupInetEgress, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err := f.probe.egress.Update(replacement); err != nil {
		t.Fatal(err)
	}
	assertObserverUnavailable(t, f.probe, c, key)
	if err := f.probe.egress.Update(f.probe.collection.Programs["observe_flow"]); err != nil {
		t.Fatal(err)
	}
	assertObserverUnavailable(t, f.probe, c, key) // restoration cannot heal it
}

func TestVMObserverMapReplacement(t *testing.T) {
	for _, name := range []string{"publication_state", "send_guards", "send_snapshots", "send_flows", "send_scope", "send_windows", "empty_window", "control-pointer"} {
		t.Run(name, func(t *testing.T) {
			f := newFixtureMode(t, "tcp4", true)
			disableHandshakeProbe(t, f)
			c, key := namedLifetimeSocket(t, f)
			mapName := name
			if name == "control-pointer" {
				mapName = "publication_state"
			}
			original := f.probe.collection.Maps[mapName]
			spec, err := ebpf.LoadCollectionSpec(f.object)
			if err != nil {
				t.Fatal(err)
			}
			// Socket storage creation also needs the ELF's BTF value type.
			replacement, err := ebpf.NewMap(spec.Maps[mapName])
			if err != nil {
				t.Fatal(err)
			}
			defer replacement.Close()
			defer func() {
				f.probe.collection.Maps[mapName] = original
				if name == "control-pointer" {
					f.probe.publication = original
				}
			}()
			if name == "control-pointer" {
				f.probe.publication = replacement
			} else {
				f.probe.collection.Maps[name] = replacement
			}
			assertObserverUnavailable(t, f.probe, c, key)
			if name == "control-pointer" {
				f.probe.publication = original
			} else {
				f.probe.collection.Maps[name] = original
			}
			assertObserverUnavailable(t, f.probe, c, key)
		})
	}
}

func TestVMObserverLostControl(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	disableHandshakeProbe(t, f)
	c, key := namedLifetimeSocket(t, f)
	original := f.probe.publication
	f.probe.publication = nil
	assertObserverUnavailable(t, f.probe, c, key)
	f.probe.publication = original
	assertObserverUnavailable(t, f.probe, c, key)
}

func TestVMObserverClosedMapWithLease(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	disableHandshakeProbe(t, f)
	c, key := namedLifetimeSocket(t, f)
	if err := f.probe.collection.Maps["send_flows"].Close(); err != nil {
		t.Fatal(err)
	}
	var retained flowObservation
	if err := f.probe.session.maps["send_flows"].lease.Lookup(key, &retained); err != nil || retained.Observation.Len == 0 {
		t.Fatalf("lease did not retain positive data: %+v, %v", retained, err)
	}
	assertObserverUnavailable(t, f.probe, c, key)
}

func TestVMObserverStopAndRestart(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	disableHandshakeProbe(t, f)
	c, key := namedLifetimeSocket(t, f)
	preexisting := f.open("preexisting.test", "fd-first", "fd")
	old := f.probe
	old.stop()
	assertRetainedName(t, old, key, c.cookie)
	assertObserverUnavailable(t, old, c, key)
	fresh, err := attachMode(f.object, f.cgroup, f.sslPath, f.cryptoPath, int(f.pid), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fresh.close)
	f.probe = fresh
	disableHandshakeProbe(t, f)
	for name, prior := range old.session.maps {
		if fresh.session.maps[name].id == prior.id {
			t.Fatal("restart reused an old collection map")
		}
	}
	f.command("handshake %d", preexisting.slot)
	if value, err := lookupPublished[observation](fresh, "send_snapshots", preexisting.cookie); !errors.Is(err, ebpf.ErrKeyNotExist) || value != (observation{}) {
		t.Fatalf("old FD was silently adopted: %+v, %v", value, err)
	}
	if value, err := lookupPublished[flowObservation](fresh, "send_flows", f.flowKey(preexisting)); !errors.Is(err, ebpf.ErrKeyNotExist) || value != (flowObservation{}) {
		t.Fatalf("old flow was silently adopted: %+v, %v", value, err)
	}
	if wireName(t, preexisting) != "preexisting.test" {
		t.Fatal("restart blocked an unobserved existing socket")
	}
	newSocket := f.open("fresh.test", "fd-first", "fd")
	f.command("handshake %d", newSocket.slot)
	if name, err := f.flow(newSocket).Observation.hostname(); err != nil || name != "fresh.test" || wireName(t, newSocket) != name {
		t.Fatalf("fresh session %q, %v", name, err)
	}
	assertObserverUnavailable(t, old, c, key)
}

func TestVMObserverConcurrentStop(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	disableHandshakeProbe(t, f)
	c, key := namedLifetimeSocket(t, f)
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 30; j++ {
				_, err := lookupPublished[flowObservation](f.probe, "send_flows", key)
				if err != nil && !errors.Is(err, errObserverUnavailable) && !errors.Is(err, errPublicationBusy) && !errors.Is(err, errPublicationChanged) {
					t.Errorf("concurrent read: %v", err)
					return
				}
			}
		}()
	}
	f.probe.stop()
	readers.Wait()
	assertObserverUnavailable(t, f.probe, c, key)
}
