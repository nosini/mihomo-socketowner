//go:build linux && amd64 && hostname_vm

package hostname

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func assertReclaimed(t *testing.T, f *fixture, cookie uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		var state uint64
		err := f.probe.collection.Maps["send_guards"].Lookup(cookie, &state)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return
		}
		if err != nil || time.Now().After(deadline) {
			t.Fatalf("guard not reclaimed: %d, %v", state, err)
		}
		time.Sleep(time.Millisecond)
	}
}
func assertPublicationHealthy(t *testing.T, f *fixture) {
	t.Helper()
	word, err := f.probe.publicationWord()
	if err != nil || word&(publicationFailed|publicationWriters) != 0 {
		t.Fatalf("unhealthy publication: %#x %v", word, err)
	}
}
func TestVMReclaimChurn(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newFixtureMode(t, network, true)
			disableHandshakeProbe(t, f)
			anchor := f.open("anchor.test", "fd-first", "fd")
			f.command("handshake %d", anchor.slot)
			if wireName(t, anchor) != "anchor.test" {
				t.Fatal("anchor TLS")
			}
			// Four tablefuls of lifetimes recycle slots while a live guard and readers
			// remain. Reclamation must not reset or evict the still-live guard.
			var wg sync.WaitGroup
			stop := make(chan struct{})
			key := f.flowKey(anchor)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					_, _ = lookupPublished[flowObservation](f.probe, "send_flows", key)
				}
			}()
			defer func() { close(stop); wg.Wait() }()
			for i := 0; i < 1024; i++ {
				c := f.open("churn.test", "fd-first", "fd")
				f.command("handshake %d", c.slot)
				if name := wireName(t, c); name != "churn.test" {
					t.Fatalf("churn %d TLS: %q", i, name)
				}
				f.command("close %d", c.slot)
				assertReclaimed(t, f, c.cookie)
				c.server.Close()
			}
			var state uint64
			if err := f.probe.collection.Maps["send_guards"].Lookup(anchor.cookie, &state); err != nil || state != 1 {
				t.Fatalf("churn changed live guard: %d %v", state, err)
			}
			// A second attempt stays excluded after all that hash-slot reuse.
			f.command("replace %d second.test", anchor.slot)
			f.command("handshake %d", anchor.slot)
			f.assertSendAmbiguous(anchor)
			c := f.open("fresh.test", "fd-first", "fd")
			f.command("handshake %d", c.slot)
			if name, err := f.flow(c).Observation.hostname(); err != nil || name != "fresh.test" {
				t.Fatalf("fresh flow %q %v", name, err)
			}
		})
	}
}
func TestVMReclaimRetainedPositive(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newPublicationFixture(t, network)
			c, key := namedLifetimeSocket(t, f)
			f.fault(publicationFault{Mask: 64})
			f.command("close %d", c.slot)
			assertReclaimed(t, f, c.cookie)
			assertRetainedName(t, f.probe, key, c.cookie)
			assertRetired(t, f.probe, c, key)
			for i := 0; i < 512; i++ {
				fresh := f.open("unused.test", "fd-first", "fd")
				f.command("close %d", fresh.slot)
				fresh.server.Close()
			}
			assertRetired(t, f.probe, c, key)
			assertRetainedName(t, f.probe, key, c.cookie)
			assertPublicationHealthy(t, f)
		})
	}
}
func TestVMReclaimPeerCloseRequiresRelease(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newPublicationFixture(t, network)
			c, key := namedLifetimeSocket(t, f)
			c.server.SetLinger(0)
			c.server.Close()
			assertRetired(t, f.probe, c, key)
			var state uint64
			if err := f.probe.collection.Maps["send_guards"].Lookup(c.cookie, &state); err != nil || state != 3 {
				t.Fatalf("reclaimed before final release: %d %v", state, err)
			}
			f.command("close %d", c.slot)
			assertReclaimed(t, f, c.cookie)
			assertPublicationHealthy(t, f)
		})
	}
}
func TestVMReclaimOrphanedOutput(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newFixtureMode(t, network, true)
			disableHandshakeProbe(t, f)
			c := f.open("orphan.test", "fd-first", "fd")
			f.command("cork-one %d", c.slot)
			// Final release flushes queued bytes after guard deletion. Late egress
			// must not recreate authority or poison otherwise healthy publication.
			f.command("close %d", c.slot)
			if wireName(t, c) != "orphan.test" {
				t.Fatal("orphan output lost")
			}
			assertReclaimed(t, f, c.cookie)
			assertPublicationHealthy(t, f)
			fresh := f.open("healthy.test", "fd-first", "fd")
			f.command("handshake %d", fresh.slot)
			if name, err := f.flow(fresh).Observation.hostname(); err != nil || name != "healthy.test" {
				t.Fatalf("late output poisoned new socket: %q %v", name, err)
			}
		})
	}
}
func TestVMReclaimDeleteFailure(t *testing.T) {
	for _, mask := range []uint64{256, 512} {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			f := newPublicationFixture(t, "tcp4")
			c, key := namedLifetimeSocket(t, f)
			f.fault(publicationFault{Mask: 64 | mask})
			f.command("close %d", c.slot)
			f.assertPublicationFailed()
			var kernelError int64
			if err := f.probe.collection.Maps["publication_error"].Lookup(uint32(0), &kernelError); err != nil || kernelError != -int64(unix.ENOENT) {
				t.Fatalf("not a real delete error: %d %v", kernelError, err)
			}
			assertRetainedName(t, f.probe, key, c.cookie)
			f.assertRejected(c)
			var fresh connection
			line := f.command("open fallback.test fd-first fd")
			if _, err := fmt.Sscanf(line, "socket %d %d %d %d", &fresh.slot, &fresh.cookie, &fresh.fd, &fresh.localPort); err != nil {
				t.Fatal(err)
			}
			f.listener.SetDeadline(time.Now().Add(time.Second))
			var err error
			fresh.server, err = f.listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.server.Close()
			f.command("handshake %d", fresh.slot)
			if wireName(t, fresh) != "fallback.test" {
				t.Fatal("delete failure interrupted TLS")
			}
		})
	}
}

func TestVMReclaimObserverChurn(t *testing.T) {
	r := newObserverVMRun(t)
	observer := r.start()
	for i := 0; i < 512; i++ {
		var slot int
		if _, err := fmt.Sscanf(r.f.command("open churn.test fd-first fd"), "socket %d", &slot); err != nil {
			t.Fatal(err)
		}
		r.f.listener.SetDeadline(time.Now().Add(5 * time.Second))
		peer, err := r.f.listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		r.f.command("close %d", slot)
		peer.Close()
	}
	select {
	case <-observer.done:
		t.Fatalf("observer restarted under sequential churn: %v", observer.err)
	default:
	}
	r.connect().named(t)
}

func TestVMReclaimHeldCallbacks(t *testing.T) {
	f := newPublicationFixture(t, "tcp4")
	command := func(op byte, want uint32) {
		t.Helper()
		packet := make([]byte, 64)
		packet[14] = op
		got, _, err := f.probe.collection.Programs["test_reclaim"].Test(packet)
		if err != nil || got != want {
			t.Fatalf("command %d: %d %v", op, got, err)
		}
	}
	const cookie = ^uint64(0)
	command(0, 1) // seed a synthetic guard using the real map
	command(1, 1) // two real callback/publication leases held across TestRun
	command(1, 1)
	command(2, 1) // retire, but cannot delete a guard with outstanding pointers
	var guard uint64
	if err := f.probe.collection.Maps["send_guards"].Lookup(cookie, &guard); err != nil || guard != 1 {
		t.Fatalf("premature delete: %d %v", guard, err)
	}
	command(1, 0) // retirement prevents any new lease
	command(3, 1) // one old callback still owns a pointer
	if err := f.probe.collection.Maps["send_guards"].Lookup(cookie, &guard); err != nil {
		t.Fatal("deleted before final callback", err)
	}
	command(3, 1) // final old callback performs deletion before publication end
	assertReclaimed(t, f, cookie)
	command(2, 1) // duplicate retirement does not delete twice or poison
	command(1, 0) // late callback cannot recreate the guard
	assertReclaimed(t, f, cookie)
	assertPublicationHealthy(t, f)
}
