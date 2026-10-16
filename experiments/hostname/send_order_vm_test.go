//go:build linux && amd64 && hostname_vm

package hostname

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/cilium/ebpf"
)

func (f *fixture) alias(c connection, name string) connection {
	f.t.Helper()
	alias := connection{server: c.server}
	line := f.command("alias %d %s", c.slot, name)
	if n, err := fmt.Sscanf(line, "socket %d %d %d %d", &alias.slot, &alias.cookie, &alias.fd, &alias.localPort); err != nil || n != 4 || alias.cookie != c.cookie || alias.fd == c.fd {
		f.t.Fatalf("alias response %q: %v", line, err)
	}
	return alias
}

func (f *fixture) assertSendAmbiguous(c connection) {
	f.t.Helper()
	if value, err := stableLookup[observation](f, "send_snapshots", c.cookie); !errors.Is(err, errSendAmbiguous) || value != (observation{}) {
		f.t.Fatalf("ambiguous snapshot exposed: %+v, %v", value, err)
	}
	if value, err := stableLookup[flowObservation](f, "send_flows", f.flowKey(c)); !errors.Is(err, errSendAmbiguous) || value != (flowObservation{}) {
		f.t.Fatalf("ambiguous flow exposed: %+v, %v", value, err)
	}
	var state uint64
	if err := f.probe.collection.Maps["send_guards"].Lookup(c.cookie, &state); err != nil || state != 3 {
		f.t.Fatalf("send guard %#x: %v", state, err)
	}
}

func (f *fixture) corkPair(c, alias connection, parallel bool) int {
	f.t.Helper()
	op := "cork-pair"
	if parallel {
		op = "parallel"
	}
	var queued int
	line := f.command("%s %d %d", op, c.slot, alias.slot)
	if n, err := fmt.Sscanf(line, "corked %d", &queued); n != 1 || err != nil || queued <= 0 {
		f.t.Fatalf("writes were not deferred: %q", line)
	}
	return queued
}

func TestVMSendDeferredAndParallel(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, tc := range []struct {
			name, second string
			parallel     bool
		}{
			{"deferred/different", "second.test", false},
			{"parallel/different", "second.test", true},
			{"deferred/same", "first.test", false},
			{"parallel/same", "first.test", true},
		} {
			t.Run(network+"/"+tc.name, func(t *testing.T) {
				f := newFixtureMode(t, network, true)
				disableHandshakeProbe(t, f)
				c := f.open("first.test", "fd-first", "fd")
				alias := f.alias(c, tc.second)
				queued := f.corkPair(c, alias, tc.parallel)
				f.command("uncork %d", c.slot)
				f.assertSendAmbiguous(c)
				wire := wireName(t, c)
				if (!tc.parallel && wire != "first.test") || (tc.parallel && wire != "first.test" && wire != tc.second) {
					t.Fatalf("unexpected first ClientHello: %q", wire)
				}
				t.Logf("excluded multiple sends: first ClientHello %q, queued %d", wire, queued)
			})
		}
	}
}

func TestVMSendUnsupportedFirstAttempt(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	disableHandshakeProbe(t, f)
	c := f.open("later.test", "fd-first", "fd")
	f.command("raw %d", c.slot)
	var raw [1]byte
	if _, err := io.ReadFull(c.server, raw[:]); err != nil || raw[0] != 'x' {
		t.Fatalf("raw first send: %q, %v", raw, err)
	}
	f.command("handshake %d", c.slot)
	f.assertSendAmbiguous(c)
	if name := wireName(t, c); name != "later.test" {
		t.Fatalf("guard interrupted later TLS: %q", name)
	}
}

func TestVMSendRejectsRetainedFlow(t *testing.T) {
	f := newPublicationFixture(t, "tcp4")
	c := f.open("first.test", "fd-first", "fd")
	f.command("handshake %d", c.slot)
	if name, err := f.flow(c).Observation.hostname(); err != nil || name != "first.test" {
		t.Fatalf("initial flow %q: %v", name, err)
	}
	// The fault object suppresses flow writes without breaking link health.
	// The independent guard must reject retained data without replacement.
	f.fault(publicationFault{Mask: 64})
	alias := f.alias(c, "second.test")
	f.command("handshake %d", alias.slot)
	var retained flowObservation
	if err := f.probe.collection.Maps["send_flows"].Lookup(f.flowKey(c), &retained); err != nil {
		t.Fatal(err)
	}
	if name, err := retained.Observation.hostname(); err != nil || name != "first.test" {
		t.Fatalf("test did not retain positive flow: %q, %v", name, err)
	}
	f.assertSendAmbiguous(c)
	if wireName(t, c) != "first.test" {
		t.Fatal("guard interrupted networking")
	}
}

func TestVMSendGuardSurvivesRecordEviction(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	disableHandshakeProbe(t, f)
	c := f.open("first.test", "fd-first", "fd")
	alias := f.alias(c, "second.test")
	f.corkPair(c, alias, false)
	f.command("uncork %d", c.slot)
	f.assertSendAmbiguous(c)
	if err := f.probe.collection.Maps["send_snapshots"].Delete(c.cookie); err != nil {
		t.Fatal(err)
	}
	if err := f.probe.collection.Maps["send_flows"].Delete(f.flowKey(c)); err != nil {
		t.Fatal(err)
	}
	// Deletion models lost LRU records. A new sending object on the same live
	// socket cannot turn an ambiguous lifetime back into a first attempt.
	f.command("replace %d third.test", alias.slot)
	f.command("handshake %d", alias.slot)
	f.assertSendAmbiguous(c)
}

func TestVMSendGuardCapacity(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	disableHandshakeProbe(t, f)
	old := f.open("older.test", "fd-first", "fd")
	f.command("handshake %d", old.slot)
	for i := 0; i < 255; i++ {
		c := f.open("unused.test", "fd-first", "fd")
		f.command("close %d", c.slot)
		c.server.Close()
	}
	// Guard entries are never evicted or deleted, including closed sockets.
	// Capacity exhaustion invalidates the collection instead of forgetting
	// that another live socket has already made multiple send attempts.
	c := f.accepted(f.command("open overflow.test fd-first fd"))
	f.command("handshake %d", c.slot)
	f.assertPublicationFailed()
	f.assertRejected(old)
	f.assertRejected(c)
	if name := wireName(t, c); name != "overflow.test" {
		t.Fatalf("guard exhaustion interrupted networking: %q", name)
	}
}

func TestVMSendGuardReadOnly(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	c := f.open("readonly.test", "fd-first", "fd")
	if err := f.probe.collection.Maps["send_guards"].Update(c.cookie, uint64(0), ebpf.UpdateAny); err == nil {
		t.Fatal("userspace reset the send guard")
	}
	if err := f.probe.collection.Maps["send_guards"].Delete(c.cookie); err == nil {
		t.Fatal("userspace removed the send guard")
	}
}
