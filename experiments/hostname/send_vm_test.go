//go:build linux && amd64 && hostname_vm

package hostname

import (
	"fmt"
	"testing"
	"time"
)

func disableHandshakeProbe(t *testing.T, f *fixture) {
	t.Helper()
	if err := f.probe.uprobe.Close(); err != nil {
		t.Fatal(err)
	}
	f.probe.uprobe = nil
}

func TestVMSendLiveFrames(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, order := range []string{"name-first", "fd-first"} {
			for _, op := range []string{"handshake", "thread", "implicit"} {
				t.Run(network+"/"+order+"/"+op, func(t *testing.T) {
					f := newFixtureMode(t, network, true)
					disableHandshakeProbe(t, f)
					c := f.open("live-send.test", order, "fd")
					start := bootNS(t)
					f.command("%s %d", op, c.slot)
					o := f.lookup(c)
					if name, err := o.hostname(); name != "live-send.test" || err != nil {
						t.Fatalf("send name %q, stage %d: %v", name, o.Pad, err)
					}
					if wireName(t, c) != "live-send.test" || o.BootNS < start || o.BootNS > bootNS(t) {
						t.Fatal("send/wire evidence mismatch")
					}
				})
			}
		}
	}
}

func TestVMSendAbandonedSetup(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	disableHandshakeProbe(t, f)
	c := f.open("abandoned.test", "fd-first", "fd")
	f.command("fail %d", c.slot)
	f.absent(c)
	c.server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var b [1]byte
	if n, err := c.server.Read(b[:]); n != 0 || err == nil {
		t.Fatalf("cancelled setup emitted bytes: %d, %v", n, err)
	}
	f.command("replace %d actual.test", c.slot)
	f.command("handshake %d", c.slot)
	o := f.lookup(c)
	if name, err := o.hostname(); err != nil || name != "actual.test" || wireName(t, c) != name {
		t.Fatalf("replacement send %q, stage %d: %v", name, o.Pad, err)
	}
}

func TestVMSendConcurrentAndReuse(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	disableHandshakeProbe(t, f)
	var live []connection
	for i := 0; i < 24; i++ {
		live = append(live, f.open(fmt.Sprintf("send-%d.test", i), "name-first", "dup"))
	}
	for i := len(live) - 1; i >= 0; i-- {
		c := live[i]
		f.command("thread %d", c.slot)
		want := fmt.Sprintf("send-%d.test", i)
		if got, err := f.lookup(c).hostname(); got != want || err != nil || wireName(t, c) != want {
			t.Fatalf("concurrent send %d: %q, %v", i, got, err)
		}
		f.command("close %d", c.slot)
	}
	for i := 0; i < 64; i++ {
		want := fmt.Sprintf("send-reuse-%d.test", i)
		c := f.open(want, "fd-first", "fd")
		f.command("handshake %d", c.slot)
		if got, err := f.lookup(c).hostname(); got != want || err != nil || wireName(t, c) != want {
			t.Fatalf("send reuse %d: %q, %v", i, got, err)
		}
		f.command("close %d", c.slot)
	}
}

func TestVMSendSharedSocketObjects(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	disableHandshakeProbe(t, f)
	old := f.open("abandoned.test", "fd-first", "fd")
	f.command("fail %d", old.slot)
	f.absent(old)
	c := connection{server: old.server}
	line := f.command("alias %d active.test", old.slot)
	if n, err := fmt.Sscanf(line, "socket %d %d %d", &c.slot, &c.cookie, &c.fd); err != nil || n != 3 || c.cookie != old.cookie || c.fd == old.fd {
		t.Fatalf("alias response %s: %v", line, err)
	}
	// The abandoned SSL object is still alive and points to this socket too.
	f.command("thread %d", c.slot)
	if name, err := f.lookup(c).hostname(); err != nil || name != "active.test" || wireName(t, c) != name {
		t.Fatalf("wrong active object: %q, %v", name, err)
	}
}

func TestVMSendUnknownPathInvalidates(t *testing.T) {
	for _, op := range []string{"raw", "raw-child"} {
		t.Run(op, func(t *testing.T) {
			f := newFixtureMode(t, "tcp4", true)
			disableHandshakeProbe(t, f)
			c := f.open("initial.test", "name-first", "fd")
			f.command("handshake %d", c.slot)
			if name, err := f.lookup(c).hostname(); err != nil || name != "initial.test" {
				t.Fatalf("initial name %q: %v", name, err)
			}
			f.command("%s %d", op, c.slot)
			var o observation
			if err := f.probe.collection.Maps["send_snapshots"].Lookup(c.cookie, &o); err != nil {
				t.Fatal(err)
			}
			if o.Cookie != c.cookie || o.Len != 0 || o.Pad != 1 {
				t.Fatalf("unsupported send retained valid evidence: %+v", o)
			}
			if o := f.flow(c); o.Observation.Len != 0 {
				t.Fatal("unsupported send retained old flow evidence")
			}
			if op == "raw-child" && o.TGID == f.pid {
				t.Fatal("test did not transfer sending to a different process")
			}
			// Invalidating metadata did not interfere with the first TLS write.
			if name := wireName(t, c); name != "initial.test" {
				t.Fatalf("wire name %q", name)
			}
		})
	}
}

func TestVMSendUnsupported(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		absent     bool
	}{
		{"memory.test", "memory", true}, {"-", "fd", false}, {"bad/name", "fd", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixtureMode(t, "tcp4", true)
			disableHandshakeProbe(t, f)
			c := f.open(tc.name, "fd-first", tc.mode)
			f.command("handshake %d", c.slot)
			if tc.absent {
				f.absent(c)
			} else if name, err := f.lookup(c).hostname(); err == nil {
				t.Fatalf("unsupported hostname %q", name)
			}
		})
	}
}
