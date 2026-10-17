//go:build linux && amd64 && hostname_vm

package hostname

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type publicationFault struct{ Mask, InitialState uint64 }

func newPublicationFixture(t *testing.T, network string) *fixture {
	t.Helper()
	object := os.Getenv("HOSTNAME_VM_FAULT_OBJECT")
	if object == "" {
		t.Skip("set HOSTNAME_VM_FAULT_OBJECT to the test-only fault object")
	}
	f := newFixtureObject(t, network, true, object)
	disableHandshakeProbe(t, f)
	if f.probe.collection.Maps["publication_faults"] == nil || f.probe.collection.Programs["test_publication"] == nil {
		t.Fatal("fault object lacks test-only controls")
	}
	return f
}
func (f *fixture) fault(config publicationFault) {
	f.t.Helper()
	if err := f.probe.collection.Maps["publication_faults"].Update(uint32(0), config, ebpf.UpdateAny); err != nil {
		f.t.Fatal(err)
	}
}
func (f *fixture) publicationCommand(command byte) uint32 {
	f.t.Helper()
	packet := make([]byte, 64)
	// Socket-filter TestRun pulls the Ethernet header before running BPF.
	packet[14] = command
	ret, _, err := f.probe.collection.Programs["test_publication"].Test(packet)
	if err != nil {
		f.t.Fatal(err)
	}
	return ret
}
func (f *fixture) assertPublicationFailed() {
	f.t.Helper()
	word, err := f.probe.publicationWord()
	if err != nil || word&publicationFailed == 0 || word&publicationWriters != 0 {
		f.t.Fatalf("failed publication word %#x: %v", word, err)
	}
	if err := f.probe.publication.Update(uint32(0), uint64(0), ebpf.UpdateAny); err == nil {
		f.t.Fatal("userspace reset the read-only failure latch")
	}
}
func (f *fixture) assertRejected(c connection) {
	f.t.Helper()
	if value, err := lookupPublished[observation](f.probe, "send_snapshots", c.cookie); !errors.Is(err, errPublicationFailed) || value != (observation{}) {
		f.t.Fatalf("snapshot exposed after failure: %+v, %v", value, err)
	}
	if value, err := lookupPublished[flowObservation](f.probe, "send_flows", f.flowKey(c)); !errors.Is(err, errPublicationFailed) || value != (flowObservation{}) {
		f.t.Fatalf("flow exposed after failure: %+v, %v", value, err)
	}
}

func TestVMPublicationNormalObject(t *testing.T) {
	f := newFixtureMode(t, "tcp4", true)
	if f.probe.collection.Maps["publication_faults"] != nil || f.probe.collection.Programs["test_publication"] != nil || f.probe.collection.Maps["packet_test_evidence"] != nil || f.probe.collection.Programs["test_packet"] != nil || f.probe.collection.Maps["reclaim_test_state"] != nil || f.probe.collection.Programs["test_reclaim"] != nil || f.probe.collection.Maps["retry_test_counts"] != nil {
		t.Fatal("ordinary observer contains fault controls")
	}
	if err := f.probe.publication.Update(uint32(0), uint64(0), ebpf.UpdateAny); err == nil {
		t.Fatal("userspace can write control word")
	}
}

func TestVMPublicationFailedInvalidation(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, target := range []struct {
			name string
			mask uint64
		}{{"snapshot", 1}, {"flow", 2}} {
			t.Run(network+"/"+target.name, func(t *testing.T) {
				f := newPublicationFixture(t, network)
				c := f.open("before-failure.test", "name-first", "fd")
				f.command("handshake %d", c.slot)
				if name, err := f.flow(c).Observation.hostname(); err != nil || name != "before-failure.test" {
					t.Fatalf("initial flow %q: %v", name, err)
				}
				f.fault(publicationFault{Mask: target.mask})
				f.command("raw %d", c.slot)
				f.assertPublicationFailed()
				var errno int64
				if err := f.probe.collection.Maps["publication_error"].Lookup(uint32(0), &errno); err != nil || errno != -int64(unix.EEXIST) {
					t.Fatalf("update did not fail with EEXIST: %d, %v", errno, err)
				}
				// Show the dangerous old value really remains in the failed map.
				var old observation
				if target.mask == 1 {
					if err := f.probe.collection.Maps["send_snapshots"].Lookup(c.cookie, &old); err != nil {
						t.Fatal(err)
					}
				} else {
					var flow flowObservation
					if err := f.probe.collection.Maps["send_flows"].Lookup(f.flowKey(c), &flow); err != nil {
						t.Fatal(err)
					}
					old = flow.Observation
				}
				if name, err := old.hostname(); err != nil || name != "before-failure.test" {
					t.Fatalf("stale value was not retained: %q, %v", name, err)
				}
				f.assertRejected(c)
				f.fault(publicationFault{}) // turning injection off cannot heal it
				f.command("raw %d", c.slot)
				f.assertRejected(c)
				if name := wireName(t, c); name != "before-failure.test" {
					t.Fatalf("publication failure interrupted TLS: %q", name)
				}
			})
		}
	}
}

func TestVMPublicationFailedInsertion(t *testing.T) {
	for _, target := range []struct {
		name string
		mask uint64
	}{{"snapshot", 8}, {"flow", 16}, {"scope", 4}, {"send-guard", 32}, {"send-window", 1024}} {
		t.Run(target.name, func(t *testing.T) {
			f := newPublicationFixture(t, "tcp4")
			old := f.open("older.test", "fd-first", "fd")
			f.command("handshake %d", old.slot)
			if name, err := f.lookup(old).hostname(); err != nil || name != "older.test" {
				t.Fatalf("initial snapshot %q: %v", name, err)
			}
			f.fault(publicationFault{Mask: target.mask})
			// The flow/scope error can happen during connect, before handshake.
			c := f.accepted(f.command("open new.test fd-first fd"))
			f.command("handshake %d", c.slot)
			f.assertPublicationFailed()
			if target.mask != 4 {
				var errno int64
				if err := f.probe.collection.Maps["publication_error"].Lookup(uint32(0), &errno); err != nil || errno != -int64(unix.ENOENT) {
					t.Fatalf("insertion did not fail with ENOENT: %d, %v", errno, err)
				}
			}
			f.assertRejected(old)
			f.assertRejected(c)
			if name := wireName(t, c); name != "new.test" {
				t.Fatalf("unobserved socket lost connectivity: %q", name)
			}
		})
	}
}

func TestVMPublicationActiveWriters(t *testing.T) {
	f := newPublicationFixture(t, "tcp4")
	c := f.open("guarded.test", "fd-first", "fd")
	for i := 0; i < 2; i++ {
		if f.publicationCommand(1) != 1 {
			t.Fatal("could not begin test writer")
		}
	}
	f.command("handshake %d", c.slot)
	var raw observation
	if err := f.probe.collection.Maps["send_snapshots"].Lookup(c.cookie, &raw); err != nil || raw.Len == 0 {
		t.Fatalf("test has no fully copied record: %+v, %v", raw, err)
	}
	for i := 0; i < 2; i++ {
		if value, err := lookupPublished[observation](f.probe, "send_snapshots", c.cookie); !errors.Is(err, errPublicationBusy) || value != (observation{}) {
			t.Fatalf("read with active writer: %+v, %v", value, err)
		}
		if f.publicationCommand(2) != 1 {
			t.Fatal("could not end test writer")
		}
	}
	if name, err := f.lookup(c).hostname(); err != nil || name != "guarded.test" {
		t.Fatalf("completed publication %q: %v", name, err)
	}
}

func TestVMPublicationCounterExhaustion(t *testing.T) {
	for _, tc := range []struct {
		name string
		word uint64
	}{{"writers", publicationWriters}, {"generation", ^(publicationFailed | publicationWriters)}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPublicationFixture(t, "tcp4")
			f.fault(publicationFault{InitialState: tc.word})
			if f.publicationCommand(3) != 1 {
				t.Fatal("could not prepare boundary state")
			}
			if f.publicationCommand(1) != 0 {
				t.Fatal("counter wrapped instead of invalidating publication")
			}
			word, err := f.probe.publicationWord()
			if err != nil || word != tc.word|publicationFailed {
				t.Fatalf("unexpected exhausted state %#x: %v", word, err)
			}
		})
	}
}
