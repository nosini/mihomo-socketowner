package hostname

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestReadSendPublished(t *testing.T) {
	missing := errors.New("guard missing")
	for _, tc := range []struct {
		name       string
		state      uint64
		named      bool
		guardError error
		interleave bool
		want       error
	}{
		{name: "single-send", state: 1, named: true},
		{name: "syn-identity", state: 0},
		{name: "positive-without-send", state: 0, named: true, want: errSendUnobserved},
		{name: "second-send-retained-flow", state: 3, named: true, want: errSendAmbiguous},
		{name: "second-send-empty-flow", state: 3, want: errSendAmbiguous},
		{name: "invalid-state", state: 2, named: true, want: errSendAmbiguous},
		{name: "lost-guard", named: true, guardError: missing, want: missing},
		{name: "send-after-guard-read", state: 1, named: true, interleave: true, want: errPublicationChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generation := publicationStep
			input := flowObservation{Cookie: 123, Observation: observation{Cookie: 123}}
			if tc.named {
				input.Observation.Len = 12
				copy(input.Observation.Hostname[:], "first.test")
			}
			got, err := readSendPublished(func() (uint64, error) { return generation, nil }, func(out *flowObservation) error {
				*out = input // stale positive data really was copied
				return nil
			}, func(cookie uint64) (uint64, error) {
				if cookie != input.Cookie {
					t.Fatalf("guard checked for wrong socket: %d", cookie)
				}
				if tc.interleave {
					generation += publicationStep
				}
				return tc.state, tc.guardError
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want %v", err, tc.want)
			}
			if err != nil && got != (flowObservation{}) {
				t.Fatalf("rejected read exposed %+v", got)
			}
			if err == nil && got != input {
				t.Fatal("lost stable record")
			}
		})
	}
}

func TestSendGuardMapContract(t *testing.T) {
	want := &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 256, Flags: unix.BPF_F_RDONLY}
	if err := validateSendGuardMap(want); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"missing", "evicting", "key", "value", "capacity", "writable", "extra-flags"} {
		t.Run(change, func(t *testing.T) {
			m := want.Copy()
			switch change {
			case "missing":
				m = nil
			case "evicting":
				m.Type = ebpf.LRUHash
			case "key":
				m.KeySize = 4
			case "value":
				m.ValueSize = 16
			case "capacity":
				m.MaxEntries++
			case "writable":
				m.Flags = 0
			case "extra-flags":
				m.Flags |= unix.BPF_F_NO_PREALLOC
			}
			if err := validateSendGuardMap(m); err == nil {
				t.Fatal("accepted incompatible send guard")
			}
		})
	}
}
