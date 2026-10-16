package hostname

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestReadPublished(t *testing.T) {
	lookupError := errors.New("record lookup failed")
	controlError := errors.New("control unavailable")
	for _, tc := range []struct {
		name                                 string
		before, after                        uint64
		beforeErr, recordErr, afterErr, want error
		lookup                               bool
	}{
		{name: "stable", before: publicationStep, after: publicationStep, lookup: true},
		{name: "failed-before", before: publicationFailed, want: errPublicationFailed},
		{name: "active-before", before: publicationStep + 1, want: errPublicationBusy},
		{name: "active-after", after: publicationStep + 1, want: errPublicationChanged, lookup: true},
		{name: "entire-write-between-reads", after: publicationStep, want: errPublicationChanged, lookup: true},
		{name: "failed-after", after: publicationFailed, want: errPublicationFailed, lookup: true},
		{name: "missing-control", beforeErr: controlError, want: controlError},
		{name: "lost-control", afterErr: controlError, want: controlError, lookup: true},
		{name: "lookup-error", recordErr: lookupError, want: lookupError, lookup: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads, calls := 0, 0
			control := func() (uint64, error) {
				reads++
				if reads == 1 {
					return tc.before, tc.beforeErr
				}
				return tc.after, tc.afterErr
			}
			got, err := readPublished(control, func(out *string) error { calls++; *out = "stale.test"; return tc.recordErr })
			if !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want %v", err, tc.want)
			}
			if (calls != 0) != tc.lookup {
				t.Fatalf("data lookup called %d times", calls)
			}
			if err != nil && got != "" {
				t.Fatalf("error exposed record %q", got)
			}
			if err == nil && got != "stale.test" {
				t.Fatalf("lost stable record %q", got)
			}
		})
	}
}

func TestPublicationMapContract(t *testing.T) {
	want := &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1, Flags: unix.BPF_F_RDONLY}
	if err := validatePublicationMap(want); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"missing", "type", "key", "value", "capacity", "writable", "extra-flags"} {
		t.Run(change, func(t *testing.T) {
			m := want.Copy()
			switch change {
			case "missing":
				m = nil
			case "type":
				m.Type = ebpf.Hash
			case "key":
				m.KeySize = 8
			case "value":
				m.ValueSize = 16
			case "capacity":
				m.MaxEntries = 2
			case "writable":
				m.Flags = 0
			case "extra-flags":
				m.Flags |= unix.BPF_F_MMAPABLE
			}
			if err := validatePublicationMap(m); err == nil {
				t.Fatal("accepted incompatible control map")
			}
		})
	}
}
