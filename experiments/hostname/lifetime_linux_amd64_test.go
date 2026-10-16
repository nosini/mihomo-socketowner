package hostname

import (
	"errors"
	"testing"
)

func TestReadObserved(t *testing.T) {
	for _, failAt := range []int{0, 1, 2} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			checks, lookups := 0, 0
			input := observation{Cookie: 42, Len: 11}
			got, err := readObserved(func() error {
				checks++
				if checks == failAt {
					return errObserverUnavailable
				}
				return nil
			}, func() (uint64, error) { return publicationStep, nil }, func(out *observation) error {
				lookups++
				*out = input
				return nil
			}, func(uint64) (uint64, error) { return 1, nil })
			if failAt == 0 {
				if err != nil || got != input || checks != 2 {
					t.Fatalf("stable read: %+v, %v, checks %d", got, err, checks)
				}
			} else if !errors.Is(err, errObserverUnavailable) || got != (observation{}) {
				t.Fatalf("dead observer exposed %+v, %v", got, err)
			}
			if failAt == 1 && lookups != 0 {
				t.Fatal("data was read without initial observer validation")
			}
			if failAt == 2 && lookups != 1 {
				t.Fatal("test did not copy retained data before final validation")
			}
		})
	}
}

func TestLiveLookupRequiresSession(t *testing.T) {
	for _, p := range []*probe{
		{liveSend: true},
		{liveSend: true, session: &observerSession{owner: &probe{}}},
	} {
		value, err := lookupPublished[observation](p, "send_snapshots", uint64(1))
		if !errors.Is(err, errObserverUnavailable) || value != (observation{}) {
			t.Fatalf("missing/foreign session exposed %+v, %v", value, err)
		}
	}
}
