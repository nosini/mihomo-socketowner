package hostname

import (
	"errors"
	"testing"
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
