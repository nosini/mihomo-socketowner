package hostname

import (
	"testing"
	"time"
)

func TestReaderCandidateRejectsMissingAuthority(t *testing.T) {
	for _, candidate := range []*Candidate{nil, {}, {name: "route.invalid", deadline: time.Now().Add(-time.Second)}} {
		if err := candidate.Validate(); err == nil {
			t.Fatal("accepted absent/expired authority")
		}
	}
	var reader *Reader
	if candidate, err := reader.Lookup(TCPFlow{}, time.Now().Add(time.Second)); err == nil || candidate != nil {
		t.Fatal("accepted absent reader")
	}
}
