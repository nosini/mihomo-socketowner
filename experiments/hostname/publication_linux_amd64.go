package hostname

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	publicationFailed  uint64 = 1 << 63
	publicationWriters uint64 = 0xffff
	publicationStep    uint64 = 1 << 16
)

var (
	errPublicationFailed  = errors.New("hostname publication failed for this observer")
	errPublicationBusy    = errors.New("hostname publication is in progress")
	errPublicationChanged = errors.New("hostname publication changed during lookup")
)

func validatePublicationMap(m *ebpf.MapSpec) error {
	if m == nil || m.Type != ebpf.Array || m.KeySize != 4 || m.ValueSize != 8 || m.MaxEntries != 1 || m.Flags != unix.BPF_F_RDONLY {
		return fmt.Errorf("incompatible publication control map")
	}
	return nil
}

// readPublished returns no record on any failure, including a change between
// the two control reads. This is not a cached health check. The data lookup
// must belong to the very same observer collection as the control map.
func readPublished[T any](control func() (uint64, error), record func(*T) error) (T, error) {
	var zero T
	before, err := control()
	if err != nil {
		return zero, err
	}
	if before&publicationFailed != 0 {
		return zero, errPublicationFailed
	}
	if before&publicationWriters != 0 {
		return zero, errPublicationBusy
	}
	var value T
	if err := record(&value); err != nil {
		return zero, err
	}
	after, err := control()
	if err != nil {
		return zero, err
	}
	if after&publicationFailed != 0 {
		return zero, errPublicationFailed
	}
	if after != before {
		return zero, errPublicationChanged
	}
	return value, nil
}

func (p *probe) publicationWord() (uint64, error) {
	var word uint64
	err := p.publication.Lookup(uint32(0), &word)
	return word, err
}

func lookupPublished[T any](p *probe, name string, key interface{}) (T, error) {
	lookup := func(value *T) error { return p.collection.Maps[name].Lookup(key, value) }
	if p.publication == nil {
		// The intentionally unsafe baseline retains its original behavior.
		var value T
		err := lookup(&value)
		return value, err
	}
	return readPublished(p.publicationWord, lookup)
}
