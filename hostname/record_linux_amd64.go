package hostname

import (
	"errors"
	"fmt"
	"strings"
)

var errObserverUnavailable = ErrUnavailable

type observation struct {
	Cookie   uint64
	BootNS   uint64
	TGID     uint32
	FD       int32
	Len      int32
	Pad      uint32
	Hostname [256]byte
}

type flowKey struct {
	Netns                       uint64
	Source, Destination         [16]byte
	SourcePort, DestinationPort uint16
	Pad                         uint32
}

type flowObservation struct {
	Cookie               uint64
	Observation          observation
	Sequence, PayloadLen uint32
	PacketNS             uint64
}

type sendRecord interface {
	sendCookie() uint64
	hasHostname() bool
}

func (o observation) sendCookie() uint64     { return o.Cookie }
func (o observation) hasHostname() bool      { return o.Len != 0 }
func (o flowObservation) sendCookie() uint64 { return o.Cookie }
func (o flowObservation) hasHostname() bool  { return o.Observation.Len != 0 }

var (
	errSendUnobserved = errors.New("hostname has no observed send attempt")
	errSendAmbiguous  = errors.New("hostname excluded by the socket send guard")
)

func checkSendState(state uint64, named bool) error {
	switch state {
	case 0:
		// The SYN publishes flow identity before a send exists. That empty
		// record is useful diagnostic evidence, never a positive hostname.
		if named {
			return errSendUnobserved
		}
		return nil
	case 1:
		return nil
	default:
		return errSendAmbiguous
	}
}

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

func (o observation) hostname() (string, error) {
	if o.Len < 2 || o.Len >= int32(len(o.Hostname)) || o.Hostname[o.Len-1] != 0 {
		return "", fmt.Errorf("missing or truncated hostname")
	}
	name := string(o.Hostname[:o.Len-1])
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return "", fmt.Errorf("invalid hostname length")
	}
	// IPs are not DNS routing names, including numeric IPv4 input.
	numeric := true
	for _, c := range name {
		if c != '.' && (c < '0' || c > '9') {
			numeric = false
		}
	}
	if numeric {
		return "", fmt.Errorf("numeric hostname")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("invalid hostname character")
			}
		}
	}
	// Validate the original characters before case folding: Unicode case
	// folding can otherwise turn an unsupported character into ASCII.
	return strings.ToLower(name), nil
}
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

func readSendPublished[T sendRecord](control func() (uint64, error), lookup func(*T) error, guard func(uint64) (uint64, error)) (T, error) {
	return readPublished(control, func(value *T) error {
		if err := lookup(value); err != nil {
			return err
		}
		state, err := guard((*value).sendCookie())
		if err != nil {
			return err
		}
		return checkSendState(state, (*value).hasHostname())
	})
}
func readObserved[T sendRecord](healthy func() error, control func() (uint64, error), lookup func(*T) error, guard func(uint64) (uint64, error)) (T, error) {
	return readSendPublished(func() (uint64, error) {
		if err := healthy(); err != nil {
			return 0, err
		}
		return control()
	}, lookup, guard)
}
