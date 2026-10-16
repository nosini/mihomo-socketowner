package hostname

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

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

func validateSendGuardMap(m *ebpf.MapSpec) error {
	if m == nil || m.Type != ebpf.Hash || m.KeySize != 8 || m.ValueSize != 8 || m.MaxEntries != 256 || m.Flags != unix.BPF_F_RDONLY {
		return fmt.Errorf("incompatible send guard map")
	}
	return nil
}

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
