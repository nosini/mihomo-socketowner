// Package hostname reads optional application hostname evidence from a trusted
// socketowner observer using hostname protocol v1, layout profile 3
// (bounded initial-write retries and final-release guard reclamation).
//
// A candidate is tentative. Call Validate after evaluating rules and immediately
// before committing the route; fall back to ordinary routing on any error.
// Evidence identifies an ordinary transport TLS name, never an ECH inner name.
// The original destination must remain the dial destination.
//
// Only Linux amd64 is supported. The observer is installed and managed separately;
// this module never loads programs, opens pins or inspects application processes.
package hostname

import (
	"errors"
	"fmt"
	"net/netip"
)

const ProtocolVersion = 1
const LayoutProfile = 1  // frozen historical profile
const ReclaimProfile = 2 // frozen final-release profile
const InitialWindowProfile = 3

// ErrUnavailable means the observer session cannot authorize a name. All errors
// from this package require ordinary routing fallback; error text is diagnostic.
var ErrUnavailable = errors.New("hostname observer session is unavailable")

// ErrNoFlow means the observer has no record of the flow, normally because
// another process opened the connection (or its record was evicted). Observed
// connections have a record from their SYN onward, so callers should return
// unknown at once instead of waiting. It wraps ErrUnavailable.
var ErrNoFlow = fmt.Errorf("%w: flow was not observed", ErrUnavailable)

// TCPFlow identifies the full post-NAT accepted TCP flow in its network namespace.
// Source and destination must be unzoned, valid, same-family endpoints with
// nonzero ports. IPv4-mapped IPv6 addresses are normalized to IPv4.
// The proxy socket cookie is different from the application socket cookie.
type TCPFlow struct {
	Netns               uint64
	Source, Destination netip.AddrPort
}
