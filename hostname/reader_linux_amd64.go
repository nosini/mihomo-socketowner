package hostname

import (
	"context"
	"errors"
	"time"
)

// Reader owns one authenticated observer session. Its methods, and candidates
// from it, may be used concurrently. Close is idempotent and revokes candidates.
type Reader struct{ authority *authorityReader }

// DialReader authenticates the root observer and obtains only frozen read-only
// maps and a kernel peer pidfd. It never opens pins or reopens a numeric PID.
func DialReader(path string, deadline time.Time) (*Reader, error) {
	return DialReaderContext(context.Background(), path, deadline)
}

// DialReaderContext also interrupts bootstrap reads when configuration is
// disabled or replaced. The original deadline still bounds every I/O operation.
func DialReaderContext(ctx context.Context, path string, deadline time.Time) (*Reader, error) {
	r, _, err := dialAuthorityContext(ctx, path, deadline)
	if err != nil {
		return nil, err
	}
	return &Reader{authority: r}, nil
}

func (r *Reader) Close() {
	if r != nil && r.authority != nil {
		r.authority.close()
	}
}

// Candidate retains the original reader instance and exact record. Name is a
// tentative ordinary TLS name, never an ECH-inner claim. Validate must run after
// rule evaluation and before committing an outbound. There is no cached grant.
type Candidate struct {
	reader   *authorityReader
	key      flowKey
	record   flowObservation
	name     string
	deadline time.Time
}

func (c *Candidate) Name() string {
	if c == nil {
		return ""
	}
	return c.name
}

func (r *Reader) Lookup(flow TCPFlow, deadline time.Time) (*Candidate, error) {
	if r == nil || r.authority == nil || flow.Netns == 0 || !flow.Source.IsValid() || !flow.Destination.IsValid() || flow.Source.Port() == 0 || flow.Destination.Port() == 0 || flow.Source.Addr().Zone() != "" || flow.Destination.Addr().Zone() != "" || flow.Source.Addr().Unmap().Is4() != flow.Destination.Addr().Unmap().Is4() || !time.Now().Before(deadline) {
		return nil, errors.New("unusable hostname flow or deadline")
	}
	key := flowKey{Netns: flow.Netns, Source: flow.Source.Addr().Unmap().As16(), Destination: flow.Destination.Addr().Unmap().As16(), SourcePort: flow.Source.Port(), DestinationPort: flow.Destination.Port()}
	record, err := r.authority.lookup(key)
	if err != nil {
		return nil, err
	}
	name, err := record.Observation.hostname()
	if err != nil || record.Cookie == 0 || record.Cookie != record.Observation.Cookie || !time.Now().Before(deadline) {
		return nil, errors.New("unusable hostname candidate")
	}
	return &Candidate{reader: r.authority, key: key, record: record, name: name, deadline: deadline}, nil
}

func (c *Candidate) Validate() error {
	if c == nil || c.reader == nil || c.name == "" || !time.Now().Before(c.deadline) {
		return errors.New("expired hostname candidate")
	}
	current, err := c.reader.lookup(c.key)
	if err != nil {
		return err
	}
	// Emitting later segments of the same immutable window advances only the
	// per-packet fields. The socket and its original observation must not change.
	if current.Cookie != c.record.Cookie || current.Observation != c.record.Observation || !time.Now().Before(c.deadline) {
		return errors.New("changed or expired hostname candidate")
	}
	return nil
}
