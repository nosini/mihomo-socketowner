//go:build !linux || !amd64

package hostname

import (
	"context"
	"time"
)

type Reader struct{}
type Candidate struct{}

func DialReader(string, time.Time) (*Reader, error) { return nil, ErrUnavailable }
func DialReaderContext(context.Context, string, time.Time) (*Reader, error) {
	return nil, ErrUnavailable
}
func (*Reader) Close()                                        {}
func (*Reader) Lookup(TCPFlow, time.Time) (*Candidate, error) { return nil, ErrUnavailable }
func (*Candidate) Name() string                               { return "" }
func (*Candidate) Validate() error                            { return ErrUnavailable }
