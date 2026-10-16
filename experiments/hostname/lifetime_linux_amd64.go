package hostname

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var errObserverUnavailable = errors.New("hostname observer session is unavailable")

type observerMap struct {
	lease *ebpf.Map
	id    ebpf.MapID
}
type observerLink struct {
	name  string
	get   func() link.Link
	info  *link.Info
	lease link.Link
}

// Session identities and map leases are immutable. Only stop/close mutate the
// owner, under mu. Retained data FDs alone never authorize a hostname lookup.
// This is the in-process experiment's lifecycle contract, not a public ABI.
type observerSession struct {
	mu      sync.RWMutex
	revoked atomic.Bool
	owner   *probe
	maps    map[string]observerMap
	links   []observerLink
}

func mapIdentity(m *ebpf.Map) (ebpf.MapID, error) {
	if m == nil {
		return 0, errors.New("missing map")
	}
	info, err := m.Info()
	if err != nil {
		return 0, err
	}
	id, ok := info.ID()
	if !ok || id == 0 {
		return 0, errors.New("map has no identity")
	}
	return id, nil
}

func sameObserverLink(want, got *link.Info) bool {
	if want == nil || got == nil || want.ID == 0 || want.Program == 0 ||
		want.ID != got.ID || want.Program != got.Program || want.Type != got.Type {
		return false
	}
	if c := want.Cgroup(); c != nil {
		actual := got.Cgroup()
		// BPF_LINK_DETACH leaves a live FD with cgroup identity zero.
		return c.CgroupId != 0 && actual != nil && *c == *actual
	}
	if tracing := want.Tracing(); tracing != nil {
		actual := got.Tracing()
		return tracing.TargetBtfId != 0 && actual != nil && *tracing == *actual
	}
	return false // legacy attachments without inspectable BPF links are excluded
}

func newObserverSession(p *probe) (_ *observerSession, err error) {
	if !p.liveSend || p.session != nil {
		return nil, errObserverUnavailable // an owner gets exactly one session
	}
	s := &observerSession{owner: p, maps: make(map[string]observerMap)}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	for _, name := range []string{"publication_state", "send_guards", "send_snapshots", "send_flows", "send_scope"} {
		m := p.collection.Maps[name]
		id, err := mapIdentity(m)
		if err != nil {
			return nil, fmt.Errorf("observer map %s: %w", name, err)
		}
		lease, err := m.Clone()
		if err != nil {
			return nil, err
		}
		// Keeping the map alive also prevents its kernel ID being recycled.
		s.maps[name] = observerMap{lease, id}
	}
	s.links = []observerLink{
		{name: "create", get: func() link.Link { return p.cgroup }},
		{name: "release", get: func() link.Link { return p.release }},
		{name: "state", get: func() link.Link { return p.lifetime }},
		{name: "send", get: func() link.Link { return p.send }},
		{name: "egress", get: func() link.Link { return p.egress }},
	}
	for i := range s.links {
		l := &s.links[i]
		if l.get() == nil {
			return nil, fmt.Errorf("missing observer %s link", l.name)
		}
		l.info, err = l.get().Info()
		if err != nil || !sameObserverLink(l.info, l.info) {
			return nil, fmt.Errorf("uninspectable observer %s link: %v", l.name, err)
		}
		// Keep this kernel link identity alive even if its owner's original
		// FD is unexpectedly closed. ID reuse cannot authorize a new link.
		l.lease, err = link.NewFromID(l.info.ID)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *observerSession) unavailable(reason string) error {
	s.revoked.Store(true)
	return fmt.Errorf("%w: %s", errObserverUnavailable, reason)
}

// Called on both sides of every lookup, never cached or replaced by a TTL.
func (s *observerSession) healthy() error {
	if s.revoked.Load() {
		return errObserverUnavailable
	}
	for name, m := range s.maps {
		id, err := mapIdentity(s.owner.collection.Maps[name])
		if err != nil || id != m.id {
			return s.unavailable("replaced or closed " + name)
		}
		id, err = mapIdentity(m.lease)
		if err != nil || id != m.id {
			return s.unavailable("lost " + name + " lease")
		}
	}
	id, err := mapIdentity(s.owner.publication)
	if err != nil || id != s.maps["publication_state"].id {
		return s.unavailable("replaced publication control")
	}
	for _, l := range s.links {
		if l.get() == nil {
			return s.unavailable("missing " + l.name + " link")
		}
		info, err := l.get().Info()
		if err != nil || !sameObserverLink(l.info, info) {
			return s.unavailable("detached or replaced " + l.name + " link")
		}
		info, err = l.lease.Info()
		if err != nil || !sameObserverLink(l.info, info) {
			return s.unavailable("lost " + l.name + " link lease")
		}
	}
	return nil
}

func (s *observerSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked.Store(true)
	for _, l := range s.links {
		if l.lease != nil {
			l.lease.Close()
		}
	}
	for _, m := range s.maps {
		m.lease.Close()
	}
}

func readObserved[T sendRecord](healthy func() error, control func() (uint64, error), lookup func(*T) error, guard func(uint64) (uint64, error)) (T, error) {
	return readSendPublished(func() (uint64, error) {
		if err := healthy(); err != nil {
			return 0, err
		}
		return control()
	}, lookup, guard)
}

func lookupSession[T sendRecord](p *probe, name string, key interface{}) (T, error) {
	var zero T
	s := p.session
	if s == nil || s.owner != p {
		return zero, errObserverUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if name != "send_snapshots" && name != "send_flows" {
		return zero, errors.New("unsupported observer record map")
	}
	return readObserved(s.healthy, func() (uint64, error) {
		var word uint64
		err := s.maps["publication_state"].lease.Lookup(uint32(0), &word)
		return word, err
	}, func(value *T) error {
		return s.maps[name].lease.Lookup(key, value)
	}, func(cookie uint64) (uint64, error) {
		var state uint64
		err := s.maps["send_guards"].lease.Lookup(cookie, &state)
		return state, err
	})
}
