package hostname

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

var authorityMapNames = [4]string{"authority", "publication_state", "send_guards", "send_flows"}

type authorityManifest struct {
	Maps [4]ebpf.MapID
}

type authorityReader struct {
	mu       sync.RWMutex
	revoked  atomic.Bool
	maps     [4]*ebpf.Map
	manifest authorityManifest
	pidfd    int
	pidstat  unix.Stat_t
}

func validateAuthorityMap(index int, info *ebpf.MapInfo) bool {
	types := [4]ebpf.MapType{ebpf.Array, ebpf.Array, ebpf.Hash, ebpf.LRUHash}
	keys := [4]uint32{4, 4, 8, 48}
	values := [4]uint32{8, 8, 8, 312}
	limits := [4]uint32{1, 1, 256, 256}
	// BPF_F_RDONLY is an FD-open flag, stripped from MapInfo.Flags. Freeze
	// supplies the global syscall write prohibition, including reopened FDs.
	return info.Type == types[index] && info.KeySize == keys[index] && info.ValueSize == values[index] && info.MaxEntries == limits[index] && info.Flags == 0 && info.Frozen()
}

// Inputs and manifest come from one trusted bootstrap, never a caller-supplied
// PID/path lookup. Own references prevent map/pidfd identity recycling. Each
// reconnect constructs a new reader; a previous one can never acquire a new epoch.
func newAuthorityReader(manifest authorityManifest, maps [4]*ebpf.Map, pidfd int) (_ *authorityReader, err error) {
	r := &authorityReader{manifest: manifest, pidfd: -1}
	defer func() {
		if err != nil {
			r.close()
		}
	}()
	for i, m := range maps {
		if m == nil || manifest.Maps[i] == 0 {
			return nil, fmt.Errorf("missing authority map %d", i)
		}
		flags, e := unix.FcntlInt(uintptr(m.FD()), unix.F_GETFL, 0)
		if e != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
			return nil, fmt.Errorf("authority map %d is not read-only", i)
		}
		r.maps[i], err = m.Clone()
		if err != nil {
			return nil, err
		}
	}
	r.pidfd, err = unix.FcntlInt(uintptr(pidfd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(r.pidfd, &fs); err != nil || fs.Type != unix.PID_FS_MAGIC {
		return nil, fmt.Errorf("authority requires a pidfs pidfd: %v", err)
	}
	if err = unix.Fstat(r.pidfd, &r.pidstat); err != nil {
		return nil, err
	}
	if err = r.healthy(); err != nil {
		return nil, err
	}
	return r, nil
}

func pidfdAlive(fd int) error {
	if fd < 0 {
		return errObserverUnavailable
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	if err != nil || n != 0 || poll[0].Revents != 0 {
		return fmt.Errorf("%w: exited or invalid observer pidfd (%v)", errObserverUnavailable, err)
	}
	return nil
}

func (r *authorityReader) healthy() error {
	fail := func(reason string) error {
		r.revoked.Store(true)
		return fmt.Errorf("%w: %s", errObserverUnavailable, reason)
	}
	if r.revoked.Load() {
		return errObserverUnavailable
	}
	var stat unix.Stat_t
	if err := unix.Fstat(r.pidfd, &stat); err != nil || stat.Ino != r.pidstat.Ino || stat.Dev != r.pidstat.Dev {
		return fail("lost pidfd identity")
	}
	if err := pidfdAlive(r.pidfd); err != nil {
		return fail(err.Error())
	}
	for i, m := range r.maps {
		if m == nil {
			return fail("missing map")
		}
		info, err := m.Info()
		if err != nil {
			return fail(err.Error())
		}
		id, ok := info.ID()
		if !ok || id != r.manifest.Maps[i] || !validateAuthorityMap(i, info) {
			return fail(fmt.Sprintf("map %s identity/layout: id %d expected %d, info %+v", authorityMapNames[i], id, r.manifest.Maps[i], info))
		}
	}
	var active uint64
	if err := r.maps[0].Lookup(uint32(0), &active); err != nil || active != 1 {
		return fail(fmt.Sprintf("inactive authority %d: %v", active, err))
	}
	return nil
}

func (r *authorityReader) lookup(key flowKey) (flowObservation, error) {
	return r.read(func(value *flowObservation) error {
		return r.maps[3].Lookup(key, value)
	})
}

func (r *authorityReader) read(lookup func(*flowObservation) error) (flowObservation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return readObserved(r.healthy, func() (uint64, error) {
		var word uint64
		err := r.maps[1].Lookup(uint32(0), &word)
		return word, err
	}, lookup, func(cookie uint64) (uint64, error) {
		var state uint64
		err := r.maps[2].Lookup(cookie, &state)
		return state, err
	})
}

func (r *authorityReader) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked.Store(true)
	for i, m := range r.maps {
		if m != nil {
			m.Close()
			r.maps[i] = nil
		}
	}
	if r.pidfd >= 0 {
		unix.Close(r.pidfd)
		r.pidfd = -1
	}
}
