package hostname

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type bootstrapJournal struct {
	Version           uint32
	Boot              string
	PID               int
	PIDNS, Dev, Inode uint64
	Pin               string
	Ready             bool
	Manifest          authorityManifest
	PinRoot           string
	PinDev, PinInode  uint64
}

type bootstrapOwner struct {
	runtime, pins string
	lock          *os.File
	journal       *bootstrapJournal
	listener      *net.UnixListener
	done          chan struct{}
}

func rootDirectory(path string, mode uint32) error {
	if err := trustedBootstrapPath(path, false); err != nil {
		return err
	}
	if err := unix.Mkdir(path, mode); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil || stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0777 != mode {
		return fmt.Errorf("unsafe hostname owner directory %s", path)
	}
	return nil
}

func secureOwnerFile(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Nlink != 1 {
		unix.Close(fd)
		return nil, errors.New("unsafe hostname owner file")
	}
	return os.NewFile(uintptr(fd), path), nil
}

func newBootstrapOwner(runtime, pins string, deadline time.Time) (_ *bootstrapOwner, err error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("hostname owner requires a privileged initializer")
	}
	if err := rootDirectory(runtime, 0755); err != nil {
		return nil, err
	}
	if err := rootDirectory(filepath.Join(runtime, "state"), 0700); err != nil {
		return nil, err
	}
	if err := trustedBootstrapPath(filepath.Join(pins, "epoch"), false); err != nil {
		return nil, err
	}
	var pinStat unix.Stat_t
	if err := unix.Lstat(pins, &pinStat); err != nil || pinStat.Mode&0777 != 0700 {
		return nil, errors.New("hostname pin root must be private")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(pins, &fs); err != nil || fs.Type != unix.BPF_FS_MAGIC {
		return nil, errors.New("hostname owner requires private bpffs")
	}
	o := &bootstrapOwner{runtime: runtime, pins: pins}
	o.lock, err = secureOwnerFile(filepath.Join(runtime, "state", "lock"), unix.O_CREAT|unix.O_RDWR)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			o.lock.Close()
		}
	}()
	if err = unix.Flock(int(o.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("hostname owner already running: %w", err)
	}
	if err = o.recover(deadline); err != nil {
		return nil, err
	}
	return o, nil
}

func ownerEnvironment() (boot string, pidns uint64, err error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", 0, err
	}
	var ns unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &ns); err != nil {
		return "", 0, err
	}
	return strings.TrimSpace(string(data)), ns.Ino, nil
}

func (o *bootstrapOwner) journalPath() string { return filepath.Join(o.runtime, "state", "journal") }
func (o *bootstrapOwner) socketPath() string  { return filepath.Join(o.runtime, "bootstrap.sock") }
func (o *bootstrapOwner) pinPath() string     { return filepath.Join(o.pins, "epoch-"+o.journal.Pin) }

func syncOwnerDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (o *bootstrapOwner) writeJournal() error {
	next := o.journalPath() + ".next"
	file, err := secureOwnerFile(next, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY)
	if err != nil {
		return err
	}
	defer os.Remove(next)
	err = json.NewEncoder(file).Encode(o.journal)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return err
	}
	if err := os.Rename(next, o.journalPath()); err != nil {
		return err
	}
	return syncOwnerDirectory(filepath.Dir(next))
}

// The journal is committed before the first attachment can be pinned. Recovery
// may therefore clean partial setup without guessing which phase crashed.
func (o *bootstrapOwner) begin() (string, error) {
	if o.journal != nil {
		return "", errors.New("hostname instance already exists")
	}
	boot, ns, err := ownerEnvironment()
	if err != nil {
		return "", err
	}
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(pidfd)
	var stat unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstatfs(pidfd, &fs); err != nil || fs.Type != unix.PID_FS_MAGIC {
		return "", errors.New("hostname recovery requires pidfs process identities")
	}
	if err := unix.Fstat(pidfd, &stat); err != nil {
		return "", err
	}
	var instance [16]byte
	if _, err := rand.Read(instance[:]); err != nil {
		return "", err
	}
	o.journal = &bootstrapJournal{Version: 1, Boot: boot, PIDNS: ns, PID: os.Getpid(), Dev: stat.Dev, Inode: stat.Ino, Pin: hex.EncodeToString(instance[:])}
	var pinStat unix.Stat_t
	if err := unix.Stat(o.pins, &pinStat); err != nil {
		return "", err
	}
	o.journal.PinRoot, o.journal.PinDev, o.journal.PinInode = o.pins, pinStat.Dev, pinStat.Ino
	if err := o.writeJournal(); err != nil {
		return "", err
	}
	if err := os.Mkdir(o.pinPath(), 0700); err != nil {
		return "", err
	}
	return o.pinPath(), nil
}

func (o *bootstrapOwner) removeSocket() error {
	var stat unix.Stat_t
	err := unix.Lstat(o.socketPath(), &stat)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("refusing to remove a foreign hostname endpoint")
	}
	return os.Remove(o.socketPath())
}

func (o *bootstrapOwner) removePins() error {
	var dirStat unix.Stat_t
	if err := unix.Lstat(o.pinPath(), &dirStat); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil || dirStat.Uid != 0 || dirStat.Mode&unix.S_IFMT != unix.S_IFDIR || dirStat.Mode&0777 != 0700 {
		return errors.New("unsafe hostname instance directory")
	}
	entries, err := os.ReadDir(o.pinPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	allowed := map[string]bool{"last_seeded": true}
	for _, name := range authorityMapNames {
		allowed[name] = true
	}
	for _, name := range []string{"create", "release", "state", "send", "egress"} {
		allowed["link_"+name] = true
	}
	for _, entry := range entries {
		var stat unix.Stat_t
		if err := unix.Lstat(filepath.Join(o.pinPath(), entry.Name()), &stat); err != nil || !allowed[entry.Name()] || stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0077 != 0 {
			return errors.New("refusing to remove unexpected hostname pin contents")
		}
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(o.pinPath(), entry.Name())); err != nil {
			return err
		}
	}
	return os.Remove(o.pinPath())
}

func (o *bootstrapOwner) clearJournal() error {
	if err := os.Remove(o.journalPath()); err != nil {
		return err
	}
	if err := syncOwnerDirectory(filepath.Dir(o.journalPath())); err != nil {
		return err
	}
	o.journal = nil
	return nil
}

func (o *bootstrapOwner) recover(deadline time.Time) error {
	file, err := secureOwnerFile(o.journalPath(), unix.O_RDONLY)
	if errors.Is(err, unix.ENOENT) {
		// No committed intent means setup never reached pinning/publication.
		if _, err := os.Lstat(o.socketPath()); !errors.Is(err, os.ErrNotExist) {
			return errors.New("hostname endpoint exists without an ownership journal")
		}
		return o.removeJournalTemporary()
	}
	if err != nil {
		return err
	}
	defer file.Close()
	var j bootstrapJournal
	data, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil || len(data) > 16384 {
		return errors.New("oversized hostname recovery journal")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("invalid hostname journal trailer")
	}
	name, err := hex.DecodeString(j.Pin)
	boot, ns, envErr := ownerEnvironment()
	var pinStat unix.Stat_t
	pinErr := unix.Stat(o.pins, &pinStat)
	if err != nil || len(name) != 16 || hex.EncodeToString(name) != j.Pin || j.Version != 1 || j.PID <= 0 || j.PID > 1<<31-1 || j.Inode == 0 || j.Dev == 0 || j.Boot != boot || j.PIDNS != ns || envErr != nil || pinErr != nil || j.PinRoot != o.pins || j.PinDev != pinStat.Dev || j.PinInode != pinStat.Ino {
		return errors.New("incompatible hostname recovery journal")
	}
	pidfd, err := unix.PidfdOpen(j.PID, 0)
	if err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	if err == nil {
		defer unix.Close(pidfd)
		var stat unix.Stat_t
		if err := unix.Fstat(pidfd, &stat); err != nil {
			return err
		}
		// A reused numeric PID is not the original owner. Never signal it.
		for stat.Dev == j.Dev && stat.Ino == j.Inode {
			poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
			n, err := unix.Poll(poll, 0)
			if err != nil || poll[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
				return errors.New("cannot establish original hostname owner exit")
			}
			if n != 0 && poll[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
				break
			}
			if !time.Now().Before(deadline) {
				return errors.New("original hostname owner is still alive")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	o.journal = &j
	if err := o.removeSocket(); err != nil {
		return err
	}
	if err := o.removePins(); err != nil {
		return err
	}
	if err := o.clearJournal(); err != nil {
		return err
	}
	return o.removeJournalTemporary()
}

func (o *bootstrapOwner) removeJournalTemporary() error {
	path := o.journalPath() + ".next"
	file, err := secureOwnerFile(path, unix.O_RDONLY)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	file.Close()
	return os.Remove(path)
}

func (o *bootstrapOwner) publish(p *probe, r *authorityReader, uid, gid uint32) error {
	if p == nil || p.session == nil || r == nil || o.journal == nil || o.journal.Ready || o.journal.PID != os.Getpid() || r.pidstat.Dev != o.journal.Dev || r.pidstat.Ino != o.journal.Inode {
		return errors.New("hostname publisher is not the journal owner")
	}
	if err := p.session.healthy(); err != nil {
		return err
	}
	if err := r.healthy(); err != nil {
		return err
	}
	for i, name := range authorityMapNames {
		if i != 0 {
			id, err := mapIdentity(p.collection.Maps[name])
			if err != nil || id != r.manifest.Maps[i] {
				return errors.New("hostname reader does not match the observer collection")
			}
		}
		m, err := ebpf.LoadPinnedMap(filepath.Join(o.pinPath(), name), &ebpf.LoadPinOptions{ReadOnly: true})
		if err != nil {
			return err
		}
		id, e := mapIdentity(m)
		m.Close()
		if e != nil || id != r.manifest.Maps[i] {
			return errors.New("hostname publication uses foreign maps")
		}
	}
	for _, l := range p.session.links {
		pinned, err := link.LoadPinnedLink(filepath.Join(o.pinPath(), "link_"+l.name), nil)
		if err != nil {
			return err
		}
		info, e := pinned.Info()
		pinned.Close()
		if e != nil || !sameObserverLink(l.info, info) {
			return errors.New("hostname publication lacks a required pinned attachment")
		}
	}
	o.journal.Manifest, o.journal.Ready = r.manifest, true
	if err := o.writeJournal(); err != nil {
		return err
	}
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: o.socketPath(), Net: "unixpacket"})
	if err != nil {
		return err
	}
	o.listener = l
	l.SetUnlinkOnClose(false)
	if err := os.Chown(o.socketPath(), 0, int(gid)); err != nil {
		l.Close()
		return err
	}
	if err := os.Chmod(o.socketPath(), 0660); err != nil {
		l.Close()
		return err
	}
	instance, _ := hex.DecodeString(o.journal.Pin)
	var id [16]byte
	copy(id[:], instance)
	o.done = make(chan struct{})
	go func() {
		defer close(o.done)
		for {
			c, err := l.AcceptUnix()
			if err != nil {
				return
			}
			// One bounded handshake at a time, with no unbounded goroutine/FD queue.
			_ = serveBootstrap(c, uid, id, r, time.Now().Add(200*time.Millisecond))
		}
	}()
	return nil
}

func (o *bootstrapOwner) finish(p *probe, r *authorityReader) error {
	if o.listener != nil {
		o.listener.Close()
		if o.done != nil {
			<-o.done
		}
	}
	if o.journal != nil && o.journal.Ready {
		if r == nil || r.manifest != o.journal.Manifest {
			return errors.New("missing authority for owned hostname shutdown")
		}
		state, err := changeAuthority(r.maps[0], false)
		if err != nil || state != 3 {
			return fmt.Errorf("hostname revocation failed: %d, %v", state, err)
		}
	}
	if r != nil {
		r.close()
	}
	if p != nil {
		p.close()
	}
	if o.journal != nil {
		if err := o.removeSocket(); err != nil {
			return err
		}
		if err := o.removePins(); err != nil {
			return err
		}
		if err := o.clearJournal(); err != nil {
			return err
		}
	}
	if o.lock != nil {
		err := o.lock.Close()
		o.lock = nil
		if !errors.Is(err, os.ErrClosed) {
			return err
		}
	}
	return nil
}
