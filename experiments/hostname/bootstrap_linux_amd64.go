package hostname

// Hostname protocol v1/profile 3; historical profiles remain frozen in
// hostname/CONTRACT.md and PROFILE2.md; current obligations are in PROFILE3.md.
// This contract is deliberately separate from the owner-map ABI.
// The socket-creating process is also the observer/cleanup owner. Socket
// activation, descriptor delegation and alternate PID namespaces are excluded.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const bootstrapBytes = 80

var bootstrapMagic = [8]byte{'M', 'H', 'N', 'A', 'M', 'E', '0', '1'}

type bootstrapHeader struct {
	Kind     uint16
	Count    uint16
	Nonce    [16]byte
	Instance [16]byte
	Manifest authorityManifest
	Profile  uint32 // zero preserves the frozen profile-1 golden envelope
}

func (h bootstrapHeader) encode() []byte {
	b := make([]byte, bootstrapBytes)
	copy(b, bootstrapMagic[:])
	binary.LittleEndian.PutUint16(b[8:], 1)
	binary.LittleEndian.PutUint16(b[10:], h.Kind)
	binary.LittleEndian.PutUint16(b[14:], h.Count)
	copy(b[16:32], h.Nonce[:])
	copy(b[32:48], h.Instance[:])
	for i, id := range h.Manifest.Maps {
		binary.LittleEndian.PutUint32(b[48+i*4:], uint32(id))
	}
	profile := h.Profile
	if profile == 0 {
		profile = 1
	}
	binary.LittleEndian.PutUint32(b[64:], profile)
	return b
}

func decodeBootstrap(b []byte) (bootstrapHeader, error) {
	var h bootstrapHeader
	if len(b) != bootstrapBytes || !bytes.Equal(b[:8], bootstrapMagic[:]) || binary.LittleEndian.Uint16(b[8:]) != 1 ||
		binary.LittleEndian.Uint16(b[12:]) != 0 || (binary.LittleEndian.Uint32(b[64:]) != 1 && binary.LittleEndian.Uint32(b[64:]) != 2 && binary.LittleEndian.Uint32(b[64:]) != 3) || !bytes.Equal(b[68:], make([]byte, 12)) {
		return h, errors.New("incompatible hostname bootstrap envelope")
	}
	if binary.LittleEndian.Uint32(b[64:]) >= 2 {
		h.Profile = binary.LittleEndian.Uint32(b[64:])
	}
	h.Kind, h.Count = binary.LittleEndian.Uint16(b[10:]), binary.LittleEndian.Uint16(b[14:])
	copy(h.Nonce[:], b[16:32])
	copy(h.Instance[:], b[32:48])
	for i := range h.Manifest.Maps {
		h.Manifest.Maps[i] = ebpf.MapID(binary.LittleEndian.Uint32(b[48+i*4:]))
	}
	return h, nil
}

func closeBootstrapFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			unix.Close(fd)
		}
	}
}

func receiveBootstrap(c *net.UnixConn) ([]byte, []int, error) {
	data, oob := make([]byte, bootstrapBytes+1), make([]byte, unix.CmsgSpace(16*4))
	n, oobn, flags, _, readErr := c.ReadMsgUnix(data, oob)
	// Go's Linux ReadMsgUnix uses MSG_CMSG_CLOEXEC. Parse/own all delivered
	// rights before rejecting any other part of the packet, including truncation.
	var fds []int
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err == nil {
		for _, m := range messages {
			if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SCM_RIGHTS {
				err = errors.New("unexpected bootstrap ancillary message")
				continue
			}
			rights, e := unix.ParseUnixRights(&m)
			fds = append(fds, rights...)
			if e != nil {
				err = e
			}
		}
	}
	if readErr != nil || err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n != bootstrapBytes {
		closeBootstrapFDs(fds)
		return nil, nil, fmt.Errorf("invalid bootstrap packet: read %v, ancillary %v, flags %d, length %d", readErr, err, flags, n)
	}
	return data[:n], fds, nil
}

func bootstrapPeer(c *net.UnixConn, uid uint32, wantPIDFD bool) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	pidfd := -1
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil || cred.Uid != uid {
			sockErr = fmt.Errorf("unauthorized bootstrap peer: %v", e)
			return
		}
		if wantPIDFD {
			pidfd, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
			if sockErr == nil {
				_, sockErr = unix.FcntlInt(uintptr(pidfd), unix.F_SETFD, unix.FD_CLOEXEC)
			}
		}
	})
	if err != nil || sockErr != nil {
		if pidfd >= 0 {
			unix.Close(pidfd)
		}
		return -1, errors.Join(err, sockErr)
	}
	return pidfd, nil
}

func serveBootstrap(c *net.UnixConn, readerUID uint32, instance [16]byte, r *authorityReader, deadline time.Time) error {
	defer c.Close()
	c.SetDeadline(deadline)
	if _, err := bootstrapPeer(c, readerUID, false); err != nil {
		return err
	}
	data, fds, err := receiveBootstrap(c)
	defer closeBootstrapFDs(fds)
	if err != nil {
		return err
	}
	h, err := decodeBootstrap(data)
	if err != nil || h.Profile != 3 || h.Kind != 1 || h.Count != 0 || len(fds) != 0 || h.Nonce == [16]byte{} || h.Instance != [16]byte{} || h.Manifest != (authorityManifest{}) {
		return errors.New("invalid hostname bootstrap request")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.healthy(); err != nil {
		return err
	}
	h.Kind, h.Count, h.Instance, h.Manifest = 2, 4, instance, r.manifest
	rights := unix.UnixRights(r.maps[0].FD(), r.maps[1].FD(), r.maps[2].FD(), r.maps[3].FD())
	n, oobn, err := c.WriteMsgUnix(h.encode(), rights, nil)
	if err != nil || n != bootstrapBytes || oobn != len(rights) {
		return fmt.Errorf("hostname bootstrap send: %v", err)
	}
	return r.healthy() // receiver also validates its own pidfd/gate after receipt
}

func trustedBootstrapPath(path string, socket bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) >= 108 {
		return errors.New("hostname bootstrap requires a canonical pathname socket")
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		var s unix.Stat_t
		if err := unix.Lstat(dir, &s); err != nil || s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Uid != 0 || s.Mode&0022 != 0 {
			return errors.New("untrusted hostname bootstrap directory")
		}
		if dir == "/" {
			break
		}
	}
	if socket {
		var s unix.Stat_t
		if err := unix.Lstat(path, &s); err != nil || s.Uid != 0 || s.Mode&unix.S_IFMT != unix.S_IFSOCK || s.Mode&0007 != 0 {
			return errors.New("untrusted hostname bootstrap socket")
		}
	}
	return nil
}

func receiveAuthority(c *net.UnixConn, deadline time.Time) (_ *authorityReader, instance [16]byte, err error) {
	defer c.Close()
	c.SetDeadline(deadline)
	pidfd, err := bootstrapPeer(c, 0, true)
	if err != nil {
		return nil, instance, err
	}
	defer unix.Close(pidfd)
	request := bootstrapHeader{Kind: 1, Profile: 3}
	if _, err := rand.Read(request.Nonce[:]); err != nil {
		return nil, instance, err
	}
	if _, err := c.Write(request.encode()); err != nil {
		return nil, instance, err
	}
	data, fds, err := receiveBootstrap(c)
	defer closeBootstrapFDs(fds)
	if err != nil {
		return nil, instance, err
	}
	h, err := decodeBootstrap(data)
	if err != nil || h.Profile != request.Profile || h.Kind != 2 || h.Count != 4 || len(fds) != 4 || h.Nonce != request.Nonce || h.Instance == [16]byte{} {
		return nil, instance, errors.New("invalid hostname bootstrap response")
	}
	var maps [4]*ebpf.Map
	for i := range maps {
		fd := fds[i]
		fds[i] = -1 // NewMapFromFD takes ownership, including on failure
		maps[i], err = ebpf.NewMapFromFD(fd)
		if err != nil {
			return nil, instance, err
		}
		defer maps[i].Close()
	}
	r, err := newAuthorityReader(h.Manifest, maps, pidfd)
	if err != nil {
		return nil, instance, err
	}
	if !time.Now().Before(deadline) {
		r.close()
		return nil, instance, errors.New("hostname bootstrap deadline expired")
	}
	return r, h.Instance, nil
}

func dialAuthority(path string, deadline time.Time) (*authorityReader, [16]byte, error) {
	return dialAuthorityContext(context.Background(), path, deadline)
}

func dialAuthorityContext(ctx context.Context, path string, deadline time.Time) (*authorityReader, [16]byte, error) {
	if err := trustedBootstrapPath(path, true); err != nil {
		return nil, [16]byte{}, err
	}
	c, err := (&net.Dialer{Deadline: deadline}).DialContext(ctx, "unixpacket", path)
	if err != nil {
		return nil, [16]byte{}, err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	r, instance, err := receiveAuthority(c.(*net.UnixConn), deadline)
	if err == nil && ctx.Err() != nil {
		r.close()
		return nil, [16]byte{}, ctx.Err()
	}
	return r, instance, err
}
