package hostname

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func bootstrapSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var pair [2]*net.UnixConn
	for i, fd := range fds {
		file := os.NewFile(uintptr(fd), "bootstrap-pair")
		conn, err := net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		pair[i] = conn.(*net.UnixConn)
		pair[i].SetDeadline(time.Now().Add(time.Second))
		t.Cleanup(func() { pair[i].Close() })
	}
	return pair[0], pair[1]
}

func TestBootstrapEnvelope(t *testing.T) {
	valid := bootstrapHeader{Kind: 1, Nonce: [16]byte{1}}.encode()
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"short", func(b []byte) []byte { return b[:79] }},
		{"long", func(b []byte) []byte { return append(b, 0) }},
		{"magic", func(b []byte) []byte { b[0] ^= 1; return b }},
		{"version", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[8:], 2); return b }},
		{"status", func(b []byte) []byte { b[12] = 1; return b }},
		{"profile", func(b []byte) []byte { b[64] = 4; return b }},
		{"reserved", func(b []byte) []byte { b[79] = 1; return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeBootstrap(tc.edit(bytes.Clone(valid))); err == nil {
				t.Fatal("accepted incompatible envelope")
			}
		})
	}
}

func TestBootstrapTruncationClosesRights(t *testing.T) {
	for _, tc := range []struct {
		name         string
		size, rights int
	}{{"short", 79, 4}, {"long", 81, 4}, {"payload-truncated", 200, 4}, {"rights-truncated", 80, 32}} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := bootstrapSocketPair(t)
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer read.Close()
			fds := make([]int, tc.rights)
			for i := range fds {
				fds[i] = int(write.Fd())
			}
			if _, _, err := a.WriteMsgUnix(make([]byte, tc.size), unix.UnixRights(fds...), nil); err != nil {
				t.Fatal(err)
			}
			write.Close()
			if _, fds, err := receiveBootstrap(b); err == nil || len(fds) != 0 {
				t.Fatalf("accepted malformed packet or leaked rights: %v %v", fds, err)
			}
			read.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := read.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("received writer FDs were not closed: %v", err)
			}
		})
	}
}

func TestBootstrapRightsCloseOnExec(t *testing.T) {
	a, b := bootstrapSocketPair(t)
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, _, err := a.WriteMsgUnix(make([]byte, bootstrapBytes), unix.UnixRights(int(file.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	_, fds, err := receiveBootstrap(b)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBootstrapFDs(fds)
	if len(fds) != 1 {
		t.Fatal(fds)
	}
	flags, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("received FD is inheritable: %d %v", flags, err)
	}
}

func TestBootstrapPeerDenial(t *testing.T) {
	a, b := bootstrapSocketPair(t)
	if _, err := bootstrapPeer(a, uint32(os.Geteuid()+1), true); err == nil {
		t.Fatal("accepted the wrong kernel peer UID")
	}
	// Authentication happens before reading a request or touching map handles.
	if err := serveBootstrap(b, uint32(os.Geteuid()+1), [16]byte{1}, nil, time.Now().Add(time.Second)); err == nil {
		t.Fatal("unauthorized peer reached publication")
	}
}

func TestBootstrapRejectsProfile1BeforeGrant(t *testing.T) {
	a, b := bootstrapSocketPair(t)
	request := bootstrapHeader{Kind: 1, Nonce: [16]byte{1}} // frozen profile 1
	if _, err := a.Write(request.encode()); err != nil {
		t.Fatal(err)
	}
	// A nil authority reader proves the incompatible request fails before any
	// healthy/map access or FD grant. The peer UID is otherwise authorized.
	if err := serveBootstrap(b, uint32(os.Geteuid()), [16]byte{1}, nil, time.Now().Add(time.Second)); err == nil {
		t.Fatal("profile-1 request accepted by reclaiming publisher")
	}
	if _, fds, err := receiveBootstrap(a); err == nil || len(fds) != 0 {
		t.Fatalf("incompatible profile received rights: %v %v", fds, err)
	}
}
