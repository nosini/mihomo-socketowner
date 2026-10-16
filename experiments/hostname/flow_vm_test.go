//go:build linux && amd64 && hostname_vm

package hostname

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// Privileged fault injection models LRU eviction through the kernel now that
// flow descriptors are read-only. External authority also freezes these maps.
func deleteVMFlow(t *testing.T, m *ebpf.Map, key flowKey) {
	t.Helper()
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, key); err != nil {
		t.Fatal(err)
	}
	instructions := asm.Instructions{}
	for i := 0; i < data.Len(); i += 4 {
		instructions = append(instructions, asm.StoreImm(asm.R10, int16(i-data.Len()), int64(binary.LittleEndian.Uint32(data.Bytes()[i:i+4])), asm.Word))
	}
	instructions = append(instructions, asm.LoadMapPtr(asm.R1, m.FD()), asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -int32(data.Len())), asm.FnMapDeleteElem.Call(), asm.Return())
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "evict_flow", Type: ebpf.SocketFilter, License: "GPL", Instructions: instructions})
	if err != nil {
		t.Fatal(err)
	}
	defer program.Close()
	if result, _, err := program.Test(make([]byte, 64)); err != nil || result != 0 {
		t.Fatalf("kernel flow eviction failed: %d, %v", result, err)
	}
}

func (f *fixture) flowKey(c connection) flowKey {
	f.t.Helper()
	peer := c.server.RemoteAddr().(*net.TCPAddr).AddrPort()
	local := c.server.LocalAddr().(*net.TCPAddr).AddrPort()
	raw, err := c.server.SyscallConn()
	if err != nil {
		f.t.Fatal(err)
	}
	var ns, acceptedCookie uint64
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		ns, socketErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
		if socketErr == nil {
			acceptedCookie, socketErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		}
	}); err != nil || socketErr != nil {
		f.t.Fatalf("socket identity: %v, %v", err, socketErr)
	}
	if acceptedCookie == c.cookie {
		f.t.Fatal("test did not distinguish accepted and application sockets")
	}
	return flowKey{Netns: ns, Source: peer.Addr().As16(), Destination: local.Addr().As16(), SourcePort: peer.Port(), DestinationPort: local.Port()}
}

func (f *fixture) flow(c connection) flowObservation {
	f.t.Helper()
	key := f.flowKey(c)
	o, err := stableLookup[flowObservation](f, "send_flows", key)
	if err != nil {
		f.t.Fatalf("flow %+v: %v", key, err)
	}
	if o.Cookie != c.cookie {
		f.t.Fatalf("flow cookie %d, application cookie %d", o.Cookie, c.cookie)
	}
	return o
}

func TestVMSendFlow(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newFixtureMode(t, network, true)
			disableHandshakeProbe(t, f)
			c := f.open("flow.test", "name-first", "fd")
			if o := f.flow(c); o.Observation.Len != 0 {
				t.Fatal("name existed before the sending operation")
			}
			f.command("handshake %d", c.slot)
			if o := f.flow(c); o.Observation.Len == 0 {
				t.Fatal("name not published by egress")
			}
			if name, err := f.flow(c).Observation.hostname(); err != nil || name != "flow.test" || wireName(t, c) != name {
				t.Fatalf("flow name %q: %v", name, err)
			}
		})
	}
}

func runVM(t *testing.T, command string, args ...string) {
	t.Helper()
	if output, err := exec.Command(command, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %s: %v", command, args, output, err)
	}
}

func originalDestination(t *testing.T, c connection, ipv6 bool) netip.AddrPort {
	t.Helper()
	raw, err := c.server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var storage [128]byte
	length := uint32(16)
	level := unix.IPPROTO_IP
	if ipv6 {
		level = unix.IPPROTO_IPV6
		length = 28
	}
	var socketErr unix.Errno
	if err := raw.Control(func(fd uintptr) {
		_, _, socketErr = unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(level), 80, uintptr(unsafe.Pointer(&storage[0])), uintptr(unsafe.Pointer(&length)), 0)
	}); err != nil || socketErr != 0 {
		t.Fatalf("original destination: %v, %v", err, socketErr)
	}
	var address netip.Addr
	if ipv6 {
		if length != 28 {
			t.Fatalf("original IPv6 sockaddr length %d", length)
		}
		address = netip.AddrFrom16([16]byte(storage[8:24]))
	} else {
		if length != 16 {
			t.Fatalf("original IPv4 sockaddr length %d", length)
		}
		address = netip.AddrFrom4([4]byte(storage[4:8]))
	}
	return netip.AddrPortFrom(address, binary.BigEndian.Uint16(storage[2:4]))
}

func TestVMSendRedirectCollision(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newFixtureMode(t, network, true)
			disableHandshakeProbe(t, f)
			family, destinations := "ip", []string{"127.0.0.2", "127.0.0.3"}
			if network == "tcp6" {
				family, destinations = "ip6", []string{"fd12::2", "fd12::3"}
				for _, addr := range destinations {
					runVM(t, "ip", "-6", "addr", "add", addr+"/128", "dev", "lo", "nodad")
				}
			}
			port := f.listener.Addr().(*net.TCPAddr).Port
			rules := fmt.Sprintf(`table inet hostname_redirect {
				chain output { type nat hook output priority dstnat; policy accept;
					%s daddr { %s } tcp dport 443 redirect to :%d
				}
				chain postrouting { type nat hook postrouting priority srcnat; policy accept; }
			}`, family, strings.Join(destinations, ", "), port)
			cmd := exec.Command("nft", "-f", "-")
			cmd.Stdin = strings.NewReader(rules)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("nft: %s: %v", output, err)
			}
			defer runVM(t, "nft", "delete", "table", "inet", "hostname_redirect")
			var sourcePort int
			for i, destination := range destinations {
				f.command("destination %s 443", destination)
				name := fmt.Sprintf("redirect-%d.test", i)
				c := f.open(name, "fd-first", "fd")
				if got := originalDestination(t, c, network == "tcp6"); got != netip.AddrPortFrom(netip.MustParseAddr(destination), 443) {
					t.Fatalf("original destination lost: %s", got)
				}
				if i == 0 {
					sourcePort = c.localPort
					f.command("source %d", sourcePort)
				} else {
					if c.localPort != sourcePort || c.server.RemoteAddr().(*net.TCPAddr).Port == sourcePort {
						t.Fatal("test did not force source-port translation")
					}
				}
				if o := f.flow(c); o.Observation.Len != 0 {
					t.Fatal("new redirected flow had stale name")
				}
				f.command("handshake %d", c.slot)
				if got, err := f.flow(c).Observation.hostname(); err != nil || got != name || wireName(t, c) != name {
					t.Fatalf("redirect name %q: %v", got, err)
				}
			}
		})
	}
}
