//go:build linux && sockowner_vm

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Run as root in a dedicated network namespace, with ip and nft on PATH:
// sudo unshare --net sh -c 'ip link set lo up; ./socketowner.test -test.v -test.run Redirect'
// A private cgroup keeps the test's BPF attachments away from other processes.
func TestRedirectSourcePort(t *testing.T) {
	selfNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initNS, err := os.Readlink("/proc/1/ns/net")
	if err != nil || selfNS == initNS {
		t.Fatal("run in a dedicated network namespace with unshare --net")
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	_, oldGroup, ok := strings.Cut(strings.TrimSpace(string(data)), "0::")
	if !ok {
		t.Fatal("cgroup v2 required")
	}
	cgroup := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("sockowner-test-%d", os.Getpid()))
	if err := os.Mkdir(cgroup, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(filepath.Join("/sys/fs/cgroup", oldGroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
			t.Error(err)
		}
		if err := os.Remove(cgroup); err != nil {
			t.Error(err)
		}
	})
	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		t.Fatal(err)
	}
	pin := fmt.Sprintf("/sys/fs/bpf/sockowner-test-%d", os.Getpid())
	t.Cleanup(func() {
		if err := detach(pin); err != nil {
			t.Error(err)
		}
		for _, path := range []string{"links", "maps", ""} {
			if err := os.Remove(filepath.Join(pin, path)); err != nil {
				t.Error(err)
			}
		}
	})
	if err := attach(cgroup, pin, false, -1); err != nil {
		t.Fatal(err)
	}
	owners, err := ebpf.LoadPinnedMap(filepath.Join(pin, "maps", mapName), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer owners.Close()
	run := func(t *testing.T, command string, args ...string) {
		t.Helper()
		if output, err := exec.Command(command, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %s: %v", command, args, output, err)
		}
	}
	run(t, "ip", "-6", "addr", "add", "fd12::2/128", "dev", "lo", "nodad")
	run(t, "ip", "-6", "addr", "add", "fd12::3/128", "dev", "lo", "nodad")
	for _, tc := range []struct {
		network string
		options bool
	}{
		{"tcp4", false}, {"tcp6", false},
		{"tcp4", true}, {"tcp6", true},
		{"udp4", false}, {"udp6", false},
	} {
		name := tc.network
		if tc.options {
			name += "-options"
		}
		loopback, destinations, family := "127.0.0.1", []string{"127.0.0.2", "127.0.0.3"}, "ip"
		if strings.HasSuffix(tc.network, "6") {
			loopback, destinations, family = "::1", []string{"fd12::2", "fd12::3"}, "ip6"
		}
		t.Run(name, func(t *testing.T) {
			protocol, ipProtocol := "tcp", uint8(unix.IPPROTO_TCP)
			var listener *net.TCPListener
			var packet *net.UDPConn
			var port int
			if strings.HasPrefix(tc.network, "tcp") {
				listener, err = net.ListenTCP(tc.network, &net.TCPAddr{IP: net.ParseIP(loopback)})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				listener.SetDeadline(time.Now().Add(5 * time.Second))
				port = listener.Addr().(*net.TCPAddr).Port
			} else {
				protocol, ipProtocol = "udp", unix.IPPROTO_UDP
				packet, err = net.ListenUDP(tc.network, &net.UDPAddr{IP: net.ParseIP(loopback)})
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				packet.SetDeadline(time.Now().Add(5 * time.Second))
				port = packet.LocalAddr().(*net.UDPAddr).Port
			}
			table := "sockowner_test"
			rules := fmt.Sprintf(`table inet %s {
				chain output { type nat hook output priority dstnat; policy accept;
					%s daddr { %s } %s dport 443 redirect to :%d
				}
				chain postrouting { type nat hook postrouting priority srcnat; policy accept; }
			}`, table, family, strings.Join(destinations, ", "), protocol, port)
			cmd := exec.Command("nft", "-f", "-")
			cmd.Stdin = strings.NewReader(rules)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("nft: %s: %v", output, err)
			}
			defer run(t, "nft", "delete", "table", "inet", table)
			var originalPort int
			for i, destination := range destinations {
				var local net.Addr = &net.TCPAddr{IP: net.ParseIP(loopback), Port: originalPort}
				if packet != nil {
					local = &net.UDPAddr{IP: net.ParseIP(loopback), Port: originalPort}
				}
				dialer := net.Dialer{
					Timeout:   5 * time.Second,
					LocalAddr: local,
					Control: func(_, _ string, raw syscall.RawConn) error {
						var sockErr error
						err := raw.Control(func(fd uintptr) {
							sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
							if sockErr == nil && tc.options {
								if family == "ip" {
									sockErr = unix.SetsockoptString(int(fd), unix.IPPROTO_IP, unix.IP_OPTIONS, string([]byte{1, 1, 1, 1}))
								} else {
									// One IPv6 destination-options header containing PadN.
									sockErr = unix.SetsockoptString(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DSTOPTS, string([]byte{0, 0, 1, 4, 0, 0, 0, 0}))
								}
							}
						})
						if err != nil {
							return err
						}
						return sockErr
					},
				}
				client, err := dialer.DialContext(context.Background(), tc.network, net.JoinHostPort(destination, "443"))
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				var peer netip.AddrPort
				if listener != nil {
					originalPort = client.LocalAddr().(*net.TCPAddr).Port
					server, err := listener.AcceptTCP()
					if err != nil {
						t.Fatal(err)
					}
					defer server.Close()
					peer = server.RemoteAddr().(*net.TCPAddr).AddrPort()
				} else {
					originalPort = client.LocalAddr().(*net.UDPAddr).Port
					if _, err := client.Write([]byte("x")); err != nil {
						t.Fatal(err)
					}
					var buf [1]byte
					if _, peer, err = packet.ReadFromUDPAddrPort(buf[:]); err != nil {
						t.Fatal(err)
					}
				}
				if i == 1 && peer.Port() == uint16(originalPort) {
					t.Fatal("test did not force a source-port collision")
				}
				raw, err := client.(syscall.Conn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var cookie uint64
				var sockErr error
				if err := raw.Control(func(fd uintptr) {
					cookie, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
				}); err != nil || sockErr != nil {
					t.Fatalf("netns cookie: %v, %v", err, sockErr)
				}
				key := struct {
					Netns uint64
					Addr  [16]byte
					Port  uint16
					Proto uint8
					Pad   [5]byte
				}{Netns: cookie, Addr: peer.Addr().As16(), Port: peer.Port(), Proto: ipProtocol}
				var owner struct {
					TGID, UID uint32
					BootNS    uint64
				}
				err = owners.Lookup(&key, &owner)
				t.Logf("socket port %d, redirected port %d, owner %d", originalPort, peer.Port(), owner.TGID)
				if err != nil || owner.TGID != uint32(os.Getpid()) {
					t.Errorf("owner = %+v, lookup error = %v; want PID %d", owner, err, os.Getpid())
				}
			}
		})
	}
}
