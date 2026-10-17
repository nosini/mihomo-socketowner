//go:build linux && amd64 && hostname_vm

package hostname

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const tunVMDevice = "hnTun0"

// tunVMRemote puts the server in a second network namespace behind a veth pair.
// Its address is not local, so the observed client's packets can be routed into
// the TUN device while Mihomo's own dial leaves through the veth.
func tunVMRemote(t *testing.T, network string) (*net.TCPListener, netip.AddrPort) {
	t.Helper()
	local, remote, prefix := "192.0.2.1", "192.0.2.2", "/24"
	if network == "tcp6" {
		local, remote, prefix = "2001:db8:5::1", "2001:db8:5::2", "/64"
	}
	runVM(t, "ip", "link", "add", "hnveth0", "type", "veth", "peer", "name", "hnveth1")
	t.Cleanup(func() { exec.Command("ip", "link", "del", "hnveth0").Run() })
	type listened struct {
		l   *net.TCPListener
		err error
	}
	tid, result, configured := make(chan int, 1), make(chan listened, 1), make(chan struct{})
	go func() {
		// Never unlocked: the thread exits with this goroutine, while the
		// namespace lives on through the listener and the veth peer.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			tid <- 0
			result <- listened{nil, err}
			return
		}
		tid <- unix.Gettid()
		<-configured
		l, err := net.ListenTCP(network, &net.TCPAddr{IP: net.ParseIP(remote)})
		result <- listened{l, err}
	}()
	id := <-tid
	if id == 0 {
		t.Fatal((<-result).err)
	}
	ns := fmt.Sprintf("--net=/proc/%d/task/%d/ns/net", os.Getpid(), id)
	address := func(args ...string) []string {
		if network == "tcp6" {
			return append(args, "nodad")
		}
		return args
	}
	runVM(t, "ip", "link", "set", "hnveth1", "netns", strconv.Itoa(id))
	runVM(t, "nsenter", ns, "ip", "link", "set", "lo", "up")
	runVM(t, "nsenter", append([]string{ns, "ip", "addr", "add", remote + prefix, "dev", "hnveth1"}, address()...)...)
	runVM(t, "nsenter", ns, "ip", "link", "set", "hnveth1", "up")
	runVM(t, "ip", address("addr", "add", local+prefix, "dev", "hnveth0")...)
	runVM(t, "ip", "link", "set", "hnveth0", "up")
	close(configured)
	r := <-result
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { r.l.Close() })
	return r.l, r.l.Addr().(*net.TCPAddr).AddrPort()
}

// routeVMIntoTUN policy-routes every TCP connection to target into the TUN
// device, except the helper's own (UID 1000) outbound dial.
func routeVMIntoTUN(t *testing.T, network string, target netip.AddrPort) {
	t.Helper()
	family, flag := "ip", "-4"
	if network == "tcp6" {
		family, flag = "ip6", "-6"
	}
	runVM(t, "ip", flag, "route", "add", "default", "dev", tunVMDevice, "table", "677")
	runVM(t, "ip", flag, "rule", "add", "fwmark", "0x2a5", "table", "677")
	t.Cleanup(func() { exec.Command("ip", flag, "rule", "del", "fwmark", "0x2a5", "table", "677").Run() })
	nft := fmt.Sprintf(`table inet hostname_tun {
 chain output { type route hook output priority mangle; policy accept;
 meta skuid != 1000 %s daddr %s tcp dport %d meta mark set 0x2a5
 }
}`, family, target.Addr(), target.Port())
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nft)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %s: %v", output, err)
	}
	t.Cleanup(func() { exec.Command("nft", "delete", "table", "inet", "hostname_tun").Run() })
	// Translated replies arrive on the TUN from a source routed via the veth.
	for _, path := range []string{"/proc/sys/net/ipv4/conf/all/rp_filter", "/proc/sys/net/ipv4/conf/" + tunVMDevice + "/rp_filter"} {
		if err := os.WriteFile(path, []byte("0"), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

// The TUN system stack reports the application's original tuple; Mihomo keys
// the lookup by it in the accepted socket's namespace.
func TestVMHostnameNativeTUN(t *testing.T) {
	path := os.Getenv("HOSTNAME_VM_NATIVE_MIHOMO")
	if path == "" {
		t.Skip("set HOSTNAME_VM_NATIVE_MIHOMO to the experimental native helper")
	}
	t.Setenv("HOSTNAME_VM_MIHOMO", path)
	t.Setenv("HOSTNAME_VM_ROUTE_NATIVE", "1")
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, scenario := range []string{"healthy", "wait", "unavailable", "crash", "unobserved"} {
			t.Run(network+"/"+scenario, func(t *testing.T) {
				remote, target := tunVMRemote(t, network)
				root, pins := bootstrapVMRoot(t)
				f := newFixtureListener(t, network, true, "", false, remote)
				f.command("any-source")
				a, ready := bootstrapVMEpoch(t, f, root, pins, "")
				h := newRouteVMHelperTUN(t, network, 250, ready.Endpoint, tunVMDevice)
				if e := h.read(t, "ready"); e.Address != tunVMDevice {
					t.Fatalf("helper inbound %q", e.Address)
				}
				routeVMIntoTUN(t, network, target)
				var c connection
				if scenario == "unobserved" {
					// This process is outside the observed cgroup; its flow has
					// no record and must not wait for the budget.
					plain, err := net.DialTimeout(network, target.String(), 3*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer plain.Close()
				} else {
					c = f.socket(f.command("open route.invalid name-first fd"))
				}
				accepted := h.read(t, "accepted")
				source, err := netip.ParseAddrPort(accepted.Source)
				if err != nil || accepted.Original != target.String() || !strings.HasPrefix(source.Addr().String(), map[string]string{"tcp4": "172.31.255.", "tcp6": "fdfe:dcba:9876::"}[network]) {
					t.Fatalf("not a TUN system-stack connection: %+v", accepted)
				}
				if scenario == "unavailable" {
					a.observer.exchange(t, authorityVMRequest{Command: "stop"})
				}
				h.reply(t, "")
				h.read(t, "native-start")
				if scenario == "wait" {
					time.Sleep(20 * time.Millisecond)
				}
				if scenario != "unobserved" {
					f.command("handshake %d", c.slot)
				}
				matched := false
				var dial routeVMEvent
				for {
					e := h.read(t, "")
					if e.Kind == "matched" {
						if matched || e.Name != "route.invalid" {
							t.Fatalf("invalid match %+v", e)
						}
						matched = true
						if scenario == "crash" {
							a.observer.cmd.Process.Kill()
							<-a.observer.done
						}
						if err := h.enc.Encode(struct{ Close, Reload bool }{}); err != nil {
							t.Fatal(err)
						}
						continue
					}
					if e.Kind != "dial" {
						t.Fatalf("native path requested supervisor data: %+v", e)
					}
					dial = e
					break
				}
				want, wantMatch := "DIRECT", scenario == "healthy" || scenario == "wait" || scenario == "crash"
				if scenario == "healthy" || scenario == "wait" {
					want = "NAMED"
				}
				if dial.Proxy != want || dial.Host != "" || dial.Original != target.String() || matched != wantMatch {
					t.Fatalf("wrong TUN route %+v matched=%v want %s", dial, matched, want)
				}
				if scenario == "unobserved" && time.Duration(dial.ElapsedNS) > 100*time.Millisecond {
					t.Fatalf("unobserved flow waited %v", time.Duration(dial.ElapsedNS))
				}
				if time.Duration(dial.ElapsedNS) > time.Second {
					t.Fatal("native wait exceeded its bounded budget")
				}
				h.read(t, "connected")
				remote.SetDeadline(time.Now().Add(3 * time.Second))
				server, err := remote.AcceptTCP()
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				if scenario == "unobserved" {
					return
				}
				c.server = server
				if name := wireName(t, c); name != "route.invalid" {
					t.Fatal("TUN lookup changed TLS bytes")
				}
				f.command("close %d", c.slot)
			})
		}
	}
}
