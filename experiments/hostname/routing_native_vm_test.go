//go:build linux && amd64 && hostname_vm

package hostname

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestVMHostnameNativeLookup(t *testing.T) {
	path := os.Getenv("HOSTNAME_VM_NATIVE_MIHOMO")
	if path == "" {
		t.Skip("set HOSTNAME_VM_NATIVE_MIHOMO to the experimental native helper")
	}
	t.Setenv("HOSTNAME_VM_MIHOMO", path)
	t.Setenv("HOSTNAME_VM_ROUTE_NATIVE", "1")
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, process := range []string{"off", "always"} {
			for _, scenario := range []string{"healthy", "wait", "late", "unavailable", "bootstrap-stalled", "disable", "reload", "crash"} {
				t.Run(network+"/"+process+"/"+scenario, func(t *testing.T) {
					root, pins := bootstrapVMRoot(t)
					f := newFixtureSetup(t, network, true, "", false)
					a, ready := bootstrapVMEpoch(t, f, root, pins, "")
					h := newRouteVMHelperEndpoint(t, network, 250, process, "", ready.Endpoint)
					listener := h.read(t, "ready")
					_, port, err := net.SplitHostPort(listener.Address)
					if err != nil {
						t.Fatal(err)
					}
					target := f.listener.Addr().(*net.TCPAddr).AddrPort()
					family := "ip"
					if network == "tcp6" {
						family = "ip6"
					}
					nft := fmt.Sprintf(`table inet hostname_native {
 chain output { type nat hook output priority dstnat; policy accept;
 socket cgroupv2 level 1 "hostname-experiment-%d" %s daddr %s tcp dport %d redirect to :%s
 }
}`, f.pid, family, target.Addr(), target.Port(), port)
					cmd := exec.Command("nft", "-f", "-")
					cmd.Stdin = strings.NewReader(nft)
					if output, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("nft: %s: %v", output, err)
					}
					defer runVM(t, "nft", "delete", "table", "inet", "hostname_native")
					c := f.socket(f.command("open route.invalid name-first fd"))
					accepted := h.read(t, "accepted")
					if accepted.Cookie == c.cookie || accepted.Original != target.String() {
						t.Fatal("wrong accepted/original flow")
					}
					var fake *authorityVMProcess
					if scenario == "unavailable" || scenario == "bootstrap-stalled" {
						a.observer.exchange(t, authorityVMRequest{Command: "stop"})
						if scenario == "bootstrap-stalled" {
							fake = startAuthorityVMProcess(t, "bootstrap-fake", nil)
							fake.exchange(t, authorityVMConfig{Endpoint: ready.Endpoint, Attack: "stall-context"})
						}
					}
					h.reply(t, "")
					h.read(t, "native-start")
					if scenario == "wait" {
						time.Sleep(20 * time.Millisecond)
					}
					if scenario == "late" {
						time.Sleep(300 * time.Millisecond)
					}
					f.command("handshake %d", c.slot)
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
							if err := h.enc.Encode(struct{ Close, Reload bool }{scenario == "disable", scenario == "reload"}); err != nil {
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
					want := "DIRECT"
					if scenario == "healthy" || scenario == "wait" {
						want = "NAMED"
					}
					wantMatch := scenario != "late" && scenario != "unavailable" && scenario != "bootstrap-stalled"
					if dial.Proxy != want || dial.Host != "" || dial.Original != target.String() || matched != wantMatch {
						t.Fatalf("wrong native route %+v matched=%v want %s", dial, matched, want)
					}
					if (scenario == "late" || scenario == "bootstrap-stalled") && time.Duration(dial.ElapsedNS) < 250*time.Millisecond {
						t.Fatal("wait was not exercised")
					}
					if time.Duration(dial.ElapsedNS) > time.Second {
						t.Fatal("native wait exceeded its bounded budget")
					}
					h.read(t, "connected") // helper also rejects retained BPF/pidfd FDs at this dial
					if fake != nil {
						var phase authorityVMReply
						fake.conn.SetReadDeadline(time.Now().Add(time.Second))
						if err := fake.dec.Decode(&phase); err != nil || phase.Phase != "request" {
							t.Fatal("bootstrap did not reach the stalled publisher")
						}
						<-fake.done
						if fake.err != nil {
							t.Fatal(fake.err)
						}
					}
					f.listener.SetDeadline(time.Now().Add(3 * time.Second))
					c.server, err = f.listener.AcceptTCP()
					if err != nil {
						t.Fatal(err)
					}
					defer c.server.Close()
					if name := wireName(t, c); name != "route.invalid" {
						t.Fatal("native lookup changed TLS bytes")
					}
					f.command("close %d", c.slot)
					c.server.Close()
					if err := h.dec.Decode(&routeVMEvent{}); !errors.Is(err, io.EOF) && !errors.Is(err, unix.ECONNRESET) {
						t.Fatalf("extra native route: %v", err)
					}
					<-h.done
					if h.err != nil {
						t.Fatalf("native Mihomo failed: %v", h.err)
					}
				})
			}
		}
	}
}
