//go:build linux && amd64 && hostname_vm

package hostname

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestVMHostnameReaderCommit(t *testing.T) {
	if os.Getenv("HOSTNAME_VM_READER_MIHOMO") == "" {
		t.Skip("set HOSTNAME_VM_READER_MIHOMO to the two-module reader helper")
	}
	t.Setenv("HOSTNAME_VM_MIHOMO", os.Getenv("HOSTNAME_VM_READER_MIHOMO"))
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, process := range []string{"off", "always"} {
			for _, scenario := range []string{"healthy", "crash", "revoke", "second-send", "evict", "expired", "close-reader", "restart", "after-commit"} {
				t.Run(network+"/"+process+"/"+scenario, func(t *testing.T) {
					root, pins := bootstrapVMRoot(t)
					f := newFixtureSetup(t, network, true, "", false)
					a, ready := bootstrapVMEpoch(t, f, root, pins, "")
					budget := 1000 // leave room for the deliberate restart barrier
					if scenario == "expired" {
						budget = 250
					}
					h := newRouteVMHelperEndpoint(t, network, budget, process, "", ready.Endpoint)
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
					nft := fmt.Sprintf(`table inet hostname_commit { chain output { type nat hook output priority dstnat; policy accept;
 socket cgroupv2 level 1 "hostname-experiment-%d" %s daddr %s tcp dport %d redirect to :%s
 }
}`, f.pid, family, target.Addr(), target.Port(), port)
					cmd := exec.Command("nft", "-f", "-")
					cmd.Stdin = strings.NewReader(nft)
					if output, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("nft: %s: %v", output, err)
					}
					defer runVM(t, "nft", "delete", "table", "inet", "hostname_commit")
					c := f.socket(f.command("open route.invalid name-first fd"))
					accepted := h.read(t, "accepted")
					if accepted.Cookie == c.cookie || accepted.Original != target.String() {
						t.Fatal("incorrect accepted flow")
					}
					src, dst := netip.MustParseAddrPort(accepted.Source), netip.MustParseAddrPort(accepted.Local)
					key := flowKey{Netns: accepted.Netns, Source: src.Addr().As16(), Destination: dst.Addr().As16(), SourcePort: src.Port(), DestinationPort: dst.Port()}
					h.reply(t, "")
					sent, matched := false, false
					var dial routeVMEvent
					for {
						e := h.read(t, "")
						if e.Kind == "lookup" {
							if !sent {
								f.command("handshake %d", c.slot)
								sent = true
							}
							h.reply(t, "") // no name is supplied by the supervisor
							continue
						}
						if e.Kind == "matched" {
							if matched || !sent || e.Name != "route.invalid" {
								t.Fatalf("unexpected match: %+v", e)
							}
							matched = true
							var raw flowObservation
							if err := a.maps[3].Lookup(key, &raw); err != nil || raw.Cookie != c.cookie {
								t.Fatal("reader matched without original positive record")
							}
							switch scenario {
							case "crash", "restart":
								a.observer.cmd.Process.Kill()
								<-a.observer.done
								if scenario == "restart" {
									bootstrapVMEpoch(t, f, root, pins, "")
								}
							case "revoke":
								a.observer.exchange(t, authorityVMRequest{Command: "revoke"})
							case "second-send":
								f.command("raw %d", c.slot)
							case "evict":
								deleteVMFlow(t, a.maps[3], key)
							case "expired":
								time.Sleep(300 * time.Millisecond)
							}
							if scenario == "close-reader" {
								h.conn.SetWriteDeadline(time.Now().Add(time.Second))
								if err := h.enc.Encode(struct{ Close bool }{true}); err != nil {
									t.Fatal(err)
								}
							} else {
								h.reply(t, "")
							}
							continue
						}
						if e.Kind != "dial" {
							t.Fatalf("unexpected event: %+v", e)
						}
						dial = e
						break
					}
					want := "DIRECT"
					if scenario == "healthy" || scenario == "after-commit" {
						want = "NAMED"
					}
					if !matched || dial.Proxy != want || dial.Host != "" || dial.Original != target.String() {
						t.Fatalf("stale or incorrect route %+v, wanted %s", dial, want)
					}
					if scenario != "expired" && time.Duration(dial.ElapsedNS) >= time.Duration(budget)*time.Millisecond {
						t.Fatal("expiry masked the authority/correlation check")
					}
					h.read(t, "connected")
					if scenario == "after-commit" {
						a.observer.cmd.Process.Kill()
						<-a.observer.done
					}
					f.listener.SetDeadline(time.Now().Add(3 * time.Second))
					c.server, err = f.listener.AcceptTCP()
					if err != nil {
						t.Fatal(err)
					}
					defer c.server.Close()
					if name := wireName(t, c); name != "route.invalid" {
						t.Fatal("relay changed ClientHello")
					}
					f.command("close %d", c.slot)
					c.server.Close()
					if err := h.dec.Decode(&routeVMEvent{}); !errors.Is(err, io.EOF) && !errors.Is(err, unix.ECONNRESET) {
						t.Fatalf("extra event after commit: %v", err)
					}
					<-h.done
					if h.err != nil {
						t.Fatalf("unprivileged Mihomo failed: %v", h.err)
					}
				})
			}
		}
	}
}
