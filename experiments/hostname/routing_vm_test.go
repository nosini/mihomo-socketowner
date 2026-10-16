//go:build linux && amd64 && hostname_vm

package hostname

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Private inherited-socket protocol shared with Mihomo's test-only helper.
// No maps, links, pins or observer authority are transferred to that process.
type routeVMEvent struct {
	Kind, Address, Source, Local, Original, Name, Proxy, Host, RuleHost, SniffHost string
	Netns, Cookie                                                                  uint64
	ElapsedNS                                                                      int64
}
type routeVMReply struct{ Name string }

type routeVMHelper struct {
	conn net.Conn
	enc  *json.Encoder
	dec  *json.Decoder
	cmd  *exec.Cmd
	log  bytes.Buffer
	done chan struct{}
	err  error
}

func newRouteVMHelper(t *testing.T, network string, budget int, processMode, policy string) *routeVMHelper {
	t.Helper()
	path := os.Getenv("HOSTNAME_VM_MIHOMO")
	if path == "" {
		t.Skip("set HOSTNAME_VM_MIHOMO to Mihomo's hostname_vm tunnel test binary")
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := os.NewFile(uintptr(fds[0]), "route-parent"), os.NewFile(uintptr(fds[1]), "route-child")
	conn, err := net.FileConn(parent)
	parent.Close()
	if err != nil {
		child.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	h := &routeVMHelper{conn: conn, enc: json.NewEncoder(conn), dec: json.NewDecoder(conn), done: make(chan struct{})}
	h.cmd = exec.CommandContext(ctx, path, "-test.run", "^TestVMHostnameRouteHelper$", "-test.timeout", "18s")
	address := "127.0.0.1:0"
	if network == "tcp6" {
		address = "[::1]:0"
	}
	h.cmd.Env = append(os.Environ(), "HOSTNAME_VM_ROUTE_HELPER=1", "HOSTNAME_VM_ROUTE_BUDGET_MS="+strconv.Itoa(budget), "HOSTNAME_VM_ROUTE_PROCESS="+processMode, "HOSTNAME_VM_ROUTE_LISTEN="+address, "HOSTNAME_VM_ROUTE_POLICY="+policy)
	h.cmd.ExtraFiles = []*os.File{child}
	h.cmd.Stdout, h.cmd.Stderr = &h.log, &h.log
	err = h.cmd.Start()
	child.Close()
	if err != nil {
		conn.Close()
		cancel()
		t.Fatal(err)
	}
	go func() { h.err = h.cmd.Wait(); close(h.done) }()
	t.Cleanup(func() {
		conn.Close()
		cancel()
		<-h.done // reap on all failure paths too
		if t.Failed() {
			t.Log(h.log.String())
		}
	})
	return h
}

func (h *routeVMHelper) read(t *testing.T, kind string) routeVMEvent {
	t.Helper()
	h.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var e routeVMEvent
	if err := h.dec.Decode(&e); err != nil {
		t.Fatalf("Mihomo control: %v", err)
	}
	if kind != "" && e.Kind != kind {
		t.Fatalf("Mihomo event %+v, wanted %s", e, kind)
	}
	return e
}

func (h *routeVMHelper) reply(t *testing.T, name string) {
	t.Helper()
	h.conn.SetWriteDeadline(time.Now().Add(time.Second))
	if err := h.enc.Encode(routeVMReply{Name: name}); err != nil {
		t.Fatal(err)
	}
}

func TestVMHostnameRoutingDeadline(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, scenario := range []string{"current", "before-deadline", "late", "observer-stopped", "lookup-stalled", "reply-late", "sniff", "mapping-hosts"} {
			for _, processMode := range []string{"off", "always"} {
				t.Run(network+"/"+scenario+"/process-"+processMode, func(t *testing.T) {
					budget := 250
					if scenario == "current" {
						budget = 0
					}
					// Start the optional helper first so a missing path skips cheaply.
					h := newRouteVMHelper(t, network, budget, processMode, scenario)
					ready := h.read(t, "ready")
					f := newFixtureMode(t, network, true)
					disableHandshakeProbe(t, f)
					original := f.listener.Addr().String()
					_, redirectPort, err := net.SplitHostPort(ready.Address)
					if err != nil {
						t.Fatal(err)
					}
					target := f.listener.Addr().(*net.TCPAddr).AddrPort()
					family := "ip"
					if network == "tcp6" {
						family = "ip6"
					}
					// Redirect only the target application's private cgroup. Proxy
					// sockets must not reenter this listener (including on loopback,
					// where Mihomo deliberately does not apply routing marks).
					nft := fmt.Sprintf(`table inet hostname_route {
					 chain output { type nat hook output priority dstnat; policy accept;
					  socket cgroupv2 level 1 "hostname-experiment-%d" %s daddr %s tcp dport %d redirect to :%s
					 }
					}`, f.pid, family, target.Addr(), target.Port(), redirectPort)
					cmd := exec.Command("nft", "-f", "-")
					cmd.Stdin = strings.NewReader(nft)
					if output, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("nft: %s: %v", output, err)
					}
					defer runVM(t, "nft", "delete", "table", "inet", "hostname_route")
					c := f.socket(f.command("open route.invalid name-first fd"))
					accepted := h.read(t, "accepted")
					if accepted.Original != original || accepted.Cookie == c.cookie || accepted.Netns == 0 {
						t.Fatalf("original destination or socket identity: %+v; application %+v", accepted, c)
					}
					src, dst := netip.MustParseAddrPort(accepted.Source), netip.MustParseAddrPort(accepted.Local)
					key := flowKey{Netns: accepted.Netns, Source: src.Addr().As16(), Destination: dst.Addr().As16(), SourcePort: src.Port(), DestinationPort: dst.Port()}
					lookup := func() string {
						o, err := lookupPublished[flowObservation](f.probe, "send_flows", key)
						if err != nil {
							return ""
						}
						name, err := o.Observation.hostname()
						if err != nil {
							return ""
						}
						if o.Cookie != c.cookie || o.Observation.Cookie != c.cookie || o.Observation.TGID != f.pid {
							t.Fatalf("wrong application identity: %+v", o)
						}
						return name
					}
					if name := lookup(); name != "" {
						t.Fatalf("hostname available before ClientHello: %q", name)
					}
					if scenario == "observer-stopped" {
						f.probe.stop()
					}
					h.reply(t, "") // release the accepted inbound
					lookups := 0
					var dial routeVMEvent
					for {
						e := h.read(t, "")
						if e.Kind == "dial" {
							dial = e
							break
						}
						if e.Kind != "lookup" {
							t.Fatalf("unexpected event: %+v", e)
						}
						lookups++
						name := lookup()
						if lookups == 1 {
							if name != "" {
								t.Fatal("first lookup preceded the sending operation")
							}
							if scenario == "before-deadline" || scenario == "observer-stopped" || scenario == "reply-late" || scenario == "sniff" || scenario == "mapping-hosts" {
								f.command("handshake %d", c.slot)
							}
							if scenario == "reply-late" {
								name = lookup()
								if name != "route.invalid" {
									t.Fatal("no positive record for delayed response")
								}
								time.Sleep(time.Duration(budget+50) * time.Millisecond)
							}
						}
						if scenario != "lookup-stalled" {
							h.reply(t, name)
						}
					}
					want := "DIRECT"
					if scenario == "before-deadline" || scenario == "sniff" || scenario == "mapping-hosts" {
						want = "NAMED"
					}
					if dial.Proxy != want || dial.Original != original || dial.Host != "" {
						t.Fatalf("route/dial %+v, expected %s to %s", dial, want, original)
					}
					if want == "NAMED" && dial.RuleHost != "route.invalid" {
						t.Fatalf("real RuleHost did not select application name: %+v", dial)
					}
					if scenario == "sniff" && dial.SniffHost != "route.invalid" {
						t.Fatalf("TLS sniff did not run: %+v", dial)
					}
					h.read(t, "connected") // reject dial failures before testing relay
					elapsed := time.Duration(dial.ElapsedNS)
					if elapsed > time.Second || (budget > 0 && want == "DIRECT" && elapsed < time.Duration(budget)*time.Millisecond) {
						t.Fatalf("unexpected bounded routing time %s (budget %dms)", elapsed, budget)
					}
					if scenario == "current" || scenario == "late" || scenario == "lookup-stalled" {
						// No ClientHello until the real outbound has already been chosen.
						f.command("handshake %d", c.slot)
						if name := lookup(); name != "route.invalid" {
							t.Fatalf("late evidence missing: %q", name)
						}
					}
					f.listener.SetDeadline(time.Now().Add(3 * time.Second))
					c.server, err = f.listener.AcceptTCP()
					if err != nil {
						t.Fatal(err)
					}
					defer c.server.Close()
					if name := wireName(t, c); name != "route.invalid" {
						t.Fatalf("Mihomo forwarded wrong ClientHello: %q", name)
					}
					// A late name never causes a second dial or a route change.
					f.command("close %d", c.slot)
					c.server.Close()
					// A reply queued as the deadline expires (including an unknown
					// result) can remain unread and reset the peer at close. Still
					// reject any further event and require successful helper exit.
					if err := h.dec.Decode(&routeVMEvent{}); !errors.Is(err, io.EOF) && !errors.Is(err, unix.ECONNRESET) {
						t.Fatalf("expected helper closure after the committed connection closed: %v", err)
					}
					<-h.done
					if h.err != nil {
						t.Fatalf("Mihomo helper failed: %v", h.err)
					}
					if (scenario == "before-deadline" || scenario == "sniff" || scenario == "mapping-hosts") && lookups < 2 {
						t.Fatal("did not test evidence arriving after an initial miss")
					}
					if scenario == "current" && lookups != 0 {
						t.Fatal("unmodified routing path unexpectedly waited for evidence")
					}
					t.Logf("%s after %s, %d lookups; preserved %s", dial.Proxy, elapsed, lookups, original)
				})
			}
		}
	}
}
