//go:build linux && amd64 && hostname_vm

package hostname

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	H "github.com/nosini/socketowner/hostname"
)

// Only test-control is inherited. The public module obtains all authority
// through the real endpoint as the configured nonroot reader.
func runContractVMReader(t *testing.T, config authorityVMConfig, dec *json.Decoder, enc *json.Encoder) {
	if os.Geteuid() != 1000 {
		t.Fatal("contract reader must be unprivileged")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !strings.Contains(string(status), "CapEff:\t0000000000000000") {
		t.Fatal("reader has capabilities", err)
	}
	before := countVMFDs(t)
	r, err := H.DialReader(config.Endpoint, time.Now().Add(2*time.Second))
	if err != nil {
		if after := countVMFDs(t); after != before {
			t.Fatalf("bootstrap leaked FDs: %d -> %d", before, after)
		}
		if err := enc.Encode(authorityVMReply{Unknown: true, Error: err.Error()}); err != nil {
			t.Fatal(err)
		}
		return
	}
	defer r.Close()
	if err := enc.Encode(authorityVMReply{}); err != nil {
		t.Fatal(err)
	}
	var candidate *H.Candidate
	for {
		var request authorityVMRequest
		if err := dec.Decode(&request); err != nil {
			return
		}
		reply := authorityVMReply{}
		switch request.Command {
		case "lookup":
			k := request.Key
			candidate, err = r.Lookup(H.TCPFlow{Netns: k.Netns, Source: netip.AddrPortFrom(netip.AddrFrom16(k.Source).Unmap(), k.SourcePort), Destination: netip.AddrPortFrom(netip.AddrFrom16(k.Destination).Unmap(), k.DestinationPort)}, time.Now().Add(time.Second))
			if err == nil {
				reply.Name = candidate.Name()
			}
		case "validate":
			err = candidate.Validate()
		case "close":
			r.Close()
			r.Close()
			err = candidate.Validate()
			if after := countVMFDs(t); after != before {
				t.Fatalf("reader retained FDs after Close: %d -> %d", before, after)
			}
		default:
			t.Fatal("invalid contract reader command")
		}
		if err != nil {
			reply.Unknown, reply.NoFlow, reply.Error = true, errors.Is(err, H.ErrNoFlow), err.Error()
		}
		if err := enc.Encode(reply); err != nil {
			t.Fatal(err)
		}
	}
}

func countVMFDs(t *testing.T) int {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(fds)
}

func TestVMHostnameContract(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, event := range []string{"close", "second-send", "stop", "crash", "expiry"} {
			t.Run(network+"/"+event, func(t *testing.T) {
				root, pins := bootstrapVMRoot(t)
				f := newFixtureSetup(t, network, true, "", false)
				a, ready := bootstrapVMEpoch(t, f, root, pins, "")
				c, key := a.named(t)
				h := startAuthorityVMProcess(t, "contract-reader", nil)
				if reply := h.exchange(t, authorityVMConfig{Endpoint: ready.Endpoint}); reply.Unknown {
					t.Fatal(reply)
				}
				if reply := h.exchange(t, authorityVMRequest{Command: "lookup", Key: key}); reply.Unknown || reply.Name != "authority.test" {
					t.Fatal(reply)
				}
				if reply := h.exchange(t, authorityVMRequest{Command: "validate"}); reply.Unknown {
					t.Fatal(reply)
				}
				switch event {
				case "close":
					if reply := h.exchange(t, authorityVMRequest{Command: "close"}); !reply.Unknown {
						t.Fatal("Close retained candidate")
					}
				case "second-send":
					f.command("raw %d", c.slot)
				case "stop":
					a.observer.exchange(t, authorityVMRequest{Command: "stop"})
				case "crash":
					a.observer.cmd.Process.Kill()
					<-a.observer.done
				case "expiry":
					time.Sleep(1100 * time.Millisecond)
				}
				if reply := h.exchange(t, authorityVMRequest{Command: "validate"}); !reply.Unknown {
					t.Fatal("stale candidate validated")
				}
				if event != "expiry" {
					if reply := h.exchange(t, authorityVMRequest{Command: "lookup", Key: key}); !reply.Unknown {
						t.Fatal("invalid session/flow authorized another candidate")
					}
				}
			})
		}
	}
}

// Only a flow without any record is reported as unobserved. An observed socket
// has its SYN record before the proxy accepts, even before its first send.
func TestVMHostnameContractUnobservedFlow(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			root, pins := bootstrapVMRoot(t)
			f := newFixtureSetup(t, network, true, "", false)
			_, ready := bootstrapVMEpoch(t, f, root, pins, "")
			c := f.accepted(f.command("open pending.test name-first fd"))
			h := startAuthorityVMProcess(t, "contract-reader", nil)
			if reply := h.exchange(t, authorityVMConfig{Endpoint: ready.Endpoint}); reply.Unknown {
				t.Fatal(reply)
			}
			key := f.flowKey(c)
			if reply := h.exchange(t, authorityVMRequest{Command: "lookup", Key: key}); !reply.Unknown || reply.NoFlow {
				t.Fatalf("observed socket before its first send: %+v", reply)
			}
			key.SourcePort ^= 1
			if reply := h.exchange(t, authorityVMRequest{Command: "lookup", Key: key}); !reply.Unknown || !reply.NoFlow {
				t.Fatalf("flow without a record: %+v", reply)
			}
		})
	}
}

// Window-limited ClientHello segments rewrite the flow record's packet fields
// between Lookup and Validate. Only a changed observation may fail validation.
func TestVMHostnameContractRetriedWindow(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, change := range []string{"unchanged", "rename"} {
			t.Run(network+"/"+change, func(t *testing.T) {
				root, pins := bootstrapVMRoot(t)
				f := newFixtureSetup(t, network, true, "", false)
				_, ready := bootstrapVMEpoch(t, f, root, pins, "")
				smallReceiveWindow(t, f)
				c := f.accepted(f.command("open retry-window.test fd-first fd"))
				f.command("retry-alpn %d", c.slot)
				if hello := f.command("handshake %d", c.slot); hello != fmt.Sprintf("handshake %d -1 3", c.slot) {
					t.Fatalf("ClientHello did not stop on a pending write: %s", hello)
				}
				h := startAuthorityVMProcess(t, "contract-reader", nil)
				if reply := h.exchange(t, authorityVMConfig{Endpoint: ready.Endpoint}); reply.Unknown {
					t.Fatal(reply)
				}
				if reply := h.exchange(t, authorityVMRequest{Command: "lookup", Key: f.flowKey(c)}); reply.Unknown || reply.Name != "retry-window.test" {
					t.Fatal(reply)
				}
				if change == "rename" {
					f.command("rename %d other-window.test", c.slot)
				}
				// Like the proxy before route commitment, read the whole record
				// without replying: the client's ACK of a reply would republish
				// the flow without a name, which is correct but not this case.
				drainClientHello(t, f, c)
				reply := h.exchange(t, authorityVMRequest{Command: "validate"})
				if change == "unchanged" && reply.Unknown {
					t.Fatalf("remaining window segments invalidated the candidate: %+v", reply)
				}
				if change == "rename" && !reply.Unknown {
					t.Fatal("renamed retry validated the original candidate")
				}
			})
		}
	}
}

// drainClientHello reads one complete TLS record while the client retries its
// pending write, sending nothing back.
func drainClientHello(t *testing.T, f *fixture, c connection) {
	t.Helper()
	done := make(chan error, 1)
	c.server.SetReadDeadline(time.Now().Add(3 * time.Second))
	go func() {
		header := make([]byte, 5)
		if _, err := io.ReadFull(c.server, header); err != nil {
			done <- err
			return
		}
		_, err := io.ReadFull(c.server, make([]byte, int(header[3])<<8|int(header[4])))
		done <- err
	}()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		f.command("handshake %d", c.slot)
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("incomplete ClientHello record: %v", err)
			}
			return
		default:
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("pending ClientHello did not complete")
}

func TestVMHostnameContractBadPublisher(t *testing.T) {
	for _, attack := range []string{"nonce", "version", "profile", "legacy-profile", "profile-2", "missing", "extra", "truncated-rights", "wrong-type"} {
		t.Run(attack, func(t *testing.T) {
			root, _ := bootstrapVMRoot(t)
			endpoint := filepath.Join(root, "contract.sock")
			fake := startAuthorityVMProcess(t, "bootstrap-fake", nil)
			fake.exchange(t, authorityVMConfig{Endpoint: endpoint, Attack: attack})
			h := startAuthorityVMProcess(t, "contract-reader", nil)
			if reply := h.exchange(t, authorityVMConfig{Endpoint: endpoint}); !reply.Unknown || reply.Error == "" {
				t.Fatal("bad publisher granted a session", reply)
			}
		})
	}
}

func TestVMHostnameContractResidentObserver(t *testing.T) {
	run := newObserverVMRun(t)
	observer := run.start()
	a := run.connect()
	_, key := a.named(t)
	h := startAuthorityVMProcess(t, "contract-reader", nil)
	if reply := h.exchange(t, authorityVMConfig{Endpoint: ObserverEndpoint(run.root)}); reply.Unknown {
		t.Fatal(reply)
	}
	if reply := h.exchange(t, authorityVMRequest{Command: "lookup", Key: key}); reply.Unknown || reply.Name != "authority.test" {
		t.Fatal(reply)
	}
	observer.cmd.Process.Signal(syscall.SIGTERM)
	if err := observer.wait(t); err != nil {
		t.Fatal(err)
	}
	if reply := h.exchange(t, authorityVMRequest{Command: "validate"}); !reply.Unknown {
		t.Fatal("resident stop retained candidate")
	}
	run.assertStopped()
}

func TestVMHostnameContractBootstrapCancellation(t *testing.T) {
	root, _ := bootstrapVMRoot(t)
	endpoint := filepath.Join(root, "canceled.sock")
	fake := startAuthorityVMProcess(t, "bootstrap-fake", nil)
	fake.exchange(t, authorityVMConfig{Endpoint: endpoint, Attack: "stall-context"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	before := countVMFDs(t)
	done := make(chan error, 1)
	go func() {
		r, err := H.DialReaderContext(ctx, endpoint, time.Now().Add(5*time.Second))
		if r != nil {
			r.Close()
		}
		done <- err
	}()
	var phase authorityVMReply
	fake.conn.SetReadDeadline(time.Now().Add(time.Second))
	if err := fake.dec.Decode(&phase); err != nil || phase.Phase != "request" {
		t.Fatalf("bootstrap did not wait for response: %+v %v", phase, err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled bootstrap granted session")
		}
	case <-time.After(time.Second):
		t.Fatal("bootstrap ignored cancellation")
	}
	if after := countVMFDs(t); after != before {
		t.Fatalf("cancellation leaked FDs: %d -> %d", before, after)
	}
}
