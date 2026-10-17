//go:build linux && amd64 && hostname_vm

package hostname

import (
	"context"
	"encoding/json"
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
			reply.Unknown, reply.Error = true, err.Error()
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
