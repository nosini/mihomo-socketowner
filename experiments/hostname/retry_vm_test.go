//go:build linux && amd64 && hostname_vm

package hostname

import (
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func retryCount(t *testing.T, f *fixture, key uint32) uint64 {
	t.Helper()
	var count uint64
	if err := f.probe.collection.Maps["retry_test_counts"].Lookup(key, &count); err != nil {
		t.Fatal(err)
	}
	return count
}
func smallReceiveWindow(t *testing.T, f *fixture) {
	t.Helper()
	raw, err := f.listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) { socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 1024) }); err != nil || socketErr != nil {
		t.Fatalf("receive window: %v %v", err, socketErr)
	}
	f.command("tiny-send")
}
func TestVMInitialWindowLarge(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newPublicationFixture(t, network)
			c := f.open("large-window.test", "fd-first", "fd")
			f.command("large-alpn %d", c.slot)
			f.command("handshake %d", c.slot)
			flow := f.flow(c)
			if name, err := flow.Observation.hostname(); err != nil || name != "large-window.test" || flow.PayloadLen <= 4096 {
				t.Fatalf("large first window: %+v %v", flow, err)
			}
			if wireName(t, c) != "large-window.test" {
				t.Fatal("large ClientHello")
			}
			if retryCount(t, f, 2) != 0 {
				t.Fatal("large initial write rejected")
			}
		})
	}
}
func TestVMInitialWindowShortWrite(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newPublicationFixture(t, network)
			smallReceiveWindow(t, f)
			c := f.open("retry-window.test", "fd-first", "fd")
			f.command("retry-alpn %d", c.slot)
			first := f.command("handshake %d", c.slot)
			t.Logf("initial %s", first)
			if retryCount(t, f, 0) != 1 || retryCount(t, f, 1) == 0 {
				t.Fatalf("did not exercise initial short write and actual retry: first=%d retry=%d rejected=%d", retryCount(t, f, 0), retryCount(t, f, 1), retryCount(t, f, 2))
			}
			initial := f.lookup(c)
			if name := completeRetryHello(t, f, c); name != "retry-window.test" {
				t.Fatal(name)
			}
			var latest observation
			if err := f.probe.collection.Maps["send_snapshots"].Lookup(c.cookie, &latest); err != nil {
				t.Fatal(err)
			}
			if latest.BootNS != initial.BootNS || latest.Pad != 0 || latest.Len == 0 {
				t.Fatalf("retry changed original grant: first=%d latest=%d stage=%d len=%d accepted=%d rejected=%d", initial.BootNS, latest.BootNS, latest.Pad, latest.Len, retryCount(t, f, 1), retryCount(t, f, 2))
			}
			if retryCount(t, f, 2) != 0 {
				t.Fatal("verified retry rejected")
			}
			t.Logf("accepted %d actual retry hooks", retryCount(t, f, 1))
		})
	}
}

// The peer only parses ClientHello; no testing.Fatal runs in its goroutine.
func completeRetryHello(t *testing.T, f *fixture, c connection) string {
	t.Helper()
	type reply struct {
		name string
		err  error
	}
	done := make(chan reply, 1)
	c.server.SetDeadline(time.Now().Add(3 * time.Second))
	go func() {
		var name string
		peer := tls.Server(c.server, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			name = hello.ServerName
			return nil, errors.New("fixture stops at ClientHello")
		}})
		err := peer.Handshake()
		done <- reply{name, err}
	}()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		f.command("handshake %d", c.slot)
		select {
		case r := <-done:
			if r.name == "" {
				t.Fatalf("no complete ClientHello: %v", r.err)
			}
			return r.name
		default:
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("pending first window did not complete")
	return ""
}
func TestVMInitialWindowRetryMismatch(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, operation := range []string{"rename", "mutate-write", "alias"} {
			t.Run(network+"/"+operation, func(t *testing.T) {
				f := newPublicationFixture(t, network)
				smallReceiveWindow(t, f)
				c := f.open("original-window.test", "fd-first", "fd")
				f.command("retry-alpn %d", c.slot)
				f.command("handshake %d", c.slot)
				if retryCount(t, f, 1) == 0 {
					t.Fatal("no real retry")
				}
				key := f.flowKey(c)
				if name, err := f.flow(c).Observation.hostname(); err != nil || name != "original-window.test" {
					t.Fatalf("initial name: %q %v", name, err)
				}
				var before, after sendEvidence
				windows := f.probe.collection.Maps["send_windows"]
				if err := windows.Lookup(c.cookie, &before); err != nil {
					t.Fatal(err)
				}
				f.fault(publicationFault{Mask: 64}) // retain the original positive flow
				changed := c
				switch operation {
				case "rename":
					f.command("rename %d changed.test", c.slot)
				case "mutate-write":
					f.command("mutate-write %d", c.slot)
				case "alias":
					changed = f.alias(c, "original-window.test")
				}
				f.command("handshake %d", changed.slot)
				f.assertSendAmbiguous(c)
				assertRetainedName(t, f.probe, key, c.cookie)
				if err := windows.Lookup(c.cookie, &after); err != nil || before != after {
					t.Fatalf("retry changed the initial capture: %v", err)
				}
				if retryCount(t, f, 2) == 0 {
					t.Fatal("no rejected retry")
				}
				assertPublicationHealthy(t, f)
			})
		}
	}
}
func TestVMInitialWindowRejectsNonHello(t *testing.T) {
	f := newPublicationFixture(t, "tcp4")
	c := f.open("nonhello.test", "fd-first", "fd")
	f.command("mutate-write %d", c.slot)
	f.command("handshake %d", c.slot)
	f.assertSendAmbiguous(c)
	var window sendEvidence
	if err := f.probe.collection.Maps["send_windows"].Lookup(c.cookie, &window); err != nil || window.Ready != 0 || window.Len != 0 {
		t.Fatalf("non-ClientHello captured: %v", err)
	}
}
