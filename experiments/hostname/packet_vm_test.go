//go:build linux && amd64 && hostname_vm

package hostname

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

const sendBytesMax = 4096

type sendEvidence struct {
	Sequence, Len uint32
	Bytes         [sendBytesMax]byte
	LifetimeReady uint64
}

// Socket-filter TestRun consumes the Ethernet header before executing BPF.
func syntheticPacket(ipv6 bool, sequence uint32, payload []byte, ipOptions, tcpOptions int) []byte {
	ipLen := 20 + ipOptions
	if ipv6 {
		ipLen = 40
	}
	total := ipLen + 20 + tcpOptions + len(payload)
	packet := make([]byte, 14+total)
	ip := packet[14:]
	if ipv6 {
		binary.BigEndian.PutUint16(packet[12:], 0x86dd)
		ip[0], ip[6] = 0x60, 6
		binary.BigEndian.PutUint16(ip[4:], uint16(total-40))
	} else {
		binary.BigEndian.PutUint16(packet[12:], 0x0800)
		ip[0], ip[9] = 0x40|byte(ipLen/4), 6
		binary.BigEndian.PutUint16(ip[2:], uint16(total))
	}
	tcp := ip[ipLen:]
	binary.BigEndian.PutUint16(tcp, 12345)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	binary.BigEndian.PutUint32(tcp[4:], sequence)
	tcp[12], tcp[13] = byte((20+tcpOptions)/4)<<4, 0x18
	copy(tcp[20+tcpOptions:], payload)
	return packet
}

func TestVMPacketMatcher(t *testing.T) {
	f := newPublicationFixture(t, "tcp4")
	var evidence sendEvidence
	evidence.Sequence, evidence.Len = 0xffffff80, sendBytesMax
	for i := range evidence.Bytes {
		evidence.Bytes[i] = byte(i*73 + 19)
	}
	for _, ipv6 := range []bool{false, true} {
		for _, tc := range []struct {
			name                  string
			offset, length        int
			ipOptions, tcpOptions int
			mutate                func([]byte) []byte
			captured              uint32
			want                  bool
		}{
			{name: "full-write", length: sendBytesMax, captured: sendBytesMax, want: true},
			{name: "first-segment", length: 536, captured: sendBytesMax, want: true},
			{name: "middle-segment-wrap", offset: 537, length: 1097, captured: sendBytesMax, want: true},
			{name: "last-byte", offset: sendBytesMax - 1, length: 1, captured: sendBytesMax, want: true},
			{name: "header-options", length: 65, ipOptions: 4, tcpOptions: 12, captured: sendBytesMax, want: true},
			{name: "ack-only", captured: sendBytesMax},
			{name: "uncaptured", length: 32},
			{name: "oversize-capture", length: 32, captured: sendBytesMax + 1},
			{name: "before-window", offset: -1, length: 1, captured: sendBytesMax},
			{name: "past-window", offset: sendBytesMax, length: 1, captured: sendBytesMax},
			{name: "crosses-end", offset: sendBytesMax - 1, length: 2, captured: sendBytesMax},
			{name: "truncated", length: 64, captured: sendBytesMax, mutate: func(p []byte) []byte { return p[:len(p)-1] }},
			{name: "extra-trailer", length: 64, captured: sendBytesMax, mutate: func(p []byte) []byte { return append(p, 0) }},
			{name: "wrong-version", length: 64, captured: sendBytesMax, mutate: func(p []byte) []byte { p[14] = 0x70; return p }},
		} {
			t.Run(fmt.Sprintf("ipv6=%t/%s", ipv6, tc.name), func(t *testing.T) {
				input := evidence
				input.Len = tc.captured
				if err := f.probe.collection.Maps["packet_test_evidence"].Update(uint32(0), input, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				payload := make([]byte, tc.length)
				for i := range payload {
					index := tc.offset + i
					if index >= 0 && index < len(input.Bytes) {
						payload[i] = input.Bytes[index]
					}
				}
				packet := syntheticPacket(ipv6, input.Sequence+uint32(tc.offset), payload, tc.ipOptions, tc.tcpOptions)
				if tc.mutate != nil {
					packet = tc.mutate(packet)
				}
				ret, _, err := f.probe.collection.Programs["test_packet"].Test(packet)
				if err != nil || (ret == 1) != tc.want {
					t.Fatalf("match %d, want %t: %v", ret, tc.want, err)
				}
			})
		}
		// Change bytes on either side of chunk boundaries and at the limit.
		for _, index := range []int{0, 31, 32, 63, 64, 4095} {
			t.Run(fmt.Sprintf("ipv6=%t/changed-byte-%d", ipv6, index), func(t *testing.T) {
				if err := f.probe.collection.Maps["packet_test_evidence"].Update(uint32(0), evidence, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				payload := evidence.Bytes
				payload[index] ^= 1
				ret, _, err := f.probe.collection.Programs["test_packet"].Test(syntheticPacket(ipv6, evidence.Sequence, payload[:], 0, 0))
				if err != nil || ret != 0 {
					t.Fatalf("changed byte accepted: %d, %v", ret, err)
				}
			})
		}
		for _, bad := range []string{"syn", "fin", "rst", "urgent", "no-ack", "tcp-short", "tcp-long", "tcp-reserved", "non-tcp", "bad-ip-length", "fragment-or-extension"} {
			t.Run(fmt.Sprintf("ipv6=%t/%s", ipv6, bad), func(t *testing.T) {
				packet := syntheticPacket(ipv6, evidence.Sequence, evidence.Bytes[:64], 0, 0)
				ip := packet[14:]
				tcpOffset := 20
				if ipv6 {
					tcpOffset = 40
				}
				tcp := ip[tcpOffset:]
				switch bad {
				case "syn":
					tcp[13] |= 2
				case "fin":
					tcp[13] |= 1
				case "rst":
					tcp[13] |= 4
				case "urgent":
					tcp[13] |= 32
				case "no-ack":
					tcp[13] = 8
				case "tcp-short":
					tcp[12] = 0x40
				case "tcp-long":
					tcp[12] = 0xf0
					packet = packet[:14+tcpOffset+20]
					if ipv6 {
						binary.BigEndian.PutUint16(ip[4:], 20)
					} else {
						binary.BigEndian.PutUint16(ip[2:], 40)
					}
				case "tcp-reserved":
					tcp[12] |= 1
				case "non-tcp":
					if ipv6 {
						ip[6] = 17
					} else {
						ip[9] = 17
					}
				case "bad-ip-length":
					if ipv6 {
						ip[4], ip[5] = 0, 0
					} else {
						ip[2], ip[3] = 0, 10
					}
				case "fragment-or-extension":
					if ipv6 {
						ip[6] = 44
					} else {
						ip[6] = 0x20
					}
				}
				ret, _, err := f.probe.collection.Programs["test_packet"].Test(packet)
				if err != nil || ret != 0 {
					t.Fatalf("unsupported packet accepted: %d, %v", ret, err)
				}
			})
		}
	}
}

func requireQueued(t *testing.T, line string) {
	t.Helper()
	var queued int
	if n, err := fmt.Sscanf(line, "corked %d", &queued); n != 1 || err != nil || queued <= 0 {
		t.Fatalf("no verified unsent bytes: %q", line)
	}
}

func TestVMPacketControlBeforePayload(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newFixtureMode(t, network, true)
			disableHandshakeProbe(t, f)
			c := f.open("payload.test", "fd-first", "fd")
			requireQueued(t, f.command("cork-one %d", c.slot))
			if name, err := f.lookup(c).hostname(); err != nil || name != "payload.test" {
				t.Fatalf("no live send observation: %q, %v", name, err)
			}
			before := f.flow(c)
			if before.Observation.Len != 0 {
				t.Fatal("hostname published before any data packet")
			}
			if _, err := c.server.Write([]byte{'P'}); err != nil {
				t.Fatal(err)
			}
			requireQueued(t, f.command("ack %d", c.slot))
			after := f.flow(c)
			if after.PacketNS <= before.PacketNS || after.PayloadLen != 0 || after.Observation.Len != 0 {
				t.Fatalf("ACK did not stay unknown: before %+v, after %+v", before, after)
			}
			f.command("uncork %d", c.slot)
			flow := f.flow(c)
			if flow.PayloadLen == 0 || flow.PayloadLen > sendBytesMax || flow.PacketNS <= after.PacketNS {
				t.Fatalf("no matched payload publication: %+v", flow)
			}
			if name, err := flow.Observation.hostname(); err != nil || name != "payload.test" || wireName(t, c) != name {
				t.Fatalf("payload name %q: %v", name, err)
			}
		})
	}
}

func TestVMPacketRetransmission(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newFixtureMode(t, network, true)
			disableHandshakeProbe(t, f)
			c := f.open("retransmit.test", "fd-first", "fd")
			port := f.listener.Addr().(*net.TCPAddr).Port
			rules := fmt.Sprintf(`table inet hostname_payload_drop {
				chain input { type filter hook input priority filter; policy accept;
					tcp dport %d meta length > 100 drop
				}
			}`, port)
			cmd := exec.Command("nft", "-f", "-")
			cmd.Stdin = strings.NewReader(rules)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("nft: %s: %v", output, err)
			}
			installed := true
			defer func() {
				if installed {
					runVM(t, "nft", "delete", "table", "inet", "hostname_payload_drop")
				}
			}()
			f.command("handshake %d", c.slot)
			first := f.flow(c)
			if first.PayloadLen == 0 || first.Observation.Len == 0 {
				t.Fatal("first emitted payload was not matched")
			}
			c.server.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			var byte [1]byte
			if n, err := c.server.Read(byte[:]); n != 0 || err == nil {
				t.Fatalf("drop rule did not withhold payload: %d, %v", n, err)
			}
			deleteVMFlow(t, f.probe.collection.Maps["send_flows"], f.flowKey(c))
			runVM(t, "nft", "delete", "table", "inet", "hostname_payload_drop")
			installed = false
			deadline := time.Now().Add(3 * time.Second)
			for {
				flow, err := stableLookup[flowObservation](f, "send_flows", f.flowKey(c))
				if err == nil && flow.Observation.Len != 0 {
					if flow.PacketNS <= first.PacketNS || flow.Sequence-first.Sequence >= first.PayloadLen || flow.PayloadLen > first.PayloadLen-(flow.Sequence-first.Sequence) {
						t.Fatal("retransmission was outside the captured window")
					}
					break
				}
				if (err != nil && !errors.Is(err, ebpf.ErrKeyNotExist)) || time.Now().After(deadline) {
					t.Fatalf("no retransmitted evidence: %+v, %v", flow, err)
				}
				time.Sleep(5 * time.Millisecond)
			}
			if name := wireName(t, c); name != "retransmit.test" {
				t.Fatalf("retransmitted ClientHello %q", name)
			}
		})
	}
}

func TestVMPacketChangedPayload(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newFixtureMode(t, network, true)
			disableHandshakeProbe(t, f)
			c := f.open("changed.test", "fd-first", "fd")
			// This test profile uses 32-byte established TCP headers with
			// timestamps. Restrict the rule to that header shape and verify
			// that the peer actually receives the modified first byte.
			rules := fmt.Sprintf(`table inet hostname_payload_change {
				chain output { type filter hook output priority mangle; policy accept;
					tcp dport %d tcp doff 8 meta length > 100 @th,256,8 set 0
				}
			}`, f.listener.Addr().(*net.TCPAddr).Port)
			cmd := exec.Command("nft", "-f", "-")
			cmd.Stdin = strings.NewReader(rules)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("nft: %s: %v", output, err)
			}
			defer runVM(t, "nft", "delete", "table", "inet", "hostname_payload_change")
			f.command("handshake %d", c.slot)
			c.server.SetReadDeadline(time.Now().Add(3 * time.Second))
			var first [1]byte
			if _, err := io.ReadFull(c.server, first[:]); err != nil || first[0] != 0 {
				t.Fatalf("payload was not changed from TLS content type 0x16: %x, %v", first, err)
			}
			f.assertSendAmbiguous(c)
		})
	}
}

func TestVMPacketCaptureLimit(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			f := newFixtureMode(t, network, true)
			disableHandshakeProbe(t, f)
			c := f.open("large.test", "fd-first", "fd")
			f.command("large-alpn %d", c.slot)
			f.command("handshake %d", c.slot)
			var raw flowObservation
			if err := f.probe.collection.Maps["send_flows"].Lookup(f.flowKey(c), &raw); err != nil || raw.PayloadLen <= sendBytesMax {
				t.Fatalf("test did not emit an oversized first write: %d, %v", raw.PayloadLen, err)
			}
			f.assertSendAmbiguous(c)
			if name := wireName(t, c); name != "large.test" {
				t.Fatalf("capture limit interrupted TLS: %q", name)
			}
			// Per-socket exclusion must leave another socket usable.
			other := f.open("small.test", "fd-first", "fd")
			f.command("handshake %d", other.slot)
			if name, err := f.flow(other).Observation.hostname(); err != nil || name != "small.test" || wireName(t, other) != name {
				t.Fatalf("capture limit affected another socket: %q, %v", name, err)
			}
		})
	}
}
