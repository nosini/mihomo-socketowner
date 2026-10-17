package hostname

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// Fixed bytes, independent of encode, prevent silent wire-version reuse.
func TestV1EnvelopeGolden(t *testing.T) {
	want, err := hex.DecodeString("4d484e414d453031010002000000040001000000000000000000000000000000020000000000000000000000000000000300000004000000050000000600000001000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	h := bootstrapHeader{Kind: 2, Count: 4, Nonce: [16]byte{1}, Instance: [16]byte{2}, Manifest: authorityManifest{}}
	h.Manifest.Maps[0], h.Manifest.Maps[1], h.Manifest.Maps[2], h.Manifest.Maps[3] = 3, 4, 5, 6
	if !bytes.Equal(h.encode(), want) {
		t.Fatalf("envelope changed: %x", h.encode())
	}
	if got, err := decodeBootstrap(want); err != nil || got != h {
		t.Fatalf("golden response: %+v: %v", got, err)
	}
}

func TestV1RecordLayout(t *testing.T) {
	var key flowKey
	var record flowObservation
	var obs observation
	for name, pair := range map[string][2]uintptr{
		"key size":            {unsafe.Sizeof(key), 48},
		"source":              {unsafe.Offsetof(key.Source), 8},
		"destination":         {unsafe.Offsetof(key.Destination), 24},
		"source port":         {unsafe.Offsetof(key.SourcePort), 40},
		"destination port":    {unsafe.Offsetof(key.DestinationPort), 42},
		"key padding":         {unsafe.Offsetof(key.Pad), 44},
		"record size":         {unsafe.Sizeof(record), 312},
		"observation":         {unsafe.Offsetof(record.Observation), 8},
		"sequence":            {unsafe.Offsetof(record.Sequence), 296},
		"payload length":      {unsafe.Offsetof(record.PayloadLen), 300},
		"packet timestamp":    {unsafe.Offsetof(record.PacketNS), 304},
		"observation size":    {unsafe.Sizeof(obs), 288},
		"boot timestamp":      {unsafe.Offsetof(obs.BootNS), 8},
		"tgid":                {unsafe.Offsetof(obs.TGID), 16},
		"fd":                  {unsafe.Offsetof(obs.FD), 20},
		"name length":         {unsafe.Offsetof(obs.Len), 24},
		"observation padding": {unsafe.Offsetof(obs.Pad), 28},
		"hostname":            {unsafe.Offsetof(obs.Hostname), 32},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: %d, want %d", name, pair[0], pair[1])
		}
	}
	// Decode a record assembled by offsets rather than Go struct assignment.
	b := make([]byte, 312)
	binary.LittleEndian.PutUint64(b, 123)
	binary.LittleEndian.PutUint64(b[8:], 123)
	binary.LittleEndian.PutUint32(b[32:], 15)
	copy(b[40:], "MiXeD.Example.\x00")
	var decoded flowObservation
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &decoded); err != nil {
		t.Fatal(err)
	}
	if got, err := decoded.Observation.hostname(); err != nil || got != "mixed.example" {
		t.Fatalf("%q: %v", got, err)
	}
}

func TestReaderCloseConcurrentAndInvalidFlows(t *testing.T) {
	r := &Reader{authority: &authorityReader{pidfd: -1}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); r.Close(); r.Close() }()
	}
	wg.Wait()
	valid := TCPFlow{Netns: 1, Source: netip.MustParseAddrPort("127.0.0.1:123"), Destination: netip.MustParseAddrPort("127.0.0.1:443")}
	for _, flow := range []TCPFlow{{}, valid, {Netns: 1, Source: netip.MustParseAddrPort("[fe80::1%eth0]:123"), Destination: netip.MustParseAddrPort("[fe80::2%eth0]:443")}} {
		if c, err := r.Lookup(flow, time.Now().Add(time.Second)); err == nil || c != nil {
			t.Fatal("closed reader authorized flow")
		}
	}
}

func TestReclaimProfileEnvelope(t *testing.T) {
	h := bootstrapHeader{Kind: 2, Count: 4, Profile: 2}
	wire := h.encode()
	if wire[64] != 2 {
		t.Fatalf("wrong profile: %x", wire)
	}
	got, err := decodeBootstrap(wire)
	if err != nil || got != h {
		t.Fatalf("reclaim envelope: %+v, %v", got, err)
	}
	wire[64] = 3
	if _, err := decodeBootstrap(wire); err == nil {
		t.Fatal("unknown profile accepted")
	}
}
