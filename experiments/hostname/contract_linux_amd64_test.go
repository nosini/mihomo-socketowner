package hostname

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// The publisher is deliberately independent of the reader module. These fixed
// wire bytes and BTF offsets pin profile 1 even when diagnostic internals evolve.
func TestHostnameV1PublisherContract(t *testing.T) {
	golden, err := hex.DecodeString("4d484e414d453031010002000000040001000000000000000000000000000000020000000000000000000000000000000300000004000000050000000600000001000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	h := bootstrapHeader{Kind: 2, Count: 4, Nonce: [16]byte{1}, Instance: [16]byte{2}, Manifest: authorityManifest{Maps: [4]ebpf.MapID{3, 4, 5, 6}}}
	if !bytes.Equal(h.encode(), golden) {
		t.Fatalf("v1 envelope changed: %x", h.encode())
	}
	spec, err := observerSpec()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][4]uint32{
		"publication_state": {uint32(ebpf.Array), 4, 8, 1},
		"send_guards":       {uint32(ebpf.Hash), 8, 8, 256},
		"send_flows":        {uint32(ebpf.LRUHash), 48, 312, 256},
	} {
		m := spec.Maps[name]
		if m == nil || [4]uint32{uint32(m.Type), m.KeySize, m.ValueSize, m.MaxEntries} != want {
			t.Fatalf("v1 map %s changed: %+v", name, m)
		}
	}
	for name, want := range map[string]struct {
		size   uint32
		fields []contractMember
	}{
		"flow_key":         {48, []contractMember{{"netns", 0, 8}, {"source", 8, 16}, {"destination", 24, 16}, {"source_port", 40, 2}, {"destination_port", 42, 2}, {"pad", 44, 4}}},
		"observation":      {288, []contractMember{{"cookie", 0, 8}, {"boot_ns", 8, 8}, {"tgid", 16, 4}, {"fd", 20, 4}, {"len", 24, 4}, {"pad", 28, 4}, {"hostname", 32, 256}}},
		"flow_observation": {312, []contractMember{{"cookie", 0, 8}, {"observation", 8, 288}, {"sequence", 296, 4}, {"payload_len", 300, 4}, {"packet_ns", 304, 8}}},
	} {
		var typ *btf.Struct
		if err := spec.Types.TypeByName(name, &typ); err != nil {
			t.Fatal(err)
		}
		if typ.Size != want.size || len(typ.Members) != len(want.fields) {
			t.Fatalf("v1 %s changed: %+v", name, typ)
		}
		for i, field := range want.fields {
			m := typ.Members[i]
			size, err := btf.Sizeof(m.Type)
			if err != nil || m.Name != field.name || int(m.Offset) != field.offset*8 || size != field.size {
				t.Errorf("v1 %s member %d changed: %+v (size %d, error %v)", name, i, m, size, err)
			}
		}
	}
}

type contractMember struct {
	name         string
	offset, size int
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
	wire[64] = 4
	if _, err := decodeBootstrap(wire); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestInitialWindowProfileEnvelope(t *testing.T) {
	h := bootstrapHeader{Kind: 2, Count: 4, Profile: 3}
	wire := h.encode()
	if wire[64] != 3 {
		t.Fatalf("wrong profile: %x", wire)
	}
	if got, err := decodeBootstrap(wire); err != nil || got != h {
		t.Fatalf("initial-window envelope: %+v %v", got, err)
	}
}
