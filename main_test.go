package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

// Both embedded objects must parse and agree on the programs and the layout
// mihomo reads (component/process/sockowner_linux.go).
func TestObjects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		object []byte
		order  binary.ByteOrder
	}{
		{"bpfel", objectLE, binary.LittleEndian},
		{"bpfeb", objectBE, binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tc.object))
			if err != nil {
				t.Fatal(err)
			}
			if spec.ByteOrder != tc.order {
				t.Fatalf("byte order %v", spec.ByteOrder)
			}
			want := map[string]ebpf.AttachType{
				"sock_create": ebpf.AttachCGroupInetSockCreate,
				"connect4":    ebpf.AttachCGroupInet4Connect,
				"connect6":    ebpf.AttachCGroupInet6Connect,
				"sendmsg4":    ebpf.AttachCGroupUDP4Sendmsg,
				"sendmsg6":    ebpf.AttachCGroupUDP6Sendmsg,
				"egress":      ebpf.AttachCGroupInetEgress,
			}
			if len(spec.Programs) != len(want) {
				t.Fatalf("%d programs", len(spec.Programs))
			}
			for name, attach := range want {
				if p := spec.Programs[name]; p == nil || p.AttachType != attach {
					t.Errorf("program %s: %+v", name, p)
				}
			}
			m := spec.Maps[mapName]
			if m == nil || m.Type != ebpf.LRUHash || m.KeySize != 32 || m.ValueSize != 16 {
				t.Fatalf("map %s: %+v", mapName, m)
			}
		})
	}
}

// The exec-path objects must carry the LSM hooks, the iterator and the maps
// mihomo reads (execPathValue in component/process/sockowner_linux.go).
func TestExecObjects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		object []byte
		order  binary.ByteOrder
	}{
		{"bpfel", execObjectLE, binary.LittleEndian},
		{"bpfeb", execObjectBE, binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tc.object))
			if err != nil {
				t.Fatal(err)
			}
			if spec.ByteOrder != tc.order {
				t.Fatalf("byte order %v", spec.ByteOrder)
			}
			want := map[string]struct {
				typ    ebpf.ProgramType
				attach ebpf.AttachType
			}{
				"record_exec": {ebpf.LSM, ebpf.AttachLSMMac},
				"record_fork": {ebpf.LSM, ebpf.AttachLSMMac},
				"record_free": {ebpf.LSM, ebpf.AttachLSMMac},
				"seed_tasks":  {ebpf.Tracing, ebpf.AttachTraceIter},
			}
			if len(spec.Programs) != len(want) {
				t.Fatalf("%d programs", len(spec.Programs))
			}
			for name, w := range want {
				if p := spec.Programs[name]; p == nil || p.Type != w.typ || p.AttachType != w.attach {
					t.Errorf("program %s: %+v", name, p)
				}
			}
			const valueSize = 24 + 1024
			for name, typ := range map[string]ebpf.MapType{"exec_tasks": ebpf.TaskStorage, "exec_recent": ebpf.LRUHash} {
				m := spec.Maps[name]
				if m == nil || m.Type != typ || m.KeySize != 4 || m.ValueSize != valueSize {
					t.Errorf("map %s: %+v", name, m)
				}
			}
			for _, name := range execMapNames {
				if spec.Maps[name] == nil {
					t.Errorf("pinned map %s missing", name)
				}
			}
		})
	}
}
