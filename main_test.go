package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
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
// mihomo reads (execPathValue in component/process/sockowner_linux.go), and
// share the socket storage of the socket-owner objects.
func TestExecObjects(t *testing.T) {
	for _, tc := range []struct {
		name       string
		object     []byte
		sockObject []byte
		order      binary.ByteOrder
	}{
		{"bpfel", execObjectLE, objectLE, binary.LittleEndian},
		{"bpfeb", execObjectBE, objectBE, binary.BigEndian},
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
				"seed_tasks": {ebpf.Tracing, ebpf.AttachTraceIter},
			}
			for _, name := range execPrograms {
				want[name] = struct {
					typ    ebpf.ProgramType
					attach ebpf.AttachType
				}{ebpf.LSM, ebpf.AttachLSMMac}
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
			// attach gives the exec-path object the socket-owner object's map.
			sockSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tc.sockObject))
			if err != nil {
				t.Fatal(err)
			}
			m, s := spec.Maps[sockMapName], sockSpec.Maps[sockMapName]
			if m == nil || s == nil || m.Type != s.Type || m.KeySize != s.KeySize || m.ValueSize != s.ValueSize || m.Flags != s.Flags {
				t.Errorf("map %s: %+v, socket-owner object: %+v", sockMapName, m, s)
			}
		})
	}
}

// A reader must be able to pass through the pin directory to the maps, also
// when an earlier version created it for root alone. The links stay the
// loader's, and so does the maps directory, which an earlier version gave to
// a reader user; the reader group only gets read access.
func TestMakePinDirs(t *testing.T) {
	pin := filepath.Join(t.TempDir(), "mihomo")
	maps := filepath.Join(pin, "maps")
	if err := os.MkdirAll(maps, 0o700); err != nil {
		t.Fatal(err)
	}
	gid := os.Getgid()
	if os.Getuid() == 0 { // can test taking the directory back
		gid = 4242
		if err := os.Chown(maps, 4243, 4243); err != nil {
			t.Fatal(err)
		}
	}
	links, maps, err := makePinDirs(pin, gid)
	if err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]os.FileMode{pin: 0o711, links: 0o700, maps: 0o750} {
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v", dir, fi.Mode().Perm(), want)
		}
	}
	fi, err := os.Stat(maps)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != os.Getuid() || int(st.Gid) != gid {
		t.Errorf("%s: owner %d:%d, want %d:%d", maps, st.Uid, st.Gid, os.Getuid(), gid)
	}
}
