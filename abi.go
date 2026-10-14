package main

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// See docs/map-interface.md. Breaking changes require a new ABI version and
// a separate pin directory so readers cannot mix maps from different ABIs.
const (
	abiVersion    uint32 = 1
	abiVersionMap        = "abi_version"
)

// validateMapABI checks the public maps before loading an embedded object.
// The loader must only advertise the ABI its objects actually implement.
func validateMapABI(spec *ebpf.CollectionSpec, execPaths bool) error {
	type mapLayout struct {
		typ        ebpf.MapType
		key, value uint32
	}
	want := map[string]mapLayout{
		mapName: {ebpf.LRUHash, 32, 16},
	}
	if execPaths {
		want = map[string]mapLayout{
			"exec_tasks":  {ebpf.TaskStorage, 4, 1048},
			"exec_recent": {ebpf.LRUHash, 4, 1048},
		}
	}
	for name, w := range want {
		m := spec.Maps[name]
		if m == nil || m.Type != w.typ || m.KeySize != w.key || m.ValueSize != w.value {
			return fmt.Errorf("socketowner ABI v%d: incompatible map %s: %+v", abiVersion, name, m)
		}
	}
	return nil
}

// pinABIVersion publishes a frozen marker before conn_owners becomes visible.
// Freeze prevents userspace from changing the advertised ABI after attach.
func pinABIVersion(path string, gid int) error {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       abiVersionMap,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		Contents:   []ebpf.MapKV{{Key: uint32(0), Value: abiVersion}},
	})
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Freeze(); err != nil {
		return err
	}
	if err := m.Pin(path); err != nil {
		return err
	}
	return setReader(path, 0o440, gid)
}
