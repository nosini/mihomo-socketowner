// Command socketowner attaches the socket-owner BPF programs to a cgroup
// and pins them, so that mihomo can look up the process behind a connection
// without holding BPF privileges itself. With -exec-paths it also records the
// executable of every process, so mihomo needn't read /proc to name it.
//
// It needs CAP_BPF and CAP_NET_ADMIN (or root), plus CAP_CHOWN for
// -reader-group and CAP_PERFMON for -exec-paths, and exits after attaching.
// The links pinned in <pin>/links keep the programs attached until "detach"
// removes them. The map is pinned on its own in <pin>/maps, so that directory
// can be shared with mihomo without exposing the links. Both directories are kept across attach
// and detach, so a bind mount of maps sees the map that replaces an old one.
// <pin> itself can be passed through by anyone, so that a reader that can
// reach <pin> can open the maps. The pins stay the loader's: a reader that
// owned them could make them writable and forge entries.
package main

//go:generate clang -O2 -g -Wall -target bpfel -c bpf/sockowner.c -o sockowner_bpfel.o
//go:generate clang -O2 -g -Wall -target bpfeb -c bpf/sockowner.c -o sockowner_bpfeb.o
//go:generate clang -O2 -g -Wall -target bpfel -c bpf/execpath.c -o execpath_bpfel.o
//go:generate clang -O2 -g -Wall -target bpfeb -c bpf/execpath.c -o execpath_bpfeb.o
//go:generate llvm-strip -g sockowner_bpfel.o sockowner_bpfeb.o execpath_bpfel.o execpath_bpfeb.o

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var (
	//go:embed sockowner_bpfel.o
	objectLE []byte
	//go:embed sockowner_bpfeb.o
	objectBE []byte
	//go:embed execpath_bpfel.o
	execObjectLE []byte
	//go:embed execpath_bpfeb.o
	execObjectBE []byte
)

const mapName = "conn_owners"

// The socket storage that both objects record socket owners in.
const sockMapName = "sock_owners"

// The exec-path maps, which mihomo looks for next to mapName.
var execMapNames = []string{"exec_tasks", "exec_recent"}

// The LSM programs in the exec-path object; seed_tasks is run, not attached.
var execPrograms = []string{"record_exec", "record_fork", "record_free", "record_send", "record_connect"}

func main() {
	cgroup := flag.String("cgroup", "/sys/fs/cgroup", "cgroup v2 directory to attach to")
	pin := flag.String("pin", "/sys/fs/bpf/mihomo", "bpffs directory for the pinned links and map")
	readerGroup := flag.String("reader-group", "", "group given read access to the pinned maps (name or ID)")
	execPaths := flag.Bool("exec-paths", false, "also record each process's executable (needs CAP_PERFMON and the BPF LSM)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [flags] attach|detach\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var err error
	switch flag.Arg(0) {
	case "attach":
		var gid int
		if gid, err = lookupGroup(*readerGroup); err == nil {
			err = attach(*cgroup, *pin, *execPaths, gid)
		}
	case "detach":
		err = detach(*pin)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// lookupGroup returns the ID of the group given read access to the pinned
// maps, or -1 to leave them to the loader's group.
func lookupGroup(group string) (int, error) {
	if group == "" {
		return -1, nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		if g, err = user.LookupGroupId(group); err != nil {
			return 0, err
		}
	}
	return strconv.Atoi(g.Gid)
}

func nativeObject(le, be []byte) []byte {
	if binary.NativeEndian.Uint16([]byte{1, 0}) == 1 {
		return le
	}
	return be
}

// load loads object, using the given maps in place of those of the same name.
func load(object []byte, maps map[string]*ebpf.Map, execPaths bool) (*ebpf.CollectionSpec, *ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, nil, err
	}
	if err := validateMapABI(spec, execPaths); err != nil {
		return nil, nil, err
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: maps})
	if err != nil {
		return nil, nil, fmt.Errorf("load: %w", err)
	}
	return spec, coll, nil
}

func attach(cgroup, pin string, execPaths bool, gid int) error {
	spec, coll, err := load(nativeObject(objectLE, objectBE), nil, false)
	if err != nil {
		return err
	}
	defer coll.Close()
	var execColl *ebpf.Collection
	if execPaths {
		shared := map[string]*ebpf.Map{sockMapName: coll.Maps[sockMapName]}
		if _, execColl, err = load(nativeObject(execObjectLE, execObjectBE), shared, true); err != nil {
			return fmt.Errorf("exec paths: %w", err)
		}
		defer execColl.Close()
	}

	// Replace an earlier attachment as a whole. mihomo notices the new map
	// pin and reopens it.
	if err := detach(pin); err != nil {
		return err
	}
	links, maps, err := makePinDirs(pin, gid)
	if err != nil {
		return err
	}

	for name, prog := range coll.Programs {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroup,
			Attach:  spec.Programs[name].AttachType,
			Program: prog,
		})
		if err != nil {
			detach(pin)
			return fmt.Errorf("attach %s: %w", name, err)
		}
		err = l.Pin(filepath.Join(links, name))
		l.Close()
		if err != nil {
			detach(pin)
			return fmt.Errorf("pin %s: %w", name, err)
		}
	}

	if execColl != nil {
		if err := attachExec(execColl, links, maps, gid); err != nil {
			detach(pin)
			return err
		}
	}

	if err := pinABIVersion(filepath.Join(maps, abiVersionMap), gid); err != nil {
		detach(pin)
		return fmt.Errorf("pin ABI version: %w", err)
	}

	// Pinned last: mihomo looks for the version and exec-path maps when it notices a
	// new socket-owner map.
	mapPath := filepath.Join(maps, mapName)
	if err := coll.Maps[mapName].Pin(mapPath); err != nil {
		detach(pin)
		return fmt.Errorf("pin %s: %w", mapName, err)
	}
	return setReader(mapPath, 0o440, gid)
}

// makePinDirs creates the directories for the links and maps in pin and
// gives the reader group access to the maps directory. The reader must be
// able to pass through pin, while the links directory stays the loader's
// alone. MkdirAll and Mkdir don't change existing directories, so their modes
// are set explicitly.
func makePinDirs(pin string, gid int) (links, maps string, err error) {
	links = filepath.Join(pin, "links")
	maps = filepath.Join(pin, "maps")
	if err := os.MkdirAll(pin, 0o711); err != nil {
		return "", "", err
	}
	if err := os.Chmod(pin, 0o711); err != nil {
		return "", "", err
	}
	for _, dir := range []string{links, maps} {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", "", err
		}
	}
	if err := os.Chmod(links, 0o700); err != nil {
		return "", "", err
	}
	if err := setReader(maps, 0o750, gid); err != nil {
		return "", "", err
	}
	return links, maps, nil
}

// attachExec attaches the exec-path hooks, adds the processes that are already
// running and pins the maps.
func attachExec(coll *ebpf.Collection, links, maps string, gid int) error {
	for _, name := range execPrograms {
		l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs[name]})
		if err != nil {
			return fmt.Errorf("attach %s: %w", name, err)
		}
		err = l.Pin(filepath.Join(links, name))
		l.Close()
		if err != nil {
			return fmt.Errorf("pin %s: %w", name, err)
		}
	}

	// Each read of the iterator runs seed_tasks on the next process.
	it, err := link.AttachIter(link.IterOptions{Program: coll.Programs["seed_tasks"]})
	if err != nil {
		return fmt.Errorf("attach seed_tasks: %w", err)
	}
	defer it.Close()
	r, err := it.Open()
	if err != nil {
		return fmt.Errorf("seed_tasks: %w", err)
	}
	_, err = io.Copy(io.Discard, r)
	r.Close()
	if err != nil {
		return fmt.Errorf("seed_tasks: %w", err)
	}

	for _, name := range execMapNames {
		path := filepath.Join(maps, name)
		if err := coll.Maps[name].Pin(path); err != nil {
			return fmt.Errorf("pin %s: %w", name, err)
		}
		if err := setReader(path, 0o440, gid); err != nil {
			return err
		}
	}
	return nil
}

// setReader gives path to the loader's user and to gid, or the loader's group
// if gid is -1, with mode. It also takes back a path that an earlier version
// gave to a reader user.
func setReader(path string, mode os.FileMode, gid int) error {
	if gid < 0 {
		gid = os.Getgid()
	}
	if err := os.Chown(path, os.Getuid(), gid); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// detach removes the pins in the links and maps directories but keeps the
// directories. Unpinning the links detaches the programs once nothing else
// holds them.
func detach(pin string) error {
	for _, dir := range []string{"links", "maps"} {
		dir = filepath.Join(pin, dir)
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		for _, e := range entries {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
