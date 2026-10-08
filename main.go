// Command mihomo-sockowner attaches the socket-owner BPF programs to a cgroup
// and pins them, so that mihomo can look up the process behind a connection
// without holding BPF privileges itself.
//
// It needs CAP_BPF and CAP_NET_ADMIN (or root), plus CAP_CHOWN for
// -reader-user and -reader-group, and exits after attaching. The links pinned
// in <pin>/links keep the programs attached until "detach" removes them. The
// map is pinned on its own in <pin>/maps, so that directory can be shared with
// mihomo without exposing the links. Both directories are kept across attach
// and detach, so a bind mount of maps sees the map that replaces an old one.
package main

//go:generate clang -O2 -g -Wall -target bpfel -c bpf/sockowner.c -o sockowner_bpfel.o
//go:generate clang -O2 -g -Wall -target bpfeb -c bpf/sockowner.c -o sockowner_bpfeb.o
//go:generate llvm-strip -g sockowner_bpfel.o sockowner_bpfeb.o

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
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
)

const mapName = "conn_owners"

func main() {
	cgroup := flag.String("cgroup", "/sys/fs/cgroup", "cgroup v2 directory to attach to")
	pin := flag.String("pin", "/sys/fs/bpf/mihomo", "bpffs directory for the pinned links and map")
	readerUser := flag.String("reader-user", "", "user given read access to the pinned map (name or ID)")
	readerGroup := flag.String("reader-group", "", "group given read access to the pinned map (name or ID)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [flags] attach|detach\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var err error
	switch flag.Arg(0) {
	case "attach":
		var uid, gid int
		if uid, gid, err = lookupReader(*readerUser, *readerGroup); err == nil {
			err = attach(*cgroup, *pin, uid, gid)
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

// lookupReader returns the IDs to own the pinned map and its directory, or -1
// to leave them to root.
func lookupReader(name, group string) (uid, gid int, err error) {
	uid, gid = -1, -1
	if name != "" {
		u, err := user.Lookup(name)
		if err != nil {
			if u, err = user.LookupId(name); err != nil {
				return 0, 0, err
			}
		}
		uid, _ = strconv.Atoi(u.Uid)
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			if g, err = user.LookupGroupId(group); err != nil {
				return 0, 0, err
			}
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	return uid, gid, nil
}

func object() []byte {
	if binary.NativeEndian.Uint16([]byte{1, 0}) == 1 {
		return objectLE
	}
	return objectBE
}

func attach(cgroup, pin string, uid, gid int) error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object()))
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer coll.Close()

	// Replace an earlier attachment as a whole. mihomo notices the new map
	// pin and reopens it.
	if err := detach(pin); err != nil {
		return err
	}
	links := filepath.Join(pin, "links")
	maps := filepath.Join(pin, "maps")
	if err := os.MkdirAll(links, 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(maps, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	// Mkdir doesn't change an existing directory, so set its mode explicitly.
	if err := setReader(maps, 0o750, uid, gid); err != nil {
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

	mapPath := filepath.Join(maps, mapName)
	if err := coll.Maps[mapName].Pin(mapPath); err != nil {
		detach(pin)
		return fmt.Errorf("pin %s: %w", mapName, err)
	}
	return setReader(mapPath, 0o440, uid, gid)
}

// setReader gives path to root, or to uid and gid where they are set, with
// mode.
func setReader(path string, mode os.FileMode, uid, gid int) error {
	if uid < 0 {
		uid = 0
	}
	if gid < 0 {
		gid = 0
	}
	if err := os.Chown(path, uid, gid); err != nil {
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
