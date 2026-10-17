// Command mihomo-hostname-observer runs the experimental hostname observer for
// one OpenSSL process and serves the authenticated endpoint that Mihomo's
// hostname-discovery reader connects to.
//
// "run" stays in the foreground until SIGTERM, SIGINT or SIGHUP, or until the
// target exits. It revokes every reader before detaching, then removes its
// endpoint and pins. State left by a crash is recovered on the next run, or by
// "cleanup". "prepare" records the selected process birth for safe service
// restarts with "run-registered". Under systemd it reports READY=1. It needs root.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/nosini/socketowner/experiments/hostname"
)

type options struct {
	runtime, pin, cgroup, profile string
	ssl, crypto, libc             string
	readerUser, readerGroup       string
	targetPID                     int
	registration                  string
}

func main() {
	var o options
	flag.StringVar(&o.registration, "registration", "/run/mihomo-hostname-target/target.json", "root-private, boot-bound service target registration")
	flag.StringVar(&o.runtime, "runtime", "/run/mihomo-hostname", "root-owned runtime directory holding bootstrap.sock")
	flag.StringVar(&o.pin, "pin", "/sys/fs/bpf/mihomo-hostname", "private bpffs directory for this observer's pins")
	flag.StringVar(&o.cgroup, "cgroup", "", "cgroup v2 directory containing the target (required for run/prepare)")
	flag.IntVar(&o.targetPID, "target-pid", 0, "process ID of the OpenSSL application to observe (required for run/prepare)")
	flag.StringVar(&o.profile, "profile", "", "library profile; only "+hostname.ObserverProfile+" is supported (required for run/prepare)")
	flag.StringVar(&o.ssl, "libssl", "", "libssl file the target has mapped (required for run/prepare)")
	flag.StringVar(&o.crypto, "libcrypto", "", "libcrypto file the target has mapped (required for run/prepare)")
	flag.StringVar(&o.libc, "libc", "", "libc file the target has mapped (required for run/prepare)")
	flag.StringVar(&o.readerUser, "reader-user", "", "only user allowed to connect, normally mihomo (name or ID; required for run)")
	flag.StringVar(&o.readerGroup, "reader-group", "", "group given access to the endpoint (name or ID; required for run)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [flags] run|prepare|run-registered|cleanup\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	var err error
	switch flag.Arg(0) {
	case "run", "prepare":
		var config hostname.ObserverConfig
		if config, err = o.config(); err == nil {
			if flag.Arg(0) == "prepare" {
				err = hostname.PrepareObserver(o.registration, config)
			} else {
				err = run(config, "")
			}
		}
	case "run-registered":
		err = run(hostname.ObserverConfig{}, o.registration)
	case "cleanup":
		err = hostname.CleanupObserver(o.runtime, o.pin)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func (o options) config() (hostname.ObserverConfig, error) {
	for _, required := range []struct{ name, value string }{
		{"cgroup", o.cgroup}, {"profile", o.profile}, {"libssl", o.ssl}, {"libcrypto", o.crypto},
		{"libc", o.libc}, {"reader-user", o.readerUser}, {"reader-group", o.readerGroup},
	} {
		if required.value == "" {
			return hostname.ObserverConfig{}, fmt.Errorf("-%s is required", required.name)
		}
	}
	uid, err := lookupUser(o.readerUser)
	if err != nil {
		return hostname.ObserverConfig{}, err
	}
	gid, err := lookupGroup(o.readerGroup)
	if err != nil {
		return hostname.ObserverConfig{}, err
	}
	return hostname.ObserverConfig{
		Runtime: o.runtime, Pins: o.pin, Cgroup: o.cgroup, Profile: o.profile, TargetPID: o.targetPID,
		SSL: o.ssl, Crypto: o.crypto, C: o.libc, ReaderUID: uid, ReaderGID: gid,
	}, nil
}

func run(config hostname.ObserverConfig, registration string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()
	ready := func() {
		fmt.Fprintln(os.Stderr, "serving hostname readers")
		if err := notify("READY=1"); err != nil {
			fmt.Fprintln(os.Stderr, "systemd notification:", err)
		}
	}
	var err error
	if registration != "" {
		err = hostname.RunRegisteredObserver(ctx, registration, ready)
	} else {
		err = hostname.RunObserver(ctx, config, ready)
	}
	if err == nil {
		fmt.Fprintln(os.Stderr, "observer stopped")
	}
	return err
}

// notify sends a systemd service notification when NOTIFY_SOCKET is set.
func notify(state string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if path[0] == '@' {
		path = "\x00" + path[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(state))
	return err
}

func lookupUser(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		if u, err = user.LookupId(name); err != nil {
			return 0, err
		}
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(id), err
}

func lookupGroup(name string) (uint32, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		if g, err = user.LookupGroupId(name); err != nil {
			return 0, err
		}
	}
	id, err := strconv.ParseUint(g.Gid, 10, 32)
	return uint32(id), err
}
