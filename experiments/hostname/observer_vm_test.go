//go:build linux && amd64 && hostname_vm

package hostname

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type observerVMCommand struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	log  bytes.Buffer
}

type observerVMRun struct {
	t            *testing.T
	f            *fixture
	binary       string
	registration string
	root         string
	pins         string
}

func (r *observerVMRun) args(command string, pid int, ssl string) []string {
	if command == "run" && r.registration != "" {
		return []string{"-registration", r.registration, "run-registered"}
	}
	return []string{"-runtime", r.root, "-pin", r.pins, "-cgroup", r.f.cgroup, "-target-pid", strconv.Itoa(pid),
		"-profile", ObserverProfile, "-libssl", ssl, "-libcrypto", r.f.cryptoPath, "-libc", profileLibc,
		"-reader-user", "1000", "-reader-group", "1000", command}
}

func (r *observerVMRun) command(args ...string) *observerVMCommand {
	t := r.t
	t.Helper()
	o := &observerVMCommand{cmd: exec.Command(r.binary, args...), done: make(chan struct{})}
	o.cmd.Stdout, o.cmd.Stderr = &o.log, &o.log
	return o
}

// finished runs a command expected to exit by itself and returns its status.
func (r *observerVMRun) finished(args ...string) (int, string) {
	r.t.Helper()
	o := r.command(args...)
	err := o.cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		r.t.Fatal(err)
	}
	return o.cmd.ProcessState.ExitCode(), o.log.String()
}

// start runs the resident observer and waits for its systemd readiness message.
func (r *observerVMRun) start() *observerVMCommand {
	t := r.t
	t.Helper()
	notify := filepath.Join(r.root, "notify")
	os.Remove(notify)
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notify, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	o := r.command(r.args("run", int(r.f.pid), r.f.sslPath)...)
	o.cmd.Env = append(os.Environ(), "NOTIFY_SOCKET="+notify)
	if err := o.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { o.err = o.cmd.Wait(); close(o.done) }()
	t.Cleanup(func() {
		o.cmd.Process.Kill()
		<-o.done
		if t.Failed() {
			t.Logf("observer: %s", o.log.String())
		}
	})
	l.SetReadDeadline(time.Now().Add(10 * time.Second))
	message := make([]byte, 64)
	n, err := l.Read(message)
	if err != nil || string(message[:n]) != "READY=1" {
		t.Fatalf("observer readiness %q: %v\n%s", message[:n], err, o.log.String())
	}
	return o
}

func (o *observerVMCommand) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-o.done:
		return o.err
	case <-time.After(10 * time.Second):
		t.Fatalf("observer did not exit: %s", o.log.String())
		return nil
	}
}

// instance returns the only observer pin directory, or "" when none remains.
func (r *observerVMRun) instance() string {
	r.t.Helper()
	entries, err := os.ReadDir(r.pins)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		r.t.Fatal(err)
	}
	if len(entries) == 0 {
		return ""
	}
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "epoch-") {
		r.t.Fatalf("unexpected pins: %v", entries)
	}
	return filepath.Join(r.pins, entries[0].Name())
}

// connect gives the fixture a reader for the running instance. The resident
// observer does not pin last_seeded, so the fixture's socket-creation check
// uses the newest map of that name instead.
func (r *observerVMRun) connect() *authorityVMFixture {
	t := r.t
	t.Helper()
	a := &authorityVMFixture{f: r.f, path: r.instance()}
	if a.path == "" {
		t.Fatal("running observer has no pins")
	}
	var seed *ebpf.Map
	for id := ebpf.MapID(0); ; {
		next, err := ebpf.MapGetNextID(id)
		if err != nil {
			break
		}
		id = next
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		if info, err := m.Info(); err == nil && info.Name == "last_seeded" {
			if seed != nil {
				seed.Close()
			}
			seed = m
		} else {
			m.Close()
		}
	}
	if seed == nil {
		t.Fatal("observer has no last_seeded map")
	}
	t.Cleanup(func() { seed.Close() })
	r.f.probe = &probe{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{"last_seeded": seed}}}
	var reply authorityVMReply
	a.reader, reply = bootstrapVMReader(t, a, ObserverEndpoint(r.root))
	if reply.Unknown || reply.Error != "" {
		t.Fatalf("reader bootstrap: %+v", reply)
	}
	return a
}

func (r *observerVMRun) assertStopped() {
	t := r.t
	t.Helper()
	if path := r.instance(); path != "" {
		t.Fatalf("observer left pins in %s", path)
	}
	for _, path := range []string{ObserverEndpoint(r.root), filepath.Join(r.root, "state", "journal")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("observer left %s: %v", path, err)
		}
	}
}

func newObserverVMRun(t *testing.T) *observerVMRun {
	t.Helper()
	binary := os.Getenv("HOSTNAME_VM_OBSERVER")
	if binary == "" {
		t.Skip("set HOSTNAME_VM_OBSERVER to the built mihomo-hostname-observer")
	}
	root, pins := bootstrapVMRoot(t)
	// The command creates its own instance below a pin directory it owns.
	pins = filepath.Join(pins, "observer")
	return &observerVMRun{t: t, binary: binary, root: root, pins: pins,
		f: newFixtureSetup(t, "tcp4", true, "", false)}
}

func TestVMObserverInterruptedPoll(t *testing.T) {
	r := newObserverVMRun(t)
	o := r.start()
	pid := o.cmd.Process.Pid
	// SIGURG is handled by the Go runtime and does not request observer
	// shutdown. Direct it at a thread blocked in ppoll so the syscall returns
	// EINTR, rather than hoping a process-wide signal reaches that thread.
	for interrupted := 0; interrupted < 8; interrupted++ {
		deadline := time.Now().Add(3 * time.Second)
		found := false
		for !found && time.Now().Before(deadline) {
			select {
			case <-o.done:
				t.Fatalf("observer exited on poll interruption: %v: %s", o.err, o.log.String())
			default:
			}
			tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
			if err != nil {
				t.Fatal(err)
			}
			for _, task := range tasks {
				state, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/syscall", pid, task.Name()))
				if err != nil || !strings.HasPrefix(string(state), strconv.Itoa(unix.SYS_PPOLL)+" ") {
					continue
				}
				tid, err := strconv.Atoi(task.Name())
				if err != nil {
					t.Fatal(err)
				}
				if err := unix.Tgkill(pid, tid, unix.SIGURG); err != nil {
					t.Fatal(err)
				}
				found = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !found {
			t.Fatal("observer never blocked in ppoll")
		}
	}
	a := r.connect()
	_, key := a.named(t)
	if got := a.reader.exchange(t, authorityVMRequest{Command: "lookup", Key: key}); got.Unknown || got.Error != "" {
		t.Fatalf("observer lost authority after poll interruption: %+v", got)
	}
	o.cmd.Process.Signal(syscall.SIGTERM)
	if err := o.wait(t); err != nil {
		t.Fatal(err)
	}
	r.assertStopped()
}

func TestVMObserverCommandLifecycle(t *testing.T) {
	r := newObserverVMRun(t)
	o := r.start()
	a := r.connect()
	_, key := a.named(t)

	if status, log := r.finished(r.args("run", int(r.f.pid), r.f.sslPath)...); status != 1 || !strings.Contains(log, "already running") {
		t.Fatalf("second observer: %d %s", status, log)
	}
	if status, log := r.finished(r.args("cleanup", 0, "")...); status != 1 || !strings.Contains(log, "already running") {
		t.Fatalf("cleanup of a running observer: %d %s", status, log)
	}
	if err := o.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := o.wait(t); err != nil {
		t.Fatalf("SIGTERM: %v\n%s", err, o.log.String())
	}
	assertAuthorityUnknown(t, a.reader, key)
	r.assertStopped()

	// A restart is a fresh instance: the old socket stays unknown.
	o = r.start()
	b := r.connect()
	if b.path == a.path {
		t.Fatal("restart reused the instance")
	}
	unknown := b.reader.exchange(t, authorityVMRequest{Command: "lookup", Key: key})
	if !unknown.Unknown || unknown.Name != "" || unknown.Cookie != 0 {
		t.Fatalf("restart adopted an old socket: %+v", unknown)
	}
	b.named(t)

	// A crash leaves pins for recovery; readers reject the dead instance.
	crashed := b.path
	if err := o.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	o.wait(t)
	assertAuthorityUnknown(t, b.reader, key)
	if r.instance() != crashed {
		t.Fatal("crash pins disappeared before recovery")
	}
	if status, log := r.finished(r.args("cleanup", 0, "")...); status != 0 {
		t.Fatalf("cleanup after crash: %d %s", status, log)
	}
	r.assertStopped()

	// The next run recovers a crash by itself.
	o = r.start()
	crashed = r.instance()
	o.cmd.Process.Kill()
	o.wait(t)
	o = r.start()
	if path := r.instance(); path == crashed || path == "" {
		t.Fatalf("restart did not replace crashed instance %s with %s", crashed, path)
	}
	d := r.connect()
	d.named(t)

	// The observer stops by itself, revoked, when its target exits.
	_, key = d.named(t)
	r.f.stdin.Close()
	if err := o.wait(t); err != nil {
		t.Fatalf("target exit: %v\n%s", err, o.log.String())
	}
	if !strings.Contains(o.log.String(), "observer stopped") {
		t.Fatalf("unexpected exit log: %s", o.log.String())
	}
	assertAuthorityUnknown(t, d.reader, key)
	r.assertStopped()
}

func TestVMObserverCommandRefusals(t *testing.T) {
	r := newObserverVMRun(t)
	profile := r.args("run", int(r.f.pid), r.f.sslPath)
	for i := range profile {
		if profile[i] == ObserverProfile {
			profile[i] = "openssl-3.5.4-x86-64-v3"
		}
	}
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		// libcrypto in place of libssl: wrong hash.
		"library": {r.args("run", int(r.f.pid), r.f.cryptoPath), "unsupported binary"},
		// The test process is outside the fixture's cgroup.
		"cgroup": {r.args("run", os.Getpid(), r.f.sslPath), "target is not inside"},
		// A symlink to the right file is not the mapped path.
		"symlink": {r.args("run", int(r.f.pid), filepath.Join(filepath.Dir(r.f.sslPath), "libssl.so.3")), "symbolic links"},
		"profile": {profile, "unsupported observer profile"},
	} {
		t.Run(name, func(t *testing.T) {
			if status, log := r.finished(c.args...); status != 1 || !strings.Contains(log, c.want) {
				t.Fatalf("expected refusal %q: %d %s", c.want, status, log)
			}
			r.assertStopped()
		})
	}
	// Nothing above blocks a valid observer.
	o := r.start()
	r.connect().named(t)
	o.cmd.Process.Signal(syscall.SIGTERM)
	if err := o.wait(t); err != nil {
		t.Fatal(err)
	}
	r.assertStopped()
	var stat unix.Stat_t
	if err := unix.Stat(r.pins, &stat); err != nil || stat.Mode&0777 != 0700 || stat.Uid != 0 {
		t.Fatalf("pin directory: %+v %v", stat, err)
	}
}

// Send guards are never reclaimed. Exhausting them poisons the instance, so
// the observer revokes, cleans up and fails; a restart starts a fresh table.
func TestVMObserverCommandGuardExhaustion(t *testing.T) {
	r := newObserverVMRun(t)
	o := r.start()
	a := r.connect()
	_, key := a.named(t)
	exited := false
	for i := 0; i < 300 && !exited; i++ {
		// Not fixture.accepted: once detached, new sockets are not seeded.
		var slot int
		if _, err := fmt.Sscanf(r.f.command("open exhaust.test fd-first fd"), "socket %d", &slot); err != nil {
			t.Fatal(err)
		}
		r.f.listener.SetDeadline(time.Now().Add(5 * time.Second))
		server, err := r.f.listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { server.Close() })
		select {
		case <-o.done:
			exited = true
		default:
		}
	}
	if !exited {
		select {
		case <-o.done:
		case <-time.After(2 * time.Second):
			t.Fatal("observer kept running with an exhausted guard table")
		}
	}
	if o.err == nil || !strings.Contains(o.log.String(), errPublicationFailed.Error()) {
		t.Fatalf("exhaustion exit: %v\n%s", o.err, o.log.String())
	}
	assertAuthorityUnknown(t, a.reader, key)
	r.assertStopped()
	r.start()
	r.connect().named(t)
}

func TestVMObserverRegistration(t *testing.T) {
	r := newObserverVMRun(t)
	registration := filepath.Join(r.root, "target", "target.json")
	args := append([]string{"-registration", registration}, r.args("prepare", int(r.f.pid), r.f.sslPath)...)
	if status, log := r.finished(args...); status != 0 {
		t.Fatalf("prepare: %d %s", status, log)
	}
	original, err := os.ReadFile(registration)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := loadRegistration(registration)
	if err != nil || reg.Config.TargetPID != int(r.f.pid) {
		t.Fatalf("registration: %+v %v", reg, err)
	}
	for name, change := range map[string]func(*observerRegistration){
		"boot":         func(v *observerRegistration) { v.Target.Boot += "x" },
		"pidns":        func(v *observerRegistration) { v.Target.PIDNS++ },
		"pidfs-device": func(v *observerRegistration) { v.Target.Dev++ },
		"pidfs-inode":  func(v *observerRegistration) { v.Target.Inode++ },
		"version":      func(v *observerRegistration) { v.Version++ },
	} {
		t.Run(name, func(t *testing.T) {
			v := reg
			change(&v)
			data, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(registration, data, 0600); err != nil {
				t.Fatal(err)
			}
			if status, log := r.finished("-registration", registration, "run-registered"); status != 1 {
				t.Fatalf("stale registration: %d %s", status, log)
			}
			r.assertStopped()
		})
	}
	for _, data := range [][]byte{[]byte("{}"), append(append([]byte(nil), original...), []byte(" {}")...), []byte(strings.Repeat(" ", 17000))} {
		if err := os.WriteFile(registration, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRegistration(registration); err == nil {
			t.Fatal("invalid registration accepted")
		}
	}
	if err := os.WriteFile(registration, original, 0600); err != nil {
		t.Fatal(err)
	}
	os.Chmod(registration, 0644)
	if _, err := loadRegistration(registration); err == nil {
		t.Fatal("nonprivate registration accepted")
	}
	os.Chmod(registration, 0600)
	symlink := filepath.Join(r.root, "target", "symlink")
	if err := os.Symlink(registration, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRegistration(symlink); err == nil {
		t.Fatal("symlink registration accepted")
	}
	// An explicitly registered birth can run repeatedly while that target lives.
	r.registration = registration
	o := r.start()
	a := r.connect()
	_, key := a.named(t)
	o.cmd.Process.Signal(syscall.SIGTERM)
	if err := o.wait(t); err != nil {
		t.Fatal(err)
	}
	assertAuthorityUnknown(t, a.reader, key)
	r.assertStopped()
	o = r.start()
	r.connect().named(t)
	o.cmd.Process.Signal(syscall.SIGTERM)
	if err := o.wait(t); err != nil {
		t.Fatal(err)
	}
	r.assertStopped()

	// Like the service's ExecStopPost, cleanup gets no path flags after a
	// crash; it must find the registered runtime and pins.
	o = r.start()
	o.cmd.Process.Kill()
	o.wait(t)
	if r.instance() == "" {
		t.Fatal("crash pins disappeared before cleanup")
	}
	if status, log := r.finished("-registration", registration, "cleanup"); status != 0 {
		t.Fatalf("registered cleanup: %d %s", status, log)
	}
	r.assertStopped()
}
