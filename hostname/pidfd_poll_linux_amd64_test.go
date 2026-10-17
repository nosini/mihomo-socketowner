package hostname

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// Also run under strace's one-shot ppoll EINTR injection; see the reader module's DEVELOPMENT.md.
func TestPidfdLiveness(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := pidfdAlive(fd); err != nil {
		t.Fatalf("live observer rejected: %v", err)
	}
	child := exec.Command("/bin/sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	dead, err := unix.PidfdOpen(child.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dead)
	child.Process.Kill()
	child.Wait()
	if err := pidfdAlive(dead); !errors.Is(err, errObserverUnavailable) {
		t.Fatalf("exited observer accepted: %v", err)
	}
}

// Repeated ppoll EINTR injection must also fail closed without spinning.
func TestPidfdInvalid(t *testing.T) {
	if err := pidfdAlive(1 << 30); !errors.Is(err, errObserverUnavailable) {
		t.Fatalf("invalid pidfd accepted: %v", err)
	}
}
