package hostname

import (
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestTargetBirthIdentity(t *testing.T) {
	a, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skip(err)
	}
	defer unix.Close(a)
	want, err := targetIdentity(a)
	if err != nil {
		t.Fatal(err)
	}
	b, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(b)
	got, err := targetIdentity(b)
	if err != nil || got != want || got.Inode == 0 || got.Boot == "" {
		t.Fatalf("process birth changed: %+v %+v %v", want, got, err)
	}
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := targetIdentity(int(f.Fd())); err == nil {
		t.Fatal("non-pidfd accepted")
	}
}
