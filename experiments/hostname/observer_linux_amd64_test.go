package hostname

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestObserverObject(t *testing.T) {
	spec, err := observerSpec()
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePublicationMap(spec.Maps["publication_state"]); err != nil {
		t.Fatal(err)
	}
	if err := validateSendGuardMap(spec.Maps["send_guards"]); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"target_tgid", "socket_method", "ssl_base", "crypto_base", "libc_base", "curl_base"} {
		if spec.Variables[name] == nil {
			t.Fatalf("embedded object lacks %s", name)
		}
	}
}

func TestObserverConfig(t *testing.T) {
	valid := ObserverConfig{
		Runtime: "/run/mihomo-hostname", Pins: "/sys/fs/bpf/mihomo-hostname", Cgroup: "/sys/fs/cgroup/app.slice",
		Profile: ObserverProfile, TargetPID: 100, SSL: "/usr/lib64/libssl.so.3", Crypto: "/usr/lib64/libcrypto.so.3",
		C: "/usr/lib64/libc.so.6", ReaderUID: 1000, ReaderGID: 1000,
	}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ObserverConfig){
		"profile":      func(c *ObserverConfig) { c.Profile = "openssl-3.5.4-x86-64-v3" },
		"pid":          func(c *ObserverConfig) { c.TargetPID = 0 },
		"root reader":  func(c *ObserverConfig) { c.ReaderUID = 0 },
		"relative":     func(c *ObserverConfig) { c.SSL = "usr/lib64/libssl.so.3" },
		"unclean":      func(c *ObserverConfig) { c.Crypto = "/usr/lib64/../lib64/libcrypto.so.3" },
		"trailing":     func(c *ObserverConfig) { c.Cgroup += "/" },
		"empty libc":   func(c *ObserverConfig) { c.C = "" },
		"long runtime": func(c *ObserverConfig) { c.Runtime = "/run/" + strings.Repeat("a", 100) },
	} {
		c := valid
		change(&c)
		if err := c.validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, c)
		}
	}
}

func TestTargetInCgroup(t *testing.T) {
	var fs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		t.Skip("needs cgroup v2 at /sys/fs/cgroup")
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.HasPrefix(string(data), "0::/") {
		t.Skip("needs a pure cgroup v2 process")
	}
	if err := targetInCgroup(os.Getpid(), "/sys/fs/cgroup"); err != nil {
		t.Fatal(err)
	}
	if err := targetInCgroup(os.Getpid(), t.TempDir()); err == nil {
		t.Fatal("accepted a directory outside cgroup v2")
	}
}

func TestCurlObserverConfig(t *testing.T) {
	valid := ObserverConfig{Runtime: "/run/hostname", Pins: "/sys/fs/bpf/hostname", Cgroup: "/sys/fs/cgroup/app",
		Profile: CurlObserverProfile, TargetPID: 100, SSL: "/lib/ssl", Crypto: "/lib/crypto", C: "/lib/libc",
		Curl: "/lib/libcurl", ReaderUID: 1000}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ObserverConfig){
		"missing curl":           func(c *ObserverConfig) { c.Curl = "" },
		"relative curl":          func(c *ObserverConfig) { c.Curl = "lib/curl" },
		"unclean curl":           func(c *ObserverConfig) { c.Curl = "/lib/../lib/curl" },
		"base profile with curl": func(c *ObserverConfig) { c.Profile = ObserverProfile },
	} {
		c := valid
		change(&c)
		if err := c.validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
