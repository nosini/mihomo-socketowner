package hostname

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHostname(t *testing.T) {
	maxName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, tc := range []struct{ input, want string }{
		{"Example.COM.", "example.com"}, {"xn--bcher-kva.example", "xn--bcher-kva.example"},
		{maxName, maxName}, {maxName + ".", maxName},
		{"", ""}, {"127.0.0.1", ""}, {"::1", ""}, {"bad/name", ""},
		{"bad\x00name", ""}, {"-bad.test", ""}, {"bad-.test", ""}, {"a..test", ""},
		{"a..", ""}, {"bücher.test", ""}, {"K.test", ""}, {strings.Repeat("a", 64) + ".test", ""},
		{strings.Repeat("a.", 127) + "b", ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			o := observation{Len: int32(len(tc.input) + 1)}
			copy(o.Hostname[:], tc.input)
			got, err := o.hostname()
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	for _, n := range []int32{-1, 0, 1, 256, 257} {
		if _, err := (observation{Len: n}).hostname(); err == nil {
			t.Fatalf("accepted length %d", n)
		}
	}
	o := observation{Len: 3, Hostname: [256]byte{'a', 'b', 'c'}}
	if _, err := o.hostname(); err == nil {
		t.Fatal("accepted unterminated string")
	}
	if binary.Size(observation{}) != 288 {
		t.Fatal("snapshot layout changed")
	}
}

func TestRejectUnknownBinary(t *testing.T) {
	p := filepath.Join(t.TempDir(), "library.so")
	if err := os.WriteFile(p, []byte("unsupported"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkBinary(p, sslSHA256); err == nil {
		t.Fatal("accepted unsupported library")
	}
	link := filepath.Join(t.TempDir(), "link.so")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := checkBinary(link, sslSHA256); err == nil {
		t.Fatal("followed a library symlink")
	}
}

func TestMappingBase(t *testing.T) {
	maps := "7f1234000000-7f1234030000 r--p 00000000 00:01 12 /lib/libcrypto.so\n" +
		"7f1234030000-7f1234040000 r-xp 00030000 00:01 12 /lib/libcrypto.so\n"
	id := fileIdentity{dev: unix.Mkdev(0, 1), ino: 12}
	if base, err := mappingBase(maps, "/lib/libcrypto.so", id); err != nil || base != 0x7f1234000000 {
		t.Fatalf("base %#x, error %v", base, err)
	}
	for _, m := range []string{"", strings.ReplaceAll(maps, "00000000", "00001000"), strings.ReplaceAll(maps, "/lib/libcrypto.so", "/lib/libcrypto.so (deleted)"),
		strings.ReplaceAll(maps, "00:01 12", "00:02 12"), strings.ReplaceAll(maps, "00:01 12", "00:01 13"), strings.ReplaceAll(maps, "00:01 12", "0001 12")} {
		if _, err := mappingBase(m, "/lib/libcrypto.so", id); err == nil {
			t.Fatal("accepted unavailable mapping")
		}
	}
}
