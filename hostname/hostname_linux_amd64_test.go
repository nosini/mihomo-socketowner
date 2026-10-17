package hostname

import (
	"encoding/binary"
	"strings"
	"testing"
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
