package main

import "testing"

func TestParseByteSize(t *testing.T) {
	ok := map[string]uint32{"4MiB": 4 << 20, "512KiB": 512 << 10, "1GiB": 1 << 30, "65536": 65536, " 16 MiB ": 16 << 20, "4096B": 4096}
	for in, want := range ok {
		if got, err := parseByteSize(in); err != nil || got != want {
			t.Errorf("parseByteSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "3MiB", "4MB", "abc", "-1KiB", "8GiB", "1.5MiB"} {
		if got, err := parseByteSize(in); err == nil {
			t.Errorf("parseByteSize(%q) = %d, want error", in, got)
		}
	}
}
