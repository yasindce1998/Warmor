package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/integrity"
)

func writeDB(t *testing.T, bins map[string]*integrity.BinaryHash) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db.json")
	db := &integrity.Database{Version: 1, Binaries: bins}
	if err := db.Save(path); err != nil {
		t.Fatal(err)
	}
	return path
}

const (
	shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func TestLoadIntegrityDigests(t *testing.T) {
	good := writeDB(t, map[string]*integrity.BinaryHash{
		"/bin/a":  {SHA256: shaA},
		"/bin/a2": {SHA256: shaA}, // same content, deduped
		"/bin/b":  {SHA256: shaB}, // upper case, normalized
	})

	got, err := loadIntegrityDigests("enforce", good)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	want := []string{shaA, strings.ToLower(shaB)}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("digests = %v, want %v", got, want)
	}

	if got, err := loadIntegrityDigests("off", ""); err != nil || got != nil {
		t.Fatalf("off without db = %v, %v; want nil, nil", got, err)
	}
}

func TestLoadIntegrityDigests_Misconfig(t *testing.T) {
	good := writeDB(t, map[string]*integrity.BinaryHash{"/bin/a": {SHA256: shaA}})
	empty := writeDB(t, map[string]*integrity.BinaryHash{})
	badHash := writeDB(t, map[string]*integrity.BinaryHash{"/bin/a": {SHA256: "nothex"}})
	short := writeDB(t, map[string]*integrity.BinaryHash{"/bin/a": {SHA256: "abcd"}})
	corrupt := filepath.Join(t.TempDir(), "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, mode, db, wantErr string
	}{
		{"db without mode", "off", good, "--integrity-mode is off"},
		{"mode without db", "enforce", "", "requires --integrity-db"},
		{"bad mode", "block", good, "invalid --integrity-mode"},
		{"empty db", "enforce", empty, "is empty"},
		{"non-hex digest", "audit", badHash, "invalid sha256"},
		{"short digest", "audit", short, "invalid sha256"},
		{"corrupt db", "audit", corrupt, "parse database"},
		{"missing db", "audit", "/nonexistent/db.json", "read database"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadIntegrityDigests(tc.mode, tc.db)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
