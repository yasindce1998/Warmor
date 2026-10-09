package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/internal/integrity"
)

// fakeRootFS creates a rootfs with two executables and one non-executable.
func fakeRootFS(t *testing.T) string {
	t.Helper()
	rootfs := t.TempDir()
	for _, d := range []string{"bin", "usr/bin"} {
		if err := os.MkdirAll(filepath.Join(rootfs, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(rootfs, "bin", "sh"), "#!/bin/true\nshell", 0o755)
	mustWrite(t, filepath.Join(rootfs, "usr", "bin", "tool"), "tool-binary", 0o755)
	mustWrite(t, filepath.Join(rootfs, "usr", "bin", "README.md"), "not executable", 0o644)
	return rootfs
}

func mustWrite(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestScan_WritesDatabase(t *testing.T) {
	rootfs := fakeRootFS(t)
	dbPath := filepath.Join(t.TempDir(), "db.json")
	_, stderr := runMain(t, "", "-rootfs", rootfs, "-o", dbPath)
	assertContains(t, "stderr", stderr, "Scanning "+rootfs, "Found 2 executables", "Database written to "+dbPath)

	db, err := integrity.LoadDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if db.RootFS != rootfs || len(db.Binaries) != 2 {
		t.Fatalf("db rootfs=%q binaries=%d", db.RootFS, len(db.Binaries))
	}
	for _, p := range []string{"/bin/sh", "/usr/bin/tool"} {
		if db.Binaries[p] == nil || db.Binaries[p].SHA256 == "" {
			t.Errorf("missing/empty hash for %s", p)
		}
	}
}

func TestScan_DefaultOutputInCwd(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	runMain(t, "", "-rootfs", fakeRootFS(t))
	if _, err := os.Stat(filepath.Join(cwd, "integrity-db.json")); err != nil {
		t.Errorf("default output not written: %v", err)
	}
}

// writeHostDB builds a database whose keys are absolute host paths, which is
// what Database.Verify actually hashes (see TestVerify_IgnoresRootFS).
func writeHostDB(t *testing.T, files map[string]string, rootfs string) string {
	t.Helper()
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	db, err := integrity.ScanPaths(paths)
	if err != nil {
		t.Fatal(err)
	}
	db.RootFS = rootfs
	dbPath := filepath.Join(t.TempDir(), "db.json")
	if err := db.Save(dbPath); err != nil {
		t.Fatal(err)
	}
	return dbPath
}

func TestVerify_AllPass(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "one")
	f2 := filepath.Join(dir, "two")
	mustWrite(t, f1, "1", 0o755)
	mustWrite(t, f2, "2", 0o755)
	dbPath := writeHostDB(t, map[string]string{f1: "", f2: ""}, "")

	stdout, stderr := runMain(t, "", "-verify", dbPath, "-rootfs", dir)
	assertContains(t, "stderr", stderr, "Verifying 2 binaries against "+dir, "Results: 2 passed, 0 failed, 0 missing")
	if stdout != "" {
		t.Errorf("no FAIL/MISSING lines expected, got %q", stdout)
	}
}

func TestVerify_RootFSFromDatabase(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bin")
	mustWrite(t, f, "x", 0o755)
	dbPath := writeHostDB(t, map[string]string{f: ""}, "/stored/rootfs")
	_, stderr := runMain(t, "", "-verify", dbPath)
	assertContains(t, "stderr", stderr, "against /stored/rootfs", "1 passed")
}

func TestVerify_TamperedAndMissing(t *testing.T) {
	dir := t.TempDir()
	tampered := filepath.Join(dir, "tampered")
	gone := filepath.Join(dir, "gone")
	mustWrite(t, tampered, "original", 0o755)
	mustWrite(t, gone, "here for now", 0o755)
	dbPath := writeHostDB(t, map[string]string{tampered: "", gone: ""}, dir)

	mustWrite(t, tampered, "modified!", 0o755)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}

	r := runChild(t, nil, "-verify", dbPath)
	if r.code != 1 {
		t.Errorf("exit = %d, want 1", r.code)
	}
	assertContains(t, "stdout", r.stdout, "FAIL     "+tampered, "MISSING  "+gone)
	assertContains(t, "stderr", r.stderr, "Results: 0 passed, 1 failed, 1 missing")
}

// BUG: database keys are rootfs-relative ("/bin/sh") but runVerify never joins
// them with --rootfs, so Database.Verify hashes the *host* path. A freshly
// scanned rootfs therefore cannot verify against itself. This test pins the
// current behaviour; flip the expectations when the bug is fixed.
func TestVerify_IgnoresRootFS(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "usr", "local", "sbin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A name that is vanishingly unlikely to exist on the host.
	name := "warmor-integrity-test-" + filepath.Base(rootfs)
	mustWrite(t, filepath.Join(rootfs, "usr", "local", "sbin", name), "bin", 0o755)

	dbPath := filepath.Join(t.TempDir(), "db.json")
	runMain(t, "", "-rootfs", rootfs, "-o", dbPath)

	r := runChild(t, nil, "-verify", dbPath, "-rootfs", rootfs)
	if r.code == 0 {
		t.Skip("verify now honours --rootfs; update this test to assert success")
	}
	assertContains(t, "stdout", r.stdout, "MISSING  /usr/local/sbin/"+name)
}

func TestScanVerify_Errors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	mustWrite(t, bad, "{not json", 0o644)
	noRoot := filepath.Join(dir, "noroot.json")
	data, _ := json.Marshal(integrity.Database{Version: 1, Binaries: map[string]*integrity.BinaryHash{}})
	mustWrite(t, noRoot, string(data), 0o644)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no rootfs", nil, "--rootfs is required"},
		{"unwritable output", []string{"-rootfs", fakeRootFS(t), "-o", filepath.Join(dir, "x", "y", "db.json")}, "error writing database"},
		{"missing db", []string{"-verify", filepath.Join(dir, "nope.json")}, "error loading database"},
		{"corrupt db", []string{"-verify", bad}, "error loading database"},
		{"no rootfs for verify", []string{"-verify", noRoot}, "--rootfs required for verification"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runChild(t, nil, tt.args...)
			if r.code != 1 {
				t.Errorf("exit = %d, want 1 (stderr: %s)", r.code, r.stderr)
			}
			assertContains(t, "stderr", r.stderr, tt.want)
		})
	}
}

func TestScan_Version(t *testing.T) {
	r := runChild(t, nil, "-version")
	if r.code != 0 {
		t.Fatalf("exit = %d", r.code)
	}
	assertContains(t, "stdout", r.stdout, "warmor-integrity-scan dev")
}
