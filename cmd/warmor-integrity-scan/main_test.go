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

// scanDB scans rootfs into a database file and returns its path.
func scanDB(t *testing.T, rootfs string) string {
	t.Helper()
	db, err := integrity.ScanRootFS(rootfs)
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "db.json")
	if err := db.Save(dbPath); err != nil {
		t.Fatal(err)
	}
	return dbPath
}

func TestVerify_AllPass(t *testing.T) {
	rootfs := fakeRootFS(t)
	dbPath := scanDB(t, rootfs)

	stdout, stderr := runMain(t, "", "-verify", dbPath, "-rootfs", rootfs)
	assertContains(t, "stderr", stderr, "Verifying 2 binaries against "+rootfs, "Results: 2 passed, 0 failed, 0 missing")
	if stdout != "" {
		t.Errorf("no FAIL/MISSING lines expected, got %q", stdout)
	}
}

func TestVerify_RootFSFromDatabase(t *testing.T) {
	rootfs := fakeRootFS(t)
	dbPath := scanDB(t, rootfs)
	_, stderr := runMain(t, "", "-verify", dbPath)
	assertContains(t, "stderr", stderr, "against "+rootfs, "2 passed")
}

// TestVerify_FlagOverridesDatabaseRootFS checks that --rootfs, not the path
// stored at scan time, is what gets verified (e.g. after copying the image).
func TestVerify_FlagOverridesDatabaseRootFS(t *testing.T) {
	rootfs := fakeRootFS(t)
	dbPath := scanDB(t, rootfs)
	moved := filepath.Join(t.TempDir(), "moved")
	if err := os.Rename(rootfs, moved); err != nil {
		t.Fatal(err)
	}
	_, stderr := runMain(t, "", "-verify", dbPath, "-rootfs", moved)
	assertContains(t, "stderr", stderr, "against "+moved, "Results: 2 passed, 0 failed, 0 missing")
}

func TestVerify_TamperedAndMissing(t *testing.T) {
	rootfs := fakeRootFS(t)
	dbPath := scanDB(t, rootfs)

	mustWrite(t, filepath.Join(rootfs, "usr", "bin", "tool"), "modified!", 0o755)
	if err := os.Remove(filepath.Join(rootfs, "bin", "sh")); err != nil {
		t.Fatal(err)
	}

	r := runChild(t, nil, "-verify", dbPath)
	if r.code != 1 {
		t.Errorf("exit = %d, want 1", r.code)
	}
	assertContains(t, "stdout", r.stdout, "FAIL     /usr/bin/tool", "MISSING  /bin/sh")
	assertContains(t, "stderr", r.stderr, "Results: 0 passed, 1 failed, 1 missing")
}

// TestVerify_HonoursRootFS is a regression test: database keys are
// rootfs-relative ("/usr/local/sbin/x") and verify used to hash the host path
// instead, so a freshly scanned rootfs could not verify against itself.
func TestVerify_HonoursRootFS(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "usr", "local", "sbin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A name that is vanishingly unlikely to exist on the host.
	name := "warmor-integrity-test-" + filepath.Base(rootfs)
	mustWrite(t, filepath.Join(rootfs, "usr", "local", "sbin", name), "bin", 0o755)

	dbPath := filepath.Join(t.TempDir(), "db.json")
	runMain(t, "", "-rootfs", rootfs, "-o", dbPath)

	stdout, stderr := runMain(t, "", "-verify", dbPath, "-rootfs", rootfs)
	assertContains(t, "stderr", stderr, "Results: 1 passed, 0 failed, 0 missing")
	if stdout != "" {
		t.Errorf("no FAIL/MISSING lines expected, got %q", stdout)
	}
}

// TestVerify_SymlinkCannotEscapeRootFS ensures a symlink inside the rootfs
// pointing at an absolute host path is resolved inside the rootfs, so a
// tampered image cannot make verify hash (and pass on) a host binary.
func TestVerify_SymlinkCannotEscapeRootFS(t *testing.T) {
	host := filepath.Join(t.TempDir(), "hostbin")
	// Same content as the scanned binary, so hashing it would wrongly pass.
	mustWrite(t, host, "tool-binary", 0o755)

	rootfs := fakeRootFS(t)
	dbPath := scanDB(t, rootfs)
	tool := filepath.Join(rootfs, "usr", "bin", "tool")
	if err := os.Remove(tool); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(host, tool); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	r := runChild(t, nil, "-verify", dbPath)
	if r.code != 1 {
		t.Errorf("exit = %d, want 1", r.code)
	}
	assertContains(t, "stdout", r.stdout, "MISSING  /usr/bin/tool")
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
