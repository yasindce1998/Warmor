package integrity

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

func writeFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
}

func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-binary")
	content := []byte("#!/bin/sh\necho hello world\n")
	writeFile(t, path, content, 0755)

	hash, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if hash.SHA256 == "" {
		t.Error("expected non-empty SHA256")
	}
	if hash.FastHash == 0 {
		t.Error("expected non-zero fast hash")
	}
	if hash.Size != int64(len(content)) {
		t.Errorf("size mismatch: got %d want %d", hash.Size, len(content))
	}
}

func TestHashFileConsistency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary")
	writeFile(t, path, []byte("consistent content"), 0755)

	h1, _ := HashFile(path)
	h2, _ := HashFile(path)

	if h1.SHA256 != h2.SHA256 {
		t.Error("SHA256 not consistent")
	}
	if h1.FastHash != h2.FastHash {
		t.Error("FastHash not consistent")
	}
}

func TestFastHashBytes(t *testing.T) {
	data := []byte("hello world")
	h1 := FastHashBytes(data)
	h2 := FastHashBytes(data)
	if h1 != h2 {
		t.Error("FastHashBytes not consistent")
	}
	if h1 == 0 {
		t.Error("expected non-zero hash")
	}
}

func TestFastHashPath(t *testing.T) {
	h1 := FastHashPath("/usr/bin/nginx")
	h2 := FastHashPath("/usr/bin/nginx")
	h3 := FastHashPath("/usr/bin/curl")

	if h1 != h2 {
		t.Error("same path should produce same hash")
	}
	if h1 == h3 {
		t.Error("different paths should produce different hashes")
	}
}

func TestScanRootFS(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "usr", "bin")
	mkdirAll(t, binDir)
	writeFile(t, filepath.Join(binDir, "nginx"), []byte("fake-nginx"), 0755)
	writeFile(t, filepath.Join(binDir, "curl"), []byte("fake-curl"), 0755)
	writeFile(t, filepath.Join(binDir, "readme.txt"), []byte("not executable"), 0644)

	db, err := ScanRootFS(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Binaries) != 2 {
		t.Fatalf("expected 2 binaries, got %d", len(db.Binaries))
	}
	if _, ok := db.Binaries["/usr/bin/nginx"]; !ok {
		t.Error("expected /usr/bin/nginx in database")
	}
	if _, ok := db.Binaries["/usr/bin/curl"]; !ok {
		t.Error("expected /usr/bin/curl in database")
	}
}

func TestDatabaseSaveAndLoad(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "usr", "bin")
	mkdirAll(t, binDir)
	writeFile(t, filepath.Join(binDir, "app"), []byte("application"), 0755)

	db, _ := ScanRootFS(root)

	dbPath := filepath.Join(t.TempDir(), "integrity.json")
	if err := db.Save(dbPath); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Binaries) != len(db.Binaries) {
		t.Fatalf("loaded %d binaries, expected %d", len(loaded.Binaries), len(db.Binaries))
	}
	for path, orig := range db.Binaries {
		l, ok := loaded.Binaries[path]
		if !ok {
			t.Errorf("missing %s in loaded db", path)
			continue
		}
		if l.SHA256 != orig.SHA256 {
			t.Errorf("SHA256 mismatch for %s", path)
		}
	}
}

func TestDatabaseVerify(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "app")
	writeFile(t, binPath, []byte("original"), 0755)

	db, _ := ScanPaths([]string{binPath})

	ok, err := db.Verify(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected verify to pass for unchanged file")
	}

	writeFile(t, binPath, []byte("tampered"), 0755)
	ok, err = db.Verify(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected verify to fail for tampered file")
	}
}

func TestDatabaseVerifyUnknownPath(t *testing.T) {
	db := &Database{Binaries: make(map[string]*BinaryHash)}
	ok, err := db.Verify("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected false for unknown path")
	}
}

func TestCheckerPass(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "good")
	writeFile(t, binPath, []byte("trusted binary"), 0755)

	db, _ := ScanPaths([]string{binPath})
	checker := NewChecker(db)

	result, err := checker.Check(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if result != CheckPass {
		t.Errorf("expected PASS, got %s", result)
	}
}

func TestCheckerFail(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "binary")
	writeFile(t, binPath, []byte("original"), 0755)

	db, _ := ScanPaths([]string{binPath})
	writeFile(t, binPath, []byte("tampered!"), 0755)

	checker := NewChecker(db)
	result, err := checker.Check(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if result != CheckFail {
		t.Errorf("expected FAIL, got %s", result)
	}
}

func TestCheckerUnknownDeny(t *testing.T) {
	db := &Database{Binaries: make(map[string]*BinaryHash)}
	checker := NewChecker(db)

	result, _ := checker.Check("/some/unknown/binary")
	if result != CheckUnknown {
		t.Errorf("expected UNKNOWN, got %s", result)
	}
}

func TestCheckerUnknownAllow(t *testing.T) {
	db := &Database{Binaries: make(map[string]*BinaryHash)}
	checker := NewChecker(db, WithAllowUnknown(true))

	result, _ := checker.Check("/some/unknown/binary")
	if result != CheckPass {
		t.Errorf("expected PASS with allow-unknown, got %s", result)
	}
}

func TestCheckerCaching(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "cached")
	writeFile(t, binPath, []byte("binary"), 0755)

	db, _ := ScanPaths([]string{binPath})
	checker := NewChecker(db)

	r1, _ := checker.Check(binPath)
	writeFile(t, binPath, []byte("changed"), 0755)
	r2, _ := checker.Check(binPath)

	if r1 != r2 {
		t.Error("cached result should be the same")
	}

	checker.ClearCache()
	r3, _ := checker.Check(binPath)
	if r3 != CheckFail {
		t.Errorf("after cache clear, expected FAIL, got %s", r3)
	}
}

func TestCheckerCheckEvent(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "app")
	writeFile(t, binPath, []byte("original"), 0755)
	db, _ := ScanPaths([]string{binPath})

	writeFile(t, binPath, []byte("tampered"), 0755)
	checker := NewChecker(db)

	event := &streaming.SecurityEvent{
		EventType: "exec",
		Filename:  binPath,
		PID:       1234,
		Comm:      "app",
		CgroupID:  999,
	}

	result := checker.CheckEvent(event)
	if result == nil {
		t.Fatal("expected denial for tampered binary")
	}
	if result.Action != 1 { // ActionDeny
		t.Errorf("expected ActionDeny, got %d", result.Action)
	}

	violations := checker.Violations()
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Path != binPath {
		t.Errorf("violation path mismatch")
	}
}

func TestCheckerCheckEventNonExec(t *testing.T) {
	db := &Database{Binaries: make(map[string]*BinaryHash)}
	checker := NewChecker(db)

	event := &streaming.SecurityEvent{
		EventType: "file",
		Filename:  "/etc/passwd",
	}
	result := checker.CheckEvent(event)
	if result != nil {
		t.Error("non-exec events should not be checked")
	}
}

func TestEnricher(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "verified")
	writeFile(t, binPath, []byte("content"), 0755)
	db, _ := ScanPaths([]string{binPath})

	enricher := NewEnricher(NewChecker(db))
	event := &streaming.SecurityEvent{
		EventType: "exec",
		Filename:  binPath,
	}

	enricher.Enrich(context.Background(), event)
	if event.Labels["integrity"] != "PASS" {
		t.Errorf("expected PASS label, got %s", event.Labels["integrity"])
	}
}

func TestLookupFastHash(t *testing.T) {
	db := &Database{
		Binaries: map[string]*BinaryHash{
			"/usr/bin/nginx": {Path: "/usr/bin/nginx", SHA256: "abc123", FastHash: 42},
		},
	}

	hash := FastHashPath("/usr/bin/nginx")
	entry := db.LookupFastHash(hash)
	if entry == nil {
		t.Fatal("expected to find entry by fast hash")
	}
	if entry.SHA256 != "abc123" {
		t.Errorf("unexpected SHA256: %s", entry.SHA256)
	}
}

type fakeInfo struct {
	name string
	mode os.FileMode
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return nil }

func TestIsExecutable(t *testing.T) {
	tests := []struct {
		name string
		mode os.FileMode
		goos string
		want bool
	}{
		{"nginx", 0755, "linux", true},
		{"nginx", 0644, "linux", false}, // extensionless but not +x
		{"run.sh", 0644, "linux", false},
		{"app.exe", 0644, "darwin", false},
		{"nginx", 0644, "windows", true},
		{"run.sh", 0644, "windows", true},
		{"APP.EXE", 0644, "windows", true},
		{"readme.txt", 0644, "windows", false},
	}
	for _, tt := range tests {
		if got := isExecutable(fakeInfo{tt.name, tt.mode}, tt.goos); got != tt.want {
			t.Errorf("isExecutable(%s, %o, %s) = %v, want %v", tt.name, tt.mode, tt.goos, got, tt.want)
		}
	}
}

func TestScanRootFSSkipsNonExecutableExtensionless(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("extensionless files are executables on Windows")
	}
	root := t.TempDir()
	binDir := filepath.Join(root, "usr", "bin")
	mkdirAll(t, binDir)
	writeFile(t, filepath.Join(binDir, "app"), []byte("app"), 0755)
	writeFile(t, filepath.Join(binDir, "LICENSE"), []byte("text"), 0644)

	db, err := ScanRootFS(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := db.Binaries["/usr/bin/LICENSE"]; ok || len(db.Binaries) != 1 {
		t.Errorf("binaries = %v, want only /usr/bin/app", db.Binaries)
	}
}

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
}

func TestHashFileInRootSymlinksStayInRoot(t *testing.T) {
	host := t.TempDir()
	hostBin := filepath.Join(host, "busybox")
	writeFile(t, hostBin, []byte("HOST"), 0755)

	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	mkdirAll(t, binDir)
	writeFile(t, filepath.Join(binDir, "busybox"), []byte("CONTAINER"), 0755)
	want, _ := HashFile(filepath.Join(binDir, "busybox"))

	// Absolute target: must resolve to <root>/bin/busybox, not the host path.
	symlinkOrSkip(t, "/bin/busybox", filepath.Join(binDir, "sh"))
	// Relative target climbing past the root is clamped at the root.
	symlinkOrSkip(t, "../../../../../../bin/busybox", filepath.Join(binDir, "ash"))
	// A target naming a host absolute path is re-anchored and thus missing.
	symlinkOrSkip(t, hostBin, filepath.Join(binDir, "escape"))

	for _, name := range []string{"/bin/sh", "/bin/ash"} {
		got, err := HashFileInRoot(root, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.SHA256 != want.SHA256 || got.Path != name {
			t.Errorf("%s: got %+v, want container busybox", name, got)
		}
	}
	if _, err := HashFileInRoot(root, "/bin/escape"); err == nil {
		t.Error("/bin/escape: expected error, symlink must not reach the host")
	}

	db, err := ScanRootFS(root)
	if err != nil {
		t.Fatal(err)
	}
	if db.Binaries["/bin/sh"] == nil || db.Binaries["/bin/sh"].SHA256 != want.SHA256 {
		t.Errorf("scan hashed /bin/sh = %+v, want container busybox", db.Binaries["/bin/sh"])
	}
	if _, ok := db.Binaries["/bin/escape"]; ok {
		t.Error("scan must skip symlinks escaping the rootfs")
	}
}

func TestHashFileInRootErrors(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "bin"))
	if _, err := HashFileInRoot(filepath.Join(root, "nope"), "/bin/x"); err == nil {
		t.Error("expected error for missing rootfs")
	}
	if _, err := HashFileInRoot(root, "/bin"); err == nil {
		t.Error("expected error for directory")
	}
	if _, err := HashFileInRoot(root, "/bin/missing"); err == nil {
		t.Error("expected error for missing file")
	}
	loop := filepath.Join(root, "bin", "loop")
	symlinkOrSkip(t, "/bin/loop", loop)
	if _, err := HashFileInRoot(root, "/bin/loop"); err == nil {
		t.Error("expected error for symlink loop")
	}
}

func TestDatabaseVerifyInRoot(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "usr", "bin")
	mkdirAll(t, binDir)
	writeFile(t, filepath.Join(binDir, "app"), []byte("original"), 0755)
	db, err := ScanRootFS(root)
	if err != nil {
		t.Fatal(err)
	}

	if ok, err := db.VerifyInRoot(root, "/usr/bin/app"); err != nil || !ok {
		t.Fatalf("VerifyInRoot = %v, %v; want true", ok, err)
	}
	if ok, err := db.VerifyInRoot(root, "/usr/bin/unknown"); err != nil || ok {
		t.Errorf("unknown path = %v, %v; want false, nil", ok, err)
	}
	writeFile(t, filepath.Join(binDir, "app"), []byte("tampered"), 0755)
	if ok, err := db.VerifyInRoot(root, "/usr/bin/app"); err != nil || ok {
		t.Errorf("tampered = %v, %v; want false, nil", ok, err)
	}
	os.Remove(filepath.Join(binDir, "app"))
	if _, err := db.VerifyInRoot(root, "/usr/bin/app"); err == nil {
		t.Error("expected error for missing file")
	}
}
