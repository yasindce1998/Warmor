//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPhysicalTempDirWithAliasedSystemTemp(t *testing.T) {
	if os.Getenv("WARMOR_ALIASED_TEMP_CHILD") == "1" {
		dir := PhysicalTempDir(t)
		physical, err := filepath.EvalSymlinks(dir)
		if err != nil {
			t.Fatal(err)
		}
		if dir != physical {
			t.Fatalf("temp directory still contains aliases: %q -> %q", dir, physical)
		}
		if rel, err := filepath.Rel(os.Getenv("WARMOR_PHYSICAL_TEMP_PARENT"), dir); err != nil || !filepath.IsLocal(rel) {
			t.Fatalf("temp directory escaped physical fixture root: %q (%v)", dir, err)
		}
		if rel, err := filepath.Rel(os.TempDir(), dir); err == nil && filepath.IsLocal(rel) {
			t.Fatalf("fixture did not exercise aliased system temp: %q", dir)
		}
		return
	}
	root := PhysicalTempDir(t)
	physical := filepath.Join(root, "private", "var", "folders", "T")
	if err := os.MkdirAll(physical, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "var")
	if err := os.Symlink(filepath.Join(root, "private", "var"), alias); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPhysicalTempDirWithAliasedSystemTemp$")
	cmd.Env = append(os.Environ(), "WARMOR_ALIASED_TEMP_CHILD=1", "WARMOR_PHYSICAL_TEMP_PARENT="+physical, "TMPDIR="+filepath.Join(alias, "folders", "T"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("aliased temp child: %v\n%s", err, output)
	}
}
