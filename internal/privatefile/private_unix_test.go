//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package privatefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenAppendProtectsOnlyPrivateLeafAndRecording(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(parent, "store")
	if err := os.Mkdir(store, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store, "events")
	if err := os.WriteFile(path, []byte("legacy"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := OpenAppend(path, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{parent: 0755, store: 0700, path: 0600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode %o, want %o", path, info.Mode().Perm(), want)
		}
	}
	// Even a private leaf cannot make a nonsticky writable ancestor safe.
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenAppend(path, true, false); err == nil {
		_ = f.Close()
		t.Fatal("accepted untrusted ancestor")
	}
}

func TestOpenAppendRejectsAliasesWithoutChangingTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0644); err != nil {
		t.Fatal(err)
	}
	for name, link := range map[string]func(string, string) error{"symlink": os.Symlink, "hardlink": os.Link} {
		path := filepath.Join(dir, name)
		if err := link(target, path); err != nil {
			t.Fatal(err)
		}
		if f, err := OpenAppend(path, false, false); err == nil {
			_ = f.Close()
			t.Fatalf("accepted %s", name)
		}
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" || info.Mode().Perm() != 0644 {
		t.Fatalf("unsafe alias modified target: %q mode %o", data, info.Mode().Perm())
	}
}

func TestRotateChecksDescriptorAndNeverOverwritesArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events")
	f, err := OpenAppend(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("original"); err != nil {
		t.Fatal(err)
	}
	archive := path + ".1"
	if err := os.WriteFile(archive, []byte("archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Rotate(path, archive, f); err == nil {
		t.Fatal("overwrote an existing archive")
	}
	if data, err := os.ReadFile(archive); err != nil || string(data) != "archive" {
		t.Fatalf("archive changed: %q %v", data, err)
	}
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Rotate(path, path+".2", f); err == nil {
		t.Fatal("rotated a different file than the opened descriptor")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "replacement" {
		t.Fatalf("replacement changed: %q %v", data, err)
	}
}
