//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package streaming

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

// Umask is process-global: only mutate it in a child, never the test runner.
func TestFileRecordingPermissionsUmask022(t *testing.T) {
	if os.Getenv("WARMOR_PRIVATE_FILE_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFileRecordingPermissionsUmask022$")
		cmd.Env = append(os.Environ(), "WARMOR_PRIVATE_FILE_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, output)
		}
		return
	}
	syscall.Umask(0022)
	dir := t.TempDir()
	path := filepath.Join(dir, "events.ndjson")
	// Tighten a legacy world-readable file before appending argv.
	if err := os.WriteFile(path, []byte("legacy\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".1234", []byte("old secret"), 0644); err != nil {
		t.Fatal(err)
	}
	sink, err := NewFileSink(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	event := FromAPIEvent(&api.Event{Process: &api.ProcessEvent{Args: []string{"app", "--password", "secret-token"}}}, nil)
	for i := 0; i < 3; i++ {
		if err := sink.Write(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(path + "*")
	if len(files) < 3 {
		t.Fatalf("rotation not exercised: %v", files)
	}
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe recording %s: %v %v", file, info, err)
		}
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "secret-token") {
		t.Fatal("private recording lost replay inputs")
	}
	// New path, independently of the tightened legacy path.
	fresh, err := NewFileSink(filepath.Join(dir, "fresh"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	info, _ := os.Stat(filepath.Join(dir, "fresh"))
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	// Symlinks, hardlinks, and symlink parent components are never followed.
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if s, err := NewFileSink(link, 0); err == nil {
		s.Close()
		t.Fatal("followed symlink")
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	if s, err := NewFileSink(hard, 0); err == nil {
		s.Close()
		t.Fatal("accepted hardlink")
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if s, err := NewFileSink(filepath.Join(alias, "new"), 0); err == nil {
		s.Close()
		t.Fatal("followed symlink directory")
	}
	shared := filepath.Join(dir, "shared")
	if err := os.Mkdir(shared, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0777); err != nil {
		t.Fatal(err)
	}
	if s, err := NewFileSink(filepath.Join(shared, "new"), 0); err == nil {
		s.Close()
		t.Fatal("accepted other-user-writable parent")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := NewFileSink(fifo, 0); err == nil {
		s.Close()
		t.Fatal("accepted nonregular recording")
	}
	archiveLog := filepath.Join(dir, "archive-log")
	if err := os.Symlink(target, archiveLog+".1234"); err != nil {
		t.Fatal(err)
	}
	if s, err := NewFileSink(archiveLog, 0); err == nil {
		s.Close()
		t.Fatal("followed legacy archive symlink")
	}
	// A swapped active path must not redirect rotation/reopening into a target.
	rotating, err := NewFileSink(filepath.Join(dir, "rotate"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rotating.Close()
	if err := rotating.Write(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "rotate")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "rotate")); err != nil {
		t.Fatal(err)
	}
	if err := rotating.Write(context.Background(), event); err == nil {
		t.Fatal("rotation followed swapped symlink")
	}
	data, _ = os.ReadFile(target)
	info, _ = os.Stat(target)
	if string(data) != "unchanged" || info.Mode().Perm() != 0644 {
		t.Fatal("unsafe target modified")
	}
}
