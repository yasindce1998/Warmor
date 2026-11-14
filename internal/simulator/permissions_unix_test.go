//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package simulator

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestEventStorePermissionsUmask022(t *testing.T) {
	if os.Getenv("WARMOR_PRIVATE_STORE_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestEventStorePermissionsUmask022$")
		cmd.Env = append(os.Environ(), "WARMOR_PRIVATE_STORE_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, output)
		}
		return
	}
	syscall.Umask(0022)
	root := t.TempDir()
	dir := filepath.Join(root, "new", "store")
	store, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "events-2001-01-01.ndjson")
	if err := os.WriteFile(old, []byte("old secret"), 0644); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
	oldInfo, _ := os.Stat(old)
	if oldInfo.Mode().Perm() != 0600 {
		t.Fatal("legacy daily recording not secured")
	}
	defer store.Close()
	for _, path := range []string{filepath.Dir(dir), dir} {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0700 {
			t.Fatalf("unsafe directory: %s %v", path, info.Mode())
		}
	}
	path := filepath.Join(dir, "events-"+time.Now().UTC().Format("2006-01-02")+".ndjson")
	event := streaming.FromAPIEvent(&api.Event{Process: &api.ProcessEvent{Args: []string{"--password", "secret-token"}}}, nil)
	if err := store.Write(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	// Simulate a legacy/permissive existing store on daily reopen.
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	store.curDate = "previous-day"
	if err := store.Write(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0700 {
		t.Fatal(info.Mode())
	}
	info, _ = os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "secret-token") {
		t.Fatal("missing replay input")
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	store.curDate = "previous-day"
	if err := store.Write(context.Background(), event); err == nil {
		t.Fatal("rotation followed symlink")
	}
	if err := store.Write(context.Background(), event); err == nil {
		t.Fatal("retry followed symlink")
	}
	data, _ = os.ReadFile(target)
	info, _ = os.Stat(target)
	if string(data) != "unchanged" || info.Mode().Perm() != 0644 {
		t.Fatal("modified symlink target")
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if s, err := NewEventStore(alias); err == nil {
		s.Close()
		t.Fatal("followed store directory symlink")
	}
}
