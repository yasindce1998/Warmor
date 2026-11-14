//go:build windows

package streaming

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/windows"
)

func assertWindowsOwnerDACL(t *testing.T, path string) {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !windows.EqualSid(owner, u.User.Sid) {
		t.Fatalf("unexpected owner: %v %v", owner, err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("unprotected DACL: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 {
		t.Fatalf("not an owner-only DACL: %v", err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
		ace.Mask != windows.STANDARD_RIGHTS_ALL|0x1ff || !windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), u.User.Sid) {
		t.Fatalf("unexpected ACL: %s", sd.String())
	}
}

func TestWindowsPrivateRecordingRotationAndQueueDrain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.ndjson")
	for _, p := range []string{path, path + ".1234"} {
		if err := os.WriteFile(p, []byte("legacy\n"), 0644); err != nil {
			t.Fatal(err)
		}
		ownRecordingFixture(t, p)
	}
	sink, err := NewFileSink(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	pipeline := NewPipeline(PipelineConfig{Sinks: []Sink{sink}, BufferSize: 32})
	for i := 0; i < 8; i++ {
		pipeline.Emit(&api.Event{PID: uint32(i + 1), Process: &api.ProcessEvent{Args: []string{"app", "--password", "secret-token"}}}, nil)
	}
	if err := pipeline.Close(); err != nil {
		t.Fatal(err)
	}
	if stats := pipeline.Stats(); stats.EventsDropped != 0 || stats.SinkErrors != 0 {
		t.Fatalf("recording delivery failed: %+v", stats)
	}
	files, err := filepath.Glob(path + "*")
	if err != nil || len(files) < 9 {
		t.Fatalf("rotation not exercised: %v %v", files, err)
	}
	for _, file := range files {
		assertWindowsOwnerDACL(t, file)
	}
	if data, err := os.ReadFile(path); err != nil || !strings.Contains(string(data), "secret-token") {
		t.Fatalf("private recording lost replay input: %q %v", data, err)
	}
	if _, err := sink.file.WriteString("closed"); err == nil {
		t.Fatal("pipeline close left recording handle open")
	}
}

func ownRecordingFixture(t *testing.T, path string) {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, u.User.Sid, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsFileSinkRejectsUnsafeArchivesAndReopen(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events")
	if err := os.Symlink(target, path+".1234"); err != nil {
		t.Fatal(err)
	}
	if sink, err := NewFileSink(path, 1); err == nil {
		_ = sink.Close()
		t.Fatal("accepted linked legacy archive")
	}
	path = filepath.Join(dir, "rotate")
	sink, err := NewFileSink(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	if err := sink.Write(context.Background(), sampleEvent(1)); err != nil {
		t.Fatal(err)
	}
	// Rename is possible because the recording handle shares DELETE. Replace
	// the path with a symlink; the descriptor check must reject rotation and
	// reopen must not redirect recording into the target.
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := sink.Write(context.Background(), sampleEvent(2)); err == nil {
			t.Fatal("reopen followed swapped symlink")
		}
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "keep" {
		t.Fatalf("unsafe target changed: %q %v", data, err)
	}
}

func permissiveWindowsArchiveFixture(t *testing.T, path string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("legacy secret\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ownRecordingFixture(t, path)
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;OW)(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	return windowsArchiveSecurity(t, path)
}

func windowsArchiveSecurity(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

func TestWindowsFileSinkSecuresCaseVariantLegacyArchives(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "Events.ndjson")
	permissiveWindowsArchiveFixture(t, active)
	archives := []string{"Events.ndjson.1234", "EVENTS.NDJSON.2345.1", "eVeNtS.NdJsOn.3456"}
	recordings := []string{active}
	for _, name := range archives {
		path := filepath.Join(dir, name)
		permissiveWindowsArchiveFixture(t, path)
		recordings = append(recordings, path)
	}
	unrelated := filepath.Join(dir, "EVENTS.NDJSON.notes")
	before := permissiveWindowsArchiveFixture(t, unrelated)
	sink, err := NewFileSink(filepath.Join(dir, "events.ndjson"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range recordings {
		assertWindowsOwnerDACL(t, path)
		if data, err := os.ReadFile(path); err != nil || string(data) != "legacy secret\n" {
			t.Fatalf("legacy recording changed: %q %v", data, err)
		}
	}
	if after := windowsArchiveSecurity(t, unrelated); after != before {
		t.Fatalf("changed unrelated sibling ACL: before %s, after %s", before, after)
	}
}

func TestWindowsFileSinkRejectsCaseVariantLinkedArchives(t *testing.T) {
	for name, link := range map[string]func(string, string) error{"symlink": os.Symlink, "hardlink": os.Link} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			before := permissiveWindowsArchiveFixture(t, target)
			if err := link(target, filepath.Join(dir, "EVENTS.NDJSON.1234")); err != nil {
				t.Fatal(err)
			}
			if sink, err := NewFileSink(filepath.Join(dir, "events.ndjson"), 0); err == nil {
				_ = sink.Close()
				t.Fatal("accepted case-variant linked archive")
			}
			if after := windowsArchiveSecurity(t, target); after != before {
				t.Fatalf("changed linked target ACL: before %s, after %s", before, after)
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "legacy secret\n" {
				t.Fatalf("linked target changed: %q %v", data, err)
			}
		})
	}
}
