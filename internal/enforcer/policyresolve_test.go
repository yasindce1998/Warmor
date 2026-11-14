package enforcer

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type policyResolveFileInfo struct{ mode os.FileMode }

func (i policyResolveFileInfo) Name() string       { return "current" }
func (i policyResolveFileInfo) Size() int64        { return 0 }
func (i policyResolveFileInfo) Mode() os.FileMode  { return i.mode }
func (i policyResolveFileInfo) ModTime() time.Time { return time.Time{} }
func (i policyResolveFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i policyResolveFileInfo) Sys() any           { return nil }

func TestPolicyRevisionResolutionRetriesOnlyConfirmedSymlinkRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.wasm")
	link := filepath.Join(filepath.Dir(path), "current")
	transient := &os.PathError{Op: "readlink", Path: link, Err: syscall.EINVAL}
	calls, stats := 0, 0
	want := filepath.Join(filepath.Dir(path), "revision-validated", "module.wasm")
	got, err := resolvePolicyRevisionPathRetry(path, func(p string) (string, error) {
		if p != path {
			t.Fatalf("resolution changed caller path: %s", p)
		}
		calls++
		if calls <= 2 {
			return "", transient
		}
		return want, nil
	}, func(p string) (os.FileInfo, error) {
		stats++
		if p != link {
			t.Fatalf("confirmed wrong entry: %s", p)
		}
		return policyResolveFileInfo{mode: os.ModeSymlink}, nil
	})
	if err != nil || got != want || calls != 3 || stats != 2 {
		t.Fatalf("transient resolution not recovered exactly: got=%s err=%v calls=%d stats=%d", got, err, calls, stats)
	}
}

func TestPolicyRevisionResolutionFailsClosedAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		mode      os.FileMode
		statErr   error
		wantCalls int
	}{
		{"non-link", &os.PathError{Op: "readlink", Path: "current", Err: syscall.EINVAL}, 0, nil, 1},
		{"missing-after-race", &os.PathError{Op: "readlink", Path: "current", Err: syscall.EINVAL}, os.ModeSymlink, os.ErrNotExist, 1},
		{"permission", &os.PathError{Op: "readlink", Path: "current", Err: os.ErrPermission}, os.ModeSymlink, nil, 1},
		{"missing", &os.PathError{Op: "lstat", Path: "current", Err: os.ErrNotExist}, os.ModeSymlink, nil, 1},
		{"other-operation", &os.PathError{Op: "open", Path: "current", Err: syscall.EINVAL}, os.ModeSymlink, nil, 1},
		{"persistent-race", &os.PathError{Op: "readlink", Path: "current", Err: syscall.EINVAL}, os.ModeSymlink, nil, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got, err := resolvePolicyRevisionPathRetry("policy.wasm", func(string) (string, error) {
				calls++
				return "", tc.err
			}, func(string) (os.FileInfo, error) {
				return policyResolveFileInfo{mode: tc.mode}, tc.statErr
			})
			if got != "" || !errors.Is(err, tc.err) || calls != tc.wantCalls {
				t.Fatalf("resolution did not fail closed: got=%s err=%v calls=%d", got, err, calls)
			}
		})
	}
}
