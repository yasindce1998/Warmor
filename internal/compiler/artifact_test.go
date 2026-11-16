package compiler

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/policybuild"
)

func TestArtifactPublicationFailures(t *testing.T) {
	failure := errors.New("injected publication failure")
	for _, stage := range []string{"write", "short write", "sync", "close", "rename", "cancel before commit", "directory sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.wasm")
			old := []byte("previous complete artifact")
			next := []byte("next complete artifact")
			if err := os.WriteFile(path, old, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := newArtifactPublisher()
			switch stage {
			case "write":
				p.write = func(f *os.File, b []byte) (int, error) {
					n, _ := f.Write(b[:3])
					return n, failure
				}
			case "short write":
				p.write = func(f *os.File, b []byte) (int, error) { return f.Write(b[:3]) }
			case "sync":
				p.fileSync = func(*os.File) error { return failure }
			case "close":
				p.close = func(f *os.File) error { _ = f.Close(); return failure }
			case "rename":
				p.replace = func(string, string) (bool, error) { return false, failure }
			case "cancel before commit":
				p.close = func(f *os.File) error { cancel(); return f.Close() }
			case "directory sync":
				p.replace = func(from, to string) (bool, error) {
					_, err := replaceArtifact(from, to)
					if err != nil {
						t.Fatal(err)
					}
					return true, failure
				}
			}
			result, err := p.publish(ctx, path, next)
			if err == nil || result != "" {
				t.Fatalf("publish = %q, %v; want error without success result", result, err)
			}
			wantErr := failure
			if stage == "cancel before commit" {
				wantErr = context.Canceled
			} else if stage == "short write" {
				wantErr = io.ErrShortWrite
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("error = %v, want %v", err, wantErr)
			}
			if got := errors.Is(err, ErrArtifactPublicationIndeterminate); got != (stage == "directory sync") {
				t.Fatalf("indeterminate = %v, error = %v", got, err)
			}
			want := old
			if stage == "directory sync" {
				want = next // Never falsely promise rollback after replacement.
			}
			assertArtifactContents(t, path, want)
			assertOnlyOutput(t, dir, "policy.wasm")
		})
	}
}

func TestArtifactPublicationModesAndCommitBoundary(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new private", true: "preserve 0600"}[existing], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.wasm")
			if existing {
				if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := newArtifactPublisher()
			p.replace = func(from, to string) (bool, error) {
				if filepath.Dir(from) != filepath.Dir(to) {
					t.Fatal("staging file is not in destination directory")
				}
				// Complete staged bytes and a closed handle precede replacement.
				assertArtifactContents(t, from, []byte("complete"))
				published, err := replaceArtifact(from, to)
				cancel() // Too late: do not misreport a committed build as canceled.
				return published, err
			}
			got, err := p.publish(ctx, path, []byte("complete"))
			if err != nil || got != path {
				t.Fatalf("publish = %q, %v", got, err)
			}
			assertArtifactContents(t, path, []byte("complete"))
			assertOnlyOutput(t, dir, "policy.wasm")
			if runtime.GOOS != "windows" {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				want := os.FileMode(0o600)
				if info.Mode().Perm() != want {
					t.Fatalf("mode = %o, want %o", info.Mode().Perm(), want)
				}
			}
		})
	}
}

func TestArtifactPublicationDefaultPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	got, err := newArtifactPublisher().publish(context.Background(), "", []byte("complete"))
	if err != nil || got != filepath.Join(dir, "policy.wasm") {
		t.Fatalf("default output = %q, %v", got, err)
	}
}

func TestArtifactPublicationReplacementFailureCleansStage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.wasm")
	if err := os.WriteFile(path, []byte("previous complete artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newArtifactPublisher()
	p.replace = func(from, to string) (bool, error) {
		// Use a real OS rename failure, with an existing nonempty directory as
		// its target, rather than depending on permission failures as root.
		blocked := filepath.Join(dir, "blocked")
		if err := os.Mkdir(blocked, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(blocked, "keep"), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		return replaceArtifact(from, blocked)
	}
	if _, err := p.publish(context.Background(), path, []byte("next")); err == nil {
		t.Fatal("expected OS replacement failure")
	}
	assertArtifactContents(t, path, []byte("previous complete artifact"))
	assertArtifactContents(t, filepath.Join(dir, "blocked", "keep"), []byte("keep"))
	assertOnlyOutput(t, dir, "blocked", "policy.wasm")
}

func TestArtifactPublicationProtectedOutputs(t *testing.T) {
	for _, kind := range []string{"read-only", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.wasm")
			old := []byte("keep protected output")
			var target string
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(path, "child")
			case "symlink":
				target = filepath.Join(t.TempDir(), "target")
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			default:
				target = path
			}
			if err := os.WriteFile(target, old, 0o600); err != nil {
				t.Fatal(err)
			}
			if kind == "read-only" {
				if err := os.Chmod(path, 0o444); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
			}
			_, err := newArtifactPublisher().publish(context.Background(), path, []byte("new"))
			if err == nil || errors.Is(err, ErrArtifactPublicationIndeterminate) {
				t.Fatalf("protected output error = %v, want pre-commit failure", err)
			}
			assertArtifactContents(t, target, old)
			assertOnlyOutput(t, dir, "policy.wasm")
			if kind == "symlink" {
				if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("symlink changed: %v, %v", info, err)
				}
			}
		})
	}
}

func TestReadBuiltArtifactBoundAndFileType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "built.wasm")
	if err := os.WriteFile(path, []byte("small"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readBuiltArtifact(path)
	if err != nil || string(data) != "small" {
		t.Fatalf("read small artifact = %q, %v", data, err)
	}
	if err := os.Truncate(path, maxCompiledArtifactBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := readBuiltArtifact(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized artifact error = %v", err)
	}
	if _, err := readBuiltArtifact(dir); err == nil {
		t.Fatal("directory accepted")
	}
	link := filepath.Join(dir, "link.wasm")
	if err := os.Symlink(path, link); err == nil {
		if _, err := readBuiltArtifact(link); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}

func TestArtifactHardLinksRejected(t *testing.T) {
	for _, candidate := range []bool{false, true} {
		t.Run(map[bool]string{false: "destination", true: "cargo output"}[candidate], func(t *testing.T) {
			dir := t.TempDir()
			path, alias := filepath.Join(dir, "policy.wasm"), filepath.Join(dir, "alias.wasm")
			old := []byte("keep linked artifact")
			if err := os.WriteFile(path, old, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(path, alias); err != nil {
				t.Fatalf("create hard link: %v", err)
			}
			var err error
			if candidate {
				_, err = readBuiltArtifact(path)
			} else {
				_, err = newArtifactPublisher().publish(context.Background(), path, []byte("new"))
			}
			if err == nil || !strings.Contains(err.Error(), "singly-linked") || errors.Is(err, ErrArtifactPublicationIndeterminate) {
				t.Fatalf("hard-linked artifact error = %v, want pre-commit link rejection", err)
			}
			assertArtifactContents(t, path, old)
			assertArtifactContents(t, alias, old)
			first, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			second, err := os.Stat(alias)
			if err != nil || !os.SameFile(first, second) {
				t.Fatalf("hard-link identity changed: %v", err)
			}
			assertOnlyOutput(t, dir, "alias.wasm", "policy.wasm")
		})
	}
}

func TestArtifactHandleChecksRejectChanges(t *testing.T) {
	dir := t.TempDir()
	path, other := filepath.Join(dir, "policy.wasm"), filepath.Join(dir, "other.wasm")
	for _, name := range []string{path, other} {
		if err := os.WriteFile(name, []byte("artifact"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := openArtifact(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := checkedArtifactInfo(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkArtifactIdentity(other, f, info); err == nil {
		t.Fatal("different pathname identity accepted")
	}
	if err := checkArtifactIdentity(path, f, info); err != nil {
		t.Fatalf("unchanged pathname identity rejected: %v", err)
	}
	alias := filepath.Join(dir, "alias.wasm")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := checkedArtifactInfo(f); err == nil || !strings.Contains(err.Error(), "singly-linked") {
		t.Fatalf("new hard link on already-open handle: %v", err)
	}
	link := filepath.Join(dir, "symlink.wasm")
	if err := os.Symlink(path, link); err == nil {
		if err := checkArtifactIdentity(link, f, info); err == nil {
			t.Fatal("symlink pathname identity accepted")
		}
	}
}

func TestBuildArtifactValidationBeforePublication(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake toolchain uses POSIX shell executables")
	}
	metadata := policybuild.Metadata{Compiler: Identity, DefaultAction: "deny"}
	raw := []byte{0, 97, 115, 109, 1, 0, 0, 0}
	withMetadata, err := policybuild.Append(raw, metadata)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append(bytes.Clone(withMetadata), withMetadata[8:]...)
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"valid", raw, ""},
		{"invalid header", []byte("not wasm"), "invalid WASM header"},
		{"truncated section", append(bytes.Clone(raw), 0, 4, 1), "truncated WASM section"},
		{"already has metadata", withMetadata, "already present"},
		{"duplicate metadata", duplicate, "duplicate build metadata"},
		{"oversized", nil, "exceeds"},
		{"hardlinked cargo output", raw, "singly-linked"},
		{"hardlinked destination", raw, "singly-linked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin, work, outDir := t.TempDir(), t.TempDir(), t.TempDir()
			fixture := filepath.Join(t.TempDir(), "raw.wasm")
			if err := os.WriteFile(fixture, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.name == "oversized" {
				if err := os.Truncate(fixture, maxCompiledArtifactBytes+1); err != nil {
					t.Fatal(err)
				}
			}
			policy, err := Parse([]byte(sampleYAML))
			if err != nil {
				t.Fatal(err)
			}
			wasmFile := "warmor_policy_" + crateIdentifier(policy.Name) + ".wasm"
			for tool, script := range map[string]string{
				"rustup": "#!/bin/sh\necho wasm32-unknown-unknown\n",
				"cargo": "#!/bin/sh\nset -eu\n" +
					"out=\nfor arg do\ncase \"$arg\" in --emit=link=*) out=${arg#--emit=link=};; esac\ndone\n" +
					"test -n \"$out\"\n\"/bin/$WARMOR_TEST_COPY_TOOL\" \"$WARMOR_TEST_ARTIFACT\" \"$out\"\n",
			} {
				if err := os.WriteFile(filepath.Join(bin, tool), []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin)
			t.Setenv("TMPDIR", work)
			t.Setenv("WARMOR_TEST_ARTIFACT", fixture)
			copyTool := "cp"
			if tc.name == "hardlinked cargo output" {
				copyTool = "ln"
			}
			t.Setenv("WARMOR_TEST_COPY_TOOL", copyTool)
			path := filepath.Join(outDir, "policy.wasm")
			old := []byte("last known good")
			if err := os.WriteFile(path, old, 0o600); err != nil {
				t.Fatal(err)
			}
			var alias string
			if tc.name == "hardlinked destination" {
				alias = filepath.Join(t.TempDir(), "alias.wasm")
				if err := os.Link(path, alias); err != nil {
					t.Fatal(err)
				}
			}
			// Detached signatures are not published by Build (nor pair-atomic).
			if err := os.WriteFile(path+".sig", []byte("old signature"), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := Build(policy, BuildOptions{OutputPath: path})
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) || result != nil {
					t.Fatalf("Build = %+v, %v; want %q", result, err, tc.want)
				}
				assertArtifactContents(t, path, old)
			} else {
				if err != nil || result == nil || result.WasmPath != path {
					t.Fatalf("Build = %+v, %v", result, err)
				}
				want, err := policybuild.Append(raw, policybuild.Metadata{Compiler: Identity, DefaultAction: policy.DefaultAction})
				if err != nil {
					t.Fatal(err)
				}
				assertArtifactContents(t, path, want)
				// Cargo's output remains private and unmodified by publication.
				assertArtifactContents(t, filepath.Join(result.CratePath, wasmFile), raw)
				if info, err := os.Stat(result.CratePath); err != nil || info.Mode().Perm() != 0o700 {
					t.Fatalf("crate must remain private: %v, %v", info, err)
				}
			}
			Cleanup(result)
			if tc.name != "oversized" {
				assertArtifactContents(t, fixture, tc.data)
			}
			if alias != "" {
				assertArtifactContents(t, alias, old)
				first, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				second, err := os.Stat(alias)
				if err != nil || !os.SameFile(first, second) {
					t.Fatalf("Build detached destination alias: %v", err)
				}
			}
			assertArtifactContents(t, path+".sig", []byte("old signature"))
			assertOnlyOutput(t, outDir, "policy.wasm", "policy.wasm.sig")
			assertOnlyOutput(t, work)
		})
	}
}

func assertArtifactContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s contents = %q, %v; want %q", path, got, err, want)
	}
}

func assertOnlyOutput(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(names) {
		t.Fatalf("unexpected staged files or sources in %s: %v", dir, entries)
	}
	for i := range entries {
		if entries[i].Name() != names[i] {
			t.Fatalf("unexpected entry %s, want %s", entries[i].Name(), names[i])
		}
	}
}
