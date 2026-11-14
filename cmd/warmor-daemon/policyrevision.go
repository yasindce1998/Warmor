package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/policyserver"
)

// A revision is never modified after staging. Public module/signature aliases
// traverse one current pointer. Signature readers must resolve the module once
// and read its immutable sibling, not independently open both public aliases.
type stagedPolicyRevision struct{ root, dir, modulePath string }

func syncPolicyDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func replacePolicyLink(path, target string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pointer-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Remove(name); err != nil {
		return err
	}
	if err := os.Symlink(target, name); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func createPolicyRevision(root string, a *policyserver.PolicyAssignment, data, sigFile []byte) (_ *stagedPolicyRevision, err error) {
	dir, err := os.MkdirTemp(root, "revision-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	r := &stagedPolicyRevision{root: root, dir: dir, modulePath: filepath.Join(dir, "module.wasm")}
	if err := writePolicyFile(r.modulePath, data); err != nil {
		return nil, fmt.Errorf("stage module: %w", err)
	}
	if len(sigFile) > 0 {
		if err := writePolicyFile(r.modulePath+".sig", sigFile); err != nil {
			return nil, fmt.Errorf("stage signature: %w", err)
		}
	}
	metadata, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	if err := writePolicyFile(filepath.Join(dir, "metadata.json"), metadata); err != nil {
		return nil, err
	}
	if err := syncPolicyDir(dir); err != nil {
		return nil, err
	}
	if err := syncPolicyDir(root); err != nil {
		return nil, err
	}
	return r, nil
}

func stagePolicyRevision(path string, a *policyserver.PolicyAssignment, data []byte) (*stagedPolicyRevision, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root := path + ".revisions"
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	moduleAlias := filepath.Join(root, "current", "module.wasm")
	if target, _ := os.Readlink(path); target != moduleAlias {
		// Migrate a legacy pair without changing bytes. Either alias may be
		// replaced first without a mismatched pair. Preserve a current pointer
		// left by an interrupted migration, rather than overwrite recovery.
		if _, err := os.Lstat(filepath.Join(root, "current")); errors.Is(err, os.ErrNotExist) {
			old, err := os.ReadFile(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			if err == nil {
				sig, err := os.ReadFile(path + ".sig")
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return nil, err
				}
				legacy, err := createPolicyRevision(root, &policyserver.PolicyAssignment{}, old, sig)
				if err != nil {
					return nil, err
				}
				if err := legacy.commit(); err != nil {
					return nil, err
				}
			}
		} else if err != nil {
			return nil, err
		}
		if err := replacePolicyLink(path+".sig", moduleAlias+".sig"); err != nil {
			return nil, err
		}
		if err := replacePolicyLink(path, moduleAlias); err != nil {
			return nil, err
		}
		if err := syncPolicyDir(filepath.Dir(path)); err != nil {
			return nil, err
		}
	}
	var sig []byte
	if len(a.Signature) > 0 {
		sig = crypto.EncodePolicySignature(a.Signature)
	}
	return createPolicyRevision(root, a, data, sig)
}

func (r *stagedPolicyRevision) commit() error {
	current := filepath.Join(r.root, "current")
	old, err := os.Readlink(current)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if old != "" {
		if err := replacePolicyLink(filepath.Join(r.root, "previous"), old); err != nil {
			return err
		}
		if err := syncPolicyDir(r.root); err != nil {
			return err
		}
	}
	if err := replacePolicyLink(current, filepath.Base(r.dir)); err != nil {
		return err
	}
	if err := syncPolicyDir(r.root); err != nil {
		// Never acknowledge a failed durability barrier. Attempt pointer
		// rollback and surface both errors if storage remains unavailable.
		var rollback error
		if old != "" {
			rollback = replacePolicyLink(current, old)
		} else {
			rollback = os.Remove(current)
		}
		return errors.Join(err, rollback, syncPolicyDir(r.root))
	}
	return nil
}

// Remove only our unpublished candidate, not any referenced recovery revision.
func (r *stagedPolicyRevision) discard() {
	for _, pointer := range []string{"current", "previous"} {
		target, err := os.Readlink(filepath.Join(r.root, pointer))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return
		}
		if target == filepath.Base(r.dir) {
			return
		}
	}
	_ = os.RemoveAll(r.dir)
}
