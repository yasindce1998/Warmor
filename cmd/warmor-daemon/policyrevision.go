package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/policyserver"
	"github.com/yasindce1998/warmor/internal/wasm"
)

// A revision is never modified after staging. Public module/signature aliases
// traverse one current pointer. Signature readers must resolve the module once
// and read its immutable sibling, not independently open both public aliases.
type stagedPolicyRevision struct {
	root, dir, modulePath string
	syncDir               func(string) error
}

// Keep filesystem fault injection local to one publication attempt/client.
type policyRevisionStager struct {
	verifyKey ed25519.PublicKey
	dirSync   func(string) error
}

func (s policyRevisionStager) syncDir(path string) error {
	if s.dirSync != nil {
		return s.dirSync(path)
	}
	return syncPolicyDir(path)
}

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

func (s policyRevisionStager) create(root string, a *policyserver.PolicyAssignment, data, sigFile []byte) (_ *stagedPolicyRevision, err error) {
	dir, err := os.MkdirTemp(root, "revision-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	r := &stagedPolicyRevision{root: root, dir: dir, modulePath: filepath.Join(dir, "module.wasm"), syncDir: s.syncDir}
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
	if err := s.syncDir(dir); err != nil {
		return nil, err
	}
	if err := s.syncDir(root); err != nil {
		return nil, err
	}
	return r, nil
}

func stagePolicyRevision(path string, a *policyserver.PolicyAssignment, data []byte) (*stagedPolicyRevision, error) {
	return (policyRevisionStager{}).stage(path, a, data)
}

func (s policyRevisionStager) stage(path string, a *policyserver.PolicyAssignment, data []byte) (*stagedPolicyRevision, error) {
	if wasm.IsYAMLPolicy(path) {
		return nil, errors.New("server-managed policy path must not use .yaml/.yml: downloaded WASM must remain loadable on restart")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root := path + ".revisions"
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	moduleAlias := filepath.Join(root, "current", "module.wasm")
	moduleTarget, _ := os.Readlink(path)
	signatureTarget, _ := os.Readlink(path + ".sig")
	if moduleTarget != moduleAlias || signatureTarget != moduleAlias+".sig" {
		// Migrate a legacy pair without changing bytes. Either alias may be
		// replaced first without a mismatched pair. Preserve a current pointer
		// left by an interrupted migration, rather than overwrite recovery.
		if _, err := os.Lstat(filepath.Join(root, "current")); errors.Is(err, os.ErrNotExist) {
			// Match ReadVerifiedPolicy: resolve the module once, then read its
			// sibling signature, never an unrelated signature beside an alias.
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			if err == nil {
				old, err := crypto.ReadFileLimited(resolved, wasm.MaxPolicySize)
				if err != nil {
					return nil, err
				}
				sig, err := crypto.ReadFileLimited(resolved+".sig", crypto.MaxPolicySignatureFileSize)
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return nil, err
				}
				legacy, err := s.create(root, &policyserver.PolicyAssignment{}, old, sig)
				if err != nil {
					return nil, err
				}
				if s.verifyKey != nil {
					if _, err := enforcer.ReadVerifiedPolicy(legacy.modulePath, s.verifyKey); err != nil {
						legacy.discard()
						return nil, fmt.Errorf("verify migrated policy pair: %w", err)
					}
				}
				if err := legacy.commit(); err != nil {
					return nil, err
				}
			}
		} else if err != nil {
			return nil, err
		} else if s.verifyKey != nil {
			// A previous attempt may have committed the legacy revision but
			// stopped before replacing the public aliases. Validate it first.
			if _, err := enforcer.ReadVerifiedPolicy(moduleAlias, s.verifyKey); err != nil {
				return nil, fmt.Errorf("verify migration recovery pair: %w", err)
			}
		}
		if err := replacePolicyLink(path+".sig", moduleAlias+".sig"); err != nil {
			return nil, err
		}
		if err := replacePolicyLink(path, moduleAlias); err != nil {
			return nil, err
		}
	}
	// Seeing the expected aliases does not prove their earlier rename was
	// durable. Retry this barrier on every attempt, including after a crash.
	if err := s.syncDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("sync policy alias directory: %w", err)
	}
	var sig []byte
	if len(a.Signature) > 0 {
		sig = crypto.EncodePolicySignature(a.Signature)
	}
	return s.create(root, a, data, sig)
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
		if err := r.syncDir(r.root); err != nil {
			return err
		}
	}
	if err := replacePolicyLink(current, filepath.Base(r.dir)); err != nil {
		return err
	}
	if err := r.syncDir(r.root); err != nil {
		// Never acknowledge a failed durability barrier. Attempt pointer
		// rollback and surface both errors if storage remains unavailable.
		var rollback error
		if old != "" {
			rollback = replacePolicyLink(current, old)
		} else {
			rollback = os.Remove(current)
		}
		return errors.Join(err, rollback, r.syncDir(r.root))
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
