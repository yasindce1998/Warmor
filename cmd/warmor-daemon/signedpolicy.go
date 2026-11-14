package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/agentstore"
	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/policyserver"
	"github.com/yasindce1998/warmor/internal/wasm"
)

// Files are administrator-managed public configuration, reread at the commit
// boundary. No private key, remote trust discovery or time-health inference.
type assignmentKeyConfig struct {
	ID          string `json:"id"`
	PublicKey   string `json:"public_key"` // PKIX PEM contents
	CanRollback bool   `json:"can_rollback"`
}
type assignmentConfig struct {
	Scope              string                `json:"scope"`
	Audience           string                `json:"audience"`
	Keys               []assignmentKeyConfig `json:"keys"`
	Compilers          []string              `json:"compilers"`
	MaxLifetimeSeconds int64                 `json:"max_lifetime_seconds"`
	RequireEnforce     bool                  `json:"require_enforce"`
	RequireDefaultDeny bool                  `json:"require_default_deny"`
}
type clockHealth struct {
	// A local time-health supervisor atomically publishes a short-lived
	// attestation; it must stop refreshing whenever clock health is unknown.
	CheckedAt  int64 `json:"checked_at"`
	ValidUntil int64 `json:"valid_until"`
}

type signedPolicyManager struct {
	mu                          sync.Mutex
	root, configPath, clockPath string
	target                      assignment.Target
	artifact                    ed25519.PublicKey
	store                       *agentstore.Store
	now                         func() time.Time
	syncDir                     func(string) error
	commit                      func(assignment.Verified, string, assignment.Clock) error
	fatal                       error
}

func strictJSON(path string, max int64, value any) error {
	b, err := crypto.ReadFileLimited(path, max)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err == nil {
		return errors.New("trailing configuration data")
	} else if err != io.EOF {
		return err
	}
	return nil
}

func (m *signedPolicyManager) verification() (assignment.Trust, assignment.VerifyOptions, error) {
	var c assignmentConfig
	if err := strictJSON(m.configPath, 64<<10, &c); err != nil {
		return nil, assignment.VerifyOptions{}, err
	}
	target := assignment.Target{Scope: c.Scope, Audience: c.Audience}
	if target != m.target {
		return nil, assignment.VerifyOptions{}, errors.New("assignment target changed; explicit re-enrollment required")
	}
	if c.MaxLifetimeSeconds <= 0 || c.MaxLifetimeSeconds > 86400 || len(c.Compilers) == 0 || len(c.Compilers) > 64 || len(c.Keys) == 0 || len(c.Keys) > 64 {
		return nil, assignment.VerifyOptions{}, errors.New("invalid assignment trust limits")
	}
	trust := assignment.Trust{}
	for _, k := range c.Keys {
		if _, exists := trust[k.ID]; exists || k.ID == "" {
			return nil, assignment.VerifyOptions{}, errors.New("duplicate/empty assignment key ID")
		}
		pub, err := crypto.LoadPublicKeyFromPEM([]byte(k.PublicKey))
		if err != nil {
			return nil, assignment.VerifyOptions{}, err
		}
		if bytes.Equal(pub, m.artifact) {
			return nil, assignment.VerifyOptions{}, errors.New("assignment and artifact keys must be distinct")
		}
		trust[k.ID] = assignment.Key{Public: pub, Target: target, CanRollback: k.CanRollback}
	}
	clock, err := m.clock()
	if err != nil {
		return nil, assignment.VerifyOptions{}, err
	}
	return trust, assignment.VerifyOptions{Target: target, Clock: clock, SupportedABIs: []uint32{1, 2, 3, 4, 5}, AllowedCompilers: c.Compilers,
		MaxLifetime: time.Duration(c.MaxLifetimeSeconds) * time.Second, RequireEnforce: c.RequireEnforce, RequireDefaultDeny: c.RequireDefaultDeny}, nil
}

func (m *signedPolicyManager) clock() (assignment.Clock, error) {
	var health clockHealth
	if err := strictJSON(m.clockPath, 4096, &health); err != nil {
		return assignment.Clock{}, fmt.Errorf("clock health: %w", err)
	}
	now := m.now().UTC()
	if health.CheckedAt <= 0 || health.ValidUntil <= health.CheckedAt || health.ValidUntil-health.CheckedAt > 60 || now.Unix() < health.CheckedAt || now.Unix() >= health.ValidUntil {
		return assignment.Clock{}, assignment.ErrClock
	}
	return assignment.Clock{Now: now, Trusted: true}, nil
}

func openSignedPolicy(configPath, clockPath, root string, artifact ed25519.PublicKey, enroll bool) (*signedPolicyManager, error) {
	if len(artifact) != ed25519.PublicKeySize || configPath == "" || clockPath == "" || root == "" {
		return nil, errors.New("signed mode requires --verify-key, --assignment-config, --assignment-clock-health and --assignment-state-dir")
	}
	if err := checkPolicyRevisionSupport(); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	var c assignmentConfig
	if err := strictJSON(configPath, 64<<10, &c); err != nil {
		return nil, err
	}
	m := &signedPolicyManager{root: root, configPath: configPath, clockPath: clockPath, target: assignment.Target{Scope: c.Scope, Audience: c.Audience}, artifact: bytes.Clone(artifact), now: time.Now, syncDir: syncPolicyDir}
	if _, _, err := m.verification(); err != nil {
		return nil, err
	}
	var st *agentstore.Store
	if enroll {
		// The administrator must provision the private root directory. Creation
		// of replay state is never an automatic response to a missing file.
		st, err = agentstore.Create(filepath.Join(root, "assignment.json"), m.target)
	} else {
		st, err = agentstore.Open(filepath.Join(root, "assignment.json"), m.target)
	}
	if err != nil {
		return nil, err
	}
	m.store = st
	m.commit = st.Commit
	return m, nil
}

func (m *signedPolicyManager) verify(b assignment.Bundle) (assignment.Verified, error) {
	if err := crypto.VerifyPolicySignature(m.artifact, b.WASM, b.ArtifactSignature); err != nil {
		return assignment.Verified{}, err
	}
	e, err := assignment.Decode(b.Envelope)
	if err != nil {
		return assignment.Verified{}, err
	}
	if e.Deployment.Policy.Version > math.MaxInt64 {
		return assignment.Verified{}, assignment.ErrInvalid
	}
	trust, opts, err := m.verification()
	if err != nil {
		return assignment.Verified{}, err
	}
	return assignment.Verify(e, b.WASM, trust, opts)
}

func (m *signedPolicyManager) restore() (string, assignment.Deployment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.store.Snapshot()
	if err != nil {
		return "", assignment.Deployment{}, err
	}
	if st.Active == nil {
		return "", assignment.Deployment{}, errors.New("signed state has no active deployment; enroll with a signed bootstrap bundle")
	}
	path := filepath.Join(m.root, st.Active.Revision, "module.wasm")
	data, err := crypto.ReadFileLimited(path, wasm.MaxPolicySize)
	if err != nil {
		return "", assignment.Deployment{}, err
	}
	sig, err := crypto.ReadFileLimited(path+".sig", crypto.MaxPolicySignatureFileSize)
	if err != nil {
		return "", assignment.Deployment{}, err
	}
	raw, err := crypto.DecodePolicySignature(sig)
	if err != nil {
		return "", assignment.Deployment{}, err
	}
	v, err := m.verify(assignment.Bundle{Envelope: st.Active.Envelope, WASM: data, ArtifactSignature: raw})
	if err != nil {
		return "", assignment.Deployment{}, err
	}
	clock, err := m.clock()
	if err != nil {
		return "", assignment.Deployment{}, err
	}
	if clock.Now.UnixNano() < st.LastClock {
		return "", assignment.Deployment{}, assignment.ErrClock
	}
	return path, v.Envelope().Deployment, nil
}

// update never calls the PR38 current/previous pointer publisher or its discard
// method. Successfully/uncertainly published revisions are always retained.
func (m *signedPolicyManager) update(a *policyserver.PolicyAssignment, data []byte, activate func(string, assignment.Policy, func() error) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fatal != nil {
		return m.fatal
	}
	b := assignment.Bundle{Envelope: bytes.Clone(a.Envelope), WASM: bytes.Clone(data), ArtifactSignature: bytes.Clone(a.Signature)}
	v, err := m.verify(b)
	if err != nil {
		return err
	}
	d := v.Envelope().Deployment
	if d.Policy.ID != a.PolicyID || int64(d.Policy.Version) != a.Version || d.Policy.SHA256 != a.WASMHash || d.Sequence != a.DeploymentSequence {
		return errors.New("assignment metadata differs from signed envelope")
	}
	r, err := (policyRevisionStager{dirSync: m.syncDir}).create(m.root, a, b.WASM, crypto.EncodePolicySignature(b.ArtifactSignature))
	if err != nil {
		return err
	}
	committed, uncertain := false, false
	defer func() {
		if !committed && !uncertain {
			_ = os.RemoveAll(r.dir)
		}
	}()
	err = activate(r.modulePath, d.Policy, func() error {
		// Fresh admin trust and fresh health are read after drain/preparation.
		err := agentstore.WithConfigurationLock(m.configPath+".lock", func() error {
			fresh, err := m.verify(b)
			if err != nil {
				return err
			}
			clock, err := m.clock()
			if err != nil {
				return err
			}
			if err := v.CheckTime(clock); err != nil {
				return err
			}
			return m.commit(fresh, filepath.Base(r.dir), clock)
		})
		if errors.Is(err, agentstore.ErrIndeterminate) {
			uncertain = true
			m.fatal = err
		}
		committed = err == nil
		return err
	})
	if committed && err != nil {
		m.fatal = fmt.Errorf("activation failed after durable assignment commit: %w", err)
	}
	if err == nil && !committed {
		return errors.New("activation returned without durable assignment publication")
	}
	return err
}

// bootstrap is explicit first enrollment, never a fallback from Open failure.
// The caller validates candidate ABI/build/kernel posture using enforcer.New
// before commit; no live event loop starts before durable state is selected.
func (m *signedPolicyManager) bootstrap(ctx context.Context, b assignment.Bundle, opts *enforcer.Options) (*enforcer.Enforcer, error) {
	e, err := assignment.Decode(b.Envelope)
	if err != nil {
		return nil, err
	}
	d := e.Deployment
	a := &policyserver.PolicyAssignment{PolicyID: d.Policy.ID, Version: int64(d.Policy.Version), WASMHash: d.Policy.SHA256, Envelope: b.Envelope, Signature: b.ArtifactSignature, DeploymentSequence: d.Sequence}
	var enf *enforcer.Enforcer
	err = m.update(a, b.WASM, func(path string, p assignment.Policy, commit func() error) error {
		copy := *opts
		copy.SignedAssignment = &p
		var err error
		enf, err = enforcer.New(ctx, path, &copy)
		if err != nil {
			return err
		}
		if err := commit(); err != nil {
			enf.Close()
			enf = nil
			return err
		}
		return nil
	})
	return enf, err
}
