// Package assignment authenticates deployment intent, separately from offline
// signatures over policy artifacts. It does not install policies or load keys.
package assignment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Format = 1
	// Domain is deliberately distinct from raw WASM signatures and other tokens.
	Domain           = "warmor/policy-deployment/ed25519/v1\x00"
	MaxEnvelopeBytes = 16 << 10
)

var (
	ErrInvalid       = errors.New("invalid deployment envelope")
	ErrSignature     = errors.New("deployment signature verification failed")
	ErrAudience      = errors.New("deployment target not authorized")
	ErrClock         = errors.New("trusted deployment clock required")
	ErrExpired       = errors.New("deployment outside validity interval")
	ErrCompatibility = errors.New("deployment incompatible with local requirements")
	ErrRollback      = errors.New("deployment rollback not authorized")
)

// Target identifies one sequence stream. Both values are exact, case-sensitive
// provisioned identifiers, not label selectors, hostnames inferred from a
// response, wildcard patterns, or URLs fetched to discover trust.
type Target struct {
	Scope    string `json:"scope"`
	Audience string `json:"audience"`
}

type Posture struct {
	Mode               string `json:"mode"`           // enforce or audit
	DefaultAction      string `json:"default_action"` // allow or deny
	RequireDefaultDeny bool   `json:"require_default_deny"`
}

// Policy binds every declared property of the exact artifact. Compiler is an
// immutable toolchain identity (for example a release plus build digest), not a
// remotely resolved alias. These declarations are not artifact attestations:
// callers must also check actual ABI and effective runtime/kernel posture.
type Policy struct {
	ID       string  `json:"id"`
	Version  uint64  `json:"version"`
	SHA256   string  `json:"sha256"` // lowercase hex of exact WASM bytes
	ABI      uint32  `json:"abi"`
	Compiler string  `json:"compiler"`
	Posture  Posture `json:"posture"`
}

// Rollback authorizes exactly one transition from the current active deployment.
// It never lowers the sequence or policy-version high-water marks.
type Rollback struct {
	FromSequence uint64 `json:"from_sequence"`
	From         Policy `json:"from"`
	Reason       string `json:"reason"`
}

type Deployment struct {
	Format    uint32    `json:"format"`
	KeyID     string    `json:"key_id"`
	Target    Target    `json:"target"`
	Policy    Policy    `json:"policy"`
	Sequence  uint64    `json:"sequence"`
	IssuedAt  int64     `json:"issued_at"`  // inclusive UTC Unix seconds
	ExpiresAt int64     `json:"expires_at"` // exclusive UTC Unix seconds
	Rollback  *Rollback `json:"rollback"`   // null is distinct from an authorization
}

type Envelope struct {
	Deployment Deployment `json:"deployment"`
	Signature  []byte     `json:"signature"`
}

// Key is a locally provisioned assignment trust grant, never a key supplied by
// an envelope. Artifact signing keys are not implicitly assignment keys.
type Key struct {
	Public      ed25519.PublicKey
	Target      Target
	CanRollback bool
}

// Trust and VerifyOptions must not be mutated concurrently with Verify. A
// successful verification captures the then-current trust decision; serialize
// trust rotation/revocation with preparation/commit or re-verify at commit.
type Trust map[string]Key

// Clock must come from a caller that has established clock health. Merely
// calling time.Now is not proof that time is trusted. Zero/unknown fails closed.
type Clock struct {
	Now     time.Time
	Trusted bool
}

type VerifyOptions struct {
	Target             Target
	Clock              Clock
	SupportedABIs      []uint32
	AllowedCompilers   []string
	RequireEnforce     bool
	RequireDefaultDeny bool
	// MaxLifetime is mandatory and bounds the signer's validity interval.
	MaxLifetime time.Duration
}

// Verified is an immutable, unforgeable-in-Go verification result. Its zero
// value is invalid. Accessors return copies, including pointer/slice fields.
type Verified struct {
	envelope  Envelope
	checkedAt time.Time
}

func Digest(module []byte) string {
	sum := sha256.Sum256(module)
	return hex.EncodeToString(sum[:])
}

func validText(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (t Target) Validate() error {
	if !validText(t.Scope, 256) || !validText(t.Audience, 256) || strings.ContainsAny(t.Scope+t.Audience, "*?") {
		return fmt.Errorf("%w: exact scope and audience required", ErrInvalid)
	}
	return nil
}

func (p Policy) Validate() error {
	if !validText(p.ID, 256) || p.Version == 0 || p.ABI == 0 || !validText(p.Compiler, 256) {
		return fmt.Errorf("%w: policy identity/compatibility", ErrInvalid)
	}
	digest, err := hex.DecodeString(p.SHA256)
	if err != nil || len(digest) != sha256.Size || strings.ToLower(p.SHA256) != p.SHA256 {
		return fmt.Errorf("%w: lowercase SHA-256 required", ErrInvalid)
	}
	pst := p.Posture
	if (pst.Mode != "enforce" && pst.Mode != "audit") || (pst.DefaultAction != "allow" && pst.DefaultAction != "deny") ||
		(pst.RequireDefaultDeny && (pst.Mode != "enforce" || pst.DefaultAction != "deny")) {
		return fmt.Errorf("%w: posture", ErrInvalid)
	}
	return nil
}

func (d Deployment) Validate() error {
	if d.Format != Format || !validText(d.KeyID, 128) || d.Sequence == 0 || d.IssuedAt <= 0 || d.ExpiresAt <= d.IssuedAt {
		return fmt.Errorf("%w: format, signer, sequence or lifetime", ErrInvalid)
	}
	if err := d.Target.Validate(); err != nil {
		return err
	}
	if err := d.Policy.Validate(); err != nil {
		return err
	}
	if r := d.Rollback; r != nil {
		if r.FromSequence == 0 || r.FromSequence >= d.Sequence || !validText(r.Reason, 1024) {
			return fmt.Errorf("%w: rollback source/reason", ErrInvalid)
		}
		if err := r.From.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Canonical produces the v1 signature input: Domain, then the fields below in
// declaration order, with strings as u32-BE byte length + UTF-8, unsigned ints
// as fixed-width BE, timestamps as u64-BE, bools/presence as a single 0/1 byte.
// There are no maps, floats, omitted defaults, or Unicode normalization rules.
// JSON field order/whitespace are never part of the signature input.
func Canonical(d Deployment) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(Domain)
	u32 := func(v uint32) { _ = binary.Write(&b, binary.BigEndian, v) }
	u64 := func(v uint64) { _ = binary.Write(&b, binary.BigEndian, v) }
	text := func(v string) { u32(uint32(len(v))); b.WriteString(v) }
	boolean := func(v bool) {
		if v {
			b.WriteByte(1)
		} else {
			b.WriteByte(0)
		}
	}
	policy := func(p Policy) {
		text(p.ID)
		u64(p.Version)
		text(p.SHA256)
		u32(p.ABI)
		text(p.Compiler)
		text(p.Posture.Mode)
		text(p.Posture.DefaultAction)
		boolean(p.Posture.RequireDefaultDeny)
	}
	u32(d.Format)
	text(d.KeyID)
	text(d.Target.Scope)
	text(d.Target.Audience)
	policy(d.Policy)
	u64(d.Sequence)
	u64(uint64(d.IssuedAt))
	u64(uint64(d.ExpiresAt))
	boolean(d.Rollback != nil)
	if d.Rollback != nil {
		u64(d.Rollback.FromSequence)
		policy(d.Rollback.From)
		text(d.Rollback.Reason)
	}
	return b.Bytes(), nil
}

func clone(e Envelope) Envelope {
	e.Signature = slices.Clone(e.Signature)
	if e.Deployment.Rollback != nil {
		r := *e.Deployment.Rollback
		e.Deployment.Rollback = &r
	}
	return e
}

func Sign(private ed25519.PrivateKey, d Deployment) (Envelope, error) {
	if len(private) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("%w: Ed25519 private key", ErrInvalid)
	}
	data, err := Canonical(d)
	if err != nil {
		return Envelope{}, err
	}
	return clone(Envelope{Deployment: d, Signature: ed25519.Sign(private, data)}), nil
}

// Encode/Decode define a strict canonical JSON transport. Decode rejects
// duplicate/unknown fields, alternate encodings, missing fields and trailing
// data by requiring byte-for-byte re-encoding (no optional newline). Use Encode,
// not a general JSON writer, for network and disk envelopes.
func Encode(e Envelope) ([]byte, error) {
	if _, err := Canonical(e.Deployment); err != nil {
		return nil, err
	}
	if len(e.Signature) != ed25519.SignatureSize {
		return nil, ErrSignature
	}
	data, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: envelope too large", ErrInvalid)
	}
	return data, nil
}

func Decode(data []byte) (Envelope, error) {
	if len(data) > MaxEnvelopeBytes {
		return Envelope{}, fmt.Errorf("%w: envelope too large", ErrInvalid)
	}
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	canonical, err := Encode(e)
	if err != nil {
		return Envelope{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Envelope{}, fmt.Errorf("%w: noncanonical wire envelope", ErrInvalid)
	}
	return e, nil
}

func checkTime(d Deployment, c Clock) error {
	if !c.Trusted || c.Now.IsZero() || c.Now.Unix() <= 0 {
		return ErrClock
	}
	if c.Now.Unix() < d.IssuedAt || c.Now.Unix() >= d.ExpiresAt {
		return ErrExpired
	}
	return nil
}

func Verify(e Envelope, module []byte, trust Trust, opts VerifyOptions) (Verified, error) {
	data, err := Canonical(e.Deployment)
	if err != nil {
		return Verified{}, err
	}
	d := e.Deployment
	k, ok := trust[d.KeyID]
	if !ok || len(k.Public) != ed25519.PublicKeySize || len(e.Signature) != ed25519.SignatureSize || !ed25519.Verify(k.Public, data, e.Signature) {
		return Verified{}, ErrSignature
	}
	if err := opts.Target.Validate(); err != nil {
		return Verified{}, err
	}
	if d.Target != opts.Target || d.Target != k.Target {
		return Verified{}, ErrAudience
	}
	if d.Rollback != nil && !k.CanRollback {
		return Verified{}, ErrRollback
	}
	if err := checkTime(d, opts.Clock); err != nil {
		return Verified{}, err
	}
	if opts.MaxLifetime <= 0 || d.ExpiresAt-d.IssuedAt > int64(opts.MaxLifetime/time.Second) {
		return Verified{}, fmt.Errorf("%w: excessive validity interval", ErrExpired)
	}
	if !slices.Contains(opts.SupportedABIs, d.Policy.ABI) || !slices.Contains(opts.AllowedCompilers, d.Policy.Compiler) ||
		(opts.RequireEnforce && d.Policy.Posture.Mode != "enforce") || (opts.RequireDefaultDeny && !d.Policy.Posture.RequireDefaultDeny) {
		return Verified{}, ErrCompatibility
	}
	if Digest(module) != d.Policy.SHA256 {
		return Verified{}, fmt.Errorf("%w: artifact digest", ErrSignature)
	}
	return Verified{envelope: clone(e), checkedAt: opts.Clock.Now.UTC()}, nil
}

func (v Verified) Envelope() Envelope   { return clone(v.envelope) }
func (v Verified) CheckedAt() time.Time { return v.checkedAt }

// CheckTime must be called again at the durable commit boundary after slow
// compilation/preparation. A clock earlier than verification also fails closed.
func (v Verified) CheckTime(c Clock) error {
	if v.checkedAt.IsZero() {
		return ErrInvalid
	}
	if err := checkTime(v.envelope.Deployment, c); err != nil {
		return err
	}
	if c.Now.Before(v.checkedAt) {
		return ErrClock
	}
	return nil
}

// WeakerThan detects posture relaxation even when policy ID/version changes.
// There is no meaningful ordering on compiler identities or ABI numbers.
func (p Posture) WeakerThan(old Posture) bool {
	return (old.Mode == "enforce" && p.Mode != "enforce") ||
		(old.DefaultAction == "deny" && p.DefaultAction != "deny") ||
		(old.RequireDefaultDeny && !p.RequireDefaultDeny)
}
