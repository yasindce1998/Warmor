package policyhost

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	policycrypto "github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
)

// StagedPolicy is an immutable, verified snapshot, never a path or a compiled
// artifact. It can only be constructed by Stage or StageFile. Signature trust
// authorizes the bytes, not an assignment, version, rollback or workload scope.
type StagedPolicy struct {
	data   []byte
	digest string
}

func Stage(data, signature []byte, key ed25519.PublicKey) (*StagedPolicy, error) {
	if len(data) == 0 || len(data) > protocol.MaxModule || len(signature) > policycrypto.MaxPolicySignatureFileSize {
		return nil, errors.New("policy staging size limit")
	}
	snapshot := append([]byte(nil), data...)
	if err := policycrypto.VerifyPolicySignature(key, snapshot, signature); err != nil {
		return nil, err
	}
	h := sha256.Sum256(snapshot)
	return &StagedPolicy{data: snapshot, digest: hex.EncodeToString(h[:])}, nil
}

// StageFile accepts regular, non-symlink files only; it never compiles YAML,
// executes a toolchain, or loads WASM in the parent.
func StageFile(path string, key ed25519.PublicKey) (*StagedPolicy, error) {
	data, err := readRegular(path, protocol.MaxModule)
	if err != nil {
		return nil, err
	}
	sig, err := readRegular(path+policycrypto.PolicySignatureExt, policycrypto.MaxPolicySignatureFileSize)
	if err != nil {
		return nil, err
	}
	return Stage(data, sig, key)
}

func (s *StagedPolicy) Digest() string {
	if s == nil {
		return ""
	}
	return s.digest
}
