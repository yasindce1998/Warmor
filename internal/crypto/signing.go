package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// SigningKey holds an ed25519 key pair for signing policy bundles.
type SigningKey struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateSigningKey creates a new ed25519 key pair for policy signing.
func GenerateSigningKey() (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &SigningKey{Public: pub, Private: priv}, nil
}

// Sign produces an ed25519 signature over the given data.
func (sk *SigningKey) Sign(data []byte) []byte {
	return ed25519.Sign(sk.Private, data)
}

// Verify checks that sig is a valid signature of data by this key.
func (sk *SigningKey) Verify(data, sig []byte) bool {
	return ed25519.Verify(sk.Public, data, sig)
}

// VerifyWithPublicKey checks a signature using a standalone public key.
func VerifyWithPublicKey(pub ed25519.PublicKey, data, sig []byte) bool {
	return ed25519.Verify(pub, data, sig)
}

// MarshalPrivateKey encodes the private key as PKCS8 PEM.
func (sk *SigningKey) MarshalPrivateKey() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(sk.Private)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalPublicKey encodes the public key as PKIX PEM.
func (sk *SigningKey) MarshalPublicKey() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(sk.Public)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// LoadSigningKey loads a signing key pair from PEM files.
func LoadSigningKey(privPath string) (*SigningKey, error) {
	data, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	return LoadSigningKeyFromPEM(data)
}

// LoadSigningKeyFromPEM parses a private key PEM into a SigningKey.
func LoadSigningKeyFromPEM(data []byte) (*SigningKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	keyIface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := keyIface.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ed25519")
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &SigningKey{
		Public:  pub,
		Private: priv,
	}, nil
}

// LoadPublicKey loads an ed25519 public key from a PEM file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	return LoadPublicKeyFromPEM(data)
}

// LoadPublicKeyFromPEM parses a public key PEM into an ed25519 public key.
func LoadPublicKeyFromPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	keyIface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := keyIface.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not ed25519")
	}
	return pub, nil
}

// SignedPolicy represents a WASM policy with its cryptographic signature.
type SignedPolicy struct {
	WASMData  []byte `json:"wasm_data"`
	Signature []byte `json:"signature"`
	PolicyID  string `json:"policy_id"`
	Version   int64  `json:"version"`
}

// SignPolicy signs a WASM binary and returns a SignedPolicy bundle.
func SignPolicy(sk *SigningKey, policyID string, version int64, wasmData []byte) *SignedPolicy {
	sig := sk.Sign(wasmData)
	return &SignedPolicy{
		WASMData:  wasmData,
		Signature: sig,
		PolicyID:  policyID,
		Version:   version,
	}
}

// VerifyPolicy checks that a signed policy's signature is valid.
func VerifyPolicy(pub ed25519.PublicKey, sp *SignedPolicy) bool {
	return VerifyWithPublicKey(pub, sp.WASMData, sp.Signature)
}

// Detached policy signatures.
//
// A detached signature is the SignedPolicy signature (ed25519 over the exact
// WASM bytes, see SignPolicy) stored next to the module as <policy>.sig. The
// file holds the 64-byte signature base64 (std) encoded on one line, the
// same encoding the OCI bundle signature annotation uses. A raw 64-byte
// binary signature (e.g. from `openssl pkeyutl -sign -rawin`) is accepted
// too.

// PolicySignatureExt is the suffix appended to a policy path to locate its
// detached signature.
const PolicySignatureExt = ".sig"

// MaxPolicySignatureFileSize bounds how much of a signature file is read.
const MaxPolicySignatureFileSize = 4096

// ErrPolicyUnsigned is returned when a policy has no detached signature.
var ErrPolicyUnsigned = errors.New("policy is not signed")

// ErrPolicySignatureInvalid is returned when a signature does not verify.
var ErrPolicySignatureInvalid = errors.New("policy signature verification failed")

// PolicySignaturePath returns the detached signature path for policyPath.
func PolicySignaturePath(policyPath string) string {
	return policyPath + PolicySignatureExt
}

// EncodePolicySignature encodes sig in the detached signature file format.
func EncodePolicySignature(sig []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
}

// SignPolicyFile returns the detached signature file contents for wasmData.
func (sk *SigningKey) SignPolicyFile(wasmData []byte) []byte {
	return EncodePolicySignature(SignPolicy(sk, "", 0, wasmData).Signature)
}

// DecodePolicySignature parses a detached signature file (base64 text or a
// raw 64-byte signature).
func DecodePolicySignature(data []byte) ([]byte, error) {
	if len(data) == ed25519.SignatureSize {
		return append([]byte(nil), data...), nil
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode policy signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("decode policy signature: got %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

// VerifyPolicySignature checks a detached signature (in the signature file
// format) over wasmData. It fails closed on an empty, malformed or invalid
// signature.
func VerifyPolicySignature(pub ed25519.PublicKey, wasmData, sigFile []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 public key")
	}
	if len(sigFile) == 0 {
		return ErrPolicyUnsigned
	}
	sig, err := DecodePolicySignature(sigFile)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPolicySignatureInvalid, err)
	}
	if !VerifyPolicy(pub, &SignedPolicy{WASMData: wasmData, Signature: sig}) {
		return ErrPolicySignatureInvalid
	}
	return nil
}

// ReadVerifiedPolicy reads the policy at path (at most maxSize bytes) and its
// detached signature at PolicySignaturePath(path), and returns the policy
// bytes only if the signature verifies against pub. The file is read once;
// callers must load the returned bytes rather than re-reading path, so what
// runs is exactly what was verified.
func ReadVerifiedPolicy(pub ed25519.PublicKey, path string, maxSize int64) ([]byte, error) {
	data, err := ReadFileLimited(path, maxSize)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	sigPath := PolicySignaturePath(path)
	sigFile, err := ReadFileLimited(sigPath, MaxPolicySignatureFileSize)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w (no %s)", path, ErrPolicyUnsigned, sigPath)
		}
		return nil, fmt.Errorf("read policy signature: %w", err)
	}
	if err := VerifyPolicySignature(pub, data, sigFile); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return data, nil
}

// ReadFileLimited reads a regular file, failing if it exceeds maxSize bytes.
func ReadFileLimited(path string, maxSize int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxSize)
	}
	return data, nil
}
