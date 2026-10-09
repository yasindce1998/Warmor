package policybundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/yasindce1998/warmor/internal/crypto"
)

const (
	WasmMediaType   = "application/vnd.warmor.policy.wasm.v1"
	ConfigMediaType = "application/vnd.warmor.policy.config.v1+json"

	// AnnotationSignature holds the base64 (std encoding) ed25519 signature
	// over the bundle's signing payload (see signingPayload).
	AnnotationSignature = "org.warmor.policy.signature"
	// AnnotationSignatureKeyID holds the hex SHA-256 of the signer's PKIX
	// public key. It is informational only (used for error messages) and is
	// never trusted for verification.
	AnnotationSignatureKeyID = "org.warmor.policy.signature.keyid"

	// signaturePayloadSchema domain-separates bundle signatures from any
	// other use of the same ed25519 key.
	signaturePayloadSchema = "warmor.policy.bundle.signature.v1"
)

// Default size limits applied by Pull when the corresponding PullOptions
// field is zero.
const (
	DefaultMaxManifestSize int64 = 1 << 20  // 1 MiB
	DefaultMaxConfigSize   int64 = 1 << 20  // 1 MiB
	DefaultMaxWasmSize     int64 = 64 << 20 // 64 MiB
)

type BundleConfig struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

// PushOptions controls bundle signing on Push.
type PushOptions struct {
	// SigningKey signs the bundle. Required unless AllowUnsigned is set.
	SigningKey *crypto.SigningKey
	// AllowUnsigned permits pushing a bundle without a signature. Such a
	// bundle can only be pulled with PullOptions.InsecureSkipVerify.
	AllowUnsigned bool
}

// PullOptions controls verification and resource limits on Pull.
type PullOptions struct {
	// PublicKey verifies the bundle signature. Required unless
	// InsecureSkipVerify is set; if both are set the signature is still
	// verified.
	PublicKey ed25519.PublicKey
	// InsecureSkipVerify accepts bundles without verifying any signature.
	InsecureSkipVerify bool

	// Size limits in bytes; zero selects the Default* value.
	MaxManifestSize int64
	MaxConfigSize   int64
	MaxWasmSize     int64
}

func Push(ctx context.Context, ref string, wasmPath string, cfg BundleConfig, opts PushOptions) (ocispec.Descriptor, error) {
	if opts.SigningKey == nil && !opts.AllowUnsigned {
		return ocispec.Descriptor{}, errors.New("no signing key provided (refusing to push an unsigned bundle)")
	}

	wasmData, err := os.ReadFile(wasmPath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("read wasm: %w", err)
	}

	store := memory.New()

	wasmDesc, err := pushBlob(ctx, store, WasmMediaType, wasmData)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push wasm blob: %w", err)
	}
	wasmDesc.Annotations = map[string]string{
		ocispec.AnnotationTitle: "policy.wasm",
	}

	configData, err := json.Marshal(cfg)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("marshal config: %w", err)
	}
	configDesc, err := pushBlob(ctx, store, ConfigMediaType, configData)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push config blob: %w", err)
	}

	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{wasmDesc},
		Annotations: map[string]string{
			ocispec.AnnotationTitle:  cfg.Name,
			"org.warmor.policy.name": cfg.Name,
		},
	}
	if opts.SigningKey != nil {
		if err := SignManifest(&manifest, opts.SigningKey); err != nil {
			return ocispec.Descriptor{}, err
		}
	}

	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("marshal manifest: %w", err)
	}
	manifestDesc, err := pushBlob(ctx, store, ocispec.MediaTypeImageManifest, manifestData)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push manifest: %w", err)
	}

	if err := store.Tag(ctx, manifestDesc, ref); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("tag: %w", err)
	}

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("parse reference %q: %w", ref, err)
	}

	desc, err := oras.Copy(ctx, store, ref, repo, ref, oras.DefaultCopyOptions)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push to %s: %w", ref, err)
	}

	return desc, nil
}

// Pull fetches the bundle at ref, verifies it and writes the wasm layer to
// outputPath. ref may be pinned by digest (repo@sha256:...), in which case
// the manifest must match that digest. Every size limit and media type is
// checked before the corresponding blob is downloaded, and nothing is
// written to outputPath unless every check passes. It returns the manifest
// descriptor (whose digest can be used to pin future pulls).
func Pull(ctx context.Context, ref string, outputPath string, opts PullOptions) (ocispec.Descriptor, error) {
	if opts.PublicKey == nil && !opts.InsecureSkipVerify {
		return ocispec.Descriptor{}, errors.New("no verification public key provided (use an explicit insecure opt-out to pull unsigned bundles)")
	}
	maxManifest := limitOrDefault(opts.MaxManifestSize, DefaultMaxManifestSize)
	maxConfig := limitOrDefault(opts.MaxConfigSize, DefaultMaxConfigSize)
	maxWasm := limitOrDefault(opts.MaxWasmSize, DefaultMaxWasmSize)

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	repo.MaxMetadataBytes = maxManifest
	var pinned digest.Digest
	if d, err := repo.Reference.Digest(); err == nil {
		pinned = d
	}

	desc, manifestData, err := oras.FetchBytes(ctx, repo, ref, oras.FetchBytesOptions{MaxBytes: maxManifest})
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pull from %s: %w", ref, err)
	}
	if desc.MediaType != ocispec.MediaTypeImageManifest {
		return ocispec.Descriptor{}, fmt.Errorf("unexpected manifest media type %q (want %q)", desc.MediaType, ocispec.MediaTypeImageManifest)
	}
	if pinned != "" && desc.Digest != pinned {
		return ocispec.Descriptor{}, fmt.Errorf("manifest digest %s does not match pinned digest %s", desc.Digest, pinned)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("decode manifest: %w", err)
	}
	if manifest.MediaType != "" && manifest.MediaType != ocispec.MediaTypeImageManifest {
		return ocispec.Descriptor{}, fmt.Errorf("unexpected manifest mediaType field %q", manifest.MediaType)
	}
	if manifest.ArtifactType != "" && manifest.ArtifactType != ConfigMediaType {
		return ocispec.Descriptor{}, fmt.Errorf("unexpected artifact type %q (want %q or empty)", manifest.ArtifactType, ConfigMediaType)
	}
	if manifest.Config.MediaType != ConfigMediaType {
		return ocispec.Descriptor{}, fmt.Errorf("unexpected config media type %q (want %q)", manifest.Config.MediaType, ConfigMediaType)
	}
	if manifest.Config.Size < 0 || manifest.Config.Size > maxConfig {
		return ocispec.Descriptor{}, fmt.Errorf("config size %d exceeds limit %d", manifest.Config.Size, maxConfig)
	}

	var wasmDesc *ocispec.Descriptor
	for i := range manifest.Layers {
		if manifest.Layers[i].MediaType != WasmMediaType {
			continue
		}
		if wasmDesc != nil {
			return ocispec.Descriptor{}, errors.New("manifest contains more than one wasm layer")
		}
		wasmDesc = &manifest.Layers[i]
	}
	if wasmDesc == nil {
		return ocispec.Descriptor{}, fmt.Errorf("no wasm layer found in manifest")
	}
	if wasmDesc.Size < 0 || wasmDesc.Size > maxWasm {
		return ocispec.Descriptor{}, fmt.Errorf("wasm layer size %d exceeds limit %d", wasmDesc.Size, maxWasm)
	}

	// Verify the signature before downloading any blob: it binds the
	// config and layer digests, which content.FetchAll then enforces.
	if opts.PublicKey != nil {
		if err := VerifyManifest(&manifest, opts.PublicKey); err != nil {
			return ocispec.Descriptor{}, err
		}
	}

	configData, err := content.FetchAll(ctx, repo.Blobs(), manifest.Config)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("fetch config: %w", err)
	}
	var cfg BundleConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("decode config: %w", err)
	}

	data, err := content.FetchAll(ctx, repo.Blobs(), *wasmDesc)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("fetch wasm layer: %w", err)
	}
	if err := writeFileAtomic(outputPath, data, 0644); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("write wasm: %w", err)
	}
	return desc, nil
}

// SignManifest signs the config and layer descriptors of m and stores the
// signature in m's annotations. The signature lives in the manifest
// because the manifest is what the registry serves for a tag; it cannot
// cover the manifest digest itself, so it covers the content-addressed
// descriptors the manifest references instead (other annotations are
// unsigned and informational).
func SignManifest(m *ocispec.Manifest, sk *crypto.SigningKey) error {
	payload, err := signingPayload(m)
	if err != nil {
		return err
	}
	if m.Annotations == nil {
		m.Annotations = map[string]string{}
	}
	m.Annotations[AnnotationSignature] = base64.StdEncoding.EncodeToString(sk.Sign(payload))
	if id, err := KeyID(sk.Public); err == nil {
		m.Annotations[AnnotationSignatureKeyID] = id
	}
	return nil
}

// VerifyManifest checks the signature annotation on m against pub. It fails
// closed if the signature is missing or malformed.
func VerifyManifest(m *ocispec.Manifest, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 public key")
	}
	enc, ok := m.Annotations[AnnotationSignature]
	if !ok || enc == "" {
		return errors.New("bundle is not signed")
	}
	sig, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	payload, err := signingPayload(m)
	if err != nil {
		return err
	}
	if !crypto.VerifyWithPublicKey(pub, payload, sig) {
		want, _ := KeyID(pub)
		if got := m.Annotations[AnnotationSignatureKeyID]; got != "" && got != want {
			return fmt.Errorf("signature verification failed (bundle claims key %s, verifying with %s)", got, want)
		}
		return errors.New("signature verification failed")
	}
	return nil
}

// KeyID returns the hex SHA-256 of pub's PKIX DER encoding.
func KeyID(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

type payloadDescriptor struct {
	MediaType string        `json:"mediaType"`
	Digest    digest.Digest `json:"digest"`
	Size      int64         `json:"size"`
}

type signaturePayload struct {
	Schema string              `json:"schema"`
	Config payloadDescriptor   `json:"config"`
	Layers []payloadDescriptor `json:"layers"`
}

// signingPayload is the canonical byte string a bundle signature covers:
// the media type, digest and size of the config and of every layer, in
// manifest order. Struct-based JSON encoding is deterministic.
func signingPayload(m *ocispec.Manifest) ([]byte, error) {
	p := signaturePayload{
		Schema: signaturePayloadSchema,
		Config: payloadDescriptor{MediaType: m.Config.MediaType, Digest: m.Config.Digest, Size: m.Config.Size},
		Layers: make([]payloadDescriptor, 0, len(m.Layers)),
	}
	for _, l := range m.Layers {
		p.Layers = append(p.Layers, payloadDescriptor{MediaType: l.MediaType, Digest: l.Digest, Size: l.Size})
	}
	out, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal signing payload: %w", err)
	}
	return out, nil
}

func limitOrDefault(v, def int64) int64 {
	if v <= 0 {
		return def
	}
	return v
}

// writeFileAtomic writes data to a temp file next to path and renames it
// into place so a failed write never leaves a partial policy behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func pushBlob(ctx context.Context, store *memory.Store, mediaType string, data []byte) (ocispec.Descriptor, error) {
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}
	if err := store.Push(ctx, desc, bytes.NewReader(data)); err != nil {
		return ocispec.Descriptor{}, err
	}
	return desc, nil
}
