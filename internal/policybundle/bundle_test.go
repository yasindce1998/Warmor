package policybundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/memory"
)

// fakeRegistry is a minimal in-memory OCI distribution registry served over
// loopback TLS. It implements just enough of the distribution API for oras
// to push and pull a single-manifest artifact, plus hooks that let tests
// tamper with what the registry serves.
type fakeRegistry struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	blobs     map[string][]byte // digest -> content
	manifests map[string][]byte // digest -> content
	mtypes    map[string]string // digest -> media type
	tags      map[string]string // tag -> digest
	uploads   int

	// Hooks (all optional).
	rejectUploads bool                                       // 403 on blob upload
	serveBlob     func(dgst string, data []byte) []byte      // rewrite blob on GET
	serveManifest func(dgst string, data []byte) []byte      // rewrite manifest on GET
	blobLength    func(dgst string, data []byte) (int, bool) // override Content-Length
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	r := &fakeRegistry{
		t:         t,
		blobs:     map[string][]byte{},
		manifests: map[string][]byte{},
		mtypes:    map[string]string{},
		tags:      map[string]string{},
	}
	r.srv = httptest.NewUnstartedServer(http.HandlerFunc(r.handle))
	r.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	r.srv.StartTLS()
	t.Cleanup(r.srv.Close)

	// oras' default client round-trips through http.DefaultTransport at
	// request time; point it at a transport that trusts the test server.
	orig := http.DefaultTransport
	http.DefaultTransport = r.srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = orig })
	return r
}

// host returns host:port of the registry (no scheme).
func (r *fakeRegistry) host() string {
	return strings.TrimPrefix(r.srv.URL, "https://")
}

func (r *fakeRegistry) ref(repoTag string) string {
	return r.host() + "/" + repoTag
}

// putBlob seeds a blob directly into the registry.
func (r *fakeRegistry) putBlob(data []byte) ocispec.Descriptor {
	d := digest.FromBytes(data)
	r.mu.Lock()
	r.blobs[d.String()] = data
	r.mu.Unlock()
	return ocispec.Descriptor{Digest: d, Size: int64(len(data))}
}

// putManifest seeds a manifest and tags it.
func (r *fakeRegistry) putManifest(tag, mediaType string, data []byte) digest.Digest {
	d := digest.FromBytes(data)
	r.mu.Lock()
	r.manifests[d.String()] = data
	r.mtypes[d.String()] = mediaType
	r.tags[tag] = d.String()
	r.mu.Unlock()
	return d
}

func (r *fakeRegistry) handle(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	if path == "/v2/" || path == "/v2" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !strings.HasPrefix(path, "/v2/") {
		http.NotFound(w, req)
		return
	}
	rest := strings.TrimPrefix(path, "/v2/")

	switch {
	case strings.Contains(rest, "/blobs/uploads/"):
		r.handleUpload(w, req, rest)
	case strings.Contains(rest, "/blobs/"):
		r.handleBlob(w, req, rest[strings.LastIndex(rest, "/blobs/")+len("/blobs/"):])
	case strings.Contains(rest, "/manifests/"):
		r.handleManifest(w, req, rest[strings.LastIndex(rest, "/manifests/")+len("/manifests/"):])
	default:
		http.NotFound(w, req)
	}
}

func (r *fakeRegistry) handleUpload(w http.ResponseWriter, req *http.Request, rest string) {
	r.mu.Lock()
	reject := r.rejectUploads
	r.mu.Unlock()
	if reject {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"errors":[{"code":"DENIED","message":"uploads disabled"}]}`)
		return
	}
	repoName := rest[:strings.Index(rest, "/blobs/uploads/")]
	switch req.Method {
	case http.MethodPost:
		r.mu.Lock()
		r.uploads++
		id := r.uploads
		r.mu.Unlock()
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%d", repoName, id))
		w.WriteHeader(http.StatusAccepted)
	case http.MethodPut:
		data, err := io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		want := req.URL.Query().Get("digest")
		if digest.FromBytes(data).String() != want {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errors":[{"code":"DIGEST_INVALID"}]}`)
			return
		}
		r.mu.Lock()
		r.blobs[want] = data
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", want)
		w.WriteHeader(http.StatusCreated)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (r *fakeRegistry) handleBlob(w http.ResponseWriter, req *http.Request, dgst string) {
	r.mu.Lock()
	data, ok := r.blobs[dgst]
	serve := r.serveBlob
	length := r.blobLength
	r.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if serve != nil && req.Method == http.MethodGet {
		data = serve(dgst, data)
	}
	n := len(data)
	if length != nil {
		if l, override := length(dgst, data); override {
			n = l
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", dgst)
	w.Header().Set("Content-Length", strconv.Itoa(n))
	w.WriteHeader(http.StatusOK)
	if req.Method == http.MethodGet {
		if n < len(data) {
			data = data[:n]
		}
		_, _ = w.Write(data)
	}
}

func (r *fakeRegistry) handleManifest(w http.ResponseWriter, req *http.Request, ref string) {
	switch req.Method {
	case http.MethodPut:
		data, err := io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		d := digest.FromBytes(data).String()
		r.mu.Lock()
		r.manifests[d] = data
		r.mtypes[d] = req.Header.Get("Content-Type")
		if !strings.HasPrefix(ref, "sha256:") {
			r.tags[ref] = d
		}
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", d)
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet, http.MethodHead:
		r.mu.Lock()
		d := ref
		if !strings.HasPrefix(ref, "sha256:") {
			d = r.tags[ref]
		}
		data, ok := r.manifests[d]
		mt := r.mtypes[d]
		serve := r.serveManifest
		r.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`)
			return
		}
		if serve != nil && req.Method == http.MethodGet {
			data = serve(d, data)
		}
		w.Header().Set("Content-Type", mt)
		w.Header().Set("Docker-Content-Digest", d)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		if req.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// --- helpers ---

func writeWasm(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.wasm")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeWasm returns bytes with a wasm magic header and some distinct payload.
func fakeWasm(payload string) []byte {
	return append([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}, []byte(payload)...)
}

// seedBundle seeds a well-formed bundle under tag with the given wasm bytes
// and returns the wasm digest.
func seedBundle(t *testing.T, r *fakeRegistry, tag string, wasm []byte, extraLayers ...ocispec.Descriptor) digest.Digest {
	t.Helper()
	cfg, _ := json.Marshal(BundleConfig{Name: "seeded", Version: "1.0.0"})
	cfgDesc := r.putBlob(cfg)
	cfgDesc.MediaType = ConfigMediaType
	wasmDesc := r.putBlob(wasm)
	wasmDesc.MediaType = WasmMediaType

	layers := append([]ocispec.Descriptor{}, extraLayers...)
	layers = append(layers, wasmDesc)
	m := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    cfgDesc,
		Layers:    layers,
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	r.putManifest(tag, ocispec.MediaTypeImageManifest, data)
	return wasmDesc.Digest
}

func assertNoFile(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("expected %s not to exist after failed pull (stat err=%v)", p, err)
	}
}

// --- tests ---

func TestPushPullRoundTrip(t *testing.T) {
	r := newFakeRegistry(t)
	ctx := context.Background()
	wasm := fakeWasm("round-trip policy body")
	ref := r.ref("policies/roundtrip:v1")
	cfg := BundleConfig{Name: "roundtrip", Version: "1.2.3", Description: "test bundle"}

	desc, err := Push(ctx, ref, writeWasm(t, wasm), cfg)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if desc.MediaType != ocispec.MediaTypeImageManifest {
		t.Errorf("manifest media type = %q, want %q", desc.MediaType, ocispec.MediaTypeImageManifest)
	}
	if err := desc.Digest.Validate(); err != nil {
		t.Errorf("invalid manifest digest %q: %v", desc.Digest, err)
	}

	// Inspect what the registry actually stored.
	r.mu.Lock()
	manifestData := r.manifests[r.tags["v1"]]
	r.mu.Unlock()
	if manifestData == nil {
		t.Fatal("registry has no manifest tagged v1")
	}
	if digest.FromBytes(manifestData) != desc.Digest {
		t.Error("returned descriptor digest does not match stored manifest")
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(manifestData, &m); err != nil {
		t.Fatal(err)
	}
	if m.SchemaVersion != 2 {
		t.Errorf("schemaVersion = %d, want 2", m.SchemaVersion)
	}
	if m.Config.MediaType != ConfigMediaType {
		t.Errorf("config media type = %q", m.Config.MediaType)
	}
	if len(m.Layers) != 1 || m.Layers[0].MediaType != WasmMediaType {
		t.Fatalf("unexpected layers: %+v", m.Layers)
	}
	if m.Layers[0].Digest != digest.FromBytes(wasm) || m.Layers[0].Size != int64(len(wasm)) {
		t.Errorf("wasm layer descriptor mismatch: %+v", m.Layers[0])
	}
	if got := m.Layers[0].Annotations[ocispec.AnnotationTitle]; got != "policy.wasm" {
		t.Errorf("layer title = %q, want policy.wasm", got)
	}
	if got := m.Annotations["org.warmor.policy.name"]; got != cfg.Name {
		t.Errorf("policy name annotation = %q, want %q", got, cfg.Name)
	}
	if got := m.Annotations[ocispec.AnnotationTitle]; got != cfg.Name {
		t.Errorf("title annotation = %q, want %q", got, cfg.Name)
	}

	r.mu.Lock()
	cfgData := r.blobs[m.Config.Digest.String()]
	r.mu.Unlock()
	var gotCfg BundleConfig
	if err := json.Unmarshal(cfgData, &gotCfg); err != nil {
		t.Fatalf("config blob: %v", err)
	}
	if gotCfg != cfg {
		t.Errorf("config = %+v, want %+v", gotCfg, cfg)
	}

	out := filepath.Join(t.TempDir(), "pulled.wasm")
	if err := Pull(ctx, ref, out); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wasm) {
		t.Errorf("pulled wasm differs from pushed wasm")
	}
}

func TestPushIdempotent(t *testing.T) {
	r := newFakeRegistry(t)
	ctx := context.Background()
	p := writeWasm(t, fakeWasm("same"))
	ref := r.ref("policies/idem:v1")
	cfg := BundleConfig{Name: "idem", Version: "1"}

	d1, err := Push(ctx, ref, p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Push(ctx, ref, p, cfg)
	if err != nil {
		t.Fatalf("second Push: %v", err)
	}
	if d1.Digest != d2.Digest {
		t.Errorf("same inputs produced different manifest digests: %s vs %s", d1.Digest, d2.Digest)
	}
}

func TestPushRetagOverwrites(t *testing.T) {
	r := newFakeRegistry(t)
	ctx := context.Background()
	ref := r.ref("policies/retag:latest")
	cfg := BundleConfig{Name: "retag", Version: "1"}

	if _, err := Push(ctx, ref, writeWasm(t, fakeWasm("first")), cfg); err != nil {
		t.Fatal(err)
	}
	second := fakeWasm("second")
	if _, err := Push(ctx, ref, writeWasm(t, second), cfg); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.wasm")
	if err := Pull(ctx, ref, out); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, second) {
		t.Errorf("pulled %q, want latest push %q", got, second)
	}
}

func TestPushMissingWasm(t *testing.T) {
	_, err := Push(context.Background(), "localhost:5000/x:y",
		filepath.Join(t.TempDir(), "does-not-exist.wasm"), BundleConfig{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "read wasm") {
		t.Fatalf("expected read wasm error, got %v", err)
	}
}

func TestPushInvalidReference(t *testing.T) {
	p := writeWasm(t, fakeWasm("x"))
	for _, ref := range []string{"", "not a reference", "UPPER/Case:tag", "host:5000/repo:bad tag!"} {
		t.Run(ref, func(t *testing.T) {
			_, err := Push(context.Background(), ref, p, BundleConfig{Name: "x"})
			if err == nil {
				t.Fatalf("expected error for ref %q", ref)
			}
		})
	}
}

func TestPushRegistryRejectsUpload(t *testing.T) {
	r := newFakeRegistry(t)
	r.rejectUploads = true
	_, err := Push(context.Background(), r.ref("policies/denied:v1"),
		writeWasm(t, fakeWasm("x")), BundleConfig{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "push to") {
		t.Fatalf("expected push error, got %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.tags) != 0 {
		t.Errorf("tag created despite rejected upload: %v", r.tags)
	}
}

func TestPushCanceledContext(t *testing.T) {
	r := newFakeRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Push(ctx, r.ref("policies/cancel:v1"), writeWasm(t, fakeWasm("x")), BundleConfig{Name: "x"})
	if err == nil {
		t.Fatal("expected error with canceled context")
	}
}

func TestPullInvalidReference(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.wasm")
	err := Pull(context.Background(), "not a reference", out)
	if err == nil || !strings.Contains(err.Error(), "parse reference") {
		t.Fatalf("expected parse reference error, got %v", err)
	}
	assertNoFile(t, out)
}

func TestPullUnknownTag(t *testing.T) {
	r := newFakeRegistry(t)
	out := filepath.Join(t.TempDir(), "out.wasm")
	err := Pull(context.Background(), r.ref("policies/missing:v1"), out)
	if err == nil || !strings.Contains(err.Error(), "pull from") {
		t.Fatalf("expected pull error, got %v", err)
	}
	assertNoFile(t, out)
}

func TestPullTamperedWasmBlob(t *testing.T) {
	r := newFakeRegistry(t)
	wasm := fakeWasm("legit policy")
	wasmDigest := seedBundle(t, r, "v1", wasm)

	// Serve same-length content with a flipped byte for the wasm layer only.
	r.serveBlob = func(d string, data []byte) []byte {
		if d != wasmDigest.String() {
			return data
		}
		evil := bytes.Clone(data)
		evil[len(evil)-1] ^= 0xff
		return evil
	}

	out := filepath.Join(t.TempDir(), "out.wasm")
	if err := Pull(context.Background(), r.ref("policies/tamper:v1"), out); err == nil {
		t.Fatal("tampered wasm layer was accepted")
	}
	assertNoFile(t, out)
}

func TestPullReplacedWasmBlobDifferentLength(t *testing.T) {
	r := newFakeRegistry(t)
	wasmDigest := seedBundle(t, r, "v1", fakeWasm("legit"))
	r.serveBlob = func(d string, data []byte) []byte {
		if d == wasmDigest.String() {
			return fakeWasm("malicious replacement payload that is longer")
		}
		return data
	}
	out := filepath.Join(t.TempDir(), "out.wasm")
	if err := Pull(context.Background(), r.ref("policies/swap:v1"), out); err == nil {
		t.Fatal("replaced wasm layer was accepted")
	}
	assertNoFile(t, out)
}

func TestPullTruncatedWasmBlob(t *testing.T) {
	r := newFakeRegistry(t)
	wasmDigest := seedBundle(t, r, "v1", fakeWasm("a policy that will be cut short"))
	r.blobLength = func(d string, data []byte) (int, bool) {
		if d == wasmDigest.String() {
			return len(data) / 2, true
		}
		return 0, false
	}
	out := filepath.Join(t.TempDir(), "out.wasm")
	if err := Pull(context.Background(), r.ref("policies/trunc:v1"), out); err == nil {
		t.Fatal("truncated wasm layer was accepted")
	}
	assertNoFile(t, out)
}

func TestPullEmptyWasmBlobServed(t *testing.T) {
	r := newFakeRegistry(t)
	wasmDigest := seedBundle(t, r, "v1", fakeWasm("non-empty"))
	r.serveBlob = func(d string, data []byte) []byte {
		if d == wasmDigest.String() {
			return nil
		}
		return data
	}
	out := filepath.Join(t.TempDir(), "out.wasm")
	if err := Pull(context.Background(), r.ref("policies/empty:v1"), out); err == nil {
		t.Fatal("empty wasm body was accepted")
	}
	assertNoFile(t, out)
}

func TestPullTamperedConfigBlob(t *testing.T) {
	r := newFakeRegistry(t)
	seedBundle(t, r, "v1", fakeWasm("ok"))
	// Corrupt everything except the wasm layer (i.e. the config blob).
	wasmDigest := digest.FromBytes(fakeWasm("ok")).String()
	r.serveBlob = func(d string, data []byte) []byte {
		if d == wasmDigest {
			return data
		}
		evil := bytes.Clone(data)
		evil[0] ^= 0xff
		return evil
	}
	out := filepath.Join(t.TempDir(), "out.wasm")
	if err := Pull(context.Background(), r.ref("policies/cfg:v1"), out); err == nil {
		t.Fatal("tampered config blob was accepted")
	}
	assertNoFile(t, out)
}

func TestPullTamperedManifest(t *testing.T) {
	r := newFakeRegistry(t)
	seedBundle(t, r, "v1", fakeWasm("legit"))

	// Attacker substitutes a different (well-formed) manifest pointing at a
	// malicious layer while the tag still resolves to the original digest.
	evilWasm := r.putBlob(fakeWasm("evil"))
	evilWasm.MediaType = WasmMediaType
	r.serveManifest = func(_ string, data []byte) []byte {
		var m ocispec.Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return data
		}
		m.Layers = []ocispec.Descriptor{evilWasm}
		out, _ := json.Marshal(m)
		return out
	}
	out := filepath.Join(t.TempDir(), "out.wasm")
	if err := Pull(context.Background(), r.ref("policies/mf:v1"), out); err == nil {
		t.Fatal("tampered manifest was accepted")
	}
	assertNoFile(t, out)
}

func TestPullCorruptManifestJSON(t *testing.T) {
	r := newFakeRegistry(t)
	r.putManifest("v1", ocispec.MediaTypeImageManifest, []byte(`{"schemaVersion":2,"layers":[`))
	out := filepath.Join(t.TempDir(), "out.wasm")
	if err := Pull(context.Background(), r.ref("policies/corrupt:v1"), out); err == nil {
		t.Fatal("corrupt manifest JSON was accepted")
	}
	assertNoFile(t, out)
}

func TestPullNonManifestMediaType(t *testing.T) {
	// A tag pointing at an opaque (non-manifest) blob: oras copies it as a
	// leaf, and Pull must fail to decode it rather than write anything.
	r := newFakeRegistry(t)
	r.putManifest("v1", "application/vnd.example.unknown", []byte("this is not json"))
	out := filepath.Join(t.TempDir(), "out.wasm")
	err := Pull(context.Background(), r.ref("policies/opaque:v1"), out)
	if err == nil {
		t.Fatal("non-manifest artifact was accepted")
	}
	assertNoFile(t, out)
}

func TestPullNoWasmLayer(t *testing.T) {
	r := newFakeRegistry(t)
	cfg := r.putBlob([]byte(`{}`))
	cfg.MediaType = ConfigMediaType
	other := r.putBlob([]byte("tarball"))
	other.MediaType = ocispec.MediaTypeImageLayer
	m := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    cfg,
		Layers:    []ocispec.Descriptor{other},
	}
	data, _ := json.Marshal(m)
	r.putManifest("v1", ocispec.MediaTypeImageManifest, data)

	out := filepath.Join(t.TempDir(), "out.wasm")
	err := Pull(context.Background(), r.ref("policies/nowasm:v1"), out)
	if err == nil || !strings.Contains(err.Error(), "no wasm layer") {
		t.Fatalf("expected no wasm layer error, got %v", err)
	}
	assertNoFile(t, out)
}

func TestPullSkipsNonWasmLayers(t *testing.T) {
	r := newFakeRegistry(t)
	other := r.putBlob([]byte("readme"))
	other.MediaType = "text/plain"
	wasm := fakeWasm("after other layer")
	seedBundle(t, r, "v1", wasm, other)

	out := filepath.Join(t.TempDir(), "out.wasm")
	if err := Pull(context.Background(), r.ref("policies/multi:v1"), out); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, wasm) {
		t.Errorf("pulled %q, want %q", got, wasm)
	}
}

func TestPullUnwritableOutput(t *testing.T) {
	r := newFakeRegistry(t)
	seedBundle(t, r, "v1", fakeWasm("ok"))
	out := filepath.Join(t.TempDir(), "no-such-dir", "out.wasm")
	if err := Pull(context.Background(), r.ref("policies/w:v1"), out); err == nil {
		t.Fatal("expected write error for missing output directory")
	}
}

func TestPullCanceledContext(t *testing.T) {
	r := newFakeRegistry(t)
	seedBundle(t, r, "v1", fakeWasm("ok"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := filepath.Join(t.TempDir(), "out.wasm")
	if err := Pull(ctx, r.ref("policies/c:v1"), out); err == nil {
		t.Fatal("expected error with canceled context")
	}
	assertNoFile(t, out)
}

func TestPushBlobDescriptor(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	data := []byte("blob")
	desc, err := pushBlob(ctx, store, WasmMediaType, data)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Digest != digest.FromBytes(data) || desc.Size != int64(len(data)) || desc.MediaType != WasmMediaType {
		t.Errorf("unexpected descriptor %+v", desc)
	}
	ok, err := store.Exists(ctx, desc)
	if err != nil || !ok {
		t.Errorf("blob not stored: ok=%v err=%v", ok, err)
	}
	if _, err := pushBlob(ctx, store, WasmMediaType, data); err == nil {
		t.Error("expected error pushing duplicate blob")
	}
}
