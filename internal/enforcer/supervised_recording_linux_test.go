//go:build linux

package enforcer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Combine the real supervised evaluator/generation lifetime with main's private
// recording/export boundaries. Only platform publication is fake; no hooks or
// real process actions are installed, and HTTP is a test-only loopback listener.
func TestSupervisedGenerationPrivateRecordingAndRedactedExport(t *testing.T) {
	e, _, key := supervisedEnforcer(t, wasmtest.ConstPolicy(0, nil), supervisedConfig(t), true)
	const secret = "host-input-secret-token"
	dir := t.TempDir()
	path := filepath.Join(dir, "events.ndjson")
	file, err := streaming.NewFileSink(path, 1) // force private rotation for event 2
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var posted []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		mu.Lock()
		posted = append(posted, data...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	webhook := streaming.NewWebhookSink(streaming.WebhookConfig{URL: server.URL, BatchSize: 2, FlushEvery: time.Hour})
	pipeline := streaming.NewPipeline(streaming.PipelineConfig{Sinks: []streaming.Sink{file, webhook}, FlushInterval: time.Hour})
	e.pipeline = pipeline
	t.Cleanup(func() { _ = pipeline.Close() })
	makeEvent := func() *api.Event {
		return &api.Event{UID: 1000, CgroupID: 42, Filename: "/reviewed/tool", Timestamp: time.Now(),
			Process: &api.ProcessEvent{Filename: "/reviewed/tool", Args: []string{"tool", secret}}}
	}
	oldEvent := makeEvent()
	if !e.captureGeneration(oldEvent) || oldEvent.GenerationContext.ID != 1 {
		t.Fatal("old host lease was not captured")
	}
	// Process a captured old event during the new live commit's durable hook.
	// Its record must retain the old evaluator result, not the new denial.
	if err := e.ActivatePolicy(signedCandidate(t, key, wasmtest.ConstPolicy(1, nil)), func() error {
		e.handleEvent(oldEvent)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.handleEvent(makeEvent())
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	var recorded []streaming.SecurityEvent
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatal("private file rotation did not preserve both events", len(entries))
	}
	for _, entry := range entries {
		name := filepath.Join(dir, entry.Name())
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("sensitive host input recording is not private", name, err)
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte(secret)) || bytes.Contains(data, []byte("GenerationContext")) || bytes.Contains(data, []byte("DispatchBarrier")) {
			t.Fatal("recording lost input or serialized a live generation lease")
		}
		var event streaming.SecurityEvent
		if err := json.Unmarshal(bytes.TrimSpace(data), &event); err != nil {
			t.Fatal(err)
		}
		if event.SchemaVersion != streaming.EventSchemaVersion || event.PolicyInput == nil || event.PolicyInput.Process.Args[1] != secret || event.PolicyInput.GenerationContext != nil {
			t.Fatal("private recording did not retain replay input without live leases")
		}
		recorded = append(recorded, event)
	}
	mu.Lock()
	defer mu.Unlock()
	if bytes.Contains(posted, []byte(secret)) || bytes.Contains(posted, []byte(`"policy_input":`)) {
		t.Fatal("default webhook exported full supervised input")
	}
	var exported []streaming.SecurityEvent
	if err := json.Unmarshal(bytes.TrimSpace(posted), &exported); err != nil || len(exported) != 2 {
		t.Fatal("missing exported host decisions", err)
	}
	if exported[0].Decision != "allow" || exported[0].AuditOnly || exported[1].Decision != "deny" || !exported[1].AuditOnly {
		t.Fatal("host generation routing or historical audit outcome changed", exported)
	}
	for _, event := range exported {
		marked := false
		for _, issue := range event.InputIssues {
			marked = marked || issue.Field == "policy_input" && issue.State == "redacted"
		}
		if event.PolicyInput != nil || !marked || event.Enforced || event.EnforcementAttempted || event.EnforcementError != "" {
			t.Fatal("redaction changed actual enforcement outcome", event)
		}
	}
	decisions := map[string]int{}
	for _, event := range recorded {
		decisions[event.Decision]++
	}
	if decisions["allow"] != 1 || decisions["deny"] != 1 {
		t.Fatal("rotation/private export rewrote generation decisions", decisions)
	}
}

func TestSupervisedRecordingRetainsNoFollowOutputBoundary(t *testing.T) {
	root := t.TempDir()
	physical := filepath.Join(root, "physical")
	if err := os.Mkdir(physical, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(physical, alias); err != nil {
		t.Fatal(err)
	}
	if sink, err := streaming.NewFileSink(filepath.Join(alias, "events.ndjson"), 1024); err == nil {
		_ = sink.Close()
		t.Fatal("recording followed parent alias; policy input path normalization must not apply to outputs")
	}
	entries, err := os.ReadDir(physical)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected recording path changed physical output", entries, err)
	}
}

func TestMergedFramingRejectsBeforeLegacyValidationOrSupervisedPlatform(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	// The first typed document is malformed too. Main's generic framing check
	// must reject the second document before materializing typed operands.
	data := "name: framing\nversion: 1\nvariables: {bad: !!binary not-base64!}\nrules: []\n---\n{}\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePolicy(context.Background(), path, nil); err == nil || !strings.Contains(err.Error(), "expected exactly one YAML document") {
		t.Fatal("legacy validator lost generic framing-first rejection", err)
	}
	c := supervisedConfig(t)
	if e, err := New(context.Background(), path, &Options{SupervisedBackend: &c}); err == nil || e != nil || !strings.Contains(err.Error(), "compiled signed WASM") {
		t.Fatal("supervised mode admitted parent YAML decoding/compilation", err)
	}
}
