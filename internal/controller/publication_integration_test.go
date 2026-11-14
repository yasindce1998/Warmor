package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Real codegen/cargo, HTTP publication, serialized restart recovery and WASM
// evaluation, but no cluster, BPF attachment or host enforcement.
func TestPublicationInvalidUpdateRestartPreservesExecutableLastKnownGood(t *testing.T) {
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo/wasm32 required")
		}
		t.Skip("cargo/wasm32 unavailable")
	}
	apiServer := newFakeAPI()
	cr := testCR("alpha", nil)
	apiServer.addCR(cr)
	reconcile(t, newTestController(t, apiServer, Options{}))
	before := apiServer.configMaps[testConfigMap]
	wasmBefore := bytes.Clone(before.BinaryData[PolicyDataKey])
	snapshotBefore := before.Data[SnapshotDataKey]
	digestBefore := before.Metadata.Annotations[AnnotationArtifactSHA]
	// Round-trip the journal over its actual JSON wire format. The new
	// controller gets neither an in-memory accepted-source map nor a cache.
	raw, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	var restored ConfigMap
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	apiServer.configMaps[testConfigMap] = &restored
	cr.Metadata.Generation++
	cr.Spec.Rules[0].Conditions.All = []map[string]any{{"path": map[string]any{"unknownOperator": "/tmp/**"}}}
	cr.Status = &WarmorPolicyStatus{Phase: PhaseActive, NodesApplied: 23, LastApplied: "legacy-unproven"}
	apiServer.addCR(cr)
	restarted := newTestController(t, apiServer, Options{})
	reconcile(t, restarted)
	cm := apiServer.configMaps[testConfigMap]
	if !bytes.Equal(cm.BinaryData[PolicyDataKey], wasmBefore) || cm.Data[SnapshotDataKey] != snapshotBefore || cm.Metadata.Annotations[AnnotationArtifactSHA] != digestBefore {
		t.Fatal("invalid desired edit changed durable publication after restart")
	}
	if cr.Status.AcceptedGeneration != 1 || cr.Status.ObservedGeneration != 2 || cr.Status.Phase != PhaseError || cr.Status.NodesApplied != 0 || cr.Status.LastApplied != "" {
		t.Fatalf("restart confused desired/accepted/applied state: %+v", cr.Status)
	}
	requireCondition(t, cr.Status, "Published", "True", "LastKnownGoodPublished")
	requireCondition(t, cr.Status, "Applied", "Unknown", "NoNodeAcknowledgements")
	evaluatePublishedPolicy(t, cm.BinaryData[PolicyDataKey])
	// Force a real new compilation, exercising the recovered source spec
	// rather than merely reusing previously compiled bytes.
	apiServer.addCR(testCR("beta", func(s *WarmorPolicySpec) {
		s.Rules[0].Conditions.All = []map[string]any{{"path": map[string]any{"glob": "/other/**"}}}
	}))
	reconcile(t, restarted)
	cm = apiServer.configMaps[testConfigMap]
	if bytes.Equal(cm.BinaryData[PolicyDataKey], wasmBefore) || cm.Metadata.Annotations[AnnotationArtifactSHA] != digest(cm.BinaryData[PolicyDataKey]) {
		t.Fatal("new composition failed to publish changed, integrity-checked bytes")
	}
	evaluatePublishedPolicy(t, cm.BinaryData[PolicyDataKey])
}

func evaluatePublishedPolicy(t *testing.T, artifact []byte) {
	t.Helper()
	ctx := context.Background()
	runtime, err := wasm.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx)
	if err := runtime.LoadPolicyBytes(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	policy, err := wasm.NewPolicy(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close(ctx)
	for _, tc := range []struct {
		path string
		want api.Action
	}{{"/tmp/last-good-marker", api.ActionDeny}, {"/usr/bin/innocent", api.ActionAllow}} {
		action, err := policy.Evaluate(ctx, &api.Event{Process: &api.ProcessEvent{Filename: tc.path}})
		if err != nil || action != tc.want {
			t.Fatalf("published policy decision for %s = %v, %v; want %v", tc.path, action, err, tc.want)
		}
	}
}
