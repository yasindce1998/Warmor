package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
)

const testConfigMap = "warmor-system/warmor-effective-policy"

func requireCondition(t *testing.T, status *WarmorPolicyStatus, typ, value, reason string) {
	t.Helper()
	if status == nil {
		t.Fatal("missing status")
	}
	for _, condition := range status.Conditions {
		if condition.Type == typ {
			if condition.Status != value || condition.Reason != reason {
				t.Fatalf("%s condition = %+v, want %s/%s", typ, condition, value, reason)
			}
			return
		}
	}
	t.Fatalf("missing %s condition: %+v", typ, status)
}

func reconcile(t *testing.T, ctl *Controller) {
	t.Helper()
	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestReconcile_InvalidUpdateSurvivesRestartAndOtherChanges(t *testing.T) {
	compiles, restore := stubCompile(t)
	defer restore()
	api := newFakeAPI()
	cr := testCR("alpha", nil)
	api.addCR(cr)
	ctl := newTestController(t, api, Options{})
	reconcile(t, ctl)
	before := api.configMaps[testConfigMap].Data[SnapshotDataKey]
	cr.Metadata.Generation = 2
	cr.Spec.Rules[0].Event = "invalid"
	cr.Status = nil // A lost status PUT must not lose durable acceptance.
	api.addCR(cr)
	ctl = newTestController(t, api, Options{})
	reconcile(t, ctl)
	if api.configMaps[testConfigMap].Data[SnapshotDataKey] != before || len(*compiles) != 1 {
		t.Fatal("invalid update replaced or recompiled accepted snapshot")
	}
	if cr.Status.Phase != PhaseError || cr.Status.ObservedGeneration != 2 || cr.Status.AcceptedGeneration != 1 {
		t.Fatalf("desired generation confused with accepted generation: %+v", cr.Status)
	}
	requireCondition(t, cr.Status, "Validated", "False", "InvalidPolicy")
	requireCondition(t, cr.Status, "Published", "True", "LastKnownGoodPublished")
	requireCondition(t, cr.Status, "Applied", "Unknown", "NoNodeAcknowledgements")
	// An unrelated valid change composes with alpha's old deny.
	api.addCR(testCR("beta", nil))
	reconcile(t, ctl)
	last := (*compiles)[len(*compiles)-1]
	if !strings.Contains(last, "warmor-system/alpha/uid-alpha/block-tmp") || strings.Contains(last, "event: invalid") {
		t.Fatalf("last-known-good missing from changed composition: %s", last)
	}
	// Actual deletion is different from invalidation.
	delete(api.policies, "warmor-system/alpha")
	reconcile(t, ctl)
	if strings.Contains((*compiles)[len(*compiles)-1], "uid-alpha") {
		t.Fatal("explicitly deleted source was retained")
	}
	delete(api.policies, "warmor-system/beta")
	reconcile(t, ctl)
	if got := string(api.configMaps[testConfigMap].BinaryData[PolicyDataKey]); got != "default policy wasm" {
		t.Fatalf("deleting final source did not restore default: %q", got)
	}
}

func TestReconcile_RecreatedUIDCannotInheritSnapshot(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()
	api := newFakeAPI()
	api.addCR(testCR("alpha", nil))
	ctl := newTestController(t, api, Options{})
	reconcile(t, ctl)
	recreated := testCR("alpha", func(s *WarmorPolicySpec) { s.DefaultAction = "invalid" })
	recreated.Metadata.UID = "new-uid"
	api.addCR(recreated)
	reconcile(t, newTestController(t, api, Options{}))
	if api.configMaps[testConfigMap].Metadata.Annotations[AnnotationSources] != "cluster-default" || recreated.Status.AcceptedGeneration != 0 {
		t.Fatal("new UID inherited deleted object's accepted source")
	}
}

func TestReconcile_SelectorUpdateRetainsPriorGeneration(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()
	api := newFakeAPI()
	cr := testCR("alpha", nil)
	api.addCR(cr)
	reconcile(t, newTestController(t, api, Options{}))
	cr.Metadata.Generation++
	cr.Spec.Selector = &Selector{MatchLabels: map[string]string{"app": "payments"}}
	reconcile(t, newTestController(t, api, Options{}))
	if cr.Status.Phase != PhasePending || cr.Status.AcceptedGeneration != 1 {
		t.Fatalf("selector update dropped accepted source or claimed scope support: %+v", cr.Status)
	}
	requireCondition(t, cr.Status, "Ready", "False", "SelectorNotSupported")
	requireCondition(t, cr.Status, "Published", "True", "LastKnownGoodPublished")
}

func TestReconcile_AnyPresentSelectorCannotWidenScope(t *testing.T) {
	for _, selector := range []string{`{}`, `{"matchLabels":{}}`, `{"matchExpressions":[]}`, `{"matchLabels":{},"matchExpressions":[]}`} {
		for _, previouslyAccepted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/accepted=%v", selector, previouslyAccepted), func(t *testing.T) {
				compiles, restore := stubCompile(t)
				defer restore()
				api := newFakeAPI()
				cr := testCR("alpha", nil)
				api.addCR(cr)
				var beforeArtifact []byte
				var beforeSnapshot string
				if previouslyAccepted {
					reconcile(t, newTestController(t, api, Options{}))
					cm := api.configMaps[testConfigMap]
					beforeArtifact = append([]byte(nil), cm.BinaryData[PolicyDataKey]...)
					beforeSnapshot = cm.Data[SnapshotDataKey]
					cr.Metadata.Generation++
				}
				// Decode actual JSON so explicit empty objects/collections follow
				// the same nil-vs-present path as an API server response.
				if err := json.Unmarshal([]byte(selector), &cr.Spec.Selector); err != nil {
					t.Fatal(err)
				}
				cr.Spec.DefaultAction = "deny" // must never enter node-wide merge
				cr.Status = nil
				api.addCR(cr)
				reconcile(t, newTestController(t, api, Options{}))
				if cr.Status.Phase != PhasePending {
					t.Fatalf("explicit empty selector was accepted node-wide: %+v", cr.Status)
				}
				requireCondition(t, cr.Status, "Ready", "False", "SelectorNotSupported")
				requireCondition(t, cr.Status, "Validated", "False", "SelectorNotSupported")
				requireCondition(t, cr.Status, "Applied", "Unknown", "NoNodeAcknowledgements")
				cm := api.configMaps[testConfigMap]
				if previouslyAccepted {
					if cr.Status.AcceptedGeneration != 1 || cr.Status.ObservedGeneration != 2 || string(cm.BinaryData[PolicyDataKey]) != string(beforeArtifact) || cm.Data[SnapshotDataKey] != beforeSnapshot || len(*compiles) != 1 {
						t.Fatal("selector edit replaced or lost last-good node-wide source")
					}
					requireCondition(t, cr.Status, "Published", "True", "LastKnownGoodPublished")
				} else if cr.Status.AcceptedGeneration != 0 || len(*compiles) != 0 || cm.Metadata.Annotations[AnnotationSources] != "cluster-default" {
					t.Fatal("new selector-bearing policy contributed node-wide rules")
				}
			})
		}
	}
}

func TestReconcile_CompilerIdentityChangeRebuildsAfterRestart(t *testing.T) {
	compiles, restore := stubCompile(t)
	defer restore()
	identity := compilerIdentity
	t.Cleanup(func() { compilerIdentity = identity })
	api := newFakeAPI()
	api.addCR(testCR("alpha", nil))
	reconcile(t, newTestController(t, api, Options{}))
	before := api.configMaps[testConfigMap].Metadata.Annotations[AnnotationPolicySHA]
	compilerIdentity += "/upgrade"
	reconcile(t, newTestController(t, api, Options{}))
	cm := api.configMaps[testConfigMap]
	if len(*compiles) != 2 || cm.Metadata.Annotations[AnnotationPolicySHA] == before || cm.Metadata.Annotations[AnnotationCompiler] != compilerIdentity {
		t.Fatal("compiler upgrade did not rebuild unchanged policy")
	}
}

func TestReconcile_FailedUpdatesNeverAdvanceAcceptedSnapshot(t *testing.T) {
	for _, failure := range []string{"compile", "publication", "conflict"} {
		t.Run(failure, func(t *testing.T) {
			_, restore := stubCompile(t)
			defer restore()
			api := newFakeAPI()
			cr := testCR("alpha", nil)
			api.addCR(cr)
			ctl := newTestController(t, api, Options{})
			reconcile(t, ctl)
			before, _ := json.Marshal(api.configMaps[testConfigMap])
			cr.Metadata.Generation = 2
			cr.Spec.DefaultAction = "deny"
			workingCompiler := compilePolicy
			reason := "PublicationFailed"
			switch failure {
			case "compile":
				reason = "CompilationFailed"
				compilePolicy = func(context.Context, *compiler.Policy, []byte, string) ([]byte, error) {
					return nil, fmt.Errorf("injected cargo failure")
				}
			case "publication":
				api.configMapWriteError = http.StatusForbidden
			case "conflict":
				api.conflicts = 1
			}
			if _, err := ctl.Reconcile(context.Background()); err == nil {
				t.Fatal("injected failure unexpectedly succeeded")
			}
			after, _ := json.Marshal(api.configMaps[testConfigMap])
			if string(before) != string(after) || cr.Status.AcceptedGeneration != 1 {
				t.Fatal("failed publication changed prior artifact or accepted generation")
			}
			if cr.Status.Phase != PhaseError || cr.Status.LastApplied != "" || cr.Status.NodesApplied != 0 {
				t.Fatalf("failure claimed success: %+v", cr.Status)
			}
			requireCondition(t, cr.Status, "Published", "False", reason)
			compilePolicy = workingCompiler
			api.configMapWriteError = 0
			// Restart plus invalid follow-up must recover generation 1, not
			// valid-but-never-published generation 2.
			cr.Status = nil
			cr.Metadata.Generation = 3
			cr.Spec.Rules[0].Event = "invalid"
			reconcile(t, newTestController(t, api, Options{}))
			if cr.Status.AcceptedGeneration != 1 {
				t.Fatal("restart adopted uncommitted source")
			}
			cr.Metadata.Generation = 4
			cr.Spec.Rules[0].Event = "process"
			reconcile(t, ctl)
			if cr.Status.AcceptedGeneration != 4 || cr.Status.Phase != PhasePublished {
				t.Fatal("retry did not converge after failure")
			}
		})
	}
}

func TestReconcile_CompileHonorsDeadline(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()
	compilePolicy = func(ctx context.Context, _ *compiler.Policy, _ []byte, _ string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	api := newFakeAPI()
	api.addCR(testCR("alpha", nil))
	ctl := newTestController(t, api, Options{CompileTimeout: time.Millisecond})
	if _, err := ctl.Reconcile(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline was ignored: %v", err)
	}
	requireCondition(t, api.policies["warmor-system/alpha"].Status, "Compiled", "False", "CompilationFailed")
	if len(api.configMaps) != 0 {
		t.Fatal("timed-out compile published a policy")
	}
}

func TestReconcile_SnapshotTamperOrLossDoesNotDropOldPolicy(t *testing.T) {
	for _, mutation := range []string{"tamper", "missing", "oversize"} {
		t.Run(mutation, func(t *testing.T) {
			_, restore := stubCompile(t)
			defer restore()
			api := newFakeAPI()
			cr := testCR("alpha", nil)
			api.addCR(cr)
			ctl := newTestController(t, api, Options{})
			reconcile(t, ctl)
			cm := api.configMaps[testConfigMap]
			switch mutation {
			case "tamper":
				cm.Data[SnapshotDataKey] = "{}"
			case "missing":
				delete(cm.Data, SnapshotDataKey)
			case "oversize":
				cm.Data[SnapshotDataKey] = strings.Repeat("x", maxSnapshotBytes+1)
			}
			cr.Spec.Rules[0].Event = "invalid"
			if _, err := newTestController(t, api, Options{}).Reconcile(context.Background()); err == nil {
				t.Fatal("damaged snapshot silently discarded")
			}
			if api.configMapPUTs != 0 || string(cm.BinaryData[PolicyDataKey]) != "wasm(warmor-effective)" {
				t.Fatal("snapshot damage replaced old publication")
			}
			requireCondition(t, cr.Status, "Published", "False", "SnapshotUnavailable")
		})
	}
}

func TestReconcile_RefusesUnownedConfigMap(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()
	api := newFakeAPI()
	cr := testCR("alpha", nil)
	api.addCR(cr)
	api.configMaps[testConfigMap] = &ConfigMap{Metadata: ObjectMeta{Name: "warmor-effective-policy"}, Data: map[string]string{"user": "owned"}}
	if _, err := newTestController(t, api, Options{}).Reconcile(context.Background()); err == nil {
		t.Fatal("unowned ConfigMap overwritten")
	}
	requireCondition(t, cr.Status, "Published", "False", "PublicationFailed")
	if api.configMapPUTs != 0 {
		t.Fatal("unowned ConfigMap modified")
	}
}

func TestReconcile_BudgetsPreservePreviousPublication(t *testing.T) {
	for _, budget := range []string{"snapshot", "artifact"} {
		t.Run(budget, func(t *testing.T) {
			_, restore := stubCompile(t)
			defer restore()
			api := newFakeAPI()
			cr := testCR("alpha", nil)
			api.addCR(cr)
			ctl := newTestController(t, api, Options{})
			reconcile(t, ctl)
			cr.Metadata.Generation++
			cr.Spec.DefaultAction = "deny"
			if budget == "snapshot" {
				cr.Spec.Description = strings.Repeat("x", 60<<10)
				for i := range 4 {
					api.addCR(testCR(fmt.Sprintf("large-%d", i), func(s *WarmorPolicySpec) {
						s.Description = strings.Repeat("x", 60<<10)
					}))
				}
			} else {
				compilePolicy = func(context.Context, *compiler.Policy, []byte, string) ([]byte, error) {
					return make([]byte, maxConfigMapBytes), nil
				}
			}
			if _, err := ctl.Reconcile(context.Background()); err == nil {
				t.Fatal("oversize publication succeeded")
			}
			if api.configMapPUTs != 0 || cr.Status.AcceptedGeneration != 1 {
				t.Fatal("oversize publication advanced accepted state")
			}
		})
	}
}

func TestReconcile_AllNamespacesSameNameRemainDisjoint(t *testing.T) {
	compiles, restore := stubCompile(t)
	defer restore()
	api := newFakeAPI()
	for i, namespace := range []string{"team-a", "team-b"} {
		cr := testCR("same", func(s *WarmorPolicySpec) {
			s.Variables = map[string]any{"path": fmt.Sprintf("/team-%d", i)}
			s.Rules[0].Conditions.All = []map[string]any{{"path": "$path"}}
		})
		cr.Metadata.Namespace = namespace
		cr.Metadata.UID = "uid-" + namespace
		api.addCR(cr)
	}
	ctl := newTestController(t, api, Options{})
	ctl.opts.Namespace = ""
	reconcile(t, ctl)
	parsed, err := compiler.Parse([]byte((*compiles)[0]))
	if err != nil || len(parsed.Rules) != 2 {
		t.Fatalf("same-name source merge failed: %v", err)
	}
	if !strings.Contains((*compiles)[0], "/team-0") || !strings.Contains((*compiles)[0], "/team-1") {
		t.Fatal("same-name variable overwritten")
	}
	if parsed.Rules[0].Name == parsed.Rules[1].Name {
		t.Fatal("same-name source rule identities collided")
	}
	api.policies["team-a/same"].Spec.DefaultAction = "invalid"
	reconcile(t, ctl)
	if len(*compiles) != 1 {
		t.Fatal("same-name invalid source did not retain its own snapshot")
	}
}

func TestPolicyCacheKeyIncludesGeneratedSource(t *testing.T) {
	policy := &compiler.Policy{Name: "key-test", Version: 1, DefaultAction: "allow", Rules: []compiler.Rule{{
		Name: "block", Event: "process", Action: "deny", Conditions: compiler.Conditions{All: []compiler.Condition{{Field: "path", Operator: "eq", Value: "/bin/one"}}},
	}}}
	// Hold source YAML fixed while changing generated semantics.
	before, err := policyCacheKey([]byte("source"), policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.Rules[0].Conditions.All[0].Value = "/bin/two"
	after, err := policyCacheKey([]byte("source"), policy)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("generated Rust change did not invalidate revision/cache identity")
	}
}

func TestReconcile_LegacyInvalidSourceDoesNotFallBackToDefault(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()
	api := newFakeAPI()
	cr := testCR("alpha", nil)
	api.addCR(cr)
	ctl := newTestController(t, api, Options{})
	reconcile(t, ctl)
	cm := api.configMaps[testConfigMap]
	delete(cm.Data, SnapshotDataKey)
	delete(cm.Metadata.Annotations, AnnotationSnapshotSHA)
	cr.Spec.DefaultAction = "invalid"
	if _, err := ctl.Reconcile(context.Background()); err == nil {
		t.Fatal("legacy invalid source silently dropped")
	}
	if api.configMapPUTs != 0 {
		t.Fatal("legacy last publication replaced")
	}
	requireCondition(t, cr.Status, "Published", "False", "SnapshotUnavailable")
	cr.Spec.DefaultAction = "allow"
	reconcile(t, ctl)
	if api.configMaps[testConfigMap].Data[SnapshotDataKey] == "" {
		t.Fatal("valid legacy reconcile did not migrate durable source state")
	}
}

func TestReconcile_SourceBudgetInvalidatesEditWithoutDroppingAcceptedPolicy(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()
	api := newFakeAPI()
	cr := testCR("alpha", nil)
	api.addCR(cr)
	ctl := newTestController(t, api, Options{})
	reconcile(t, ctl)
	cr.Metadata.Generation++
	cr.Spec.Description = strings.Repeat("x", maxSourceBytes)
	reconcile(t, ctl)
	requireCondition(t, cr.Status, "Validated", "False", "PolicyBudgetExceeded")
	if api.configMapPUTs != 0 || cr.Status.AcceptedGeneration != 1 {
		t.Fatal("oversize edit changed prior publication")
	}
}

func TestReconcile_ImmutablePublicationPreservesAcceptedState(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()
	api := newFakeAPI()
	cr := testCR("alpha", nil)
	api.addCR(cr)
	ctl := newTestController(t, api, Options{})
	reconcile(t, ctl)
	immutable := true
	cm := api.configMaps[testConfigMap]
	cm.Immutable = &immutable
	before := cm.Data[SnapshotDataKey]
	cr.Metadata.Generation++
	cr.Spec.DefaultAction = "deny"
	if _, err := ctl.Reconcile(context.Background()); err == nil {
		t.Fatal("immutable publication unexpectedly changed")
	}
	if cm.Data[SnapshotDataKey] != before || api.configMapPUTs != 0 || cr.Status.AcceptedGeneration != 1 {
		t.Fatal("immutable ConfigMap changed accepted state")
	}
	requireCondition(t, cr.Status, "Compiled", "True", "Compiled")
	requireCondition(t, cr.Status, "Published", "False", "PublicationFailed")
}

func TestReconcile_SnapshotsExcludeUnrelatedCRMetadataAndStatus(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()
	api := newFakeAPI()
	cr := testCR("alpha", nil)
	cr.Metadata.Annotations = map[string]string{"example.com/token": "secret-annotation-value"}
	cr.Metadata.Labels = map[string]string{"private": "secret-label-value"}
	cr.Status = &WarmorPolicyStatus{LastApplied: "fake-legacy-application", NodesApplied: 99}
	api.addCR(cr)
	reconcile(t, newTestController(t, api, Options{}))
	raw := api.configMaps[testConfigMap].Data[SnapshotDataKey]
	for _, forbidden := range []string{"secret-annotation-value", "secret-label-value", "fake-legacy-application", "nodesApplied", "resourceVersion"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("source snapshot copied unrelated metadata/status: %q", forbidden)
		}
	}
	if cr.Status.LastApplied != "" || cr.Status.NodesApplied != 0 {
		t.Fatal("legacy application claims carried forward without acknowledgement")
	}
}

func TestReconcile_WatchScopeChangeDoesNotSilentlyDropAcceptedSources(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()
	api := newFakeAPI()
	api.addCR(testCR("alpha", nil))
	ctl := newTestController(t, api, Options{})
	reconcile(t, ctl)
	ctl = newTestController(t, api, Options{})
	ctl.opts.Namespace = ""
	if _, err := ctl.Reconcile(context.Background()); err == nil {
		t.Fatal("changed watch scope silently adopted old snapshot")
	}
	if api.configMapPUTs != 0 {
		t.Fatal("watch scope change replaced previous publication")
	}
	requireCondition(t, api.policies["warmor-system/alpha"].Status, "Published", "False", "SnapshotUnavailable")
}
