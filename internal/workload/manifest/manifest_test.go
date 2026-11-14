package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/workload"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func yamlPolicy(action, operand, fallback string) string {
	return fmt.Sprintf(`name: same-name
version: 1
variables: {target: %q}
rules:
  - name: same-rule
    event: process
    conditions: {all: [{comm: "$target"}]}
    action: %s
default_action: %s
`, operand, action, fallback)
}

func source(ns, uid, raw string) Source {
	return Source{Namespace: ns, UID: types.UID(uid), AcceptedGeneration: 7, ABI: 3,
		Artifact: Artifact{Digest: digest.FromString(raw), Size: len(raw), MediaType: SourceMediaType}}
}
func fixture() (Document, map[digest.Digest][]byte) {
	baseRaw := yamlPolicy("deny", "baseline-block", "allow")
	aRaw := yamlPolicy("deny", "alpha-block", "allow")
	bRaw := yamlPolicy("allow", "alpha-block", "allow")
	base := source("system", "baseline", baseRaw)
	a := source("alpha", "same-uid", aRaw)
	b := source("beta", "same-uid", bRaw)
	return Document{Version: Version, Generation: 1, Compiler: compiler.Version, Composition: CompositionVersion, Posture: Posture,
			Baseline: &base, Unknown: ScopeHandling{Mode: "audit-only"}, KnownHost: ScopeHandling{Mode: "audit-only"},
			Additions: []Addition{{Source: a}, {Source: b}}}, map[digest.Digest][]byte{
			base.Artifact.Digest: []byte(baseRaw), a.Artifact.Digest: []byte(aRaw), b.Artifact.Digest: []byte(bRaw)}
}

func identity(t *testing.T, ns string, labels map[string]string) workload.Identity {
	t.Helper()
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	in := workload.Inputs{NodeName: "node", Runtime: "containerd",
		Pods: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{UID: "pod", Name: "app", Namespace: ns, Labels: labels},
			Spec: corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "main"}}},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "main", ContainerID: "containerd://" + id,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}},
		Inventory: workload.Inventory{Containers: []*runtimeapi.Container{{Id: id, PodSandboxId: "sandbox", State: runtimeapi.ContainerState_CONTAINER_RUNNING,
			Metadata: &runtimeapi.ContainerMetadata{Name: "main"}}}, Sandboxes: []*runtimeapi.PodSandbox{{Id: "sandbox", State: runtimeapi.PodSandboxState_SANDBOX_READY,
			Metadata: &runtimeapi.PodSandboxMetadata{Uid: "pod", Name: "app", Namespace: ns}}}},
		Bindings: []workload.Binding{{CgroupID: 42, Lifetime: "boot:lifetime", ContainerID: id}}}
	snapshot, err := workload.NewSnapshot(in)
	if err != nil {
		t.Fatal(err)
	}
	i, reason := snapshot.Lookup(42, "boot:lifetime")
	if reason != workload.Verified {
		t.Fatal(reason)
	}
	return i
}
func mustManifest(t *testing.T, doc Document) *Manifest {
	t.Helper()
	m, err := New(doc)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func mustBundle(t *testing.T, m *Manifest, a map[digest.Digest][]byte) *Bundle {
	t.Helper()
	b, err := NewBundle(m, a)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func selectPod(t *testing.T, m *Manifest, ns string) Selection {
	t.Helper()
	s, err := m.SelectPod(identity(t, ns, nil), workload.Verified)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestManifestValidation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Document)
	}{
		{"missing baseline", func(d *Document) { d.Baseline = nil }},
		{"version", func(d *Document) { d.Version = "future" }},
		{"generation", func(d *Document) { d.Generation = 0 }},
		{"compiler", func(d *Document) { d.Compiler = "5" }},
		{"previous compiler", func(d *Document) { d.Compiler = "6" }},
		{"future compiler", func(d *Document) { d.Compiler = "8" }},
		{"composition", func(d *Document) { d.Composition = "merge-verdicts" }},
		{"posture", func(d *Document) { d.Posture = "enforce-everything" }},
		{"namespace", func(d *Document) { d.Additions[0].Source.Namespace = "" }},
		{"uid", func(d *Document) { d.Additions[0].Source.UID = "" }},
		{"uid slash", func(d *Document) { d.Additions[0].Source.UID = "a/b" }},
		{"uid control", func(d *Document) { d.Additions[0].Source.UID = "a\tb" }},
		{"uid unicode", func(d *Document) { d.Additions[0].Source.UID = "é" }},
		{"accepted generation", func(d *Document) { d.Additions[0].Source.AcceptedGeneration = 0 }},
		{"digest", func(d *Document) { d.Additions[0].Source.Artifact.Digest = "sha256:abc" }},
		{"media", func(d *Document) { d.Additions[0].Source.Artifact.MediaType = "application/wasm" }},
		{"size", func(d *Document) { d.Additions[0].Source.Artifact.Size = MaxArtifactBytes + 1 }},
		{"zero size", func(d *Document) { d.Additions[0].Source.Artifact.Size = 0 }},
		{"abi", func(d *Document) { d.Additions[0].Source.ABI = 4 }},
		{"duplicate", func(d *Document) { d.Additions = append(d.Additions, d.Additions[0]) }},
		{"duplicate baseline", func(d *Document) { d.Additions[0].Source = *d.Baseline }},
		{"invalid selector", func(d *Document) {
			d.Additions[0].Selector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "x", Operator: "oops"}}
		}},
		{"scope missing", func(d *Document) { d.Unknown = ScopeHandling{} }},
		{"scope implicit", func(d *Document) { d.KnownHost = ScopeHandling{Mode: "baseline"} }},
		{"scope ambiguous", func(d *Document) { d.Unknown.Baseline = d.Baseline }},
		{"mode override", func(d *Document) { d.Additions[0].Source.RuleModes = map[string]string{"same-rule": "oops"} }},
		{"sources budget", func(d *Document) { d.Additions = make([]Addition, MaxSources) }},
		{"selector budget", func(d *Document) {
			d.Additions[0].Selector.MatchExpressions = make([]metav1.LabelSelectorRequirement, 129)
		}},
		{"bundle budget", func(d *Document) {
			for i := 0; i < 9; i++ {
				s := *d.Baseline
				s.UID = types.UID(fmt.Sprint(i))
				s.Artifact.Size = MaxArtifactBytes
				d.Additions = append(d.Additions, Addition{Source: s})
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, _ := fixture()
			tt.edit(&doc)
			if _, err := New(doc); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
}

func TestCanonicalContentAndCopies(t *testing.T) {
	doc, _ := fixture()
	doc.Additions[0].Source.RuleModes = map[string]string{"same-rule": "audit"}
	m := mustManifest(t, doc)
	before := m.Digest()
	doc.Baseline.UID = "changed"
	doc.Additions[0].Source.RuleModes["same-rule"] = "enforce"
	copy := m.Document()
	copy.Baseline.UID = "changed-again"
	copy.Additions[0].Source.RuleModes["same-rule"] = "enforce"
	data := m.Bytes()
	data[0] = '!'
	if m.Digest() != before || !json.Valid(m.Bytes()) || m.Document().Baseline.UID == "changed" {
		t.Fatal("mutable manifest")
	}
	copy = m.Document()
	copy.Additions[0], copy.Additions[1] = copy.Additions[1], copy.Additions[0]
	if mustManifest(t, copy).Digest() != before {
		t.Fatal("addition order changed digest")
	}
	decoded, err := Decode(m.Bytes())
	if err != nil || decoded.Digest() != before {
		t.Fatal("round trip", err)
	}
	if _, err := Decode([]byte{0xff}); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	copy = m.Document()
	copy.Generation++
	if mustManifest(t, copy).Digest() == before {
		t.Fatal("generation absent from content hash")
	}
	for _, bad := range [][]byte{append(m.Bytes(), []byte(" {}")...), []byte(`{"version":"a","version":"b"}`), bytes.Replace(m.Bytes(), []byte(`"generation":1`), []byte(`"extra":1,"generation":1`), 1), bytes.Repeat([]byte(" "), MaxManifestBytes+1), []byte(strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34))} {
		if _, err := Decode(bad); err == nil {
			t.Fatal("accepted malformed/unknown/oversize JSON")
		}
	}
}

func TestSelectionSeparatesScopesAndNoMatch(t *testing.T) {
	doc, _ := fixture()
	m := mustManifest(t, doc)
	for _, ns := range []string{"alpha", "beta", "other"} {
		s := selectPod(t, m, ns)
		want := ns != "other"
		if s.Matched() != want || s.Scope() != VerifiedPod || s.AuditOnly() || len(s.Sources()) != 1+btoi(want) {
			t.Fatal("incorrect selection", ns)
		}
	}
	if _, err := m.SelectPod(workload.Identity{}, workload.Verified); err == nil {
		t.Fatal("zero identity accepted")
	}
	if _, err := m.SelectPod(identity(t, "alpha", nil), workload.UnknownCgroup); err == nil {
		t.Fatal("unknown selected")
	}
	u, _ := m.SelectUnknown()
	h, _ := m.SelectKnownHost()
	if !u.AuditOnly() || !h.AuditOnly() || u.Matched() || h.Matched() || len(u.Sources()) != 0 || len(h.Sources()) != 0 || u.Digest() == h.Digest() {
		t.Fatal("scope conflation")
	}
	var nilManifest *Manifest
	if _, err := nilManifest.SelectUnknown(); err == nil {
		t.Fatal("nil manifest")
	}
}
func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestSelectorsAllMatchesAndCanonicalization(t *testing.T) {
	doc, _ := fixture()
	a := doc.Additions[0]
	a.Source.UID = "second"
	a.Selector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}, MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "absent", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"z", "a"}},
		{Key: "app", Operator: metav1.LabelSelectorOpExists}}}
	doc.Additions = append(doc.Additions, a)
	m := mustManifest(t, doc)
	s, err := m.SelectPod(identity(t, "alpha", map[string]string{"app": "api"}), workload.Verified)
	if err != nil || len(s.Sources()) != 3 {
		t.Fatal("did not select every match", err)
	}
	s, err = m.SelectPod(identity(t, "alpha", map[string]string{"app": "different"}), workload.Verified)
	if err != nil || len(s.Sources()) != 2 {
		t.Fatal("selector AND failed", err)
	}
	a.Selector.MatchExpressions[0].Values = []string{"a", "z"}
	a.Selector.MatchExpressions[0], a.Selector.MatchExpressions[1] = a.Selector.MatchExpressions[1], a.Selector.MatchExpressions[0]
	doc.Additions[2] = a
	if mustManifest(t, doc).Digest() != m.Digest() {
		t.Fatal("set ordering changed digest")
	}
}

func TestBundleValidation(t *testing.T) {
	for _, kind := range []string{"missing", "extra", "corrupt", "size", "default implicit", "default log", "addition deny", "invalid policy", "override absent", "abi mismatch", "alias", "expansion"} {
		t.Run(kind, func(t *testing.T) {
			doc, a := fixture()
			s := &doc.Additions[0].Source
			raw := string(a[s.Artifact.Digest])
			originalRaw := raw
			switch kind {
			case "missing":
				delete(a, s.Artifact.Digest)
			case "extra":
				a[digest.FromString("extra")] = []byte("extra")
			case "corrupt":
				a[s.Artifact.Digest][0] = '!'
			case "size":
				s.Artifact.Size++
			case "default implicit":
				raw = strings.ReplaceAll(raw, "default_action: allow", "")
			case "default log":
				raw = strings.ReplaceAll(raw, "default_action: allow", "default_action: log")
			case "addition deny":
				raw = strings.ReplaceAll(raw, "default_action: allow", "default_action: deny")
			case "invalid policy":
				raw = strings.ReplaceAll(raw, "action: deny", "action: secret-sensitive-value")
			case "override absent":
				s.RuleModes = map[string]string{"missing": "audit"}
			case "abi mismatch":
				s.ABI = 5
			case "alias":
				raw = strings.ReplaceAll(raw, `variables: {target: "alpha-block"}`, `variables: {target: &a "alpha-block", copy: *a}`)
			case "expansion":
				raw = strings.ReplaceAll(raw, `variables: {target: "alpha-block"}`, `variables: {target: "$target"}`)
			}
			if raw != originalRaw {
				delete(a, s.Artifact.Digest)
				s.Artifact.Digest = digest.FromString(raw)
				s.Artifact.Size = len(raw)
				a[s.Artifact.Digest] = []byte(raw)
			}
			m := mustManifest(t, doc)
			if _, err := NewBundle(m, a); err == nil || strings.Contains(err.Error(), "secret-sensitive-value") {
				t.Fatal("accepted invalid bundle or leaked content", err)
			}
		})
	}
}

func TestCompositionImmutabilityLocalOverridesAndAudit(t *testing.T) {
	doc, a := fixture()
	doc.Additions[0].Source.RuleModes = map[string]string{"same-rule": "audit"}
	m := mustManifest(t, doc)
	b := mustBundle(t, m, a)
	s := selectPod(t, m, "alpha")
	copy := s.Sources()
	copy[0].UID = "evil"
	copy[1].RuleModes["same-rule"] = "enforce"
	g, err := b.Compose(s)
	if err != nil {
		t.Fatal(err)
	}
	p := g.Policy()
	if len(p.Rules) != 2 || p.Rules[0].Name != "system/baseline/same-rule" || p.Rules[1].Mode != "audit" || p.Rules[1].Reason != "Rule: same-rule" || p.Variables != nil {
		t.Fatalf("bad composed policy: %+v", p)
	}
	if p.Rules[0].Conditions.All[0].Value != "baseline-block" || p.Rules[1].Conditions.All[0].Value != "alpha-block" {
		t.Fatal("variable collision")
	}
	p.Rules[0].Action = "allow"
	p.Rules[1].Conditions.All[0].Value = "changed"
	for _, raw := range a {
		clear(raw)
	}
	if g.Policy().Rules[0].Action != "deny" || g.Policy().Rules[1].Conditions.All[0].Value != "alpha-block" {
		t.Fatal("mutable generation")
	}
	g2, err := b.Compose(s)
	if err != nil || g2.Digest() != g.Digest() || g.ABI() != 3 || g.SelectionDigest() != s.Digest() {
		t.Fatal("unstable generation", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				p := g.Policy()
				p.Rules[0].Conditions.All[0].Value = "private"
				_, err := b.Compose(s)
				if err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	u, _ := m.SelectUnknown()
	if _, err := b.Compose(u); err == nil {
		t.Fatal("compiled audit-only scope")
	}
	if _, err := b.Compose(Selection{}); err == nil {
		t.Fatal("compiled empty selection")
	}
	doc = m.Document()
	doc.Generation++
	other := mustManifest(t, doc)
	if _, err := b.Compose(selectPod(t, other, "alpha")); err == nil {
		t.Fatal("accepted foreign manifest")
	}
}

func TestDefaultDenyBoundary(t *testing.T) {
	for _, action := range []string{"allow", "log", "audit", "deny"} {
		t.Run(action, func(t *testing.T) {
			doc, a := fixture()
			doc.Additions = doc.Additions[:1]
			raw := yamlPolicy("deny", "baseline-block", "deny")
			delete(a, doc.Baseline.Artifact.Digest)
			*doc.Baseline = source("system", "baseline", raw)
			a[doc.Baseline.Artifact.Digest] = []byte(raw)
			x := action
			if x == "audit" {
				x = "deny"
				doc.Additions[0].Source.RuleModes = map[string]string{"same-rule": "audit"}
			}
			old := doc.Additions[0].Source.Artifact.Digest
			raw = yamlPolicy(x, "alpha-block", "allow")
			s := source("alpha", "same-uid", raw)
			s.RuleModes = doc.Additions[0].Source.RuleModes
			doc.Additions[0].Source = s
			delete(a, old)
			a[s.Artifact.Digest] = []byte(raw)
			// Remove the no-longer-referenced beta artifact.
			for d := range a {
				if d != s.Artifact.Digest && d != doc.Baseline.Artifact.Digest {
					delete(a, d)
				}
			}
			_, err := NewBundle(mustManifest(t, doc), a)
			if (err == nil) != (action == "deny") {
				t.Fatalf("unsafe effective default accepted: %s, %v", action, err)
			}
		})
	}
}

func TestDedicatedUnknownAndHostBaselines(t *testing.T) {
	doc, a := fixture()
	for i, h := range []*ScopeHandling{&doc.Unknown, &doc.KnownHost} {
		raw := yamlPolicy("deny", fmt.Sprint("scope-", i), "deny")
		s := source("system", fmt.Sprint("scope-", i), raw)
		*h = ScopeHandling{Mode: "baseline", Baseline: &s}
		a[s.Artifact.Digest] = []byte(raw)
	}
	m := mustManifest(t, doc)
	b := mustBundle(t, m, a)
	u, _ := m.SelectUnknown()
	h, _ := m.SelectKnownHost()
	for _, s := range []Selection{u, h} {
		g, err := b.Compose(s)
		if err != nil || len(g.Policy().Rules) != 1 || g.Policy().DefaultAction != "deny" {
			t.Fatal("scope baseline composition", err)
		}
	}
	if u.Sources()[0].UID == h.Sources()[0].UID || u.Matched() || h.Matched() {
		t.Fatal("scope baseline crossover")
	}
}

func TestZeroValuesRejectEnforcingWork(t *testing.T) {
	var m Manifest
	if _, err := NewBundle(&m, nil); err == nil {
		t.Fatal("zero manifest bundle")
	}
	if _, err := m.SelectUnknown(); err == nil {
		t.Fatal("zero manifest unknown")
	}
	if _, err := m.SelectKnownHost(); err == nil {
		t.Fatal("zero manifest host")
	}
	if _, err := m.SelectPod(identity(t, "alpha", nil), workload.Verified); err == nil {
		t.Fatal("zero manifest Pod")
	}
	var b Bundle
	if _, err := b.Compose(Selection{}); err == nil {
		t.Fatal("zero bundle composition")
	}
	var g Generation
	if _, err := g.Build(compiler.BuildOptions{RustOnly: true}); err == nil {
		t.Fatal("zero generation build")
	}
}

func TestDenyFirstReordersWithinSourcesAndPreservesTypedOperands(t *testing.T) {
	doc, _ := fixture()
	doc.Additions = nil
	raw := `name: ordering
version: 1
rules:
  - name: allow-first
    event: process
    conditions: {all: [{uid: {any_of: [0, 1000]}}]}
    action: allow
  - name: log-first
    event: process
    conditions: {all: [{comm: x}]}
    action: log
  - name: audit-first
    event: process
    conditions: {all: [{comm: x}]}
    action: deny
    mode: audit
  - name: deny-last
    event: process
    conditions: {all: [{comm: x}]}
    action: deny
default_action: allow
`
	*doc.Baseline = source("system", "baseline", raw)
	m := mustManifest(t, doc)
	b := mustBundle(t, m, map[digest.Digest][]byte{digest.FromString(raw): []byte(raw)})
	g, err := b.Compose(selectPod(t, m, "alpha"))
	if err != nil {
		t.Fatal(err)
	}
	p := g.Policy()
	if len(p.Rules) != 4 {
		t.Fatalf("expected four composed rules, got %d", len(p.Rules))
	}
	for i, name := range []string{"deny-last", "audit-first", "log-first", "allow-first"} {
		if p.Rules[i].Name != "system/baseline/"+name {
			t.Fatal("incorrect deny-first ordering")
		}
	}
	if len(p.Rules[3].Conditions.All) == 0 {
		t.Fatal("copied allow rule has no all-condition operand")
	}
	values, ok := p.Rules[3].Conditions.All[0].Value.([]any)
	if !ok || len(values) == 0 {
		t.Fatalf("expected nonempty copied numeric operand list, got %T (%v)", p.Rules[3].Conditions.All[0].Value, p.Rules[3].Conditions.All[0].Value)
	}
	values[0] = float64(999)
	if _, err := g.Build(compiler.BuildOptions{RustOnly: true}); err != nil {
		t.Fatal("copied numeric list invalid", err)
	}
	cloned := g.Policy()
	if len(cloned.Rules) != 4 || len(cloned.Rules[3].Conditions.All) == 0 {
		t.Fatal("cloned policy is missing the allow rule or its all-condition operand")
	}
	clonedValues, ok := cloned.Rules[3].Conditions.All[0].Value.([]any)
	if !ok || len(clonedValues) == 0 {
		t.Fatalf("expected nonempty cloned numeric operand list, got %T (%v)", cloned.Rules[3].Conditions.All[0].Value, cloned.Rules[3].Conditions.All[0].Value)
	}
	if clonedValues[0] != float64(0) {
		t.Fatal("list operand alias")
	}
}
