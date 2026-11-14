package workload

import (
	"reflect"
	"slices"
	"testing"

	"github.com/opencontainers/go-digest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func expr(key string, operator metav1.LabelSelectorOperator, values ...string) metav1.LabelSelector {
	return metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: key, Operator: operator, Values: values}}}
}

func TestSelectorKubernetesSemantics(t *testing.T) {
	id := verifiedIdentity(t, fixture())
	tests := []struct {
		name, namespace string
		spec            metav1.LabelSelector
		want            bool
	}{
		{"empty selects namespace", "team-a", metav1.LabelSelector{}, true},
		{"namespace isolation", "team-b", metav1.LabelSelector{}, false},
		{"label match", "team-a", metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}, true},
		{"runtime labels cannot match", "team-a", metav1.LabelSelector{MatchLabels: map[string]string{"app": "untrusted-runtime-label"}}, false},
		{"label mismatch", "team-a", metav1.LabelSelector{MatchLabels: map[string]string{"app": "worker"}}, false},
		{"absent empty label", "team-a", metav1.LabelSelector{MatchLabels: map[string]string{"absent": ""}}, false},
		{"AND labels", "team-a", metav1.LabelSelector{MatchLabels: map[string]string{"app": "api", "tier": "wrong"}}, false},
		{"In", "team-a", expr("app", metav1.LabelSelectorOpIn, "api", "worker"), true},
		{"In absent", "team-a", expr("missing", metav1.LabelSelectorOpIn, "api"), false},
		{"NotIn", "team-a", expr("app", metav1.LabelSelectorOpNotIn, "worker"), true},
		{"NotIn absent matches", "team-a", expr("missing", metav1.LabelSelectorOpNotIn, "api"), true},
		{"NotIn excluded", "team-a", expr("app", metav1.LabelSelectorOpNotIn, "api"), false},
		{"Exists", "team-a", expr("app", metav1.LabelSelectorOpExists), true},
		{"Exists absent", "team-a", expr("missing", metav1.LabelSelectorOpExists), false},
		{"DoesNotExist", "team-a", expr("missing", metav1.LabelSelectorOpDoesNotExist), true},
		{"DoesNotExist present", "team-a", expr("app", metav1.LabelSelectorOpDoesNotExist), false},
		{"labels AND expressions", "team-a", metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}, MatchExpressions: expr("tier", metav1.LabelSelectorOpNotIn, "frontend").MatchExpressions}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selector, err := CompileSelector(test.namespace, test.spec)
			if err != nil {
				t.Fatal(err)
			}
			if got := selector.Matches(id); got != test.want {
				t.Fatalf("Matches = %v, want %v", got, test.want)
			}
			if selector.Matches(Identity{}) {
				t.Fatal("unknown identity matched")
			}
		})
	}
	if (Selector{}).Matches(id) {
		t.Fatal("zero-value selector matched")
	}
}

func TestSelectorRejectsInvalidAndCopiesInputs(t *testing.T) {
	for _, spec := range []metav1.LabelSelector{
		expr("app", "Unknown", "api"), expr("app", metav1.LabelSelectorOpIn), expr("app", metav1.LabelSelectorOpNotIn),
		expr("app", metav1.LabelSelectorOpExists, "api"), expr("app", metav1.LabelSelectorOpDoesNotExist, "api"),
		expr("invalid/key/again", metav1.LabelSelectorOpExists), expr("app", metav1.LabelSelectorOpIn, "invalid value"),
		{MatchLabels: map[string]string{"invalid key": "api"}},
	} {
		if _, err := CompileSelector("team-a", spec); err == nil {
			t.Fatalf("accepted selector %+v", spec)
		}
	}
	for _, namespace := range []string{"", "*", "Team_A", "namespace/other"} {
		if _, err := CompileSelector(namespace, metav1.LabelSelector{}); err == nil {
			t.Fatalf("accepted namespace %q", namespace)
		}
	}
	spec := expr("app", metav1.LabelSelectorOpIn, "api")
	spec.MatchLabels = map[string]string{"tier": "frontend"}
	selector, err := CompileSelector("team-a", spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.MatchLabels["tier"] = "changed"
	spec.MatchExpressions[0].Values[0] = "changed"
	if !selector.Matches(verifiedIdentity(t, fixture())) {
		t.Fatal("selector aliases caller input")
	}
}

func candidate(namespace, uid string, generation int64) Candidate {
	return Candidate{Policy: PolicyGeneration{Namespace: namespace, UID: types.UID(uid), Generation: generation, Digest: digest.FromString(uid)}}
}

func TestCatalogSelectsExactGenerationsDeterministically(t *testing.T) {
	candidates := []Candidate{candidate("team-a", "uid-z", 7), candidate("team-b", "uid-a", 9), candidate("team-a", "uid-a", 2), candidate("team-a", "uid-no-match", 3)}
	candidates[3].Selector = expr("app", metav1.LabelSelectorOpIn, "worker")
	want := []PolicyGeneration{candidates[2].Policy, candidates[0].Policy}
	id := verifiedIdentity(t, fixture())
	for range 2 {
		catalog, err := NewCatalog(candidates)
		if err != nil {
			t.Fatal(err)
		}
		got := catalog.Select(id)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("selected = %+v, want %+v", got, want)
		}
		if len(catalog.Select(Identity{})) != 0 {
			t.Fatal("selected unknown")
		}
		got[0].Generation = 1000
		if !reflect.DeepEqual(catalog.Select(id), want) {
			t.Fatal("selection aliases catalog")
		}
		slices.Reverse(candidates)
	}
	var nilCatalog *Catalog
	if len(nilCatalog.Select(id)) != 0 {
		t.Fatal("nil catalog selected")
	}
	if c, err := NewCatalog(nil); err != nil || len(c.Select(id)) != 0 {
		t.Fatalf("empty catalog: %+v, %v", c, err)
	}
}

func TestCatalogRejectsInvalidAndDuplicateSources(t *testing.T) {
	for _, mutate := range []func(*Candidate){
		func(c *Candidate) { c.Policy.Namespace = "" }, func(c *Candidate) { c.Policy.UID = "" },
		func(c *Candidate) { c.Policy.Generation = 0 }, func(c *Candidate) { c.Policy.Generation = -1 },
		func(c *Candidate) { c.Policy.Digest = "" }, func(c *Candidate) { c.Policy.Digest = "sha256:bad" },
		func(c *Candidate) {
			c.Policy.Digest = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		func(c *Candidate) { c.Policy.Digest = "md5:d41d8cd98f00b204e9800998ecf8427e" },
		func(c *Candidate) { c.Selector = expr("app", "bad") },
	} {
		c := candidate("team-a", "uid-a", 1)
		mutate(&c)
		if _, err := NewCatalog([]Candidate{c}); err == nil {
			t.Fatalf("accepted candidate: %+v", c)
		}
	}
	c := candidate("team-a", "uid-a", 1)
	other := c
	other.Policy.Generation = 2
	other.Policy.Digest = digest.FromString("different artifact")
	if _, err := NewCatalog([]Candidate{c, c}); err == nil {
		t.Fatal("accepted duplicate source")
	}
	if _, err := NewCatalog([]Candidate{c, other}); err == nil {
		t.Fatal("accepted conflicting generations")
	}
	other.Policy.Namespace = "team-b"
	if _, err := NewCatalog([]Candidate{c, other}); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogLabelChangeAndGenerationReplacement(t *testing.T) {
	in := fixture()
	c := candidate("team-a", "uid-a", 1)
	c.Selector = expr("app", metav1.LabelSelectorOpIn, "api")
	catalog, err := NewCatalog([]Candidate{c})
	if err != nil {
		t.Fatal(err)
	}
	oldIdentity := verifiedIdentity(t, in)
	if len(catalog.Select(oldIdentity)) != 1 {
		t.Fatal("initial identity not selected")
	}
	in.Pods[0].Labels["app"] = "worker"
	if len(catalog.Select(verifiedIdentity(t, in))) != 0 {
		t.Fatal("label change did not remove selection")
	}
	c.Policy.Generation = 2
	c.Policy.Digest = digest.FromString("updated artifact")
	next, err := NewCatalog([]Candidate{c})
	if err != nil {
		t.Fatal(err)
	}
	c.Selector.MatchExpressions[0].Values[0] = "mutated-input"
	selected := next.Select(oldIdentity)
	if len(selected) != 1 || selected[0].Generation != 2 || selected[0].Digest != digest.FromString("updated artifact") {
		t.Fatalf("replacement = %+v", selected)
	}
	if catalog.Select(oldIdentity)[0].Generation != 1 {
		t.Fatal("old catalog mutated")
	}
}
