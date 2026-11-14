package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/kube"
)

// fakeAPI is a stand-in API server holding WarmorPolicies and the
// effective-policy ConfigMap in memory.
type fakeAPI struct {
	mu         sync.Mutex
	policies   map[string]*WarmorPolicy // "ns/name" -> object
	configMaps map[string]*ConfigMap    // "ns/name" -> object
	rv         int

	statusPUTs    map[string]int
	configMapPUTs int
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{
		policies:   map[string]*WarmorPolicy{},
		configMaps: map[string]*ConfigMap{},
		statusPUTs: map[string]int{},
	}
}

func (f *fakeAPI) addCR(cr *WarmorPolicy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rv++
	cr.Metadata.ResourceVersion = fmt.Sprint(f.rv)
	f.policies[cr.Metadata.Namespace+"/"+cr.Metadata.Name] = cr
}

func (f *fakeAPI) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/apis/warmor.io/v1alpha1/namespaces/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		rest := strings.TrimPrefix(r.URL.Path, "/apis/warmor.io/v1alpha1/namespaces/")
		parts := strings.Split(rest, "/")
		ns, resource := parts[0], parts[1]
		name := ""
		if len(parts) > 2 {
			name = parts[2]
		}
		switch {
		case resource == "warmorpolicies" && name == "" && r.Method == http.MethodGet:
			list := WarmorPolicyList{Metadata: ListMeta{ResourceVersion: fmt.Sprint(f.rv)}}
			for _, cr := range f.policies {
				if cr.Metadata.Namespace == ns {
					list.Items = append(list.Items, *cr)
				}
			}
			writeJSON(w, list)
		case resource == "warmorpolicies" && len(parts) == 4 && parts[3] == "status":
			key := ns + "/" + name
			var body WarmorPolicy
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode status body: %v", err)
			}
			// The real API server rejects a status PUT without TypeMeta
			// ("Object 'Kind' is missing"); mirror that so a regression
			// cannot pass the suite.
			if body.Kind != "WarmorPolicy" || body.APIVersion != "warmor.io/v1alpha1" {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]any{
					"message": "the object provided is unrecognized (must be of type WarmorPolicy): Object 'Kind' is missing",
					"reason":  "Invalid",
					"code":    400,
				})
				return
			}
			// The real API server also rejects an update without the
			// current resourceVersion.
			if body.Metadata.ResourceVersion == "" {
				w.WriteHeader(http.StatusConflict)
				writeJSON(w, map[string]any{
					"message": "metadata.resourceVersion: Invalid value: 0: must be specified for an update",
					"reason":  "Invalid",
					"code":    422,
				})
				return
			}
			cr, ok := f.policies[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			f.statusPUTs[key]++
			cr.Status = body.Status
			writeJSON(w, cr)
		default:
			t.Errorf("unexpected CR request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	mux.HandleFunc("/api/v1/namespaces/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/")
		parts := strings.Split(rest, "/")
		ns, resource := parts[0], parts[1]
		switch {
		case resource == "configmaps" && len(parts) == 2 && r.Method == http.MethodPost:
			var cm ConfigMap
			if err := json.NewDecoder(r.Body).Decode(&cm); err != nil {
				t.Errorf("decode configmap: %v", err)
			}
			key := ns + "/" + cm.Metadata.Name
			if _, exists := f.configMaps[key]; exists {
				w.WriteHeader(http.StatusConflict)
				return
			}
			f.rv++
			cm.Metadata.ResourceVersion = fmt.Sprint(f.rv)
			f.configMaps[key] = &cm
			writeJSON(w, cm)
		case resource == "configmaps" && len(parts) == 3:
			key := ns + "/" + parts[2]
			cm, ok := f.configMaps[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"code":404,"reason":"NotFound","message":"not found"}`)
				return
			}
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, cm)
			case http.MethodPut:
				var body ConfigMap
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode configmap: %v", err)
				}
				f.configMapPUTs++
				body.Metadata.ResourceVersion = cm.Metadata.ResourceVersion
				f.configMaps[key] = &body
				writeJSON(w, &body)
			default:
				t.Errorf("unexpected configmap method %s", r.Method)
			}
		default:
			t.Errorf("unexpected configmap request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return mux
}

// stubCompile replaces the cargo-backed compiler with a deterministic
// fake so tests need no Rust toolchain. It records the YAML it was asked
// to compile.
func stubCompile(t *testing.T) (*[]string, func()) {
	t.Helper()
	original := compilePolicy
	var seen []string
	compilePolicy = func(_ context.Context, policy *compiler.Policy, yamlBytes []byte, cacheDir string) ([]byte, error) {
		seen = append(seen, string(yamlBytes))
		return []byte("wasm(" + policy.Name + ")"), nil
	}
	return &seen, func() { compilePolicy = original }
}

func newTestController(t *testing.T, api *fakeAPI, opts Options) *Controller {
	t.Helper()
	srv := httptest.NewServer(api.handler(t))
	t.Cleanup(srv.Close)
	if opts.ConfigMapName == "" {
		opts.ConfigMapName = "warmor-effective-policy"
	}
	if opts.ConfigMapNamespace == "" {
		opts.ConfigMapNamespace = "warmor-system"
	}
	if opts.Namespace == "" {
		opts.Namespace = "warmor-system"
	}
	if opts.DefaultPolicyPath == "" {
		path := filepath.Join(t.TempDir(), "default.wasm")
		if err := os.WriteFile(path, []byte("default policy wasm"), 0o644); err != nil {
			t.Fatal(err)
		}
		opts.DefaultPolicyPath = path
	}
	return New(kube.New(&kube.Config{BaseURL: srv.URL}), opts)
}

func TestReconcile_SyncsActivePolicyAndStatus(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()

	api := newFakeAPI()
	api.addCR(testCR("alpha", nil))
	ctl := newTestController(t, api, Options{})

	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	cm := api.configMaps["warmor-system/warmor-effective-policy"]
	if cm == nil {
		t.Fatal("effective policy ConfigMap was not created")
	}
	if string(cm.BinaryData[PolicyDataKey]) != "wasm(warmor-effective)" {
		t.Errorf("configmap data = %q", cm.BinaryData[PolicyDataKey])
	}
	if cm.Metadata.Annotations[AnnotationSources] != "warmor-system/alpha" {
		t.Errorf("sources = %q", cm.Metadata.Annotations[AnnotationSources])
	}

	cr := api.policies["warmor-system/alpha"]
	if cr.Status == nil || cr.Status.Phase != PhasePublished {
		t.Fatalf("status = %+v, want Published", cr.Status)
	}
	if cr.Status.LastPublished == "" || cr.Status.LastApplied != "" || cr.Status.NodesApplied != 0 {
		t.Error("publication must not claim node application")
	}
}

func TestReconcile_SkipsUnchangedConfigMap(t *testing.T) {
	compiles, restore := stubCompile(t)
	defer restore()

	api := newFakeAPI()
	api.addCR(testCR("alpha", nil))
	ctl := newTestController(t, api, Options{})

	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	puts := api.statusPUTs["warmor-system/alpha"]
	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	if len(*compiles) != 1 {
		t.Errorf("compiled %d times, want 1 (unchanged content)", len(*compiles))
	}
	if api.configMapPUTs != 0 {
		t.Errorf("configmap updated %d times on a no-op reconcile", api.configMapPUTs)
	}
	if api.statusPUTs["warmor-system/alpha"] != puts {
		t.Error("status rewritten on a no-op reconcile")
	}
}

func TestReconcile_RecompilesOnPolicyChange(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()

	api := newFakeAPI()
	api.addCR(testCR("alpha", nil))
	ctl := newTestController(t, api, Options{})
	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	api.addCR(testCR("beta", func(s *WarmorPolicySpec) {
		s.Rules[0].Action = "allow"
	}))
	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	cm := api.configMaps["warmor-system/warmor-effective-policy"]
	sources := cm.Metadata.Annotations[AnnotationSources]
	if sources != "warmor-system/alpha,warmor-system/beta" {
		t.Errorf("sources = %q", sources)
	}
	// Most-restrictive-first: beta's allow must follow alpha's deny in
	// the compiled YAML.
	data := string(cm.BinaryData[PolicyDataKey])
	if data != "wasm(warmor-effective)" {
		t.Errorf("unexpected module %q", data)
	}
	if api.statusPUTs["warmor-system/beta"] == 0 {
		t.Error("beta status never written")
	}
}

func TestReconcile_InvalidPolicyIsErrorOthersStillSync(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()

	api := newFakeAPI()
	api.addCR(testCR("bad", func(s *WarmorPolicySpec) {
		s.Rules[0].Event = "syscall" // invalid for the daemon schema
	}))
	api.addCR(testCR("good", nil))
	ctl := newTestController(t, api, Options{})

	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	bad := api.policies["warmor-system/bad"]
	if bad.Status.Phase != PhaseError {
		t.Errorf("bad status = %+v, want Error", bad.Status)
	}
	if bad.Status.Conditions[0].Reason != "InvalidPolicy" {
		t.Errorf("condition = %+v, want validation failure", bad.Status.Conditions[0])
	}
	good := api.policies["warmor-system/good"]
	if good.Status.Phase != PhasePublished {
		t.Errorf("good status = %+v, want Published (one bad CR must not block the fleet)", good.Status)
	}
	cm := api.configMaps["warmor-system/warmor-effective-policy"]
	if cm == nil || !strings.Contains(cm.Metadata.Annotations[AnnotationSources], "warmor-system/good") {
		t.Errorf("effective policy sources = %+v", cm)
	}
	if strings.Contains(cm.Metadata.Annotations[AnnotationSources], "warmor-system/bad") {
		t.Error("invalid policy leaked into the effective policy")
	}
}

func TestReconcile_SelectorHeldPending(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()

	api := newFakeAPI()
	api.addCR(testCR("scoped", func(s *WarmorPolicySpec) {
		s.Selector = &Selector{MatchLabels: map[string]string{"app": "payments"}}
	}))
	ctl := newTestController(t, api, Options{})

	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	cr := api.policies["warmor-system/scoped"]
	if cr.Status.Phase != PhasePending {
		t.Fatalf("status = %+v, want Pending", cr.Status)
	}
	if cr.Status.Conditions[0].Reason != "SelectorNotSupported" {
		t.Errorf("condition reason = %q", cr.Status.Conditions[0].Reason)
	}
	// The effective policy still exists (the baked default), but the
	// scoped CR must not be part of it.
	cm := api.configMaps["warmor-system/warmor-effective-policy"]
	if cm == nil {
		t.Fatal("default policy ConfigMap missing")
	}
	if sources := cm.Metadata.Annotations[AnnotationSources]; sources != "cluster-default" {
		t.Errorf("sources = %q, selector-scoped policy must not contribute", sources)
	}
}

func TestReconcile_NoCRsSyncsBakedDefault(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()

	api := newFakeAPI()
	ctl := newTestController(t, api, Options{})

	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	cm := api.configMaps["warmor-system/warmor-effective-policy"]
	if cm == nil {
		t.Fatal("default policy ConfigMap was not created")
	}
	if string(cm.BinaryData[PolicyDataKey]) != "default policy wasm" {
		t.Errorf("configmap data = %q, want the baked default", cm.BinaryData[PolicyDataKey])
	}
	if cm.Metadata.Annotations[AnnotationSources] != "cluster-default" {
		t.Errorf("sources = %q", cm.Metadata.Annotations[AnnotationSources])
	}
}

func TestReconcile_OverwritesDriftedConfigMap(t *testing.T) {
	// Someone edited the ConfigMap by hand: the next reconcile (e.g. the
	// resync tick) must put the controller's policy back.
	_, restore := stubCompile(t)
	defer restore()

	api := newFakeAPI()
	api.addCR(testCR("alpha", nil))
	ctl := newTestController(t, api, Options{})
	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	cm := api.configMaps["warmor-system/warmor-effective-policy"]
	cm.BinaryData[PolicyDataKey] = []byte("tampered")

	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	cm = api.configMaps["warmor-system/warmor-effective-policy"]
	if string(cm.BinaryData[PolicyDataKey]) != "wasm(warmor-effective)" {
		t.Errorf("drifted configmap not healed: %q", cm.BinaryData[PolicyDataKey])
	}
}
