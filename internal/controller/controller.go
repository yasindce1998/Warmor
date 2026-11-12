package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/kube"
	"github.com/yasindce1998/warmor/internal/policymerge"
)

// PolicyDataKey is the ConfigMap key the compiled effective policy is
// stored under. The DaemonSet mounts the ConfigMap with this file name.
const PolicyDataKey = "policy.wasm"

// Annotations the controller stamps on the ConfigMap it manages.
const (
	AnnotationPolicySHA = "warmor.io/policy-sha256"
	AnnotationSources   = "warmor.io/sources"
	AnnotationCompiler  = "warmor.io/compiler-version"
)

// Options configures the controller.
type Options struct {
	// Namespace is the namespace whose WarmorPolicies are watched. Empty
	// means all namespaces (merged into one node-wide policy — only
	// appropriate on single-tenant clusters).
	Namespace string
	// ConfigMapNamespace and ConfigMapName identify the ConfigMap the
	// effective policy is synced into.
	ConfigMapNamespace string
	ConfigMapName      string
	// PolicyName is the name of the merged effective policy.
	PolicyName string
	// DefaultPolicyPath is a compiled .wasm synced verbatim while no
	// WarmorPolicy exists (the cluster's baked default, so "no CRs" is a
	// safe, protected state rather than an empty one).
	DefaultPolicyPath string
	// CacheDir caches compiled modules across restarts, keyed by policy
	// content. Empty disables caching (compile per change).
	CacheDir string
	// ResyncPeriod forces a full reconcile this often (self-healing: a
	// ConfigMap edited by hand is overwritten back). 0 disables.
	ResyncPeriod time.Duration
}

// Controller watches WarmorPolicy resources and keeps the effective
// policy ConfigMap in sync.
type Controller struct {
	kube *kube.Client
	opts Options
	// now is stubbed in tests.
	now func() time.Time
}

// New builds a controller.
func New(client *kube.Client, opts Options) *Controller {
	if opts.PolicyName == "" {
		opts.PolicyName = "warmor-effective"
	}
	return &Controller{kube: client, opts: opts, now: time.Now}
}

// compilePolicy compiles a parsed policy to WASM. It is a variable so
// tests can avoid needing the Rust toolchain.
var compilePolicy = func(policy *compiler.Policy, yamlBytes []byte, cacheDir string) ([]byte, error) {
	key, err := policyCacheKey(yamlBytes, policy)
	if err != nil {
		return nil, err
	}
	if cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0o750); err != nil {
			return nil, fmt.Errorf("create policy cache dir: %w", err)
		}
		cached, err := os.ReadFile(filepath.Join(cacheDir, key+".wasm"))
		if err == nil {
			return cached, nil
		}
	}

	// Build to a temporary path and rename into the cache, so an
	// interrupted build never leaves a truncated module at the cache key.
	outPath := filepath.Join(os.TempDir(), "warmor-controller-"+key+".wasm")
	result, err := compiler.Build(policy, compiler.BuildOptions{OutputPath: outPath})
	defer compiler.Cleanup(result)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("read compiled policy: %w", err)
	}
	if cacheDir != "" {
		// Best effort: a failed cache write only costs a rebuild later.
		if err := os.WriteFile(filepath.Join(cacheDir, key+".wasm"), data, 0o640); err != nil {
			log.Printf("⚠️  Policy cache write failed: %v", err)
		}
	}
	return data, nil
}

// policyCacheKey identifies a compiled policy: sha256 over the compiler
// version, the policy YAML and the generated Rust source (which changes
// whenever codegen changes, even when compiler.Version was not bumped).
// Mirrors the daemon's yaml cache key.
func policyCacheKey(yamlBytes []byte, policy *compiler.Policy) (string, error) {
	src, err := compiler.GenerateRust(policy)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprintf(h, "warmor-controller\x00%s\x00%d\x00", compiler.Version, len(yamlBytes))
	h.Write(yamlBytes)
	h.Write([]byte{0})
	h.Write([]byte(src))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// policiesPath is the REST path for listing/watching WarmorPolicies.
func (c *Controller) policiesPath() string {
	return groupPath(c.opts.Namespace) + "/warmorpolicies"
}

func groupPath(namespace string) string {
	if namespace == "" {
		return "/apis/warmor.io/v1alpha1"
	}
	return "/apis/warmor.io/v1alpha1/namespaces/" + namespace
}

func configMapPath(namespace, name string) string {
	return "/api/v1/namespaces/" + namespace + "/configmaps/" + name
}

func configMapsPath(namespace string) string {
	return "/api/v1/namespaces/" + namespace + "/configmaps"
}

// Run drives the controller until ctx is done: reconcile everything,
// watch for changes, repeat. Any event on a WarmorPolicy (or the resync
// timer) restarts the cycle with a fresh list, which keeps the loop
// level-triggered: it converges to the desired state no matter what it
// missed while down.
func (c *Controller) Run(ctx context.Context) error {
	backoff := time.Second
	const maxBackoff = time.Minute
	for {
		rv, err := c.Reconcile(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("❌ Reconcile failed: %v (retrying in %v)", err, backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = time.Second

		if err := c.watchUntilEvent(ctx, rv); err != nil && ctx.Err() == nil {
			log.Printf("⚠️  Watch ended: %v", err)
		}
	}
}

// watchUntilEvent watches the CR collection from resourceVersion rv and
// returns as soon as any event arrives, the resync timer fires, or ctx is
// done.
//
// Two independent mechanisms bound the watch, because the in-cluster e2e
// showed a watch can outlive its client-side cancellation when the pod's
// network blackholes: the resync timer above cancels the context, and the
// timeoutSeconds query parameter asks the API server to close the stream
// itself — the same belt-and-braces client-go's reflector uses. Whichever
// fires first, Run re-lists and converges.
func (c *Controller) watchUntilEvent(ctx context.Context, rv string) error {
	inner, cancel := context.WithCancel(ctx)
	defer cancel()
	gotEvent := false
	if c.opts.ResyncPeriod > 0 {
		timer := time.AfterFunc(c.opts.ResyncPeriod, cancel)
		defer timer.Stop()
	}
	// Server-side deadline: half the resync period (1–10 minutes), so the
	// client timer stays the outer bound and the loop re-lists at least as
	// often as the configured resync.
	watchTimeout := c.opts.ResyncPeriod / 2
	watchTimeout = min(max(watchTimeout, time.Minute), 10*time.Minute)
	path := c.policiesPath() +
		"?watch=true&allowWatchBookmarks=true&resourceVersion=" + url.QueryEscape(rv) +
		"&timeoutSeconds=" + strconv.Itoa(int(watchTimeout.Seconds()))
	err := c.kube.Watch(inner, path, func(kube.WatchEvent) error {
		gotEvent = true
		cancel() // one event is enough; Run re-lists everything
		return nil
	})
	// A cancellation we asked for (event seen) is not a failure, and a
	// stream ended cleanly by the server's timeoutSeconds is not one
	// either — both are the normal end of a watch cycle.
	if err != nil && (gotEvent || errors.Is(err, context.Canceled)) {
		return nil
	}
	return err
}

// Reconcile lists the WarmorPolicies, compiles the effective policy and
// syncs it into the ConfigMap, then updates every CR's status. It returns
// the list's resourceVersion to resume watching from.
func (c *Controller) Reconcile(ctx context.Context) (string, error) {
	var list WarmorPolicyList
	if err := c.kube.Get(ctx, c.policiesPath(), &list); err != nil {
		return "", fmt.Errorf("list WarmorPolicies: %w", err)
	}

	// Sort by namespace/name so the merged rule order is deterministic
	// regardless of the API server's listing order.
	items := make([]*WarmorPolicy, len(list.Items))
	for i := range list.Items {
		items[i] = &list.Items[i]
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Metadata.Namespace != items[j].Metadata.Namespace {
			return items[i].Metadata.Namespace < items[j].Metadata.Namespace
		}
		return items[i].Metadata.Name < items[j].Metadata.Name
	})

	// Render and validate each policy on its own, so a bad CR is reported
	// on that CR instead of failing the whole fleet silently.
	type accepted struct {
		cr       *WarmorPolicy
		rendered *policymerge.PolicyYAML
	}
	var ok []accepted
	statuses := make(map[string]*WarmorPolicyStatus, len(items)) // "ns/name" -> desired status
	for _, cr := range items {
		status, err := c.classify(cr)
		if err != nil {
			return "", err
		}
		statuses[cr.Metadata.Namespace+"/"+cr.Metadata.Name] = status
		if status.Phase == PhaseActive {
			ok = append(ok, accepted{cr: cr, rendered: status.rendered})
		}
	}

	// Build the desired effective policy (or fall back to the baked
	// default when no CR applies) and sync it. Compilation is lazy: it
	// only runs when the ConfigMap does not already carry this content's
	// hash, so a no-op reconcile costs one GET, not a build.
	var hash string
	var sources []string
	var compile func() ([]byte, error)
	switch {
	case len(ok) == 0:
		data, err := os.ReadFile(c.opts.DefaultPolicyPath)
		if err != nil {
			return "", fmt.Errorf("no WarmorPolicy applies and no default policy at %s: %w", c.opts.DefaultPolicyPath, err)
		}
		sum := sha256.Sum256(data)
		hash = "default:" + hex.EncodeToString(sum[:])
		compile = func() ([]byte, error) { return data, nil }
	default:
		rendered := make([]*policymerge.PolicyYAML, len(ok))
		for i, a := range ok {
			rendered[i] = a.rendered
			sources = append(sources, a.cr.Metadata.Namespace+"/"+a.cr.Metadata.Name)
		}
		effective := effectivePolicy(c.opts.PolicyName, rendered)
		yamlBytes, err := policymerge.Marshal(effective)
		if err != nil {
			return "", fmt.Errorf("render effective policy: %w", err)
		}
		parsed, err := compiler.Parse(yamlBytes)
		if err != nil {
			// Every CR validated individually, so a failure here is a
			// merge-level interaction (a controller bug, not user error).
			return "", fmt.Errorf("effective policy does not compile: %w", err)
		}
		sum := sha256.Sum256(yamlBytes)
		hash = "effective:" + hex.EncodeToString(sum[:])
		compile = func() ([]byte, error) { return compilePolicy(parsed, yamlBytes, c.opts.CacheDir) }
	}

	synced, err := c.syncConfigMap(ctx, compile, hash, sources)
	if err != nil {
		return "", err
	}

	// lastApplied moves only when a new policy was actually written; on
	// no-op reconciles the existing timestamp is carried over so the
	// status PUT below stays a no-op too.
	now := c.now().UTC().Format(time.RFC3339)
	for _, a := range ok {
		status := statuses[a.cr.Metadata.Namespace+"/"+a.cr.Metadata.Name]
		if synced {
			status.LastApplied = now
		} else if a.cr.Status != nil {
			status.LastApplied = a.cr.Status.LastApplied
		}
	}
	for _, cr := range items {
		if err := c.updateStatus(ctx, cr, statuses[cr.Metadata.Namespace+"/"+cr.Metadata.Name]); err != nil {
			log.Printf("⚠️  Status update for %s/%s failed: %v", cr.Metadata.Namespace, cr.Metadata.Name, err)
		}
	}
	return list.Metadata.ResourceVersion, nil
}

// classify renders and validates one CR and returns its desired status.
// Phase Active means the rendered policy is stored in the status' private
// rendered field for the merge step.
func (c *Controller) classify(cr *WarmorPolicy) (*WarmorPolicyStatus, error) {
	generation := cr.Metadata.Generation
	if generation == 0 {
		generation = 1
	}

	switch {
	case cr.Spec.Selector != nil && !cr.Spec.Selector.Empty():
		return &WarmorPolicyStatus{
			Phase:              PhasePending,
			ObservedGeneration: generation,
			Conditions: []PolicyCondition{{
				Type:               "Ready",
				Status:             "False",
				LastTransitionTime: c.now().UTC().Format(time.RFC3339),
				Reason:             "SelectorNotSupported",
				Message:            "spec.selector is not evaluated yet: enforcement is node-wide until per-workload policies ship, so this policy is held Pending rather than applied beyond its intended scope",
			}},
		}, nil
	}

	rendered, err := renderPolicy(cr)
	if err == nil {
		// Validate the rendered policy with the same parser the daemon
		// uses at load time, so a CR is only marked Active when the
		// module it contributes to would actually load on a node.
		var yamlBytes []byte
		yamlBytes, err = policymerge.Marshal(rendered)
		if err == nil {
			_, err = compiler.Parse(yamlBytes)
		}
	}
	if err != nil {
		return &WarmorPolicyStatus{
			Phase:              PhaseError,
			ObservedGeneration: generation,
			Conditions: []PolicyCondition{{
				Type:               "Ready",
				Status:             "False",
				LastTransitionTime: c.now().UTC().Format(time.RFC3339),
				Reason:             "InvalidPolicy",
				Message:            err.Error(),
			}},
		}, nil
	}

	status := &WarmorPolicyStatus{
		Phase:              PhaseActive,
		ObservedGeneration: generation,
		Conditions: []PolicyCondition{{
			Type:               "Ready",
			Status:             "True",
			LastTransitionTime: c.now().UTC().Format(time.RFC3339),
			Reason:             "Compiled",
			Message:            fmt.Sprintf("part of the effective policy (%d rules)", len(rendered.Rules)),
		}},
	}
	// rendered rides along privately; it is stripped before the status is
	// sent to the API server.
	status.rendered = rendered
	return status, nil
}

// syncConfigMap ensures the ConfigMap holds exactly the policy compile
// produces, creating or updating it as needed. compile runs only when the
// stored hash does not match. It returns true when a write happened.
func (c *Controller) syncConfigMap(ctx context.Context, compile func() ([]byte, error), hash string, sources []string) (bool, error) {
	annotations := map[string]string{
		AnnotationPolicySHA: hash,
		AnnotationCompiler:  compiler.Version,
	}
	if len(sources) > 0 {
		annotations[AnnotationSources] = strings.Join(sources, ",")
	} else {
		annotations[AnnotationSources] = "cluster-default"
	}
	labels := map[string]string{
		"app.kubernetes.io/managed-by": "warmor-controller",
	}

	var existing ConfigMap
	err := c.kube.Get(ctx, configMapPath(c.opts.ConfigMapNamespace, c.opts.ConfigMapName), &existing)
	switch {
	case err == nil && existing.Metadata.Annotations[AnnotationPolicySHA] == hash:
		return false, nil // already in sync
	case err != nil && !kube.IsNotFound(err):
		return false, fmt.Errorf("read ConfigMap: %w", err)
	}

	wasm, compileErr := compile()
	if compileErr != nil {
		return false, compileErr
	}

	desired := &ConfigMap{
		Metadata: ObjectMeta{
			Name:        c.opts.ConfigMapName,
			Namespace:   c.opts.ConfigMapNamespace,
			Labels:      labels,
			Annotations: annotations,
		},
		BinaryData: map[string][]byte{PolicyDataKey: wasm},
	}

	if err == nil {
		desired.Metadata.ResourceVersion = existing.Metadata.ResourceVersion
		if err := c.kube.Update(ctx, configMapPath(c.opts.ConfigMapNamespace, c.opts.ConfigMapName), desired, nil); err != nil {
			return false, fmt.Errorf("update ConfigMap: %w", err)
		}
		log.Printf("✓ Effective policy updated (%s, %d bytes)", hash, len(wasm))
		return true, nil
	}
	if err := c.kube.Create(ctx, configMapsPath(c.opts.ConfigMapNamespace), desired, nil); err != nil {
		return false, fmt.Errorf("create ConfigMap: %w", err)
	}
	log.Printf("✓ Effective policy created (%s, %d bytes)", hash, len(wasm))
	return true, nil
}

// updateStatus PUTs the status subresource when the desired status
// differs from what the CR already carries.
func (c *Controller) updateStatus(ctx context.Context, cr *WarmorPolicy, desired *WarmorPolicyStatus) error {
	desired.rendered = nil // private field, never serialized
	if statusEqual(cr.Status, desired) {
		return nil
	}
	body := &WarmorPolicy{
		// The status subresource PUT rejects a body without TypeMeta.
		Kind:       "WarmorPolicy",
		APIVersion: "warmor.io/v1alpha1",
		Metadata: ObjectMeta{
			Name:            cr.Metadata.Name,
			Namespace:       cr.Metadata.Namespace,
			ResourceVersion: cr.Metadata.ResourceVersion, // required on update
		},
		Status: desired,
	}
	path := groupPath(cr.Metadata.Namespace) + "/warmorpolicies/" + cr.Metadata.Name + "/status"
	if err := c.kube.Update(ctx, path, body, nil); err != nil {
		return err
	}
	return nil
}

// statusEqual compares everything the controller sets, ignoring fields
// it does not own.
func statusEqual(a, b *WarmorPolicyStatus) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	if a.Phase != b.Phase || a.ObservedGeneration != b.ObservedGeneration || a.LastApplied != b.LastApplied {
		return false
	}
	if len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for i := range a.Conditions {
		x, y := a.Conditions[i], b.Conditions[i]
		if x.Type != y.Type || x.Status != y.Status || x.Reason != y.Reason || x.Message != y.Message {
			return false
		}
	}
	return true
}
