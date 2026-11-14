package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	// CompileTimeout bounds builds, including Rust toolchain checks.
	CompileTimeout time.Duration
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
	if opts.CompileTimeout <= 0 {
		opts.CompileTimeout = 2 * time.Minute
	}
	return &Controller{kube: client, opts: opts, now: time.Now}
}

// compilePolicy compiles a parsed policy to WASM. It is a variable so
// tests can avoid needing the Rust toolchain.
var compilePolicy = func(ctx context.Context, policy *compiler.Policy, yamlBytes []byte, cacheDir string) ([]byte, error) {
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
	outDir, err := os.MkdirTemp("", "warmor-controller-*")
	if err != nil {
		return nil, fmt.Errorf("create build output dir: %w", err)
	}
	defer os.RemoveAll(outDir)
	outPath := filepath.Join(outDir, "policy.wasm")
	result, err := compiler.Build(policy, compiler.BuildOptions{OutputPath: outPath, Context: ctx})
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
		if err := writeCache(cacheDir, key, data); err != nil {
			log.Printf("⚠️  Policy cache write failed: %v", err)
		}
	}
	return data, nil
}

// Bump the profile when build flags or ABI contracts change. Generated Rust
// and Cargo.toml are additionally included in each revision/cache key.
var compilerIdentity = compiler.Version + "/controller-v2/wasm32-release"

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
	fmt.Fprintf(h, "warmor-controller\x00%s\x00%d\x00", compilerIdentity, len(yamlBytes))
	h.Write(yamlBytes)
	h.Write([]byte{0})
	h.Write([]byte(src))
	h.Write([]byte{0})
	h.Write([]byte(compiler.GenerateCargoToml(policy.Name)))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeCache(dir, key string, data []byte) error {
	f, err := os.CreateTemp(dir, ".policy-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, key+".wasm"))
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

	statuses := make(map[string]*WarmorPolicyStatus, len(items))
	for _, cr := range items {
		status, _ := c.classify(cr)
		statuses[sourceKey(cr)] = status
	}
	// Acceptance is committed only in the atomic ConfigMap write containing
	// both source snapshots and compiled bytes. Status is never the journal.
	existing, err := c.readConfigMap(ctx)
	if err == nil {
		err = c.reconcilePublication(ctx, items, statuses, existing)
	} else {
		c.publicationFailure(items, statuses, "PublicationFailed", err)
	}
	var statusErr error
	for _, cr := range items {
		if updateErr := c.updateStatus(ctx, cr, statuses[sourceKey(cr)]); updateErr != nil {
			statusErr = errors.Join(statusErr, fmt.Errorf("update status %s/%s: %w", cr.Metadata.Namespace, cr.Metadata.Name, updateErr))
		}
	}
	return list.Metadata.ResourceVersion, errors.Join(err, statusErr)
}

func (c *Controller) reconcilePublication(ctx context.Context, items []*WarmorPolicy, statuses map[string]*WarmorPolicyStatus, existing *ConfigMap) (err error) {
	stage := "CompilationFailed"
	defer func() {
		if err != nil {
			c.publicationFailure(items, statuses, stage, err)
		}
	}()
	previous, err := c.readSnapshot(existing)
	if err != nil {
		stage = "SnapshotUnavailable"
		return err
	}
	snapshot := sourceSnapshot{Version: 1, WatchNamespace: c.opts.Namespace}
	var rendered []*policymerge.PolicyYAML
	var sources []string
	for _, cr := range items {
		key := sourceKey(cr)
		status := statuses[key]
		if existing != nil && existing.Data[SnapshotDataKey] == "" && status.rendered == nil {
			for _, legacySource := range strings.Split(existing.Metadata.Annotations[AnnotationSources], ",") {
				if legacySource == cr.Metadata.Namespace+"/"+cr.Metadata.Name {
					stage = "SnapshotUnavailable"
					return fmt.Errorf("legacy publication lacks accepted snapshot for invalid source %s; retaining complete previous publication", legacySource)
				}
			}
		}
		var source acceptedSource
		if status.rendered != nil {
			source = snapshotSource(cr)
		} else if old, found := previous[key]; found {
			// Invalid edits (including unsupported selectors) are not deletions.
			// Another UID can never inherit a deleted object's snapshot.
			source = old
			oldStatus, _ := c.classify(old.policy())
			status.rendered = oldStatus.rendered
		} else {
			continue
		}
		snapshot.Sources = append(snapshot.Sources, source)
		rendered = append(rendered, status.rendered)
		sources = append(sources, source.Namespace+"/"+source.Name)
		if old, found := previous[key]; found {
			status.AcceptedGeneration = old.Generation
			status.PublishedDigest = existing.Metadata.Annotations[AnnotationArtifactSHA]
		}
	}
	// Only present UIDs survive. Explicit deletion of the final source
	// restores the baked default rather than retaining a deleted object.
	snapshotBytes, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode accepted sources: %w", err)
	}
	if len(snapshotBytes) > maxSnapshotBytes {
		return fmt.Errorf("accepted-source snapshot exceeds %d-byte budget", maxSnapshotBytes)
	}
	ruleCount := 0
	for _, source := range rendered {
		ruleCount += len(source.Rules)
	}
	if ruleCount > maxEffectiveRules {
		return fmt.Errorf("effective policy exceeds %d-rule budget", maxEffectiveRules)
	}
	var revision string
	var compile func() ([]byte, error)
	if len(rendered) == 0 {
		data, readErr := os.ReadFile(c.opts.DefaultPolicyPath)
		if readErr != nil {
			return fmt.Errorf("read baked default policy: %w", readErr)
		}
		revision = "default:" + digest([]byte(compilerIdentity+"\x00"+digest(data)))
		compile = func() ([]byte, error) { return data, nil }
	} else {
		yamlBytes, marshalErr := policymerge.Marshal(effectivePolicy(c.opts.PolicyName, rendered))
		if marshalErr != nil {
			return fmt.Errorf("render effective policy: %w", marshalErr)
		}
		parsed, parseErr := compiler.Parse(yamlBytes)
		if parseErr != nil {
			return fmt.Errorf("validate effective policy: %w", parseErr)
		}
		key, keyErr := policyCacheKey(yamlBytes, parsed)
		if keyErr != nil {
			return keyErr
		}
		revision = "effective:" + key
		compile = func() ([]byte, error) {
			buildCtx, cancel := context.WithTimeout(ctx, c.opts.CompileTimeout)
			defer cancel()
			return compilePolicy(buildCtx, parsed, yamlBytes, c.opts.CacheDir)
		}
	}
	for _, status := range statuses {
		if status.rendered != nil {
			status.DesiredRevision = revision
		}
	}
	// Hash the actual bytes, not just source annotations. This is an integrity
	// checksum, not authentication against an authorized ConfigMap writer.
	var wasm []byte
	if existing != nil && existing.Metadata.Annotations[AnnotationPolicySHA] == revision &&
		existing.Metadata.Annotations[AnnotationCompiler] == compilerIdentity &&
		len(existing.BinaryData[PolicyDataKey]) > 0 &&
		digest(existing.BinaryData[PolicyDataKey]) == existing.Metadata.Annotations[AnnotationArtifactSHA] {
		wasm = existing.BinaryData[PolicyDataKey]
	} else {
		wasm, err = compile()
		if err != nil {
			return err
		}
	}
	if len(wasm) == 0 {
		return fmt.Errorf("compiler produced an empty artifact")
	}
	artifactDigest := digest(wasm)
	for _, status := range statuses {
		if status.rendered != nil {
			status.DesiredDigest = artifactDigest
		}
	}
	stage = "PublicationFailed"
	synced, err := c.syncConfigMap(ctx, existing, wasm, revision, sources, string(snapshotBytes))
	if err != nil {
		return err
	}
	for _, cr := range items {
		status := statuses[sourceKey(cr)]
		if status.rendered == nil {
			continue
		}
		for _, source := range snapshot.Sources {
			if sourceKey(source.policy()) == sourceKey(cr) {
				status.AcceptedGeneration = source.Generation
			}
		}
		status.PublishedDigest = artifactDigest
		if synced {
			status.LastPublished = c.now().UTC().Format(time.RFC3339)
		} else if cr.Status != nil {
			status.LastPublished = cr.Status.LastPublished
		}
		c.setCondition(status, "Compiled", "True", "Compiled", "accepted source is part of the compiled effective artifact")
		c.setCondition(status, "Published", "True", "Published", "accepted source is published; node activation is not acknowledged")
		if status.Phase == PhasePublished {
			c.setCondition(status, "Ready", "False", "AwaitingNodeAcknowledgement", "publication does not prove that any node loaded or enforced this digest")
		} else {
			c.setCondition(status, "Published", "True", "LastKnownGoodPublished", "previous accepted generation remains published; desired spec was not accepted")
		}
	}
	return nil
}

// classify validates desired syntax, not compilation, publication or activation.
func (c *Controller) classify(cr *WarmorPolicy) (*WarmorPolicyStatus, error) {
	generation := cr.Metadata.Generation
	if generation == 0 {
		generation = 1
	}

	status := &WarmorPolicyStatus{Phase: PhasePending, ObservedGeneration: generation}
	c.setCondition(status, "Ready", "False", "AwaitingPublication", "desired policy has not been published")
	c.setCondition(status, "Validated", "Unknown", "NotValidated", "desired policy has not been validated")
	c.setCondition(status, "Compiled", "Unknown", "NotCompiled", "desired policy has not been compiled")
	c.setCondition(status, "Published", "Unknown", "NotPublished", "desired policy has not been published")
	c.setCondition(status, "Applied", "Unknown", "NoNodeAcknowledgements", "no authenticated per-node acknowledgement is available; nodesApplied and lastApplied are not asserted")
	if cr.Metadata.Namespace == "" || cr.Metadata.Name == "" || cr.Metadata.UID == "" {
		status.Phase = PhaseError
		c.setCondition(status, "Ready", "False", "InvalidIdentity", "namespace, name and UID are required for durable source identity")
		c.setCondition(status, "Validated", "False", "InvalidIdentity", "namespace, name and UID are required")
		return status, nil
	}
	if cr.Spec.Selector != nil && !cr.Spec.Selector.Empty() {
		c.setCondition(status, "Ready", "False", "SelectorNotSupported", "spec.selector is not evaluated: policy remains Pending; any previous node-wide accepted generation is retained until explicit deletion")
		c.setCondition(status, "Validated", "False", "SelectorNotSupported", "workload-scoped execution is not implemented")
		return status, nil
	}
	specBytes, specErr := json.Marshal(cr.Spec)
	if specErr != nil || len(specBytes) > maxSourceBytes || len(cr.Spec.Rules) > maxSourceRules {
		status.Phase = PhaseError
		c.setCondition(status, "Ready", "False", "PolicyBudgetExceeded", "desired spec exceeds source byte or rule budget; previous accepted generation retained")
		c.setCondition(status, "Validated", "False", "PolicyBudgetExceeded", fmt.Sprintf("maximum source size is %d bytes and %d rules", maxSourceBytes, maxSourceRules))
		return status, nil
	}

	rendered, err := renderPolicy(cr)
	if err == nil {
		// Validate the rendered policy with the same parser the daemon
		// uses for syntax validation. This does not prove node activation.
		var yamlBytes []byte
		yamlBytes, err = policymerge.Marshal(rendered)
		if err == nil {
			_, err = compiler.Parse(yamlBytes)
		}
	}
	if err != nil {
		status.Phase = PhaseError
		// Parser diagnostics may include policy operands; do not copy raw
		// source values (which users sometimes put secrets in) into status.
		c.setCondition(status, "Ready", "False", "InvalidPolicy", "desired spec failed policy validation; any previous accepted generation is retained")
		c.setCondition(status, "Validated", "False", "InvalidPolicy", "desired spec failed policy validation")
		return status, nil
	}
	status.Phase = PhasePublished // provisional; failure handling changes it
	c.setCondition(status, "Validated", "True", "Validated", fmt.Sprintf("desired spec validates (%d rules)", len(rendered.Rules)))
	// rendered rides along privately; it is stripped before the status is
	// sent to the API server.
	status.rendered = rendered
	return status, nil
}

func (c *Controller) setCondition(status *WarmorPolicyStatus, typ, value, reason, message string) {
	condition := PolicyCondition{Type: typ, Status: value, Reason: reason, Message: message, LastTransitionTime: c.now().UTC().Format(time.RFC3339)}
	for i := range status.Conditions {
		if status.Conditions[i].Type == typ {
			status.Conditions[i] = condition
			return
		}
	}
	status.Conditions = append(status.Conditions, condition)
}

func (c *Controller) publicationFailure(items []*WarmorPolicy, statuses map[string]*WarmorPolicyStatus, stage string, err error) {
	// Do not copy compiler stderr or source operands into status. Expose safe
	// actionable categories while the reconcile error retains details.
	detail := ""
	var apiError *kube.StatusError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		detail = "; compilation deadline exceeded"
	case errors.Is(err, context.Canceled):
		detail = "; operation cancelled"
	case errors.As(err, &apiError):
		detail = fmt.Sprintf("; Kubernetes API HTTP %d", apiError.Code)
	}
	for _, cr := range items {
		status := statuses[sourceKey(cr)]
		if cr.Status != nil {
			if status.AcceptedGeneration == 0 {
				status.AcceptedGeneration = cr.Status.AcceptedGeneration
			}
			status.LastPublished = cr.Status.LastPublished
			// Historical publication digest, never an active digest.
			if status.PublishedDigest == "" {
				status.PublishedDigest = cr.Status.PublishedDigest
			}
		}
		if status.Phase == PhasePublished {
			status.Phase = PhaseError
			c.setCondition(status, "Ready", "False", stage, "effective policy update failed; previous publication has not been replaced")
		}
		if stage == "CompilationFailed" {
			c.setCondition(status, "Compiled", "False", stage, "effective artifact compilation failed; previous publication retained"+detail)
		} else if stage == "PublicationFailed" && status.DesiredDigest != "" {
			c.setCondition(status, "Compiled", "True", "Compiled", "desired effective artifact compiled but could not be published")
		}
		c.setCondition(status, "Published", "False", stage, "desired publication failed; controller will retry without replacing previous bytes or accepted snapshots"+detail)
	}
}

func (c *Controller) readConfigMap(ctx context.Context) (*ConfigMap, error) {
	var existing ConfigMap
	err := c.kube.Get(ctx, configMapPath(c.opts.ConfigMapNamespace, c.opts.ConfigMapName), &existing)
	if kube.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read ConfigMap: %w", err)
	}
	if existing.Metadata.Labels["app.kubernetes.io/managed-by"] != "warmor-controller" {
		return nil, fmt.Errorf("refusing to overwrite ConfigMap not managed by warmor-controller")
	}
	return &existing, nil
}

// syncConfigMap commits artifact and accepted sources together. Conflicts are
// retried by Run using a fresh CR list AND snapshot, never a stale PUT.
func (c *Controller) syncConfigMap(ctx context.Context, existing *ConfigMap, wasm []byte, hash string, sources []string, snapshot string) (bool, error) {
	annotations := map[string]string{
		AnnotationPolicySHA:   hash,
		AnnotationCompiler:    compilerIdentity,
		AnnotationArtifactSHA: digest(wasm),
		AnnotationSnapshotSHA: digest([]byte(snapshot)),
	}
	if len(sources) > 0 {
		annotations[AnnotationSources] = strings.Join(sources, ",")
	} else {
		annotations[AnnotationSources] = "cluster-default"
	}
	labels := map[string]string{
		"app.kubernetes.io/managed-by": "warmor-controller",
	}

	desired := &ConfigMap{
		Metadata: ObjectMeta{
			Name:        c.opts.ConfigMapName,
			Namespace:   c.opts.ConfigMapNamespace,
			Labels:      labels,
			Annotations: annotations,
		},
		BinaryData: map[string][]byte{PolicyDataKey: wasm},
		Data:       map[string]string{SnapshotDataKey: snapshot},
	}
	if len(wasm)+len(snapshot) > maxConfigMapBytes {
		return false, fmt.Errorf("artifact and accepted sources exceed %d-byte ConfigMap budget", maxConfigMapBytes)
	}
	if existing != nil {
		matches := string(existing.BinaryData[PolicyDataKey]) == string(wasm) && existing.Data[SnapshotDataKey] == snapshot
		for key, value := range annotations {
			matches = matches && existing.Metadata.Annotations[key] == value
		}
		if matches {
			return false, nil
		}
		if existing.Immutable != nil && *existing.Immutable {
			return false, fmt.Errorf("managed ConfigMap is immutable; cannot publish new artifact or accepted sources")
		}
		// Preserve unowned metadata, including ownerReferences and labels.
		metadata := existing.Metadata
		if metadata.Annotations == nil {
			metadata.Annotations = make(map[string]string)
		}
		for key, value := range annotations {
			metadata.Annotations[key] = value
		}
		desired.Metadata = metadata
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
	if cr.Status != nil {
		for i := range desired.Conditions {
			for _, previous := range cr.Status.Conditions {
				current := &desired.Conditions[i]
				if previous.Type == current.Type && previous.Status == current.Status {
					current.LastTransitionTime = previous.LastTransitionTime
				}
			}
		}
	}
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
	if a.Phase != b.Phase || a.ObservedGeneration != b.ObservedGeneration || a.LastApplied != b.LastApplied ||
		a.AcceptedGeneration != b.AcceptedGeneration || a.DesiredRevision != b.DesiredRevision ||
		a.DesiredDigest != b.DesiredDigest || a.PublishedDigest != b.PublishedDigest || a.LastPublished != b.LastPublished || a.NodesApplied != b.NodesApplied {
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
