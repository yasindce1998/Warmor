package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/nodereceipt"
	"github.com/yasindce1998/warmor/internal/policybuild"
)

// EnableReceipts must be explicitly called before Run or serving any handlers.
// RequiredNodes is an operator-owned desired roster; it cannot be inferred from
// the online pods. The separate receipt listener MUST use TLS.
func (c *Controller) EnableReceipts(cfg nodereceipt.Config, posture nodereceipt.Posture) error {
	if c.receipts != nil {
		return fmt.Errorf("receipts already enabled")
	}
	cfg.Desired = c.publishedManifest
	s, err := nodereceipt.NewServer(cfg)
	if err != nil {
		return err
	}
	c.receipts, c.receiptPosture = s, posture
	// Library callers, not just the CLI, must re-evaluate expiry without new
	// policy events. Status consumers still must honor receiptExpiresAt.
	c.opts.ResyncPeriod = min(cfg.MaxAge/3, 10*time.Second)
	return nil
}

func (c *Controller) ReceiptHandler() http.Handler {
	if c.receipts == nil {
		return http.NotFoundHandler()
	}
	return c.receipts.Handler()
}

func (c *Controller) publishedManifest(ctx context.Context) (nodereceipt.Manifest, error) {
	var m nodereceipt.Manifest
	cm, err := c.readConfigMap(ctx)
	if err != nil {
		return m, err
	}
	if cm == nil {
		return m, fmt.Errorf("no desired publication")
	}
	if err := json.Unmarshal([]byte(cm.Data[nodereceipt.ManifestDataKey]), &m); err != nil {
		return m, err
	}
	if err := m.Validate(); err != nil {
		return m, err
	}
	metadata, err := policybuild.Read(cm.BinaryData[PolicyDataKey])
	if err != nil || metadata == nil || metadata.Compiler != compiler.Identity || metadata.Compiler != m.ArtifactCompiler || metadata.DefaultAction != m.DefaultAction {
		return m, fmt.Errorf("artifact build metadata mismatch")
	}
	if m.Posture != c.receiptPosture || m.Compiler != compilerIdentity || m.Compiler != cm.Metadata.Annotations[AnnotationCompiler] || m.Revision != cm.Metadata.Annotations[AnnotationPolicySHA] || m.Digest != digest(cm.BinaryData[PolicyDataKey]) || m.Digest != cm.Metadata.Annotations[AnnotationArtifactSHA] || m.SnapshotDigest != digest([]byte(cm.Data[SnapshotDataKey])) || m.SnapshotDigest != cm.Metadata.Annotations[AnnotationSnapshotSHA] {
		return m, fmt.Errorf("publication identity mismatch")
	}
	snapshot, err := c.readSnapshot(cm)
	if err != nil || len(snapshot) != len(m.Sources) {
		return m, fmt.Errorf("unverified accepted generations")
	}
	for _, source := range m.Sources {
		cr := &WarmorPolicy{Metadata: ObjectMeta{Namespace: source.Namespace, Name: source.Name, UID: source.UID}}
		accepted, ok := snapshot[sourceKey(cr)]
		if !ok || accepted.Generation != source.Generation {
			return m, fmt.Errorf("accepted generation mismatch")
		}
	}
	return m, nil
}

func (c *Controller) aggregateReceipts(ctx context.Context, items []*WarmorPolicy, statuses map[string]*WarmorPolicyStatus) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	m, err := c.publishedManifest(ctx)
	var result nodereceipt.Result
	if err == nil {
		result, err = c.receipts.Aggregate(ctx, m)
	}
	for _, cr := range items {
		status := statuses[sourceKey(cr)]
		// Unsupported selectors and retained last-known-good generations NEVER
		// acquire Applied/Ready for a newer unaccepted spec, even equal bytes.
		if status.Phase != PhasePublished || cr.Spec.Selector != nil || status.AcceptedGeneration != cr.Metadata.Generation {
			continue
		}
		if err != nil {
			c.setCondition(status, "Applied", "Unknown", "UnverifiedDesiredRoster", "desired publication or complete authorized daemon roster could not be verified")
			continue
		}
		included := false
		for _, source := range m.Sources {
			included = included || (source.Namespace == cr.Metadata.Namespace && source.Name == cr.Metadata.Name && source.UID == cr.Metadata.UID && source.Generation == cr.Metadata.Generation)
		}
		if !included || m.Digest != status.DesiredDigest || m.Revision != status.DesiredRevision {
			continue
		}
		if !result.ExpiresAt.IsZero() && !time.Now().Before(result.ExpiresAt) {
			result.Applied = 0
			result.All = false
		}
		status.NodesApplied = result.Applied
		if result.Applied > 0 {
			status.ReceiptExpiresAt = result.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		if !result.All || !time.Now().Before(result.ExpiresAt) {
			c.setCondition(status, "Applied", "Unknown", "AwaitingFreshReceipts", "not all required nodes have fresh exact-generation authenticated activation self-reports")
			continue
		}
		status.Phase = PhaseActive
		status.LastApplied = result.Oldest.UTC().Format(time.RFC3339)
		c.setCondition(status, "Applied", "True", "FreshAuthenticatedSelfReports", "all required nodes self-report this exact manifest active; this is not remote attestation or workload coverage proof")
		c.setCondition(status, "Ready", "True", "FreshAuthenticatedSelfReports", "all required authorized daemon pods supplied fresh activation receipts for this accepted generation")
	}
}
