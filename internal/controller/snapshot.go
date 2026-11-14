package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	SnapshotDataKey       = "accepted-sources.json"
	AnnotationArtifactSHA = "warmor.io/artifact-sha256"
	AnnotationSnapshotSHA = "warmor.io/accepted-sources-sha256"
	// Reserve headroom below the 1MiB data limit and the request budget
	// (binaryData is base64-encoded on the wire).
	maxSnapshotBytes  = 256 << 10
	maxConfigMapBytes = 900 << 10
	maxSourceBytes    = 64 << 10
	maxSourceRules    = 512
	maxEffectiveRules = 2048
)

// Store only policy spec and identity, never status, tokens, annotations or
// labels. Policies themselves must not contain secrets: the ConfigMap is
// readable by the agent and its authorized readers.
type acceptedSource struct {
	Namespace  string           `json:"namespace"`
	Name       string           `json:"name"`
	UID        string           `json:"uid"`
	Generation int64            `json:"generation"`
	Spec       WarmorPolicySpec `json:"spec"`
}

type sourceSnapshot struct {
	Version        int              `json:"version"`
	WatchNamespace string           `json:"watchNamespace"`
	Sources        []acceptedSource `json:"sources"`
}

func sourceKey(cr *WarmorPolicy) string {
	key, _ := json.Marshal([]string{cr.Metadata.Namespace, cr.Metadata.Name, cr.Metadata.UID})
	return string(key)
}

func snapshotSource(cr *WarmorPolicy) acceptedSource {
	return acceptedSource{cr.Metadata.Namespace, cr.Metadata.Name, cr.Metadata.UID, cr.Metadata.Generation, cr.Spec}
}

func (s acceptedSource) policy() *WarmorPolicy {
	return &WarmorPolicy{Metadata: ObjectMeta{Namespace: s.Namespace, Name: s.Name, UID: s.UID, Generation: s.Generation}, Spec: s.Spec}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (c *Controller) readSnapshot(cm *ConfigMap) (map[string]acceptedSource, error) {
	out := make(map[string]acceptedSource)
	if cm == nil {
		return out, nil
	}
	raw := cm.Data[SnapshotDataKey]
	if raw == "" {
		if cm.Metadata.Annotations[AnnotationSnapshotSHA] != "" {
			return nil, fmt.Errorf("accepted-source snapshot is missing; refusing to replace previous publication")
		}
		// Legacy publications cannot reconstruct a prior accepted spec.
		return out, nil
	}
	if len(raw) > maxSnapshotBytes || digest([]byte(raw)) != cm.Metadata.Annotations[AnnotationSnapshotSHA] {
		return nil, fmt.Errorf("accepted-source snapshot integrity check failed; refusing to replace previous publication")
	}
	var snapshot sourceSnapshot
	if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
		return nil, fmt.Errorf("decode accepted-source snapshot: %w", err)
	}
	if snapshot.Version != 1 || snapshot.WatchNamespace != c.opts.Namespace {
		return nil, fmt.Errorf("accepted-source snapshot has incompatible version or watch namespace")
	}
	for _, source := range snapshot.Sources {
		cr := source.policy()
		if source.Namespace == "" || source.Name == "" || source.UID == "" || (c.opts.Namespace != "" && source.Namespace != c.opts.Namespace) {
			return nil, fmt.Errorf("accepted-source snapshot has invalid identity")
		}
		status, _ := c.classify(cr)
		if status.rendered == nil {
			return nil, fmt.Errorf("accepted-source snapshot no longer validates for %s/%s", source.Namespace, source.Name)
		}
		key := sourceKey(cr)
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("accepted-source snapshot has duplicate identity")
		}
		out[key] = source
	}
	return out, nil
}
