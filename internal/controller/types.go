// Package controller implements the WarmorPolicy controller: it watches
// WarmorPolicy custom resources, validates and compiles them into one
// effective node policy, and syncs the compiled module into a ConfigMap
// the agent DaemonSet mounts. Agents pick changes up through their
// policy-file watcher. Publication is not acknowledgement of node activation.
package controller

import (
	"encoding/json"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

// ObjectMeta is the subset of metav1.ObjectMeta the controller uses.
type ObjectMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace,omitempty"`
	UID               string            `json:"uid,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	Generation        int64             `json:"generation,omitempty"`
	CreationTimestamp string            `json:"creationTimestamp,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	OwnerReferences   []json.RawMessage `json:"ownerReferences,omitempty"`
	Finalizers        []string          `json:"finalizers,omitempty"`
}

// WarmorPolicy is the warmorpolicies.warmor.io custom resource. It mirrors
// deploy/helm/warmor/crds/warmorpolicy-crd.yaml; fields the controller
// does not use are not modeled.
type WarmorPolicy struct {
	// TypeMeta is empty in list/watch responses (the API server strips
	// it from collections) and is filled in only for the status PUT,
	// which rejects a body without apiVersion/kind.
	Kind       string              `json:"kind,omitempty"`
	APIVersion string              `json:"apiVersion,omitempty"`
	Metadata   ObjectMeta          `json:"metadata"`
	Spec       WarmorPolicySpec    `json:"spec"`
	Status     *WarmorPolicyStatus `json:"status,omitempty"`
}

// WarmorPolicyList is the list response for WarmorPolicy.
type WarmorPolicyList struct {
	Metadata ListMeta       `json:"metadata"`
	Items    []WarmorPolicy `json:"items"`
}

// ListMeta carries the resourceVersion watches resume from.
type ListMeta struct {
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

// WarmorPolicySpec is the desired policy. Field names follow the CRD
// (camelCase), not the daemon's YAML schema (snake_case); Render bridges
// the two.
type WarmorPolicySpec struct {
	Name          string         `json:"name"`
	Version       int            `json:"version"`
	Description   string         `json:"description,omitempty"`
	Variables     map[string]any `json:"variables,omitempty"`
	Rules         []PolicyRule   `json:"rules"`
	DefaultAction string         `json:"defaultAction"`
	Selector      *Selector      `json:"selector,omitempty"`
}

// PolicyRule is one rule in a WarmorPolicy. The CRD schema allows
// conditions.all/any; the daemon schema also has not/temporal, which the
// CRD deliberately omits for now.
type PolicyRule struct {
	Name       string          `json:"name"`
	Event      string          `json:"event"`
	Conditions *RuleConditions `json:"conditions,omitempty"`
	Action     string          `json:"action"`
	Reason     string          `json:"reason,omitempty"`
}

// RuleConditions matches a rule's conditions.
type RuleConditions struct {
	All []map[string]any `json:"all,omitempty"`
	Any []map[string]any `json:"any,omitempty"`
}

// Selector scopes a policy to pods. The controller does not evaluate it
// yet (enforcement is node-wide until per-workload policies ship), so
// policies carrying any non-nil selector (including {}) are held Pending rather than silently
// applied beyond their intended scope.
type Selector struct {
	MatchLabels      map[string]string  `json:"matchLabels,omitempty"`
	MatchExpressions []LabelRequirement `json:"matchExpressions,omitempty"`
}

// LabelRequirement is one selector expression.
type LabelRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// WarmorPolicyStatus is the CRD's status subresource.
type WarmorPolicyStatus struct {
	Phase              string            `json:"phase,omitempty"`
	ObservedGeneration int64             `json:"observedGeneration,omitempty"`
	Conditions         []PolicyCondition `json:"conditions,omitempty"`
	LastApplied        string            `json:"lastApplied,omitempty"`
	NodesApplied       int               `json:"nodesApplied,omitempty"`
	AcceptedGeneration int64             `json:"acceptedGeneration,omitempty"`
	DesiredRevision    string            `json:"desiredRevision,omitempty"`
	DesiredDigest      string            `json:"desiredDigest,omitempty"`
	PublishedDigest    string            `json:"publishedDigest,omitempty"`
	LastPublished      string            `json:"lastPublished,omitempty"`
	ReceiptExpiresAt   string            `json:"receiptExpiresAt,omitempty"`

	// rendered carries the validated policy between Reconcile steps. It
	// is unexported, so it is never serialized to the API server.
	rendered *policymerge.PolicyYAML
}

// Policy phases (from the CRD's status.phase enum).
const (
	PhasePending   = "Pending"
	PhaseActive    = "Active"
	PhasePublished = "Published"
	PhaseError     = "Error"
)

// PolicyCondition is one status condition.
type PolicyCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"` // True, False or Unknown
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
}

// ConfigMap is the subset of v1.ConfigMap the controller uses. The
// compiled policy is stored under BinaryData because a WASM module is not
// valid UTF-8 and Data values must be.
type ConfigMap struct {
	Metadata   ObjectMeta        `json:"metadata"`
	Immutable  *bool             `json:"immutable,omitempty"`
	Data       map[string]string `json:"data,omitempty"`
	BinaryData map[string][]byte `json:"binaryData,omitempty"`
}
