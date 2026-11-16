// Package controlplane defines the public contract between a warmor agent and
// a policy control plane (the in-tree warmor-server or a hosted implementation
// such as warmor-saas).
//
// This package contains no enforcement logic and no server implementation. It
// is the single source of truth for wire types, HTTP routes, headers, query
// parameters and protocol versioning. Both the reference server in
// internal/policyserver and any external control plane import these names, so
// a change here is a protocol change and follows the compatibility policy in
// docs/control-plane-protocol.md.
//
// The conformance suite lives in pkg/controlplane/conformance so an external
// implementation can prove that a stock warmor agent works against it.
package controlplane
