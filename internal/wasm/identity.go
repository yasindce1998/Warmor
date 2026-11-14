package wasm

// ArtifactIdentity is captured with a pool's compiled module. Build declarations
// are artifact-authenticated only when the caller verified an artifact signature;
// they are not independent compiler provenance or WASM semantic analysis.
type ArtifactIdentity struct {
	Digest        string
	ABI           uint32
	Compiler      string
	DefaultAction string
}

// Identity returns the same module digest, ABI and build metadata used by
// CheckAssignment. Runtime reuse or loading a candidate cannot change this pool.
// Preparation identity alone is not acknowledgement of evaluator activation.
func (p *Pool) Identity() ArtifactIdentity {
	id := ArtifactIdentity{Digest: p.moduleDigest, ABI: p.abiVersion}
	if p.buildMetadata != nil {
		id.Compiler = p.buildMetadata.Compiler
		id.DefaultAction = p.buildMetadata.DefaultAction
	}
	return id
}
