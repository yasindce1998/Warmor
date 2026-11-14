package wasm

import (
	"fmt"

	"github.com/yasindce1998/warmor/internal/crypto/assignment"
)

// CheckAssignment compares the loaded bytes and actual ABI with artifact-signed
// build declarations. Missing metadata/ABI is refused only in explicit signed
// mode; legacy modules need not gain new exports or sections.
func (p *Pool) CheckAssignment(want assignment.Policy) error {
	id := p.Identity()
	if id.ABI == 0 || id.ABI != want.ABI || id.Compiler == "" || id.Compiler != want.Compiler || id.DefaultAction != want.Posture.DefaultAction || id.Digest != want.SHA256 {
		return fmt.Errorf("%w: actual artifact ABI/build metadata/digest mismatch", assignment.ErrCompatibility)
	}
	return nil
}
