package policymerge

import (
	"fmt"

	"github.com/yasindce1998/warmor/internal/compiler"
	"gopkg.in/yaml.v3"
)

// Validate delegates to the compiler's strict parser and semantic validation.
// The YAML editing representation is not a second policy language.
func Validate(p *PolicyYAML) error {
	if p == nil {
		return fmt.Errorf("policy is required")
	}
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	_, err = compiler.Parse(data)
	return err
}
