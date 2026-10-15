package policymerge

type PolicyYAML struct {
	Name          string         `yaml:"name"`
	Version       int            `yaml:"version"`
	Description   string         `yaml:"description"`
	Variables     map[string]any `yaml:"variables,omitempty"`
	Rules         []RuleYAML     `yaml:"rules"`
	DefaultAction string         `yaml:"default_action"`
}

type RuleYAML struct {
	Name       string         `yaml:"name"`
	Event      string         `yaml:"event"`
	Conditions ConditionsYAML `yaml:"conditions"`
	Action     string         `yaml:"action"`
	Mode       string         `yaml:"mode,omitempty"`
	Reason     string         `yaml:"reason,omitempty"`
	// Temporal is the rule's temporal: block, carried through verbatim
	// (the compiler validates it). Dropping it would make the rule
	// unconditional.
	Temporal map[string]any `yaml:"temporal,omitempty"`
}

type ConditionsYAML struct {
	All []map[string]any `yaml:"all,omitempty"`
	Any []map[string]any `yaml:"any,omitempty"`
	Not []map[string]any `yaml:"not,omitempty"`
}

type MergeOptions struct {
	Name        string
	Description string
	Strategy    string // "union", "intersection", "deny-wins"
	Annotate    bool
	Dedup       bool
}

type MergeResult struct {
	Policy       *PolicyYAML
	TotalRules   int
	DedupedRules int
	Sources      int
}
