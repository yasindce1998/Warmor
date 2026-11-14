package kernelmap

// GenerationRule is a complete exact static kernel identity, never a selector.
type GenerationRule struct {
	CgroupID  uint64
	EventType uint8
	Pattern   string
	Address   string
	Port      uint16
	Action    uint8
	Audit     bool
}

type GenerationDomain struct {
	CgroupID  uint64
	EventType uint8
	Mode      uint8
}

// GenerationSpec contains the entire candidate, not a delta from the old map.
type GenerationSpec struct {
	Rules       []GenerationRule
	DefaultDeny []GenerationDomain
}
