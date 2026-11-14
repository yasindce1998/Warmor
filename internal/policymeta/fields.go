package policymeta

// Shared declaration vocabulary. Compiler aliases these exact constants/types
// so its build-section writer can import policymeta without an import cycle.
// New field bits require a contract update; unknown bits never imply finite
// dependency coverage on an older reader.
const (
	FieldBitPID uint32 = 1 << iota
	FieldBitUID
	FieldBitGID
	FieldBitComm
	FieldBitPath
	FieldBitArgs
	FieldBitFlags
	FieldBitOperation
	FieldBitProtocol
	FieldBitRemoteAddr
	FieldBitRemotePort
	FieldBitLocalPort
	FieldBitTime
	FieldBitContainerAge
	FieldsUnknown uint32 = 0xFFFFFFFF
)

// StaticRule contains lossless kernel-key candidates. Action 0/1 and audit
// remain separate; RuleKey deliberately excludes the verdict for duplicate
// detection. No truncated/hash-only key is represented by this type.
type StaticRule struct {
	Event   string
	Action  uint8
	Audit   bool
	Pattern string
	Port    uint16
}
