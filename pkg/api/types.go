package api

import (
	"encoding/json"
	"fmt"
	"time"
)

// EventType represents the type of syscall event
type EventType int32

const (
	EventTypeProcess EventType = 0 // execve
	EventTypeFile    EventType = 1 // openat, read, write
	EventTypeNetwork EventType = 2 // connect, sendto, recvfrom
)

func (t EventType) String() string {
	switch t {
	case EventTypeProcess:
		return "PROCESS"
	case EventTypeFile:
		return "FILE"
	case EventTypeNetwork:
		return "NETWORK"
	default:
		return "UNKNOWN"
	}
}

// valid reports whether t is one of the defined event types.
func (t EventType) valid() bool {
	return t >= EventTypeProcess && t <= EventTypeNetwork
}

// MarshalJSON encodes t as its name. Unknown values are rejected rather than
// encoded as "UNKNOWN", which UnmarshalJSON could not read back.
func (t EventType) MarshalJSON() ([]byte, error) {
	if !t.valid() {
		return nil, fmt.Errorf("cannot marshal unknown EventType %d", int32(t))
	}
	return json.Marshal(t.String())
}

func (t *EventType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// Fall back to numeric for backward compat
		var n int32
		if err2 := json.Unmarshal(data, &n); err2 != nil {
			return fmt.Errorf("EventType must be string or number: %w", err)
		}
		// Range-check numerics just as unknown names are rejected.
		if et := EventType(n); et.valid() {
			*t = et
			return nil
		}
		return fmt.Errorf("unknown EventType: %d", n)
	}
	switch s {
	case "PROCESS":
		*t = EventTypeProcess
	case "FILE":
		*t = EventTypeFile
	case "NETWORK":
		*t = EventTypeNetwork
	default:
		return fmt.Errorf("unknown EventType: %q", s)
	}
	return nil
}

// BaseEvent contains common fields for all event types
type BaseEvent struct {
	Type      EventType `json:"type"`
	PID       uint32    `json:"pid"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Comm      string    `json:"comm"`
	Timestamp time.Time `json:"timestamp"`
	CgroupID  uint64    `json:"cgroup_id,omitempty"`
}

// ProcessEvent represents a process execution event (execve)
type ProcessEvent struct {
	BaseEvent
	Filename string   `json:"filename"`
	Args     []string `json:"args,omitempty"`
}

// FileEvent represents a file operation event (openat, read, write)
type FileEvent struct {
	BaseEvent
	Operation string `json:"operation"` // "open", "read", "write"
	Path      string `json:"path"`
	Flags     uint32 `json:"flags"`
	Mode      uint32 `json:"mode,omitempty"`
}

// NetworkEvent represents a network operation event
type NetworkEvent struct {
	BaseEvent
	Operation  string `json:"operation"`   // "connect", "sendto", "recvfrom"
	Protocol   string `json:"protocol"`    // "tcp", "udp"
	RemoteAddr string `json:"remote_addr"` // IP address
	RemotePort uint16 `json:"remote_port"`
	LocalAddr  string `json:"local_addr,omitempty"`
	LocalPort  uint16 `json:"local_port,omitempty"`
	DataSize   uint32 `json:"data_size,omitempty"`
}

// Event is a union type that can hold any event type
// Maintains backward compatibility with Phase 1/2
type Event struct {
	// Legacy fields (Phase 1/2 compatibility)
	PID       uint32    `json:"pid"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Comm      string    `json:"comm"`
	Filename  string    `json:"filename"`
	Timestamp time.Time `json:"timestamp"`

	// Phase 3 fields
	Type     EventType     `json:"type,omitempty"`
	CgroupID uint64        `json:"cgroup_id,omitempty"`
	Process  *ProcessEvent `json:"process,omitempty"`
	File     *FileEvent    `json:"file,omitempty"`
	Network  *NetworkEvent `json:"network,omitempty"`

	// LSM fields
	LSMEvent bool `json:"lsm_event,omitempty"`

	// processSet records that Type was explicitly set to EventTypeProcess
	// (the zero value), via SetType or a JSON "type" key, so GetType does
	// not fall back to sub-event inference.
	processSet bool
}

// SetType sets the event type explicitly. Unlike assigning Type directly,
// this also marks EventTypeProcess (the zero value) as explicit, so GetType
// returns it even when a File or Network sub-event is populated.
func (e *Event) SetType(t EventType) {
	e.Type = t
	e.processSet = t == EventTypeProcess
}

// eventJSON has Event's fields but none of its methods.
type eventJSON Event

// MarshalJSON encodes the event. "type" is omitted for an unset (zero)
// Type, as before, but is emitted for an explicit EventTypeProcess so the
// decoder can tell the two apart.
func (e Event) MarshalJSON() ([]byte, error) {
	var typ *EventType
	if e.Type != EventTypeProcess || e.processSet {
		t := e.Type
		typ = &t
	}
	return json.Marshal(struct {
		eventJSON
		Type *EventType `json:"type,omitempty"`
	}{eventJSON(e), typ})
}

// UnmarshalJSON decodes the event, recording whether "type" was present.
func (e *Event) UnmarshalJSON(data []byte) error {
	aux := struct {
		*eventJSON
		Type *EventType `json:"type"`
	}{eventJSON: (*eventJSON)(e)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.Type != nil {
		e.SetType(*aux.Type)
	}
	return nil
}

// GetType returns the event type. An explicit Type wins; an unset Type is
// inferred from the populated sub-event, defaulting to Process for legacy
// events. A plain struct literal cannot distinguish Type: EventTypeProcess
// from unset (both are zero), so use SetType to force Process.
func (e *Event) GetType() EventType {
	if e.Type != EventTypeProcess || e.processSet {
		return e.Type
	}
	if e.Process != nil {
		return e.Process.Type
	}
	if e.File != nil {
		return e.File.Type
	}
	if e.Network != nil {
		return e.Network.Type
	}
	// Default to Process for backward compatibility
	return EventTypeProcess
}

// ToProcessEvent converts legacy Event to ProcessEvent
func (e *Event) ToProcessEvent() *ProcessEvent {
	if e.Process != nil {
		return e.Process
	}
	// Convert legacy format
	return &ProcessEvent{
		BaseEvent: BaseEvent{
			Type:      EventTypeProcess,
			PID:       e.PID,
			UID:       e.UID,
			GID:       e.GID,
			Comm:      e.Comm,
			Timestamp: e.Timestamp,
			CgroupID:  e.CgroupID,
		},
		Filename: e.Filename,
	}
}

// Action represents the enforcement decision
type Action int32

const (
	ActionAllow Action = 0
	ActionDeny  Action = 1
	ActionLog   Action = 2
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "ALLOW"
	case ActionDeny:
		return "DENY"
	case ActionLog:
		return "LOG"
	default:
		return "UNKNOWN"
	}
}

// ActionResult contains the policy decision and metadata
type ActionResult struct {
	Action    Action
	Reason    string        // Human-readable reason
	Timestamp time.Time     // When decision was made
	Cached    bool          // Was this from cache?
	Latency   time.Duration // Evaluation latency
	Audit     bool          // True if this deny was downgraded to log (audit mode)
}

// EnforcementStats tracks enforcement metrics
type EnforcementStats struct {
	Allowed      uint64
	Denied       uint64
	Logged       uint64
	AuditDenied  uint64
	CacheHits    uint64
	CacheMisses  uint64
	TotalLatency time.Duration
}
