package simulator

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// SimulationResult contains the outcome of replaying a policy against recorded events.
type SimulationResult struct {
	IncompleteEvents int            `json:"incomplete_events"`
	EvaluationErrors int            `json:"evaluation_errors"`
	Warnings         []string       `json:"warnings,omitempty"`
	TotalEvents      int            `json:"total_events"`
	WouldAllow       int            `json:"would_allow"`
	WouldDeny        int            `json:"would_deny"`
	WouldLog         int            `json:"would_log"`
	UniqueNewDenials []DenialDetail `json:"unique_new_denials,omitempty"`
	UniqueNewAllows  []AllowDetail  `json:"unique_new_allows,omitempty"`
	Duration         time.Duration  `json:"duration"`
}

// DenialDetail describes a unique event that would be newly denied.
type DenialDetail struct {
	EventType string `json:"event_type"`
	Comm      string `json:"comm"`
	Target    string `json:"target"`
	Count     int    `json:"count"`
	Reason    string `json:"reason"`
}

// AllowDetail describes a unique event that would be newly allowed.
type AllowDetail struct {
	EventType string `json:"event_type"`
	Comm      string `json:"comm"`
	Target    string `json:"target"`
	Count     int    `json:"count"`
}

// Replay evaluates recorded events against a candidate policy.
// It compares the candidate decisions against the original recorded decisions.
func Replay(ctx context.Context, events []*streaming.SecurityEvent, evaluator *wasm.PolicyEvaluator) (*SimulationResult, error) {
	start := time.Now()
	result := &SimulationResult{}
	result.TotalEvents = len(events)

	newDenials := make(map[string]*DenialDetail)
	newAllows := make(map[string]*AllowDetail)
	warnings := make(map[string]bool)

	for _, event := range events {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if event == nil {
			return nil, fmt.Errorf("nil recorded event")
		}
		if event.SchemaVersion < 0 || event.SchemaVersion > streaming.EventSchemaVersion {
			return nil, fmt.Errorf("unsupported event schema version %d", event.SchemaVersion)
		}
		incomplete := false
		if event.SchemaVersion < 2 || event.PolicyInput == nil {
			incomplete = true
			warnings["Legacy or missing policy_input: argv, parent comm, operations and flags may be unavailable; decisions are estimates, not equivalence evidence."] = true
		}
		for _, issue := range event.InputIssues {
			incomplete = true
			warnings[fmt.Sprintf("Incomplete policy input: %s is %s; decisions are estimates.", issue.Field, issue.State)] = true
		}
		if incomplete {
			result.IncompleteEvents++
		}
		apiEvent := securityEventToAPIEvent(event)
		actionResult, err := evaluator.Evaluate(ctx, apiEvent)
		if err != nil {
			result.EvaluationErrors++
			warnings["Policy evaluation errors were counted as denials; they are not candidate policy decisions."] = true
			result.WouldDeny++
			continue
		}

		switch actionResult.Action {
		case api.ActionAllow:
			result.WouldAllow++
		case api.ActionDeny:
			result.WouldDeny++
		case api.ActionLog:
			result.WouldLog++
		}

		// Recorded decisions are lowercase ("allow"/"deny"/"log", see
		// streaming.SecurityEvent) while api.Action.String() is uppercase,
		// so compare normalized forms. "log" permits the event.
		originalDecision := normalizeDecision(event.Decision)
		newDecision := normalizeDecision(actionResult.Action.String())
		wasPermitted := originalDecision == "allow" || originalDecision == "log"
		nowPermitted := newDecision == "allow" || newDecision == "log"

		target := eventTarget(event)
		key := fmt.Sprintf("%s:%s:%s", event.EventType, event.Comm, target)

		if wasPermitted && newDecision == "deny" {
			if d, ok := newDenials[key]; ok {
				d.Count++
			} else {
				newDenials[key] = &DenialDetail{
					EventType: event.EventType,
					Comm:      event.Comm,
					Target:    target,
					Count:     1,
					Reason:    actionResult.Reason,
				}
			}
		}

		if originalDecision == "deny" && nowPermitted {
			if a, ok := newAllows[key]; ok {
				a.Count++
			} else {
				newAllows[key] = &AllowDetail{
					EventType: event.EventType,
					Comm:      event.Comm,
					Target:    target,
					Count:     1,
				}
			}
		}
	}

	for _, d := range newDenials {
		result.UniqueNewDenials = append(result.UniqueNewDenials, *d)
	}
	for _, a := range newAllows {
		result.UniqueNewAllows = append(result.UniqueNewAllows, *a)
	}

	result.Duration = time.Since(start)
	for warning := range warnings {
		result.Warnings = append(result.Warnings, warning)
	}
	sort.Strings(result.Warnings)
	return result, nil
}

func securityEventToAPIEvent(e *streaming.SecurityEvent) *api.Event {
	if e.SchemaVersion >= 2 && e.PolicyInput != nil {
		input := *e.PolicyInput
		return &input
	}
	event := &api.Event{
		PPID:      e.PPID,
		PID:       e.PID,
		UID:       e.UID,
		GID:       e.GID,
		Comm:      e.Comm,
		Filename:  e.Filename,
		Timestamp: e.Timestamp,
		CgroupID:  e.CgroupID,

		ContainerStart: e.ContainerStart,
	}

	switch e.EventType {
	case "exec", "ptrace":
		event.Type = api.EventTypeProcess
		event.Process = &api.ProcessEvent{
			BaseEvent: api.BaseEvent{
				Type: api.EventTypeProcess,
				PID:  e.PID, UID: e.UID, GID: e.GID,
				Comm: e.Comm, Timestamp: e.Timestamp,
				CgroupID: e.CgroupID,
			},
			Filename: e.Filename,
		}
	case "file", "mount":
		event.Type = api.EventTypeFile
		event.File = &api.FileEvent{
			BaseEvent: api.BaseEvent{
				Type: api.EventTypeFile,
				PID:  e.PID, UID: e.UID, GID: e.GID,
				Comm: e.Comm, Timestamp: e.Timestamp,
				CgroupID: e.CgroupID,
			},
			Path:      e.Filename,
			Operation: "open", // historical fallback; original operation unknown
		}
	case "network", "bind", "listen", "connect_unix":
		event.Type = api.EventTypeNetwork
		event.Network = &api.NetworkEvent{
			BaseEvent: api.BaseEvent{
				Type: api.EventTypeNetwork,
				PID:  e.PID, UID: e.UID, GID: e.GID,
				Comm: e.Comm, Timestamp: e.Timestamp,
				CgroupID: e.CgroupID,
			},
			Protocol:   e.Protocol,
			Operation:  "connect", // historical sensors folded bind/listen into connect
			RemoteAddr: e.RemoteAddr,
			RemotePort: e.RemotePort,
			LocalPort:  e.LocalPort,
		}
	}
	switch e.EventType {
	case "ptrace", "mount", "bind", "listen", "connect_unix":
		event.Hook = e.EventType
	}

	return event
}

func eventTarget(e *streaming.SecurityEvent) string {
	switch e.EventType {
	case "exec", "file":
		return e.Filename
	case "network":
		if strings.Contains(e.RemoteAddr, ":") {
			return net.JoinHostPort(e.RemoteAddr, strconv.Itoa(int(e.RemotePort)))
		}
		return fmt.Sprintf("%s:%d", e.RemoteAddr, e.RemotePort)
	case "bind", "listen":
		return fmt.Sprintf(":%d", e.LocalPort)
	default:
		return e.Filename
	}
}

// normalizeDecision maps a decision string in any case ("allow", "ALLOW",
// "Deny", ...) to the lowercase form the streaming pipeline records.
func normalizeDecision(d string) string {
	return strings.ToLower(strings.TrimSpace(d))
}
