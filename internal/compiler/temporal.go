package compiler

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/cliflag"
	"github.com/yasindce1998/warmor/internal/temporal"
)

// A rule's temporal: block (docs/temporal-policies.md):
//
//	temporal:
//	  max_container_age: "5m"     # Go duration, plus a day suffix ("7d")
//	  min_container_age: "30s"
//	  time_of_day:                # UTC, both ends inclusive; may wrap midnight
//	    start: { hour: 22, minute: 0 }
//	    end:   { hour: 6, minute: 0 }
//	  days_of_week: [Monday, Friday]
//
// The block is the window in which the rule's operation is permitted: the
// rule's action applies only when its conditions match AND the event is
// outside the window (temporal.Evaluate), and an unknown container age or
// wall clock counts as outside. It is parsed strictly: unknown keys, wrong
// types and out-of-range values are errors, never ignored.

var temporalKeys = []string{"max_container_age", "min_container_age", "time_of_day", "days_of_week"}

func parseTemporal(raw map[string]interface{}) (*temporal.Constraint, error) {
	if raw == nil {
		return nil, nil
	}
	if err := checkKeys(raw, temporalKeys); err != nil {
		return nil, err
	}
	c := &temporal.Constraint{}
	var err error
	if v, ok := raw["max_container_age"]; ok {
		if c.MaxContainerAge, err = parseAge("max_container_age", v); err != nil {
			return nil, err
		}
	}
	if v, ok := raw["min_container_age"]; ok {
		if c.MinContainerAge, err = parseAge("min_container_age", v); err != nil {
			return nil, err
		}
	}
	if v, ok := raw["time_of_day"]; ok {
		if c.TimeOfDay, err = parseTimeRange(v); err != nil {
			return nil, err
		}
	}
	if v, ok := raw["days_of_week"]; ok {
		if c.DaysOfWeek, err = parseDays(v); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func checkKeys(m map[string]interface{}, allowed []string) error {
	var unknown []string
	for k := range m {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("unknown key(s) %s (valid: %s)", strings.Join(unknown, ", "), strings.Join(allowed, ", "))
	}
	return nil
}

func parseAge(name string, v interface{}) (time.Duration, error) {
	s, ok := v.(string)
	if !ok {
		return 0, fmt.Errorf("%s must be a duration string such as \"5m\", \"24h\" or \"7d\", got %v", name, v)
	}
	d, err := cliflag.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if d == 0 {
		return 0, fmt.Errorf("%s must be greater than zero (omit it for no limit)", name)
	}
	return d, nil
}

func parseTimeRange(v interface{}) (*temporal.TimeRange, error) {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("time_of_day must be a map with start and end, got %v", v)
	}
	if err := checkKeys(m, []string{"start", "end"}); err != nil {
		return nil, fmt.Errorf("time_of_day: %w", err)
	}
	tr := &temporal.TimeRange{}
	for _, p := range []struct {
		name string
		dst  *temporal.TimeOfDay
	}{{"start", &tr.Start}, {"end", &tr.End}} {
		raw, ok := m[p.name]
		if !ok {
			return nil, fmt.Errorf("time_of_day.%s is required", p.name)
		}
		td, err := parseTimeOfDay(raw)
		if err != nil {
			return nil, fmt.Errorf("time_of_day.%s: %w", p.name, err)
		}
		*p.dst = td
	}
	return tr, nil
}

func parseTimeOfDay(v interface{}) (temporal.TimeOfDay, error) {
	m, ok := v.(map[string]interface{})
	if !ok {
		return temporal.TimeOfDay{}, fmt.Errorf("must be a map { hour: H, minute: M }, got %v", v)
	}
	if err := checkKeys(m, []string{"hour", "minute"}); err != nil {
		return temporal.TimeOfDay{}, err
	}
	var td temporal.TimeOfDay
	for _, p := range []struct {
		name string
		dst  *int
	}{{"hour", &td.Hour}, {"minute", &td.Minute}} {
		raw, ok := m[p.name]
		if !ok {
			return temporal.TimeOfDay{}, fmt.Errorf("%s is required", p.name)
		}
		n, ok := raw.(int)
		if !ok {
			return temporal.TimeOfDay{}, fmt.Errorf("%s must be an integer, got %v", p.name, raw)
		}
		*p.dst = n
	}
	return td, nil
}

func parseDays(v interface{}) ([]time.Weekday, error) {
	list, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("days_of_week must be a list of weekday names, got %v", v)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("days_of_week must list at least one day (omit it for every day)")
	}
	days := make([]time.Weekday, 0, len(list))
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("days_of_week[%d] must be a weekday name, got %v", i, item)
		}
		d, err := temporal.ParseWeekday(s)
		if err != nil {
			return nil, fmt.Errorf("days_of_week[%d]: %w", i, err)
		}
		days = append(days, d)
	}
	return days, nil
}

// validateTemporal checks a rule's temporal block against the rule.
func validateTemporal(r *Rule) error {
	if r.Temporal == nil {
		return nil
	}
	if r.Action == "allow" {
		// The block is the window in which the operation is permitted and
		// the action applies outside it; on an allow rule that would allow
		// exactly when the operation is not permitted.
		return fmt.Errorf("temporal constraints are only supported on deny and log rules (the action applies outside the permitted window)")
	}
	if err := r.Temporal.Validate(); err != nil {
		return fmt.Errorf("temporal: %w", err)
	}
	return nil
}

// temporalFields is the fields-read mask a rule's temporal block adds.
func temporalFields(c *temporal.Constraint) uint32 {
	var m uint32
	if c.UsesWallClock() {
		m |= FieldBitTime
	}
	if c.UsesContainerAge() {
		m |= FieldBitContainerAge
	}
	return m
}

// temporalWindowExpr returns the Rust expression that is true when the
// event is inside c's window (wall and age_ms are in scope in every
// evaluator), or "" for no constraint.
func temporalWindowExpr(c *temporal.Constraint) string {
	if c == nil {
		return ""
	}
	var parts []string
	if c.MaxContainerAge > 0 {
		parts = append(parts, fmt.Sprintf("age_at_most(age_ms, %d)", c.MaxContainerAge.Milliseconds()))
	}
	if c.MinContainerAge > 0 {
		parts = append(parts, fmt.Sprintf("age_at_least(age_ms, %d)", c.MinContainerAge.Milliseconds()))
	}
	if tr := c.TimeOfDay; tr != nil {
		parts = append(parts, fmt.Sprintf("in_time_window(wall, %d, %d)", tr.Start.Minutes(), tr.End.Minutes()))
	}
	if len(c.DaysOfWeek) > 0 {
		var mask uint32
		for _, d := range c.DaysOfWeek {
			mask |= 1 << uint(d)
		}
		parts = append(parts, fmt.Sprintf("on_weekday(wall, 0x%02X)", mask))
	}
	return strings.Join(parts, " && ")
}

func writeTemporalHelpers(b *strings.Builder) {
	b.WriteString(`// Temporal context (ABI version 3): wall clock as UTC Unix seconds and
// container age in milliseconds, each 0 when unknown. Unknown is outside
// every window, so a rule fails closed.
#[allow(dead_code)]
unsafe fn read_u48(base: *const u8, offset: usize) -> u64 {
    let mut v: u64 = 0;
    let mut i = 0;
    while i < 6 {
        v |= ((*base.add(offset + i)) as u64) << (8 * i);
        i += 1;
    }
    v
}

#[allow(dead_code)]
fn age_at_most(age_ms: u64, max_ms: u64) -> bool {
    age_ms != 0 && age_ms <= max_ms
}

#[allow(dead_code)]
fn age_at_least(age_ms: u64, min_ms: u64) -> bool {
    age_ms != 0 && age_ms >= min_ms
}

// Minutes since midnight UTC.
#[allow(dead_code)]
fn minute_of_day(wall: u32) -> u32 {
    (wall % 86400) / 60
}

// 0 = Sunday. 1970-01-01 was a Thursday.
#[allow(dead_code)]
fn weekday(wall: u32) -> u32 {
    (wall / 86400 + 4) % 7
}

// Inclusive window [start, end] in minutes of the day; start > end wraps
// past midnight.
#[allow(dead_code)]
fn in_time_window(wall: u32, start: u32, end: u32) -> bool {
    if wall == 0 {
        return false;
    }
    let now = minute_of_day(wall);
    if start <= end {
        now >= start && now <= end
    } else {
        now >= start || now <= end
    }
}

// mask has bit d set for each permitted weekday d (0 = Sunday).
#[allow(dead_code)]
fn on_weekday(wall: u32, mask: u32) -> bool {
    wall != 0 && (mask >> weekday(wall)) & 1 != 0
}

`)
}
