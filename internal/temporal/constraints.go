// Package temporal defines the time-based constraints a YAML policy rule can
// carry (its `temporal:` block) and their reference semantics.
//
// Temporal rules are not evaluated in Go at runtime: internal/compiler turns
// each Constraint into Rust that runs inside the compiled WASM policy, so
// the policy is the only rule engine. Evaluate is the specification the
// generated code is tested against (see internal/wasm's temporal end-to-end
// test), and Validate is what the compiler enforces on YAML input.
package temporal

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Constraint is the window in which a rule's operation is permitted. A rule
// with a constraint applies its action only when its conditions match AND
// the event falls outside the window, i.e. when Evaluate returns false.
//
// All set fields are AND-ed: the event is inside the window only if it
// satisfies every one of them.
type Constraint struct {
	// MaxContainerAge: inside while the container is at most this old.
	MaxContainerAge time.Duration `json:"max_container_age,omitempty"`
	// MinContainerAge: inside once the container is at least this old.
	MinContainerAge time.Duration `json:"min_container_age,omitempty"`
	// TimeOfDay: inside during this UTC window (both ends inclusive, at
	// minute resolution; start > end wraps past midnight).
	TimeOfDay *TimeRange `json:"time_of_day,omitempty"`
	// DaysOfWeek: inside on these UTC calendar days.
	DaysOfWeek []time.Weekday `json:"days_of_week,omitempty"`
}

// TimeRange is a time-of-day window in UTC.
type TimeRange struct {
	Start TimeOfDay `json:"start"`
	End   TimeOfDay `json:"end"`
}

// TimeOfDay is an hour:minute pair (UTC).
type TimeOfDay struct {
	Hour   int `json:"hour"`
	Minute int `json:"minute"`
}

// Minutes returns the minute of the day, 0-1439.
func (td TimeOfDay) Minutes() int {
	return td.Hour*60 + td.Minute
}

func (td TimeOfDay) String() string {
	return fmt.Sprintf("%02d:%02d", td.Hour, td.Minute)
}

// UsesContainerAge reports whether the constraint depends on container age.
func (c *Constraint) UsesContainerAge() bool {
	return c != nil && (c.MaxContainerAge != 0 || c.MinContainerAge != 0)
}

// UsesWallClock reports whether the constraint depends on the wall clock.
func (c *Constraint) UsesWallClock() bool {
	return c != nil && (c.TimeOfDay != nil || len(c.DaysOfWeek) > 0)
}

// Validate rejects constraints whose meaning would be unclear or that the
// generated code cannot represent exactly.
func (c *Constraint) Validate() error {
	if c == nil {
		return nil
	}
	if !c.UsesContainerAge() && !c.UsesWallClock() {
		return errors.New("temporal block sets no constraint (use max_container_age, min_container_age, time_of_day or days_of_week)")
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{{"max_container_age", c.MaxContainerAge}, {"min_container_age", c.MinContainerAge}} {
		if d.v < 0 {
			return fmt.Errorf("%s must not be negative, got %v", d.name, d.v)
		}
		if d.v%time.Millisecond != 0 {
			return fmt.Errorf("%s must be a whole number of milliseconds, got %v", d.name, d.v)
		}
	}
	if c.MaxContainerAge > 0 && c.MinContainerAge > c.MaxContainerAge {
		return fmt.Errorf("min_container_age (%v) is greater than max_container_age (%v): no container age is inside the window",
			c.MinContainerAge, c.MaxContainerAge)
	}
	if tr := c.TimeOfDay; tr != nil {
		for _, td := range []struct {
			name string
			v    TimeOfDay
		}{{"start", tr.Start}, {"end", tr.End}} {
			if td.v.Hour < 0 || td.v.Hour > 23 {
				return fmt.Errorf("time_of_day.%s.hour must be 0-23, got %d", td.name, td.v.Hour)
			}
			if td.v.Minute < 0 || td.v.Minute > 59 {
				return fmt.Errorf("time_of_day.%s.minute must be 0-59, got %d", td.name, td.v.Minute)
			}
		}
		if tr.Start == tr.End {
			return fmt.Errorf("time_of_day start and end are both %s; the window includes both ends, so this permits a single minute (widen the window)", tr.Start)
		}
	}
	seen := make(map[time.Weekday]bool, len(c.DaysOfWeek))
	for _, d := range c.DaysOfWeek {
		if d < time.Sunday || d > time.Saturday {
			return fmt.Errorf("invalid weekday %d", d)
		}
		if seen[d] {
			return fmt.Errorf("days_of_week lists %s twice", d)
		}
		seen[d] = true
	}
	return nil
}

// ParseWeekday parses a full English weekday name ("Monday"), case
// insensitively.
func ParseWeekday(s string) (time.Weekday, error) {
	for d := time.Sunday; d <= time.Saturday; d++ {
		if strings.EqualFold(s, d.String()) {
			return d, nil
		}
	}
	return 0, fmt.Errorf("unknown weekday %q (want Sunday, Monday, Tuesday, Wednesday, Thursday, Friday or Saturday)", s)
}

// Evaluate reports whether an event is inside the constraint's window.
//
// containerAge is the container's age at the event; zero or negative means
// unknown. wallClock is the event's time; the zero time (or anything not
// after the Unix epoch) means unknown. An unknown input is outside every
// window that depends on it, so a deny rule fails closed: it denies when it
// cannot show the event is inside the permitted window.
//
// Age is compared at millisecond resolution and the clock at minute
// resolution in UTC, exactly as the compiled policy sees them.
func Evaluate(c *Constraint, containerAge time.Duration, wallClock time.Time) bool {
	if c == nil {
		return true
	}

	if c.UsesContainerAge() {
		age := containerAge.Truncate(time.Millisecond)
		if age <= 0 {
			return false
		}
		if c.MaxContainerAge > 0 && age > c.MaxContainerAge {
			return false
		}
		if c.MinContainerAge > 0 && age < c.MinContainerAge {
			return false
		}
	}

	if !c.UsesWallClock() {
		return true
	}
	if !wallClock.After(time.Unix(0, 0)) {
		return false
	}
	utc := wallClock.UTC()

	if c.TimeOfDay != nil {
		now := utc.Hour()*60 + utc.Minute()
		start := c.TimeOfDay.Start.Minutes()
		end := c.TimeOfDay.End.Minutes()
		if start <= end {
			if now < start || now > end {
				return false
			}
		} else if now < start && now > end {
			// Wraps midnight, e.g. 22:00-06:00.
			return false
		}
	}

	if len(c.DaysOfWeek) > 0 && !slices.Contains(c.DaysOfWeek, utc.Weekday()) {
		return false
	}

	return true
}
