package temporal

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateNilConstraint(t *testing.T) {
	if !Evaluate(nil, 5*time.Minute, time.Now()) {
		t.Error("nil constraint should always pass")
	}
}

func TestEvaluateMaxContainerAge(t *testing.T) {
	c := &Constraint{MaxContainerAge: 30 * time.Second}

	if !Evaluate(c, 10*time.Second, time.Now()) {
		t.Error("age 10s should pass max 30s constraint")
	}
	if Evaluate(c, 60*time.Second, time.Now()) {
		t.Error("age 60s should fail max 30s constraint")
	}
}

func TestEvaluateMinContainerAge(t *testing.T) {
	c := &Constraint{MinContainerAge: 10 * time.Second}

	if Evaluate(c, 5*time.Second, time.Now()) {
		t.Error("age 5s should fail min 10s constraint")
	}
	if !Evaluate(c, 20*time.Second, time.Now()) {
		t.Error("age 20s should pass min 10s constraint")
	}
}

func TestEvaluateTimeOfDayNormal(t *testing.T) {
	c := &Constraint{
		TimeOfDay: &TimeRange{
			Start: TimeOfDay{Hour: 9, Minute: 0},
			End:   TimeOfDay{Hour: 17, Minute: 0},
		},
	}

	// 10:00 is within 09:00-17:00
	at10 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	if !Evaluate(c, 0, at10) {
		t.Error("10:00 should pass 09:00-17:00 constraint")
	}

	// 20:00 is outside 09:00-17:00
	at20 := time.Date(2024, 1, 1, 20, 0, 0, 0, time.UTC)
	if Evaluate(c, 0, at20) {
		t.Error("20:00 should fail 09:00-17:00 constraint")
	}

	// 08:00 is outside
	at8 := time.Date(2024, 1, 1, 8, 0, 0, 0, time.UTC)
	if Evaluate(c, 0, at8) {
		t.Error("08:00 should fail 09:00-17:00 constraint")
	}
}

func TestEvaluateTimeOfDayMidnightWrap(t *testing.T) {
	// 22:00-06:00 wraps midnight
	c := &Constraint{
		TimeOfDay: &TimeRange{
			Start: TimeOfDay{Hour: 22, Minute: 0},
			End:   TimeOfDay{Hour: 6, Minute: 0},
		},
	}

	// 23:00 is within 22:00-06:00
	at23 := time.Date(2024, 1, 1, 23, 0, 0, 0, time.UTC)
	if !Evaluate(c, 0, at23) {
		t.Error("23:00 should pass 22:00-06:00 constraint")
	}

	// 03:00 is within 22:00-06:00
	at3 := time.Date(2024, 1, 1, 3, 0, 0, 0, time.UTC)
	if !Evaluate(c, 0, at3) {
		t.Error("03:00 should pass 22:00-06:00 constraint")
	}

	// 12:00 is outside 22:00-06:00
	at12 := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	if Evaluate(c, 0, at12) {
		t.Error("12:00 should fail 22:00-06:00 constraint")
	}
}

func TestEvaluateDaysOfWeek(t *testing.T) {
	c := &Constraint{
		DaysOfWeek: []time.Weekday{time.Monday, time.Wednesday, time.Friday},
	}

	monday := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC) // Monday
	if !Evaluate(c, 0, monday) {
		t.Error("Monday should pass Mon/Wed/Fri constraint")
	}

	tuesday := time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC) // Tuesday
	if Evaluate(c, 0, tuesday) {
		t.Error("Tuesday should fail Mon/Wed/Fri constraint")
	}
}

func TestEvaluateCombinedConstraints(t *testing.T) {
	c := &Constraint{
		MaxContainerAge: 60 * time.Second,
		TimeOfDay: &TimeRange{
			Start: TimeOfDay{Hour: 2, Minute: 0},
			End:   TimeOfDay{Hour: 3, Minute: 0},
		},
	}

	// Within age and time window
	at230 := time.Date(2024, 1, 1, 2, 30, 0, 0, time.UTC)
	if !Evaluate(c, 30*time.Second, at230) {
		t.Error("age 30s at 02:30 should pass")
	}

	// Age exceeded
	if Evaluate(c, 90*time.Second, at230) {
		t.Error("age 90s should fail max 60s")
	}

	// Time window missed
	at10 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	if Evaluate(c, 30*time.Second, at10) {
		t.Error("10:00 should fail 02:00-03:00 constraint")
	}
}

func TestEvaluateUnknownAgeIsOutsideWindow(t *testing.T) {
	for _, c := range []*Constraint{
		{MaxContainerAge: time.Hour},
		{MinContainerAge: time.Second},
		{MaxContainerAge: time.Hour, MinContainerAge: time.Second},
	} {
		if Evaluate(c, 0, time.Now()) {
			t.Errorf("%+v: unknown (zero) age must be outside the window", c)
		}
		if Evaluate(c, -time.Second, time.Now()) {
			t.Errorf("%+v: negative age must be outside the window", c)
		}
	}
	// A time-only constraint does not care about age.
	c := &Constraint{DaysOfWeek: []time.Weekday{time.Monday}}
	if !Evaluate(c, 0, time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)) {
		t.Error("unknown age must not affect a days_of_week-only constraint")
	}
}

func TestEvaluateUnknownClockIsOutsideWindow(t *testing.T) {
	c := &Constraint{TimeOfDay: &TimeRange{Start: TimeOfDay{0, 0}, End: TimeOfDay{23, 59}}}
	if Evaluate(c, time.Minute, time.Time{}) {
		t.Error("zero wall clock must be outside a time_of_day window")
	}
	if Evaluate(c, time.Minute, time.Unix(0, 0)) {
		t.Error("epoch wall clock must be outside a time_of_day window")
	}
	// An age-only constraint does not care about the clock.
	if !Evaluate(&Constraint{MaxContainerAge: time.Hour}, time.Minute, time.Time{}) {
		t.Error("unknown clock must not affect a max_container_age-only constraint")
	}
}

func TestEvaluateUsesUTC(t *testing.T) {
	c := &Constraint{
		TimeOfDay:  &TimeRange{Start: TimeOfDay{9, 0}, End: TimeOfDay{10, 0}},
		DaysOfWeek: []time.Weekday{time.Monday},
	}
	// 09:30 UTC Monday expressed in UTC+10, where it is 19:30.
	east := time.FixedZone("UTC+10", 10*3600)
	at := time.Date(2024, 1, 1, 19, 30, 0, 0, east)
	if !Evaluate(c, 0, at) {
		t.Error("window must be evaluated in UTC, not the time's location")
	}
}

func TestEvaluateBoundaries(t *testing.T) {
	c := &Constraint{TimeOfDay: &TimeRange{Start: TimeOfDay{2, 0}, End: TimeOfDay{4, 0}}}
	day := func(h, m, s int) time.Time { return time.Date(2024, 1, 1, h, m, s, 0, time.UTC) }
	for _, tc := range []struct {
		at   time.Time
		want bool
	}{
		{day(1, 59, 59), false},
		{day(2, 0, 0), true},
		{day(4, 0, 59), true}, // the end minute is inclusive
		{day(4, 1, 0), false},
	} {
		if got := Evaluate(c, 0, tc.at); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.at.Format("15:04:05"), got, tc.want)
		}
	}

	age := &Constraint{MaxContainerAge: 5 * time.Second, MinContainerAge: time.Second}
	for _, tc := range []struct {
		age  time.Duration
		want bool
	}{
		{999 * time.Millisecond, false},
		{time.Second, true},
		{5 * time.Second, true},
		{5*time.Second + 999*time.Microsecond, true}, // millisecond resolution
		{5*time.Second + time.Millisecond, false},
	} {
		if got := Evaluate(age, tc.age, time.Now()); got != tc.want {
			t.Errorf("age %v: got %v, want %v", tc.age, got, tc.want)
		}
	}
}

func TestValidate(t *testing.T) {
	tr := func(sh, sm, eh, em int) *TimeRange {
		return &TimeRange{Start: TimeOfDay{sh, sm}, End: TimeOfDay{eh, em}}
	}
	for _, tc := range []struct {
		name string
		c    *Constraint
		err  string
	}{
		{"nil", nil, ""},
		{"max", &Constraint{MaxContainerAge: time.Minute}, ""},
		{"wrap", &Constraint{TimeOfDay: tr(22, 0, 6, 0)}, ""},
		{"empty", &Constraint{}, "sets no constraint"},
		{"negative max", &Constraint{MaxContainerAge: -time.Second}, "must not be negative"},
		{"negative min", &Constraint{MinContainerAge: -time.Second}, "must not be negative"},
		{"sub-ms", &Constraint{MaxContainerAge: 1500 * time.Microsecond}, "whole number of milliseconds"},
		{"min > max", &Constraint{MaxContainerAge: time.Second, MinContainerAge: time.Minute}, "greater than max_container_age"},
		{"min == max", &Constraint{MaxContainerAge: time.Minute, MinContainerAge: time.Minute}, ""},
		{"hour 24", &Constraint{TimeOfDay: tr(24, 0, 1, 0)}, "start.hour must be 0-23"},
		{"end hour -1", &Constraint{TimeOfDay: tr(1, 0, -1, 0)}, "end.hour must be 0-23"},
		{"minute 60", &Constraint{TimeOfDay: tr(1, 60, 2, 0)}, "start.minute must be 0-59"},
		{"equal ends", &Constraint{TimeOfDay: tr(3, 0, 3, 0)}, "single minute"},
		{"bad weekday", &Constraint{DaysOfWeek: []time.Weekday{7}}, "invalid weekday"},
		{"dup weekday", &Constraint{DaysOfWeek: []time.Weekday{time.Monday, time.Monday}}, "twice"},
	} {
		err := tc.c.Validate()
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s: error %v, want it to contain %q", tc.name, err, tc.err)
		}
	}
}

func TestParseWeekday(t *testing.T) {
	for in, want := range map[string]time.Weekday{"Monday": time.Monday, "sunday": time.Sunday, "SATURDAY": time.Saturday} {
		if got, err := ParseWeekday(in); err != nil || got != want {
			t.Errorf("ParseWeekday(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"Mon", "", "Funday"} {
		if _, err := ParseWeekday(in); err == nil {
			t.Errorf("ParseWeekday(%q) accepted", in)
		}
	}
}
