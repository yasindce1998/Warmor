package compiler

import (
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/temporal"
)

// temporalPolicy wraps a temporal block (indented YAML, without the
// "temporal:" key) in a one-rule policy.
func temporalPolicy(action, block string) string {
	return `name: t
version: 1
rules:
  - name: r
    event: process
    conditions:
      all:
        - comm: { eq: "apt" }
    action: ` + action + `
    temporal:
` + block + `
default_action: allow
`
}

func TestParseTemporal(t *testing.T) {
	p, err := Parse([]byte(temporalPolicy("deny", `      max_container_age: "1d12h"
      min_container_age: "30s"
      time_of_day:
        start: { hour: 22, minute: 15 }
        end: { hour: 6, minute: 0 }
      days_of_week: [Monday, friday]`)))
	if err != nil {
		t.Fatal(err)
	}
	got := p.Rules[0].Temporal
	want := &temporal.Constraint{
		MaxContainerAge: 36 * time.Hour,
		MinContainerAge: 30 * time.Second,
		TimeOfDay:       &temporal.TimeRange{Start: temporal.TimeOfDay{Hour: 22, Minute: 15}, End: temporal.TimeOfDay{Hour: 6}},
		DaysOfWeek:      []time.Weekday{time.Monday, time.Friday},
	}
	if got == nil || got.MaxContainerAge != want.MaxContainerAge || got.MinContainerAge != want.MinContainerAge ||
		*got.TimeOfDay != *want.TimeOfDay || len(got.DaysOfWeek) != 2 ||
		got.DaysOfWeek[0] != time.Monday || got.DaysOfWeek[1] != time.Friday {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}

	plain, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range plain.Rules {
		if r.Temporal != nil {
			t.Errorf("rule %s without a temporal block parsed one", r.Name)
		}
	}
}

func TestParseTemporal_Errors(t *testing.T) {
	for _, tc := range []struct {
		name, action, block, want string
	}{
		{"null block", "deny", ``, "must be a map"},
		{"list block", "deny", `      - max_container_age: "5m"`, "must be a map"},
		{"empty block", "deny", `      {}`, "sets no constraint"},
		{"unknown key", "deny", `      max_age: "5m"`, `unknown key(s) max_age`},
		{"typo next to valid key", "deny", "      max_container_age: \"5m\"\n      day_of_week: [Monday]", "unknown key(s) day_of_week"},
		{"bad duration", "deny", `      max_container_age: "5 minutes"`, "max_container_age"},
		{"numeric duration", "deny", `      max_container_age: 300`, "must be a duration string"},
		{"zero duration", "deny", `      max_container_age: "0s"`, "greater than zero"},
		{"negative duration", "deny", `      min_container_age: "-5m"`, "must not be negative"},
		{"sub-millisecond", "deny", `      max_container_age: "1500us"`, "whole number of milliseconds"},
		{"min above max", "deny", "      max_container_age: \"1m\"\n      min_container_age: \"1h\"", "greater than max_container_age"},
		{"hour 24", "deny", "      time_of_day:\n        start: { hour: 24, minute: 0 }\n        end: { hour: 2, minute: 0 }", "start.hour must be 0-23"},
		{"minute 60", "deny", "      time_of_day:\n        start: { hour: 1, minute: 0 }\n        end: { hour: 2, minute: 60 }", "end.minute must be 0-59"},
		{"negative hour", "deny", "      time_of_day:\n        start: { hour: -1, minute: 0 }\n        end: { hour: 2, minute: 0 }", "start.hour must be 0-23"},
		{"string hour", "deny", "      time_of_day:\n        start: { hour: \"2\", minute: 0 }\n        end: { hour: 3, minute: 0 }", "hour must be an integer"},
		{"missing minute", "deny", "      time_of_day:\n        start: { hour: 2 }\n        end: { hour: 3, minute: 0 }", "time_of_day.start: minute is required"},
		{"missing end", "deny", "      time_of_day:\n        start: { hour: 2, minute: 0 }", "time_of_day.end is required"},
		{"extra time key", "deny", "      time_of_day:\n        start: { hour: 2, minute: 0 }\n        end: { hour: 3, minute: 0 }\n        tz: UTC", "time_of_day: unknown key(s) tz"},
		{"equal ends", "deny", "      time_of_day:\n        start: { hour: 2, minute: 0 }\n        end: { hour: 2, minute: 0 }", "single minute"},
		{"unknown weekday", "deny", `      days_of_week: [Mon]`, `unknown weekday "Mon"`},
		{"empty weekdays", "deny", `      days_of_week: []`, "at least one day"},
		{"weekday not a list", "deny", `      days_of_week: Monday`, "must be a list"},
		{"duplicate weekday", "deny", `      days_of_week: [Monday, monday]`, "twice"},
		{"allow rule", "allow", `      max_container_age: "5m"`, "only supported on deny and log rules"},
	} {
		_, err := Parse([]byte(temporalPolicy(tc.action, tc.block)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want it to contain %q", tc.name, err, tc.want)
		} else if !strings.Contains(err.Error(), "temporal") {
			t.Errorf("%s: error %q does not name the temporal block", tc.name, err)
		}
	}
}

func TestParseTemporal_LogAndAuditRules(t *testing.T) {
	for _, action := range []string{"deny", "log"} {
		if _, err := Parse([]byte(temporalPolicy(action, `      max_container_age: "5m"`))); err != nil {
			t.Errorf("%s rule: %v", action, err)
		}
	}
}

func TestFieldsRead_Temporal(t *testing.T) {
	p, err := Parse([]byte(`name: t
version: 1
rules:
  - name: age
    event: network
    conditions:
      all:
        - comm: { eq: "curl" }
    action: deny
    temporal:
      max_container_age: "5m"
  - name: clock
    event: process
    conditions:
      all:
        - path: { glob: "/usr/bin/apt*" }
    action: deny
    temporal:
      days_of_week: [Tuesday]
  - name: plain
    event: file
    conditions:
      all:
        - path: { eq: "/etc/shadow" }
    action: deny
`))
	if err != nil {
		t.Fatal(err)
	}
	fr := FieldsRead(p)
	if want := FieldBitPath | FieldBitTime; fr[0] != want {
		t.Errorf("process = %v, want %v", FieldNames(fr[0]), FieldNames(want))
	}
	if want := FieldBitPath; fr[1] != want {
		t.Errorf("file = %v, want %v", FieldNames(fr[1]), FieldNames(want))
	}
	if want := FieldBitComm | FieldBitContainerAge; fr[2] != want {
		t.Errorf("network = %v, want %v", FieldNames(fr[2]), FieldNames(want))
	}
	if names := FieldNames(FieldBitTime | FieldBitContainerAge); strings.Join(names, ",") != "container_age,wall_clock" {
		t.Errorf("FieldNames = %v", names)
	}
}

func TestGenerateRust_Temporal(t *testing.T) {
	p, err := Parse([]byte(temporalPolicy("deny", `      max_container_age: "90s"
      min_container_age: "1500ms"
      time_of_day:
        start: { hour: 22, minute: 0 }
        end: { hour: 4, minute: 30 }
      days_of_week: [Sunday, Tuesday, Saturday]`)))
	if err != nil {
		t.Fatal(err)
	}
	src, err := GenerateRust(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"const OFF_WALL_CLOCK: usize = 245;",
		"const OFF_CONTAINER_AGE: usize = 249;",
		"let wall = read_u32(base, OFF_WALL_CLOCK);",
		"let age_ms = read_u48(base, OFF_CONTAINER_AGE);",
		`if (comm == "apt") && !(age_at_most(age_ms, 90000) && age_at_least(age_ms, 1500) && in_time_window(wall, 1320, 270) && on_weekday(wall, 0x45)) {`,
		"pub extern \"C\" fn abi_version() -> u32 {\n    3\n}",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated Rust missing %q", want)
		}
	}

	// Rules without a temporal block are unchanged.
	plain, err := GenerateRust(mustParse(t, sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain, `if (matches_glob(path, "/tmp/**")) {`) && !strings.Contains(plain, `if matches_glob(path, "/tmp/**") {`) {
		t.Error("plain rule check changed shape")
	}
	if strings.Contains(plain, "&& !(") {
		t.Error("plain policy has a temporal window check")
	}
}

func mustParse(t *testing.T, y string) *Policy {
	t.Helper()
	p, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
