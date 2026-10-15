package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/temporal"
	"github.com/yasindce1998/warmor/pkg/api"
)

const temporalE2EYAML = `name: temporal-e2e
version: 1
rules:
  - name: curl-only-at-startup
    event: network
    conditions:
      all:
        - comm: { eq: "curl" }
    action: deny
    reason: "curl after startup window"
    temporal:
      max_container_age: "5m"

  - name: psql-after-warmup
    event: process
    conditions:
      all:
        - comm: { eq: "psql" }
    action: deny
    reason: "psql during warmup"
    temporal:
      min_container_age: "30s"

  - name: apt-maintenance-window
    event: process
    conditions:
      all:
        - path: { glob: "/usr/bin/apt*" }
    action: deny
    reason: "apt outside maintenance window"
    temporal:
      time_of_day:
        start: { hour: 22, minute: 0 }
        end: { hour: 4, minute: 30 }
      days_of_week: [Tuesday, Thursday]

  - name: helm-weekdays
    event: process
    conditions:
      all:
        - comm: { eq: "helm" }
    action: deny
    reason: "helm on a weekend"
    temporal:
      days_of_week: [Monday, Tuesday, Wednesday, Thursday, Friday]

  - name: cron-business-hours
    event: process
    conditions:
      all:
        - comm: { eq: "cron" }
    action: log
    reason: "cron outside business hours or after the first hour"
    temporal:
      max_container_age: "1h"
      time_of_day:
        start: { hour: 9, minute: 0 }
        end: { hour: 17, minute: 0 }

  - name: shadow
    event: file
    conditions:
      all:
        - path: { eq: "/etc/shadow" }
    action: deny
default_action: allow
`

// compileTemporalPolicy builds temporalE2EYAML with cargo, or skips when the
// Rust toolchain is missing (WARMOR_REQUIRE_CARGO=1 makes that a failure).
func compileTemporalPolicy(t *testing.T) (*compiler.Policy, *PolicyEvaluator) {
	t.Helper()
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo with the wasm32-unknown-unknown target is required")
		}
		t.Skip("cargo/wasm32-unknown-unknown not available")
	}
	policy, err := compiler.Parse([]byte(temporalE2EYAML))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "temporal.wasm")
	res, err := compiler.Build(policy, compiler.BuildOptions{OutputPath: out})
	compiler.Cleanup(res)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.Close(ctx) })
	if err := rt.LoadPolicy(ctx, out); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	ev := NewPolicyEvaluator(pool, "test")
	t.Cleanup(func() { ev.Close(ctx) })
	ev.SetTimeout(5 * time.Second) // -race is slow; this is not a latency test
	return policy, ev
}

func constraintOf(t *testing.T, p *compiler.Policy, rule string) *temporal.Constraint {
	t.Helper()
	for _, r := range p.Rules {
		if r.Name == rule {
			return r.Temporal
		}
	}
	t.Fatalf("no rule %q", rule)
	return nil
}

func tprocEvent(comm, path string, ts time.Time, age time.Duration) *api.Event {
	ev := &api.Event{Comm: comm, Timestamp: ts, Process: &api.ProcessEvent{Filename: path}}
	ev.SetType(api.EventTypeProcess)
	if age > 0 {
		ev.ContainerStart = ts.Add(-age)
	}
	return ev
}

// TestTemporalPolicyEndToEnd compiles a YAML policy with temporal rules via
// cargo, runs it in the real host and checks every decision against
// temporal.Evaluate (the reference semantics) at controlled clock values
// and container ages, including both sides of every boundary.
func TestTemporalPolicyEndToEnd(t *testing.T) {
	policy, ev := compileTemporalPolicy(t)
	ctx := context.Background()

	check := func(desc string, event *api.Event, c *temporal.Constraint, age time.Duration, outside api.Action, reason string) {
		t.Helper()
		want := api.ActionAllow
		if !temporal.Evaluate(c, age, event.Timestamp) {
			want = outside
		}
		res, err := ev.Evaluate(ctx, event)
		if err != nil {
			t.Fatalf("%s: %v", desc, err)
		}
		if res.Action != want {
			t.Errorf("%s at %s (age %v): got %v, want %v", desc, event.Timestamp.UTC().Format("Mon 15:04:05"), age, res.Action, want)
		}
		if want != api.ActionAllow && res.Reason != reason {
			t.Errorf("%s: reason %q, want %q", desc, res.Reason, reason)
		}
	}

	monday := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) // a Monday
	if monday.Weekday() != time.Monday {
		t.Fatal("bad fixture date")
	}

	// Clock-only rules, across a whole week: every 7 minutes (which walks
	// through every minute of the hour over the week) plus both sides of
	// each window edge and of midnight, every day.
	var times []time.Time
	for ts := monday; ts.Before(monday.AddDate(0, 0, 7)); ts = ts.Add(7 * time.Minute) {
		times = append(times, ts)
	}
	for d := 0; d < 7; d++ {
		day := monday.AddDate(0, 0, d)
		for _, hms := range [][3]int{
			{0, 0, 0}, {23, 59, 59}, {21, 59, 59}, {22, 0, 0}, {4, 30, 0}, {4, 30, 59}, {4, 31, 0},
			{8, 59, 59}, {9, 0, 0}, {17, 0, 59}, {17, 1, 0},
		} {
			times = append(times, day.Add(time.Duration(hms[0])*time.Hour+time.Duration(hms[1])*time.Minute+time.Duration(hms[2])*time.Second))
		}
	}
	apt := constraintOf(t, policy, "apt-maintenance-window")
	helm := constraintOf(t, policy, "helm-weekdays")
	for _, ts := range times {
		check("apt", tprocEvent("apt-get", "/usr/bin/apt-get", ts, 0), apt, 0, api.ActionDeny, "apt outside maintenance window")
		check("helm", tprocEvent("helm", "/usr/local/bin/helm", ts, 0), helm, 0, api.ActionDeny, "helm on a weekend")
	}

	// Spot checks that pin the semantics independently of Evaluate.
	at := func(day, h, m int) time.Time {
		return monday.AddDate(0, 0, day).Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute)
	}
	for _, tc := range []struct {
		desc string
		ts   time.Time
		want api.Action
	}{
		{"Tue 23:00, in window", at(1, 23, 0), api.ActionAllow},
		{"Thu 03:00, in window after midnight wrap", at(3, 3, 0), api.ActionAllow},
		{"Wed 03:00, wrap hours but wrong day", at(2, 3, 0), api.ActionDeny},
		{"Tue 12:00, right day, outside hours", at(1, 12, 0), api.ActionDeny},
		{"Tue 04:30, end minute is inclusive", at(1, 4, 30), api.ActionAllow},
		{"Tue 04:31, just past the end", at(1, 4, 31), api.ActionDeny},
	} {
		res, err := ev.Evaluate(ctx, tprocEvent("apt", "/usr/bin/apt", tc.ts, 0))
		if err != nil || res.Action != tc.want {
			t.Errorf("apt %s: %+v, %v; want %v", tc.desc, res, err, tc.want)
		}
	}
	for _, tc := range []struct {
		ts   time.Time
		want api.Action
	}{{at(4, 12, 0), api.ActionAllow}, {at(5, 12, 0), api.ActionDeny}, {at(6, 23, 59), api.ActionDeny}} {
		res, err := ev.Evaluate(ctx, tprocEvent("helm", "/usr/bin/helm", tc.ts, 0))
		if err != nil || res.Action != tc.want {
			t.Errorf("helm %s: %+v, %v; want %v", tc.ts.Weekday(), res, err, tc.want)
		}
	}

	// Age rules, including unknown age (fail closed), at a fixed clock.
	noon := at(2, 12, 0)
	ages := []time.Duration{0, time.Millisecond, 29999 * time.Millisecond, 30 * time.Second,
		5 * time.Minute, 5*time.Minute + time.Millisecond, time.Hour, time.Hour + time.Millisecond, 48 * time.Hour}
	curl := constraintOf(t, policy, "curl-only-at-startup")
	psql := constraintOf(t, policy, "psql-after-warmup")
	for _, age := range ages {
		net := &api.Event{Comm: "curl", Timestamp: noon, Network: &api.NetworkEvent{RemoteAddr: "10.0.0.1", RemotePort: 443}}
		net.SetType(api.EventTypeNetwork)
		if age > 0 {
			net.ContainerStart = noon.Add(-age)
		}
		check("curl", net, curl, age, api.ActionDeny, "curl after startup window")
		check("psql", tprocEvent("psql", "/usr/bin/psql", noon, age), psql, age, api.ActionDeny, "psql during warmup")
	}
	unknown := &api.Event{Comm: "curl", Timestamp: noon, Network: &api.NetworkEvent{RemoteAddr: "10.0.0.1"}}
	unknown.SetType(api.EventTypeNetwork)
	if res, _ := ev.Evaluate(ctx, unknown); res == nil || res.Action != api.ActionDeny {
		t.Errorf("curl with unknown container age: %+v, want deny (fail closed)", res)
	}

	// Combined age + clock on a log rule.
	cron := constraintOf(t, policy, "cron-business-hours")
	for _, ts := range []time.Time{at(0, 8, 59), at(0, 9, 0), at(0, 12, 0), at(0, 17, 0), at(0, 17, 1)} {
		for _, age := range []time.Duration{0, time.Minute, time.Hour + time.Second} {
			check("cron", tprocEvent("cron", "/usr/sbin/cron", ts, age), cron, age, api.ActionLog,
				"cron outside business hours or after the first hour")
		}
	}

	// Rules without a temporal block ignore the clock entirely.
	for _, ts := range []time.Time{at(0, 3, 0), at(5, 23, 0)} {
		f := &api.Event{Timestamp: ts, File: &api.FileEvent{Path: "/etc/shadow", Operation: "open"}}
		f.SetType(api.EventTypeFile)
		if res, err := ev.Evaluate(ctx, f); err != nil || res.Action != api.ActionDeny {
			t.Errorf("shadow at %v: %+v, %v", ts, res, err)
		}
	}

	// What the module declares drives cache and kernel-map soundness.
	if !ev.TimeDependent(api.EventTypeProcess) || !ev.TimeDependent(api.EventTypeNetwork) {
		t.Error("event types with temporal rules must be time dependent")
	}
	if ev.TimeDependent(api.EventTypeFile) {
		t.Error("file has no temporal rule and must stay cacheable")
	}
	if !ev.ReadsContainerAge(api.EventTypeNetwork) || !ev.ReadsContainerAge(api.EventTypeProcess) || ev.ReadsContainerAge(api.EventTypeFile) {
		t.Error("ReadsContainerAge does not follow the age rules")
	}
}
