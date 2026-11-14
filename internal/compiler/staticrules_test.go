package compiler

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestStaticRulesExactIdentityContract(t *testing.T) {
	for _, n := range []int{127, 128, 129, 254, 255} {
		p := parsePolicyForTest(t, fmt.Sprintf(`name: lengths
version: 1
default_action: deny
rules:
  - name: exact
    event: process
    conditions:
      all:
        - path: %q
    action: allow
`, "/"+strings.Repeat("x", n-1)))
		rules, why := StaticRules(p)
		if n == 127 {
			if len(rules) != 1 || len(why) != 0 {
				t.Fatalf("127 bytes must be complete: %v %v", rules, why)
			}
		} else if len(rules) != 0 || why["process"] == "" {
			t.Fatalf("%d-byte path eligible: %v %v", n, rules, why)
		}
	}
	for _, addr := range []string{"2001:0db8::1", "2001:DB8::1", "::ffff:192.0.2.1"} {
		p := parsePolicyForTest(t, fmt.Sprintf(`name: endpoint
version: 1
default_action: deny
rules:
  - name: noncanonical
    event: network
    conditions:
      all:
        - remote_addr: %q
        - remote_port: 80
    action: allow
`, addr))
		rules, why := StaticRules(p)
		if len(rules) != 0 || why["network"] == "" {
			t.Fatalf("noncanonical %s eligible: %v %v", addr, rules, why)
		}
	}
}

func TestStaticRulesCollidingPathsPreserveFirstMatch(t *testing.T) {
	p := parsePolicyForTest(t, `name: collision
version: 1
default_action: deny
rules:
  - name: first
    event: process
    conditions:
      all:
        - path: /opt/warmor/collision-000079bb
    action: allow
  - name: collision
    event: process
    conditions:
      all:
        - path: /opt/warmor/collision-00044848
    action: deny
  - name: shadowed
    event: process
    conditions:
      all:
        - path: /opt/warmor/collision-000079bb
    action: deny
`)
	rules, why := StaticRules(p)
	if len(why) != 0 || len(rules) != 2 || rules[0].Action != 0 || rules[1].Action != 1 || rules[0].Pattern == rules[1].Pattern {
		t.Fatalf("first-match semantics lost: %+v %v", rules, why)
	}
}

func TestStaticRulesResolvedPathsStayLiteralAndBounded(t *testing.T) {
	// Static tables must use the parser's resolved value without cleaning paths
	// or applying IP-style canonicalization to literal bprm filenames.
	for _, path := range []string{"/opt/../bin/tool", "./tool", "/opt//tool", "/opt/café/tool", "/" + strings.Repeat("é", 63), "/" + strings.Repeat("é", 64), "/bin/tool\x00other"} {
		t.Run(fmt.Sprintf("%q", path), func(t *testing.T) {
			p := parsePolicyForTest(t, fmt.Sprintf(`name: resolved-path
version: 1
default_action: deny
variables:
  executable: %q
rules:
  - name: exact
    event: process
    conditions:
      all:
        - path: {eq: "$executable"}
    action: allow
`, path))
			rules, why := StaticRules(p)
			if len(path) > 127 || strings.ContainsRune(path, 0) {
				if len(rules) != 0 || why["process"] == "" {
					t.Fatalf("unsafe resolved path eligible: %+v %v", rules, why)
				}
				return
			}
			if len(rules) != 1 || rules[0].Pattern != path || len(why) != 0 {
				t.Fatalf("resolved literal path changed: %+v %v", rules, why)
			}
			if _, err := GenerateRust(p); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func parsePolicyForTest(t *testing.T, yaml string) *Policy {
	t.Helper()
	p, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestStaticRules_EligibleAllowlist(t *testing.T) {
	p := parsePolicyForTest(t, `
name: allowlist
version: 1
default_action: deny
rules:
  - name: allow-shell
    event: process
    conditions:
      all:
        - path: /bin/sh
    action: allow
  - name: allow-dns
    event: network
    conditions:
      all:
        - remote_addr: 10.0.0.1
        - remote_port: 53
    action: allow
  - name: deny-curl
    event: process
    conditions:
      all:
        - path: /usr/bin/curl
    action: deny
`)
	rules, ineligible := StaticRules(p)
	if len(ineligible) != 0 {
		t.Fatalf("ineligible = %v, want none", ineligible)
	}
	want := []StaticRule{
		{Event: "process", Action: 0, Pattern: "/bin/sh"},
		{Event: "process", Action: 1, Pattern: "/usr/bin/curl"},
		{Event: "network", Action: 0, Pattern: "10.0.0.1", Port: 53},
	}
	if !reflect.DeepEqual(rules, want) {
		t.Errorf("rules = %+v, want %+v", rules, want)
	}
}

func TestStaticRules_DefaultActionAllowIsIneligible(t *testing.T) {
	p := parsePolicyForTest(t, `
name: blocklist
version: 1
default_action: allow
rules:
  - name: deny-tmp
    event: process
    conditions:
      all:
        - path: /tmp/x
    action: deny
`)
	rules, ineligible := StaticRules(p)
	if len(rules) != 0 {
		t.Errorf("rules = %+v, want none", rules)
	}
	if _, ok := ineligible["process"]; !ok {
		t.Errorf("ineligible = %v, want a process reason", ineligible)
	}
}

func TestStaticRules_GlobRuleIsIneligible(t *testing.T) {
	p := parsePolicyForTest(t, `
name: globs
version: 1
default_action: deny
rules:
  - name: allow-bin
    event: process
    conditions:
      all:
        - path: { glob: "/usr/bin/*" }
    action: allow
`)
	rules, ineligible := StaticRules(p)
	if len(rules) != 0 {
		t.Errorf("rules = %+v, want none", rules)
	}
	if _, ok := ineligible["process"]; !ok {
		t.Errorf("ineligible = %v, want a process reason", ineligible)
	}
}

func TestStaticRules_ExtraFieldIsIneligible(t *testing.T) {
	// A path rule that also reads uid cannot be keyed exactly: the kernel
	// would apply it to every user.
	p := parsePolicyForTest(t, `
name: uid
version: 1
default_action: deny
rules:
  - name: allow-root-shell
    event: process
    conditions:
      all:
        - path: /bin/sh
        - uid: 0
    action: allow
`)
	rules, _ := StaticRules(p)
	if len(rules) != 0 {
		t.Errorf("rules = %+v, want none", rules)
	}
}

func TestStaticRules_NetworkNeedsBothEndpointFields(t *testing.T) {
	// An address without a port covers every port: not enumerable as one
	// endpoint key.
	p := parsePolicyForTest(t, `
name: addr-only
version: 1
default_action: deny
rules:
  - name: allow-dns
    event: network
    conditions:
      all:
        - remote_addr: 10.0.0.1
    action: allow
`)
	rules, ineligible := StaticRules(p)
	if len(rules) != 0 {
		t.Errorf("rules = %+v, want none", rules)
	}
	if _, ok := ineligible["network"]; !ok {
		t.Errorf("ineligible = %v, want a network reason", ineligible)
	}
}

func TestStaticRules_FirstMatchWinsOnDuplicatePatterns(t *testing.T) {
	p := parsePolicyForTest(t, `
name: dup
version: 1
default_action: deny
rules:
  - name: allow-first
    event: process
    conditions:
      all:
        - path: /bin/sh
    action: allow
  - name: deny-shadowed
    event: process
    conditions:
      all:
        - path: /bin/sh
    action: deny
`)
	rules, _ := StaticRules(p)
	if len(rules) != 1 || rules[0].Action != 0 {
		t.Errorf("rules = %+v, want only the first (allow) rule", rules)
	}
}

func TestStaticRules_TemporalAndAuditEncodings(t *testing.T) {
	p := parsePolicyForTest(t, `
name: mixed
version: 1
default_action: deny
rules:
  - name: audited-deny
    event: process
    conditions:
      all:
        - path: /tmp/x
    action: deny
    mode: audit
  - name: logged-allow
    event: process
    conditions:
      all:
        - path: /bin/true
    action: log
  - name: temporal
    event: process
    conditions:
      all:
        - path: /bin/false
    action: deny
    temporal:
      time_of_day:
        start: { hour: 9, minute: 0 }
        end: { hour: 17, minute: 0 }
`)
	rules, ineligible := StaticRules(p)
	if _, ok := ineligible["process"]; !ok {
		t.Fatalf("ineligible = %v, want a process reason (temporal rule)", ineligible)
	}
	if len(rules) != 0 {
		t.Errorf("rules = %+v, want none from an ineligible domain", rules)
	}

	// Without the temporal rule, audit and log encodings round-trip.
	p2 := parsePolicyForTest(t, `
name: mixed2
version: 1
default_action: deny
rules:
  - name: audited-deny
    event: process
    conditions:
      all:
        - path: /tmp/x
    action: deny
    mode: audit
  - name: logged-allow
    event: process
    conditions:
      all:
        - path: /bin/true
    action: log
`)
	rules2, _ := StaticRules(p2)
	want := []StaticRule{
		{Event: "process", Action: 1, Audit: true, Pattern: "/tmp/x"},
		{Event: "process", Action: 0, Audit: true, Pattern: "/bin/true"},
	}
	if !reflect.DeepEqual(rules2, want) {
		t.Errorf("rules = %+v, want %+v", rules2, want)
	}
}

func TestStaticRules_UnmatchablePatternIsIneligible(t *testing.T) {
	long := "/tmp/" + strings.Repeat("a", 300)
	p := parsePolicyForTest(t, `
name: long
version: 1
default_action: deny
rules:
  - name: allow-long
    event: process
    conditions:
      all:
        - path: `+long+`
    action: allow
`)
	rules, ineligible := StaticRules(p)
	if len(rules) != 0 {
		t.Errorf("rules = %+v, want none", rules)
	}
	if _, ok := ineligible["process"]; !ok {
		t.Errorf("ineligible = %v, want a process reason", ineligible)
	}
}

func TestEncodeStaticRules(t *testing.T) {
	rules := []StaticRule{
		{Event: "process", Action: 1, Audit: true, Pattern: "/tmp/x"},
		{Event: "network", Action: 0, Pattern: "10.0.0.1", Port: 53},
	}
	got := encodeStaticRules(rules, "process", true)
	// [eligible=1][action=1][audit=1][port=0][len=6]["/tmp/x"] — and the
	// network rule must be filtered out of the process table.
	want := append([]byte{1, 1, 1, 0, 0, 6, 0}, []byte("/tmp/x")...)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("process table = %v, want %v", got, want)
	}

	gotNet := encodeStaticRules(rules, "network", true)
	wantNet := []byte{1, 0, 0, 53, 0, 8, 0}
	wantNet = append(wantNet, []byte("10.0.0.1")...)
	if !reflect.DeepEqual(gotNet, wantNet) {
		t.Errorf("network table = %v, want %v", gotNet, wantNet)
	}

	if inel := encodeStaticRules(nil, "process", false); !reflect.DeepEqual(inel, []byte{0}) {
		t.Errorf("ineligible table = %v, want [0]", inel)
	}
}
