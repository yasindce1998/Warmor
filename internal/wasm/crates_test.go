package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

// End-to-end tests for the Rust policy crates under policies/. Each crate's
// release artifact is loaded through the same path the daemon uses
// (Runtime.LoadPolicy -> Pool -> PolicyEvaluator) and driven with events
// shaped exactly like the ones the sensors produce, so a mismatch in ABI
// selection, export names or the JSON event schema shows up as a failure.
//
// The artifacts are not checked in. Build them first:
//
//	scripts/build-rust-policies.sh
//
// Crates whose artifact is missing are skipped, so a plain `go test ./...`
// without a Rust toolchain still passes. Set WARMOR_REQUIRE_POLICY_CRATES=1
// (as CI does) to turn a missing artifact into a failure.

const crateTarget = "wasm32-unknown-unknown"

func procEvent(uid uint32, comm, filename string) *api.Event {
	ev := &api.Event{PID: 4242, UID: uid, GID: uid, Comm: comm, Filename: filename}
	ev.SetType(api.EventTypeProcess)
	return ev
}

func fileEvent(uid uint32, comm, path, op string, flags uint32) *api.Event {
	return &api.Event{
		PID: 4242, UID: uid, GID: uid, Comm: comm, Type: api.EventTypeFile,
		File: &api.FileEvent{Operation: op, Path: path, Flags: flags},
	}
}

func netEvent(uid uint32, comm, addr string, port uint16) *api.Event {
	return &api.Event{
		PID: 4242, UID: uid, GID: uid, Comm: comm, Type: api.EventTypeNetwork,
		Network: &api.NetworkEvent{
			Operation: "connect", Protocol: "tcp",
			RemoteAddr: addr, RemotePort: port, LocalPort: 40000,
		},
	}
}

type crateCase struct {
	name  string
	event *api.Event
	want  api.Action
}

type crateSuite struct {
	dir   string // directory under policies/
	lib   string // cdylib file name
	cases []crateCase
}

var crateSuites = []crateSuite{
	{
		dir: "advanced", lib: "warmor_policy_advanced.wasm",
		cases: []crateCase{
			{"benign process", procEvent(1000, "ls", "/usr/bin/ls"), api.ActionAllow},
			{"benign file", fileEvent(1000, "cat", "/app/config.json", "open", 0), api.ActionAllow},
			{"sensitive file", fileEvent(1000, "cat", "/etc/shadow", "open", 0), api.ActionLog},
			{"benign network", netEvent(1000, "curl", "93.184.216.34", 443), api.ActionAllow},
			{"non-root nc", procEvent(1000, "nc", "/usr/bin/nc"), api.ActionDeny},
		},
	},
	{
		dir: "container-escape", lib: "warmor_policy_container_escape.wasm",
		cases: []crateCase{
			{"benign process", procEvent(1000, "ls", "/usr/bin/ls"), api.ActionAllow},
			{"benign file", fileEvent(1000, "cat", "/etc/hostname", "open", 0), api.ActionAllow},
			{"benign network", netEvent(1000, "curl", "93.184.216.34", 443), api.ActionAllow},
			{"nsenter", procEvent(0, "nsenter", "/usr/bin/nsenter"), api.ActionDeny},
			{"docker socket", fileEvent(0, "sh", "/var/run/docker.sock", "open", 2), api.ActionDeny},
			{"cloud metadata", netEvent(0, "curl", "169.254.169.254", 80), api.ActionDeny},
		},
	},
	{
		dir: "cross-platform", lib: "cross_platform_policy.wasm",
		cases: []crateCase{
			{"benign process", procEvent(1000, "ls", "/usr/bin/ls"), api.ActionAllow},
			{"benign file", fileEvent(1000, "cat", "/home/user/notes.txt", "open", 0), api.ActionAllow},
			{"benign network", netEvent(1000, "curl", "93.184.216.34", 443), api.ActionAllow},
			{"exec from /tmp", procEvent(1000, "x", "/tmp/payload"), api.ActionDeny},
			{"suspicious port", netEvent(1000, "sh", "10.0.0.5", 4444), api.ActionLog},
			{"sensitive file", fileEvent(1000, "cat", "/etc/shadow", "open", 0), api.ActionLog},
		},
	},
	{
		dir: "crypto-mining", lib: "warmor_policy_crypto_mining.wasm",
		cases: []crateCase{
			{"benign process", procEvent(1000, "ls", "/usr/bin/ls"), api.ActionAllow},
			{"benign file", fileEvent(1000, "cat", "/home/user/notes.txt", "open", 0), api.ActionAllow},
			{"benign network", netEvent(1000, "curl", "93.184.216.34", 443), api.ActionAllow},
			{"xmrig", procEvent(1000, "xmrig", "/usr/local/bin/xmrig"), api.ActionDeny},
			{"stratum port", netEvent(1000, "worker", "51.15.1.1", 3333), api.ActionDeny},
		},
	},
	{
		dir: "example", lib: "warmor_policy_example.wasm",
		cases: []crateCase{
			{"benign process", procEvent(1000, "ls", "/usr/bin/ls"), api.ActionAllow},
			{"benign file", fileEvent(0, "bash", "/root/.bashrc", "open", 0), api.ActionAllow},
			{"benign network", netEvent(0, "bash", "93.184.216.34", 443), api.ActionAllow},
			{"root bash", procEvent(0, "bash", "/bin/bash"), api.ActionDeny},
		},
	},
	{
		dir: "lateral-movement", lib: "warmor_policy_lateral_movement.wasm",
		cases: []crateCase{
			{"benign process", procEvent(1000, "ls", "/usr/bin/ls"), api.ActionAllow},
			{"benign file", fileEvent(1000, "cat", "/app/config.json", "open", 0), api.ActionAllow},
			{"benign network", netEvent(1000, "curl", "93.184.216.34", 443), api.ActionAllow},
			{"impacket-psexec", procEvent(1000, "impacket-psexec", "/usr/bin/impacket-psexec"), api.ActionDeny},
			{"non-root reads /etc/shadow", fileEvent(1000, "cat", "/etc/shadow", "read", 0), api.ActionDeny},
			{"mimikatz", procEvent(0, "mimikatz", "/tmp/mimikatz"), api.ActionDeny},
		},
	},
	{
		dir: "multi", lib: "warmor_policy_multi.wasm",
		cases: []crateCase{
			{"benign process", procEvent(1000, "ls", "/usr/bin/ls"), api.ActionAllow},
			{"benign file", fileEvent(1000, "cat", "/etc/hosts", "read", 0), api.ActionAllow},
			{"root bash", procEvent(0, "bash", "/bin/bash"), api.ActionDeny},
			{"exec from /tmp", procEvent(1000, "x", "/tmp/malware"), api.ActionDeny},
			{"non-root write /etc", fileEvent(1000, "tee", "/etc/hosts", "write", 1), api.ActionDeny},
			{"non-root ssh", netEvent(1000, "ssh", "192.168.1.100", 22), api.ActionDeny},
		},
	},
	{
		dir: "supply-chain", lib: "warmor_policy_supply_chain.wasm",
		cases: []crateCase{
			{"benign process", procEvent(1000, "sh", "/bin/sh"), api.ActionAllow},
			{"benign file", fileEvent(1000, "cat", "/app/config.json", "open", 0), api.ActionAllow},
			{"apt-get at runtime", procEvent(0, "apt-get", "/usr/bin/apt-get"), api.ActionDeny},
			{"gcc at runtime", procEvent(0, "gcc", "/usr/bin/gcc"), api.ActionDeny},
			{"exec from /tmp", procEvent(1000, "x", "/tmp/dropper"), api.ActionDeny},
		},
	},
	{
		dir: "temporal-access", lib: "warmor_policy_temporal_access.wasm",
		cases: []crateCase{
			{"benign process", procEvent(1000, "ls", "/usr/bin/ls"), api.ActionAllow},
			{"benign file", fileEvent(1000, "cat", "/home/user/notes.txt", "open", 0), api.ActionAllow},
			{"benign network", netEvent(1000, "curl", "93.184.216.34", 443), api.ActionAllow},
			{"maintenance-only tool outside window", procEvent(0, "apt-get", "/usr/bin/apt-get"), api.ActionDeny},
		},
	},
	{
		dir: "zero-trust-net", lib: "warmor_policy_zero_trust_net.wasm",
		cases: []crateCase{
			{"benign process", procEvent(1000, "ls", "/usr/bin/ls"), api.ActionAllow},
			{"benign file", fileEvent(1000, "cat", "/home/user/notes.txt", "open", 0), api.ActionAllow},
			{"benign network", netEvent(1000, "java", "10.0.3.7", 5432), api.ActionAllow},
			{"external egress is audited", netEvent(1000, "curl", "93.184.216.34", 443), api.ActionLog},
			{"nmap", procEvent(1000, "nmap", "/usr/bin/nmap"), api.ActionDeny},
			{"undeclared egress port", netEvent(1000, "sh", "93.184.216.34", 6667), api.ActionDeny},
			{"resolv.conf write", fileEvent(0, "sh", "/etc/resolv.conf", "write", 1), api.ActionDeny},
			{"metadata service", netEvent(1000, "curl", "169.254.169.254", 80), api.ActionDeny},
		},
	},
}

func TestPolicyCrates(t *testing.T) {
	require := os.Getenv("WARMOR_REQUIRE_POLICY_CRATES") == "1"
	ctx := context.Background()

	for _, suite := range crateSuites {
		t.Run(suite.dir, func(t *testing.T) {
			path := filepath.Join("..", "..", "policies", suite.dir, "target", crateTarget, "release", suite.lib)
			if _, err := os.Stat(path); err != nil {
				if require {
					t.Fatalf("policy artifact missing: %v (run scripts/build-rust-policies.sh)", err)
				}
				t.Skipf("policy artifact missing (run scripts/build-rust-policies.sh): %v", err)
			}

			rt, err := NewRuntime(ctx)
			if err != nil {
				t.Fatalf("NewRuntime: %v", err)
			}
			defer rt.Close(ctx)
			if err := rt.LoadPolicy(ctx, path); err != nil {
				t.Fatalf("LoadPolicy: %v", err)
			}
			pool, err := NewPool(ctx, rt, 1)
			if err != nil {
				t.Fatalf("NewPool: %v", err)
			}
			defer pool.Close(ctx)
			eval := NewPolicyEvaluator(pool, "test-host")

			var sawAllow, sawDeny bool
			for _, tc := range suite.cases {
				res, err := eval.Evaluate(ctx, tc.event)
				if err != nil {
					t.Errorf("%s: Evaluate: %v", tc.name, err)
					continue
				}
				if res.Action != tc.want {
					t.Errorf("%s: action = %v, want %v", tc.name, res.Action, tc.want)
				}
				sawAllow = sawAllow || tc.want == api.ActionAllow
				sawDeny = sawDeny || tc.want == api.ActionDeny
			}
			if !sawAllow || !sawDeny {
				t.Errorf("suite must cover at least one ALLOW and one DENY case")
			}
		})
	}
}
