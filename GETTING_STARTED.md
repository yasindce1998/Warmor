# Getting Started with Warmor

Welcome! This guide walks you through setting up and running Warmor for the first time. No prior eBPF or WebAssembly experience needed.

> **Status:** This guide covers what current `main` actually does. Linux is the only platform that enforces. Kernel blocking covers repeat exec/connect denies only; everything else is detected and then killed with `SIGKILL`. See [Feature Status](docs/STATUS.md).

---

## What You'll Achieve

By the end of this guide, you'll have:
- Warmor running on your machine
- A security policy that denies suspicious activity (audited first, then enforced)
- Real-time visibility into what's executing on your system

---

## Before You Begin

You need a **Linux machine** (or VM/WSL2) with kernel 5.10 or newer and BTF enabled. Check with:

```bash
uname -r
# Should show 5.10+ (e.g., 6.1.0, 5.15.0)
```

> **Don't have Linux?** Use WSL2 on Windows, a VM, or a cloud instance (Ubuntu 22.04+ works great).

---

## Step 1: Install Dependencies

### Automatic (Recommended)

Run the installer script — it detects your distro and installs everything:

```bash
chmod +x scripts/install-prereqs.sh
sudo ./scripts/install-prereqs.sh
```

It will tell you exactly what got installed and what's still missing (with reasons why).

> **Known issue:** the script adds the `wasm32-wasi` Rust target, but the policy compiler needs `wasm32-unknown-unknown`. Run `rustup target add wasm32-unknown-unknown` after the script.

### Manual Install

If you prefer to install manually:

#### Ubuntu / Debian

```bash
# System packages
sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev \
  linux-headers-$(uname -r) pkg-config

# Go (1.26+)
# Download from https://go.dev/dl/ or:
sudo snap install go --classic

# Rust (1.70+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup target add wasm32-unknown-unknown
```

#### Fedora / RHEL

```bash
sudo dnf install -y clang llvm libbpf-devel kernel-devel pkg-config

# Go and Rust same as above
```

#### Arch Linux

```bash
sudo pacman -Syu --noconfirm clang llvm libbpf linux-headers pkg-config base-devel

# Go
sudo pacman -S go

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup target add wasm32-unknown-unknown
```

#### Verify Everything is Installed

```bash
go version          # Should show 1.26+
rustc --version     # Should show 1.70+
clang --version     # Any recent version
```

If all three commands work, you're ready to go.

---

## Step 2: Clone and Build

```bash
git clone https://github.com/yasindce1998/warmor.git
cd warmor
go build -o bin/ ./cmd/...
```

This builds every tool into `bin/`. The compiled BPF objects and their Go bindings are checked in, so you don't need clang for this step. If you change `bpf/*.c`, run `make build-bpf generate` to rebuild them.

`make all` does the same and also rebuilds the BPF programs, the Go bindings and the example Rust policy, so it needs clang and the Rust toolchain.

> **Build failing?** Jump to [Troubleshooting](#troubleshooting) below.

---

## Step 3: Write Your First Policy

> **Write your own policy rather than relying on the default.** `warmor-daemon` defaults to `--policy policies/example/policy.wasm`, a starter example. And start with `--audit`: without it, denied processes are SIGKILLed even if `--lsm-enforce` is off.

The easiest way to write a policy is YAML. Create a file called `my-policy.yaml`:

```yaml
name: my-first-policy
version: 1
description: "Block temp directory execution and network tools"

rules:
  - name: block-tmp-exec
    event: process
    conditions:
      all:
        - path: { glob: "/tmp/**" }
    action: deny
    reason: "No executing binaries from /tmp"

  - name: block-netcat
    event: process
    conditions:
      all:
        - path: { any_of: ["/usr/bin/nc", "/usr/bin/ncat"] }
    action: deny
    reason: "Network tools not permitted"

  - name: log-outbound-ssh
    event: network
    conditions:
      all:
        - remote_port: { any_of: [22] }
    action: log
    reason: "SSH connection logged"

default_action: allow
```

### Compile Your Policy

```bash
# Validate, then compile YAML → WASM (flags must come before the file name)
./bin/warmor-compile --validate my-policy.yaml
./bin/warmor-compile -o my-policy.wasm my-policy.yaml
```

`warmor-compile` generates Rust and runs `cargo build --target wasm32-unknown-unknown`, so it needs the Rust toolchain from Step 1. Unknown YAML keys are silently ignored. Run `./bin/warmor-compile --rust-only my-policy.yaml` to see exactly what was generated.

---

## Step 4: Run Warmor

Start in **audit mode**. Denies are logged and nothing is killed:

```bash
sudo ./bin/warmor-daemon --policy my-policy.wasm --audit --event-sink stdout
```

At startup the daemon logs its configuration and a `Security posture:` line. That line says whether LSM-BPF is loaded (enforcing or audit-only) or whether it fell back to tracepoint-only observe mode. Each evaluated event is logged as a JSON `policy_evaluation` line with `action` `ALLOW`, `DENY` or `LOG`.

When the audit log looks right, enforce:

```bash
sudo ./bin/warmor-daemon --policy my-policy.wasm --lsm-enforce
```

**What enforcement means on `main`:**
- `ALLOW` — the operation proceeds.
- `LOG` — the operation proceeds and is flagged.
- `DENY` — the daemon kills the process with `SIGKILL` after the event arrives, so the operation may already have started. For **exec and connect** the decision is also written into the kernel policy map. With `--lsm-enforce`, later identical exec/connect attempts in the same cgroup are then refused in the kernel with `EPERM`. File, bind, listen, ptrace and mount denies are never blocked in the kernel on `main`.

Press `Ctrl+C` to stop. Send `SIGHUP` to reload the policy file.

### Test It

In another terminal:

```bash
cp /usr/bin/echo /tmp/test-binary
/tmp/test-binary hello
# First run: usually "Killed" (detected, then SIGKILLed by the daemon)
/tmp/test-binary hello
# Later runs (with --lsm-enforce on a BPF-LSM kernel): "Permission denied" (blocked in the kernel)

ls /home
# → Works normally
```

---

## Step 5: Try Learning Mode (Optional)

Don't want to write rules by hand? Let Warmor watch your containers and auto-generate a policy:

```bash
# 1. Record events (audit mode, nothing is killed). The file name matches the
#    events-*.ndjson pattern that warmor-simulate reads.
sudo mkdir -p /var/lib/warmor/events
sudo ./bin/warmor-daemon --policy my-policy.wasm --audit \
  --event-sink file:/var/lib/warmor/events/events-current.ndjson

# 2. In another terminal, learn from the recording for 5 minutes
./bin/warmor-learn --events /var/lib/warmor/events/events-current.ndjson \
  --follow --duration 5m -o learned.yaml

# Review what it learned
cat learned.yaml

# 3. Test the learned policy against the recorded events (dry run)
./bin/warmor-simulate --policy learned.yaml --data /var/lib/warmor/events --since 1h
```

`warmor-learn` works offline from recorded events. There is no in-daemon learning mode flag.

---

## Common Workflows

### "I just want to monitor (not block)"

Use `--audit`:

```bash
sudo ./bin/warmor-daemon --policy my-policy.wasm --audit
# Denies are logged but nothing is killed or blocked
```

Leaving out `--lsm-enforce` alone is **not** observe-only. The kernel then only audits, but the daemon still `SIGKILL`s processes whose events the policy denies.

### "I want to test a policy before deploying"

```bash
./bin/warmor-simulate --policy candidate.yaml --data /var/lib/warmor/events --since 7d --format json -o report.json
# Shows what WOULD have been denied over the last 7 days
```

### "I want to validate my YAML without running anything"

```bash
./bin/warmor-compile --validate my-policy.yaml
# Reports errors without compiling
```

### "I want metrics in Prometheus/Grafana"

Warmor exposes metrics at `http://localhost:9090/metrics` by default:

```bash
curl http://localhost:9090/metrics | grep warmor
```

---

## Project Layout (What's Where)

```
warmor/
├── cmd/                    # All CLI tools (warmor-daemon, warmor-compile, etc.)
├── internal/               # Core engine (eBPF, WASM runtime, enforcer, etc.)
├── policies/               # Example Rust WASM policies + yaml-example/ (several have
│   ├── example/            #   known ABI issues on main; see docs/STATUS.md)
│   ├── container-escape/
│   ├── crypto-mining/
│   ├── lateral-movement/
│   ├── yaml-example/       #   53 categorized YAML policies
│   └── ...
├── examples/policies/      # 6 YAML examples
├── bpf/                    # Linux eBPF C source code
├── deploy/helm/warmor/     # Kubernetes Helm chart
└── docs/                   # Full documentation
```

---

## Kubernetes Deployment

> **Not working on `main` yet.** The Helm chart is being fixed. It has no way to enable `--lsm-enforce`, and it ships a YAML policy that the distroless image cannot compile. See [Feature Status](docs/STATUS.md#5-container-runtime-and-kubernetes).

---

## Troubleshooting

### "Permission denied"

eBPF requires root. Always run `warmor-daemon` with `sudo`.

### "Failed to load eBPF objects"

```bash
# Check kernel version (need 5.10+)
uname -r

# BTF must be available (CO-RE)
ls /sys/kernel/btf/vmlinux

# Rebuild BPF objects only if you changed bpf/*.c
make build-bpf generate && go build -o bin/ ./cmd/...
```

### "WASM policy failed to load"

```bash
# Verify the .wasm file exists and isn't empty
ls -la my-policy.wasm

# Test WASM evaluation standalone (no eBPF needed): replay a recorded
# events-*.ndjson directory through the policy
./bin/warmor-simulate --policy my-policy.wasm --data /var/lib/warmor/events
```

### Build errors with Go

```bash
# Make sure Go modules are downloaded
go mod download

# Try building just the daemon
go build -v ./cmd/warmor-daemon/
```

### "BTF not available"

Your kernel might not have BTF enabled. Check:

```bash
ls /sys/kernel/btf/vmlinux
# If missing, you need a kernel compiled with CONFIG_DEBUG_INFO_BTF=y
```

Ubuntu 22.04+, Fedora 36+, and Debian 12+ ship with BTF enabled by default.

---

## What's Next?

| Goal | Where to Go |
|------|------------|
| Understand the architecture | [docs/architecture.md](docs/architecture.md) |
| Write advanced YAML policies | [docs/policy-authoring.md](docs/policy-authoring.md) |
| Write Rust WASM policies | [docs/rust-policy-examples.md](docs/rust-policy-examples.md) |
| Deploy on Windows or macOS | [docs/PLATFORM_WINDOWS.md](docs/PLATFORM_WINDOWS.md) / [docs/PLATFORM_MACOS.md](docs/PLATFORM_MACOS.md) |
| See what ships and what doesn't | [docs/STATUS.md](docs/STATUS.md) |
| Set up fleet management | [docs/canary-rollout.md](docs/canary-rollout.md) |
| Full project overview | [docs/OVERVIEW.md](docs/OVERVIEW.md) |

---

## Need Help?

- **Issues**: [github.com/yasindce1998/warmor/issues](https://github.com/yasindce1998/warmor/issues)
- **Docs**: Browse the `docs/` directory for deep dives on every feature
- **Quick reference**: Run any tool with `--help` (e.g., `warmor-compile --help`)
