# Quick Start

Get warmor running on a Linux host.

> **Status on `main`:** Standalone Linux is the supported path. The Helm chart
> and the Kubernetes manifests do **not** work yet; they are being fixed (see
> [Kubernetes](#kubernetes-not-working-on-main-yet) below). Kernel blocking covers
> repeat exec/connect denies only; everything else is detected and then killed
> with `SIGKILL`. See [Feature Status](STATUS.md) for the full picture.

## Prerequisites

- Linux kernel 5.8+ with BTF (`ls /sys/kernel/btf/vmlinux`), x86_64 or arm64
- Root (required for eBPF)
- For kernel-level blocking: `CONFIG_BPF_LSM=y` and `bpf` listed in
  `/sys/kernel/security/lsm`. Without it, warmor falls back to tracepoint-only
  mode (detect, then kill).
- To compile YAML policies: Rust with the `wasm32-unknown-unknown` target
  (`rustup target add wasm32-unknown-unknown`). Compiling can happen on a build
  machine; the enforcing host only needs the resulting `.wasm`.

## 1. Get the binaries

### From source (tracks `main`)

```bash
git clone https://github.com/yasindce1998/warmor.git && cd warmor
go build -o bin/ ./cmd/...
```

The compiled BPF objects are checked in, so no clang is needed for this step.

### From a release

Releases ship one archive per platform containing all tools and a
`SHA256SUMS` file. Release binaries are built from the tag, not from `main`.

```bash
VERSION=v0.3.0   # pick from https://github.com/yasindce1998/warmor/releases
curl -LO https://github.com/yasindce1998/warmor/releases/download/${VERSION}/warmor-${VERSION}-linux-amd64.tar.gz
tar -xzf warmor-${VERSION}-linux-amd64.tar.gz
cd warmor-${VERSION}-linux-amd64 && sha256sum -c SHA256SUMS
sudo install -m 0755 warmor-daemon warmor-compile /usr/local/bin/
```

Use `linux-arm64` for ARM64 hosts.

## 2. Compile a policy

```bash
# Flags must come before the file name
./bin/warmor-compile --validate examples/policies/block-crypto-miners.yaml
./bin/warmor-compile -o crypto.wasm examples/policies/block-crypto-miners.yaml
```

> Every file in `examples/policies/` and `policies/yaml-example/` validates;
> CI fails if one doesn't.

You can also pass a `.yaml` file directly to `warmor-daemon --policy`. The daemon
then compiles it at startup, which needs `cargo` and the wasm32 target **on the
enforcing host**. A precompiled `.wasm` avoids that.

> **Start with `--audit`.** Without it, denied processes are SIGKILLed even
> when `--lsm-enforce` is off. The default `--policy`
> (`policies/example/policy.wasm`) is a starter example.

## 3. Run in audit mode

```bash
sudo ./bin/warmor-daemon --policy crypto.wasm --audit --event-sink stdout
```

Deny decisions are logged and nothing is killed. The startup `Security posture:`
line tells you whether LSM-BPF loaded.

## 4. Enforce

```bash
sudo ./bin/warmor-daemon --policy crypto.wasm --lsm-enforce
```

What this does on `main`:

- Every event is evaluated by the WASM policy in userspace. On **DENY** the
  process is killed with `SIGKILL` after the event arrives.
- For **exec** (exact path) and **connect** (address and port) the decision is
  also written into the kernel policy map. With `--lsm-enforce`, later
  identical attempts in the same cgroup are refused in the kernel with `EPERM`.
- File, bind, listen, ptrace and mount denies are never blocked in the kernel.
- `--require-lsm` refuses to start if LSM-BPF can't be loaded, and `--no-lsm`
  skips it.

Leaving out `--lsm-enforce` makes the kernel side audit-only, but the daemon
still kills denied processes. Use `--audit` for a true dry run.

`SIGHUP` reloads the policy file. Kernel map entries from the old policy are not
cleared on reload yet.

### Run as a systemd service

```bash
sudo install -D -m 0644 crypto.wasm /etc/warmor/policy.wasm
sudo tee /etc/systemd/system/warmor.service <<EOF
[Unit]
Description=Warmor eBPF Security Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/warmor-daemon --policy /etc/warmor/policy.wasm --audit
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now warmor
```

Swap `--audit` for `--lsm-enforce` once you trust the policy.

---

## Kubernetes (not working on main yet)

The Helm chart in `deploy/helm/warmor` is being fixed. On `main`:

- The initContainer runs `warmor-daemon --validate-policy`, a flag that does
  not exist, so pods stay in `Init`.
- The chart has no `lsmEnforce` value and never passes `--lsm-enforce`.
- The policy is shipped as YAML in a ConfigMap. The daemon would need `cargo`
  to compile it, and the distroless image does not include it.
- The `ValidatingWebhookConfiguration` has no handler, and the `WarmorPolicy`
  CRD has no controller (see [CRD usage](crd-usage.md)).
- `deploy/kubernetes/warmor-daemonset.yaml` configures the daemon through
  environment variables it does not read.

Instructions will return here once the chart works.

---

## warmorctl TUI

`warmorctl` is an interactive terminal UI for `warmor-server`. It has no
subcommands.

```bash
go install github.com/yasindce1998/warmor/cmd/warmorctl@latest

# The admin API needs a JWT with the admin role (--token or $WARMOR_TOKEN);
# --ca-cert trusts a private CA; --client-cert/--client-key for mTLS servers
export WARMOR_TOKEN=<admin-jwt>
warmorctl --server https://warmor-server:8443 --ca-cert ca.crt --client-cert admin.crt --client-key admin.key
```

Tabs:
- **Dashboard** — agent and policy summary from the server
- **Agents** — registered agents, heartbeat status, assigned policies
- **Policies** — list, create, update and delete policies
- **Rollouts** — percentage rollout management
- **Certs** — press `g` to generate a CA plus server and agent certificates, or
  `s` to generate a policy-signing key pair

There is no non-interactive `warmorctl certs generate` command. For signing
keys you can also use `warmor-policy-bundle --keygen`.

---

## mTLS Setup

Enable mutual TLS between agents and the policy server:

```bash
# Start server with mTLS (agents authenticate with client certificates;
# the admin API requires an admin JWT signed with --jwt-secret)
warmor-server \
  --addr :8443 \
  --tls-cert ./certs/server.crt \
  --tls-key ./certs/server.key \
  --ca-cert ./certs/ca.crt \
  --jwt-secret "$WARMOR_JWT_SECRET" \
  --policy-dir ./policies

# Start agent with mTLS; the downloaded policy replaces --policy
warmor-daemon \
  --policy /var/lib/warmor/policy.wasm \
  --server https://warmor-server:8443 \
  --tls-cert ./certs/agent-01.crt \
  --tls-key ./certs/agent-01.key \
  --tls-ca ./certs/ca.crt
```

The server refuses to start without authentication. Supported modes:

| Server flags | Agent / runtime auth | Admin API |
|--------------|---------------------|-----------|
| `--ca-cert --tls-cert --tls-key` | client certificate | admin JWT (needs `--jwt-secret`; disabled otherwise) |
| `--tls-cert --tls-key --jwt-secret` | JWT, role `agent` / `runtime` | admin JWT |
| `--jwt-secret` (plain HTTP) | JWT, role `agent` / `runtime` | admin JWT |
| `--insecure` (development only) | none | none |

`--ca-cert`, `--tls-cert` and `--tls-key` must be supplied as a consistent set;
`--jwt-secret` may also be given via `WARMOR_JWT_SECRET`. Agents using token
auth pass `--server-token` (or `WARMOR_SERVER_TOKEN`) instead of a client
certificate. Admin `wasm_path` values must point inside `--policy-dir`; without
it, policies cannot be created or updated over the API.

Policies downloaded from the server are **not** signature-verified by the
daemon on `main`.

---

## Monitoring Stack

```bash
cd deploy/
docker compose -f docker-compose.monitoring.yml up -d
```

This starts:
- **Prometheus** on `http://localhost:9091`, which scrapes warmor metrics
- **Grafana** on `http://localhost:3000` with a pre-provisioned dashboard (login: admin/warmor)

The daemon exports `warmor_events_total`, `warmor_cache_hits_total`,
`warmor_cache_misses_total`, `warmor_cache_size`,
`warmor_evaluation_latency_microseconds`, `warmor_policy_info`,
`warmor_events_processing_errors_total` and `warmor_audit_denied_total` on
`--metrics-port` (default 9090).

> Panels and alerts built on the LSM-decision, policy-load and heartbeat
> metrics stay empty on `main`. Those metrics are registered but never updated,
> and the eBPF-loader-failure alert references a metric that does not exist.

---

## Container Runtime Integration

### CRI-O / OCI hook (experimental)

```bash
sudo cp deploy/crio/warmor-hook.json /etc/containers/oci/hooks.d/
```

`warmor-oci-hook` reports container start/stop to `warmor-server`
(`/api/v1/containers/bind`). On `main`:

- It has no auth or TLS, so it only works against `warmor-server --insecure`.
- The server stores the bindings but nothing consumes them, so there is no
  per-container policy yet.
- The shipped hook config passes `--action start` for both stages.

### containerd / per-container policy

Not available on `main`. There are no `--containerd-socket` or
`--per-container-policy` flags. `internal/container` is library-only.

---

## What's Next

| Goal | Guide |
|------|-------|
| See what ships and what doesn't | [Feature Status](STATUS.md) |
| Auto-generate policies from audit logs | [Policy Generation](policy-generation.md) |
| Enforce SBOM-declared binaries only | [SBOM Enforcement](sbom-enforcement.md) |
| Merge multiple policies into one | [Policy Merge](policy-merge.md) |
| Compare two policies (SBOM vs audit) | [Policy Diff](policy-diff.md) |
| Push/pull compiled policies to OCI registries | [Policy Bundle](policy-bundle.md) |
| Write custom policies | [Policy Authoring](policy-authoring.md) |
| Replay events against a candidate policy | [Policy Simulator](policy-simulator.md) |
| Manage a fleet | Run `warmorctl`; see [Canary Rollout](canary-rollout.md) |
| Restrict to specific containers | `--cgroup-filter` (cgroup paths or `auto`) |
