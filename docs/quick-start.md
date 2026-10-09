# Quick Start

Get warmor running in under 5 minutes.

## Install Options

### Option A: Kubernetes (Helm)

Deploy as a DaemonSet in **audit-only mode** — nothing is blocked, safe to try on any cluster.

**Prerequisites:**
- Kubernetes 1.25+ cluster with Linux nodes (kernel 5.8+)
- `helm` v3.10+ (OCI support requires 3.8+)
- `kubectl` configured for your cluster

```bash
helm install warmor oci://ghcr.io/yasindce1998/warmor/charts/warmor \
  --version 0.2.0 \
  --namespace warmor-system --create-namespace \
  --set daemon.auditMode=true
```

Or from a local clone:
```bash
git clone https://github.com/yasindce1998/warmor.git
helm install warmor ./warmor/deploy/helm/warmor \
  --namespace warmor-system --create-namespace \
  --set daemon.auditMode=true
```

### Option B: Standalone Binary

Run directly on a Linux host (bare-metal, VM, or for local testing).

**Prerequisites:**
- Linux kernel 5.8+ (x86_64 or arm64)
- Root access (required for eBPF)

```bash
# Download latest release
curl -LO https://github.com/yasindce1998/warmor/releases/latest/download/warmor-daemon-linux-amd64
chmod +x warmor-daemon-linux-amd64
sudo mv warmor-daemon-linux-amd64 /usr/local/bin/warmor-daemon

# Verify
warmor-daemon --version
```

For ARM64 (AWS Graviton, Raspberry Pi):
```bash
curl -LO https://github.com/yasindce1998/warmor/releases/latest/download/warmor-daemon-linux-arm64
chmod +x warmor-daemon-linux-arm64
sudo mv warmor-daemon-linux-arm64 /usr/local/bin/warmor-daemon
```

**Verify checksum:**
```bash
curl -LO https://github.com/yasindce1998/warmor/releases/latest/download/warmor-daemon-linux-amd64.sha256
sha256sum -c warmor-daemon-linux-amd64.sha256
```

**Run with a policy:**
```bash
sudo warmor-daemon --policy examples/policies/kubernetes-hardening.yaml
```

**Run as a systemd service:**
```bash
sudo tee /etc/systemd/system/warmor.service <<EOF
[Unit]
Description=Warmor eBPF Security Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/warmor-daemon --policy /etc/warmor/policy.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now warmor
```

---

## Kubernetes Deployment

## 1. Install (Audit Mode)

```bash
helm install warmor oci://ghcr.io/yasindce1998/warmor/charts/warmor \
  --version 0.2.0 \
  --namespace warmor-system --create-namespace \
  --set daemon.auditMode=true
```

That's it. Warmor is now observing process executions, file access, and network connections without blocking anything.

## 2. Verify

```bash
# Check pods are running
kubectl -n warmor-system get pods -l app.kubernetes.io/name=warmor

# Check logs for events
kubectl -n warmor-system logs -l app.kubernetes.io/name=warmor --tail=20

# Check metrics endpoint
kubectl -n warmor-system port-forward ds/warmor 9090:9090 &
curl -s http://localhost:9090/metrics | grep warmor_events_total
```

## 3. Apply a Policy

Copy one of the [example policies](../examples/policies/) into your values:

```bash
helm upgrade warmor oci://ghcr.io/yasindce1998/warmor/charts/warmor \
  --version 0.2.0 \
  --namespace warmor-system \
  --set daemon.auditMode=true \
  --set-file policy.yaml=examples/policies/block-crypto-miners.yaml
```

Review the audit logs — denied events are logged but **not enforced** in audit mode.

## 4. Switch to Enforce Mode

Once you're confident the policy won't disrupt workloads:

```bash
helm upgrade warmor oci://ghcr.io/yasindce1998/warmor/charts/warmor \
  --version 0.2.0 \
  --namespace warmor-system \
  --set daemon.auditMode=false
```

## 5. Enable LSM-BPF Kernel Enforcement (Optional)

For synchronous kernel-level blocking (denied operations never execute):

```bash
helm upgrade warmor oci://ghcr.io/yasindce1998/warmor/charts/warmor \
  --version 0.2.0 \
  --namespace warmor-system \
  --set daemon.auditMode=false \
  --set daemon.lsmEnforce=true
```

**Requirements:** Linux kernel 5.7+ with `CONFIG_BPF_LSM=y`. If your kernel doesn't support LSM-BPF, warmor automatically falls back to tracepoint-only mode.

**Standalone:**
```bash
sudo warmor-daemon --policy policy.yaml --lsm-enforce
```

---

## warmorctl CLI

`warmorctl` is a terminal UI for managing warmor fleets, policies, and certificates.

### Install

```bash
go install github.com/yasindce1998/warmor/cmd/warmorctl@latest
```

### Usage

```bash
# Launch interactive TUI dashboard
warmorctl

# Connect to a specific server: the admin API needs a JWT with the admin
# role (--token or $WARMOR_TOKEN); --ca-cert trusts a private CA, and
# --client-cert/--client-key present a certificate if the server requires mTLS
export WARMOR_TOKEN=<admin-jwt>
warmorctl --server https://warmor-server:8443 --ca-cert ca.crt --client-cert admin.crt --client-key admin.key
```

The TUI provides tabs for:
- **Dashboard** — Real-time event stream and summary stats
- **Agents** — Connected agents, heartbeat status, assigned policies
- **Policies** — List/create/update/delete policies
- **Rollouts** — A/B testing rollout management
- **Certs** — Generate mTLS certificates for agents

### Generate Certificates

```bash
# Generate CA + server + agent certificates
warmorctl certs generate --ca --out ./certs/
warmorctl certs generate --server --ca-cert ./certs/ca.crt --ca-key ./certs/ca.key --out ./certs/
warmorctl certs generate --agent --ca-cert ./certs/ca.crt --ca-key ./certs/ca.key --name agent-01 --out ./certs/
```

---

## mTLS Setup

Enable mutual TLS between agents and the policy server:

```bash
# Start server with mTLS
warmor-server \
  --listen :8443 \
  --tls-cert ./certs/server.crt \
  --tls-key ./certs/server.key \
  --tls-ca ./certs/ca.crt \
  --policy-dir ./policies

# Start agent with mTLS
warmor-daemon \
  --policy policy.yaml \
  --server https://warmor-server:8443 \
  --tls-cert ./certs/agent-01.crt \
  --tls-key ./certs/agent-01.key \
  --tls-ca ./certs/ca.crt
```

---

## Monitoring Stack

Deploy Prometheus + Grafana alongside warmor for full observability:

```bash
cd deploy/
docker compose -f docker-compose.monitoring.yml up -d
```

This starts:
- **Prometheus** on `http://localhost:9091` — scrapes warmor metrics
- **Grafana** on `http://localhost:3000` — pre-provisioned dashboard (login: admin/warmor)

The Grafana dashboard shows:
- LSM hook decisions (allow/deny/audit) by type
- Decision latency histogram (P50/P95/P99)
- Policy load success/failure rates
- Agent heartbeat status

Alert rules fire on:
- Deny rate exceeding threshold (possible attack)
- Agent heartbeat missing > 5 minutes
- Policy load failures

---

## Container Runtime Integration

### containerd

Warmor integrates as a containerd shim plugin to receive container lifecycle events and scope policies per-container:

```bash
warmor-daemon \
  --policy policy.yaml \
  --containerd-socket /run/containerd/containerd.sock \
  --per-container-policy
```

### CRI-O (OCI Hooks)

Install the OCI hook configuration:

```bash
sudo cp deploy/crio/warmor-hook.json /etc/containers/oci/hooks.d/
```

### Kubernetes DaemonSet

The Helm chart deploys warmor with container runtime integration automatically:

```bash
helm install warmor oci://ghcr.io/yasindce1998/warmor/charts/warmor \
  --version 0.2.0 \
  --namespace warmor-system --create-namespace \
  --set daemon.containerRuntime=containerd \
  --set daemon.perContainerPolicy=true
```

---

## What's Next

| Goal | Guide |
|------|-------|
| Auto-generate policies from audit logs | [Policy Generation](policy-generation.md) |
| Enforce SBOM-declared binaries only | [SBOM Enforcement](sbom-enforcement.md) |
| Merge multiple policies into one | [Policy Merge](policy-merge.md) |
| Compare two policies (SBOM vs audit) | [Policy Diff](policy-diff.md) |
| Push/pull compiled policies to OCI registries | [Policy Bundle](policy-bundle.md) |
| Write custom policies | [Policy Authoring](policy-authoring.md) |
| Manage fleet with warmorctl | Run `warmorctl` for interactive TUI |
| Set up mTLS | See [mTLS Setup](#mtls-setup) above |
| Monitor with Grafana | `docker compose -f deploy/docker-compose.monitoring.yml up` |
| Enable alerting | Set `alerting.enabled=true` — see [values.yaml](../deploy/helm/warmor/values.yaml) |
| Restrict to specific containers | Use `daemon.cgroupFilter` or `--per-container-policy` |
| Deploy per-namespace policies | Install the WarmorPolicy CRD — see [CRD guide](crd-usage.md) |
| Advanced features (Phase 7+8) | [PRD — Phase 7 & 8](PRD.md#phase-7-advanced-features-weeks-23-28--complete) |

## Common Operations

```bash
# Check what warmor is seeing (top denied events)
kubectl -n warmor-system logs -l app.kubernetes.io/name=warmor | grep DENY

# View real-time dashboard
warmorctl

# List connected agents
warmorctl agents list

# Temporarily disable enforcement on a node
kubectl -n warmor-system delete pod <pod-name>  # respawns in audit mode if set

# Rollback
helm rollback warmor -n warmor-system

# Uninstall
helm uninstall warmor -n warmor-system
```

## Sizing Guide

| Cluster Size | CPU Request | Memory Request | Notes |
|-------------|-------------|----------------|-------|
| < 50 nodes  | 100m        | 128Mi          | Default values |
| 50-200 nodes | 200m       | 256Mi          | Increase if high event rate |
| 200+ nodes  | 500m        | 512Mi          | Consider per-namespace policies |

Warmor runs as a DaemonSet — one pod per node. Resource usage scales with event rate, not cluster size.
