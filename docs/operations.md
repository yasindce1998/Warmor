# Operations Guide

Running warmor beyond the first manual test: systemd deployment, fleet
management with `warmor-server`/`warmorctl`, mTLS, monitoring, and container
runtime integration. For first-time setup see
[GETTING_STARTED.md](../GETTING_STARTED.md); for flags see
[PLATFORM_LINUX.md](PLATFORM_LINUX.md).

> **Status on `main`:** standalone Linux is the supported path. The Helm
> chart and Kubernetes manifests do **not** work yet (see
> [Kubernetes](#kubernetes-not-working-on-main-yet) below). Kernel blocking
> covers repeat exec/connect denies only; everything else is detected and
> then killed with `SIGKILL`. See [Feature Status](STATUS.md).

## Run as a systemd service

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

Swap `--audit` for `--lsm-enforce` once you trust the policy. `SIGHUP`
reloads the policy file; kernel map entries from the old policy are not
cleared on reload yet.

## Policy server and mTLS

Agents can download their policy from `warmor-server` instead of a local
file. The server refuses to start without authentication. Supported modes:

| Server flags | Agent / runtime auth | Admin API |
|--------------|---------------------|-----------|
| `--ca-cert --tls-cert --tls-key` | client certificate | admin JWT (needs `--jwt-secret`; disabled otherwise) |
| `--tls-cert --tls-key --jwt-secret` | JWT, role `agent` / `runtime` | admin JWT |
| `--jwt-secret` (plain HTTP) | JWT, role `agent` / `runtime` | admin JWT |
| `--insecure` (development only) | none | none |

Mutual TLS between agents and the policy server:

```bash
# Server (agents authenticate with client certificates; the admin API
# requires an admin JWT signed with --jwt-secret)
warmor-server \
  --addr :8443 \
  --tls-cert ./certs/server.crt \
  --tls-key ./certs/server.key \
  --ca-cert ./certs/ca.crt \
  --jwt-secret "$WARMOR_JWT_SECRET" \
  --policy-dir ./policies

# Agent; the downloaded policy replaces --policy
warmor-daemon \
  --policy /var/lib/warmor/policy.wasm \
  --server https://warmor-server:8443 \
  --tls-cert ./certs/agent-01.crt \
  --tls-key ./certs/agent-01.key \
  --tls-ca ./certs/ca.crt
```

`--ca-cert`, `--tls-cert` and `--tls-key` must be supplied as a consistent
set; `--jwt-secret` may also be given via `WARMOR_JWT_SECRET`. Agents using
token auth pass `--server-token` (or `WARMOR_SERVER_TOKEN`) instead of a
client certificate. Admin `wasm_path` values must point inside
`--policy-dir`; without it, policies cannot be created or updated over the
API.

Policies downloaded from the server are signature-verified when the daemon
runs with `--verify-key` (see
[Policy Toolchain](policy-toolchain.md#detached-signatures-daemon-and-policy-server)).

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
- **Rollouts** — percentage rollout overview (view-only; create, ramp and abort via the admin API, see [Canary Rollout](canary-rollout.md))
- **Certs** — press `g` to generate a CA plus server and agent certificates, or
  `s` to generate a policy-signing key pair

There is no non-interactive `warmorctl certs generate` command. For signing
keys you can also use `warmor-policy-bundle --keygen`.

## Monitoring stack

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
`--metrics-port` (default 9090), plus the LSM-decision, policy-load,
heartbeat, WASM-exec and loader-status metrics the dashboards and alerts use.

## Container runtime integration

### CRI-O / OCI hook (experimental)

```bash
sudo cp deploy/crio/warmor-hook.json deploy/crio/warmor-hook-stop.json /etc/containers/oci/hooks.d/
```

`warmor-oci-hook` reports container start/stop to `warmor-server`
(`/api/v1/containers/bind`). On `main`:

- It has no auth or TLS, so it only works against `warmor-server --insecure`.
- The server stores the bindings but nothing consumes them, so there is no
  per-container policy yet.

### containerd / per-container policy

Not available on `main`. There are no `--containerd-socket` or
`--per-container-policy` flags. `internal/container` is library-only.

## Kubernetes

The Helm chart in `deploy/helm/warmor` installs and the daemon runs — a kind
e2e test in CI (`scripts/kind-e2e.sh`) verifies install → pods Ready →
policy loaded → metrics serving.

```bash
helm install warmor oci://ghcr.io/yasindce1998/warmor/charts/warmor
```

The image bakes in a default policy (`deploy/default-policy.yaml`, compiled
to `/etc/warmor/policy.wasm` at build time). To use your own policy, compile
it where the Rust toolchain is available and reference the resulting binary:

```bash
warmor-compile -o policy.wasm my-policy.yaml
kubectl create configmap warmor-policy --from-file=policy.wasm
helm install warmor oci://ghcr.io/yasindce1998/warmor/charts/warmor \
  --set policy.existingConfigMap=warmor-policy
```

Caveats on `main`:

- Most hosted clusters and kind nodes lack `CONFIG_BPF_LSM`, so in-cluster
  the daemon runs tracepoint-only observe mode. Kernel enforcement needs
  `daemon.lsmEnforce: true` **and** nodes with BPF-LSM enabled.
- The `ValidatingWebhookConfiguration` has no handler. Leave
  `webhook.enabled` off.
- `deploy/kubernetes/warmor-daemonset.yaml` (the static manifests) targets
  server-managed agents and expects mTLS secrets and a reachable
  `warmor-server`; prefer the chart.

### Manage policies as Kubernetes objects

Instead of compiling policies out of band, enable the WarmorPolicy
controller and `kubectl apply` policies directly — the controller
compiles them and every agent hot-reloads (see
[CRD usage](crd-usage.md)):

```bash
helm upgrade warmor oci://ghcr.io/yasindce1998/warmor/charts/warmor \
  --set controller.enabled=true
kubectl apply -f my-policy.yaml   # kind: WarmorPolicy
kubectl get wp                    # watch the phase go Active
```
