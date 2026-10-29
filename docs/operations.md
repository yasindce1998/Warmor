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

## Kubernetes (not working on main yet)

The Helm chart in `deploy/helm/warmor` is being fixed. On `main`:

- The chart has no `lsmEnforce` value and never passes `--lsm-enforce`.
- The policy is shipped as YAML in a ConfigMap. The daemon would need `cargo`
  to compile it, and the distroless image does not include it.
- The `ValidatingWebhookConfiguration` has no handler, and the `WarmorPolicy`
  CRD has no controller (see [CRD usage](crd-usage.md)).
- `deploy/kubernetes/warmor-daemonset.yaml` configures the daemon through
  environment variables it does not read.

Instructions will return here once the chart works.
