# warmor Helm chart

Deploys the warmor daemon as a DaemonSet with an optional monitoring stack
(ServiceMonitor, Prometheus alerts, Grafana dashboard).

> **Status: working on `main`.** The chart installs and the daemon runs —
> verified end-to-end by a kind test in CI (`scripts/kind-e2e.sh`): install →
> pods Ready → policy loaded → metrics serving. The image bakes in a
> compiled default policy, so no Rust toolchain is needed on the nodes.
> Caveats: on nodes without `CONFIG_BPF_LSM` (kind, most hosted clusters)
> the daemon runs tracepoint-only **observe mode** — see
> [Known issues](#known-issues).

## Install

```bash
helm install warmor oci://ghcr.io/yasindce1998/warmor/charts/warmor
```

Or from a checkout:

```bash
helm install warmor deploy/helm/warmor/
```

`image.tag` defaults to the chart's `appVersion`, which tracks the latest
release tag.

## Custom policies

The image ships with a default policy compiled at build time
(`deploy/default-policy.yaml` → `/etc/warmor/policy.wasm`). To deploy your
own, compile it where the Rust toolchain lives and mount the binary:

```bash
warmor-compile -o policy.wasm my-policy.yaml
kubectl create configmap warmor-policy --from-file=policy.wasm
helm install warmor oci://ghcr.io/yasindce1998/warmor/charts/warmor \
  --set policy.existingConfigMap=warmor-policy
```

The ConfigMap must hold the binary under the `policy.wasm` key; it is
mounted over `/etc/warmor`. Do not ship YAML policies to the cluster — the
daemon compiles YAML on the node at startup, and the distroless image has
no `cargo`.

## Values

| Key | Default | Description |
|-----|---------|-------------|
| `image.repository` / `image.tag` / `image.pullPolicy` | `ghcr.io/yasindce1998/warmor` / chart appVersion / `IfNotPresent` | Daemon image (also used by the init container) |
| `daemon.logLevel` | `info` | `--log-level` |
| `daemon.statsInterval` | `30s` | `--stats-interval` |
| `daemon.metricsPort` | `9090` | `--metrics-port`; also the scrape port |
| `daemon.auditMode` | `false` | Pass `--audit`: log deny decisions without enforcing |
| `daemon.lsmEnforce` | `false` | Pass `--lsm-enforce`: kernel-level blocking (EPERM) for cached exec/connect denies. Requires `CONFIG_BPF_LSM=y` and `bpf` in `/sys/kernel/security/lsm` on the nodes |
| `daemon.requireLSM` | `false` | Pass `--require-lsm`: fail to start unless BPF-LSM enforcement can be loaded |
| `daemon.cgroupFilter` | `""` | Pass `--cgroup-filter` (cgroup paths or `auto` for K8s pod discovery); also mounts the host cgroup fs |
| `policy.existingConfigMap` | `""` | ConfigMap (with a `policy.wasm` key) mounted over `/etc/warmor`; empty = use the policy baked into the image |
| `resources` | requests 100m/128Mi, limits 500m/256Mi | Daemon container resources |
| `tolerations` / `nodeSelector` / `affinity` | schedule everywhere | Standard DaemonSet scheduling |
| `serviceAccount.create` / `.name` / `.annotations` | `true` / auto / `{}` | Service account for the daemon |
| `podAnnotations` / `podSecurityContext` | — | Pod-level annotations / security context |
| `priorityClass.*` | enabled, value 1000000000 | PriorityClass for the daemon pods (1000000000 is the K8s maximum for user-defined classes) |
| `updateStrategy` | `RollingUpdate`, `maxUnavailable: 10%` | DaemonSet update strategy |
| `networkPolicy.enabled` / `.extraEgress` | `true` / `[]` | Restrict daemon egress |
| `podDisruptionBudget.*` | enabled, `maxUnavailable: 1` | PDB for the daemon |
| `serviceMonitor.*` | disabled | Prometheus Operator ServiceMonitor |
| `grafana.dashboardEnabled` | `false` | ConfigMap with the Grafana dashboard |
| `alerting.*` | disabled | PrometheusRule with deny-rate, daemon-down, error-rate, loader-failure, dropped-events, WASM-error and map-sync alerts |
| `webhook.*` | disabled | `ValidatingWebhookConfiguration` for the `WarmorPolicy` CRD |

## What works today

- Install → daemon Running → metrics and health endpoints, verified by the
  kind e2e test in CI (`k8s-e2e` job)
- Policy loading from the image (compiled at build time) or from a
  user-supplied ConfigMap (`policy.existingConfigMap`)
- The `validate-policy` init container loads the actual `.wasm` in a
  throwaway WASM runtime before the daemon starts
- Metrics: scrape annotations, ServiceMonitor, alert rules (they reference
  the daemon's real metric names) and the Grafana dashboard
- Flag passthrough: `--audit`, `--lsm-enforce`, `--require-lsm`,
  `--cgroup-filter`, log level, stats interval, metrics port

## Known issues

Everything below is open on `main`; see
[Feature Status](https://github.com/yasindce1998/warmor/blob/main/docs/STATUS.md)
for the tracked items.

1. **No kernel enforcement on most clusters.** Kind nodes and typical
   hosted clusters lack `CONFIG_BPF_LSM`, so the daemon degrades to
   tracepoint-only observe mode (detect, then `SIGKILL`). Set
   `daemon.lsmEnforce: true` on BPF-LSM nodes for kernel blocking;
   `daemon.requireLSM: true` makes the daemon refuse to start without it.
2. **The `WarmorPolicy` CRD has no controller.** Resources are stored but
   never applied to any node; `status` is never populated. The
   ValidatingWebhookConfiguration has no handler behind it — leave
   `webhook.enabled` off, since with `failurePolicy: Fail` enabling it
   would reject `WarmorPolicy` writes.
3. **No policy-server integration.** The chart runs a standalone daemon
   with a ConfigMap policy; there is no `warmor-server` deployment,
   mTLS or agent registration in the chart.

The static manifests in `deploy/kubernetes/` are in worse shape (they
configure the daemon through environment variables it does not read) —
prefer the chart.
