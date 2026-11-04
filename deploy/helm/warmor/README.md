# warmor Helm chart

Deploys the warmor daemon as a DaemonSet with an optional policy-server
adjacent monitoring stack (ServiceMonitor, Prometheus alerts, Grafana
dashboard).

> **Status: does not run on `main` yet.** The chart renders and passes
> `helm lint`, but the daemon container cannot start: the policy ships as
> YAML in a ConfigMap and the daemon compiles YAML policies at startup,
> which needs `cargo` — the distroless image does not include it. The
> `validate-policy` init container passes (it only schema-checks the YAML),
> then the main container crashloops. See
> [Known issues](#known-issues) for the full list and what works today.

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
| `policy.yaml` | cluster-default starter policy | Inline YAML policy mounted at `/etc/warmor/policy.yaml` |
| `resources` | requests 100m/128Mi, limits 500m/256Mi | Daemon container resources |
| `tolerations` / `nodeSelector` / `affinity` | schedule everywhere | Standard DaemonSet scheduling |
| `serviceAccount.create` / `.name` / `.annotations` | `true` / auto / `{}` | Service account for the daemon |
| `podAnnotations` / `podSecurityContext` | — | Pod-level annotations / security context |
| `priorityClass.*` | enabled, value 2000000000 | PriorityClass for the daemon pods |
| `updateStrategy` | `RollingUpdate`, `maxUnavailable: 10%` | DaemonSet update strategy |
| `networkPolicy.enabled` / `.extraEgress` | `true` / `[]` | Restrict daemon egress |
| `podDisruptionBudget.*` | enabled, `maxUnavailable: 1` | PDB for the daemon |
| `serviceMonitor.*` | disabled | Prometheus Operator ServiceMonitor |
| `grafana.dashboardEnabled` | `false` | ConfigMap with the Grafana dashboard |
| `alerting.*` | disabled | PrometheusRule with deny-rate, daemon-down, error-rate, loader-failure, dropped-events, WASM-error and map-sync alerts |
| `webhook.*` | disabled | `ValidatingWebhookConfiguration` for the `WarmorPolicy` CRD |

## What works today

- Rendering, `helm lint` and `helm template`
- The `validate-policy` init container (schema-checks the YAML policy)
- Metrics: scrape annotations, ServiceMonitor, alert rules (they reference
  the daemon's real metric names) and the Grafana dashboard
- Flag passthrough: `--audit`, `--lsm-enforce`, `--require-lsm`,
  `--cgroup-filter`, log level, stats interval, metrics port

## Known issues

Everything below is open on `main`; see
[Feature Status](https://github.com/yasindce1998/Warmor/blob/main/docs/STATUS.md)
for the tracked items.

1. **The daemon cannot start with the shipped policy.** YAML policies are
   compiled on the node at startup and the distroless image has no `cargo`.
   Fixing this needs the chart to ship (or build) a precompiled `.wasm`.
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
