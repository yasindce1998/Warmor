# warmor Helm chart

Deploys the warmor daemon as a DaemonSet with an optional monitoring stack
(ServiceMonitor, Prometheus alerts, Grafana dashboard).

**Deployment safety:** read [Runtime safety and validation limits](RUNTIME-SAFETY.md)
before enabling enforcement. Default scope is continuous exact-ID pod discovery;
it covers all pods, not labels. The chart rejects unsupported webhooks and
contradictory posture options. `make deploy-audit DRY_RUN=true` compiles, validates
and renders the selected policy without accessing a cluster.

> **Status: working on `main`.** The chart installs and the daemon runs —
> verified end-to-end by a kind test in CI (`scripts/kind-e2e.sh`): install →
> pods Ready → policy loaded → metrics serving. The image bakes in a
> compiled default policy, so no Rust toolchain is needed on the nodes.
> The default is **audit-only**: denies are reported, nothing is killed or blocked.
> On nodes without `CONFIG_BPF_LSM` (including many kind/hosted setups), kernel
> blocking is unavailable even when explicitly requested — see
> [Known issues](#known-issues).

## Install

```bash
helm install warmor oci://ghcr.io/yasindce1998/warmor/charts/warmor
```

Or from a checkout:

```bash
helm install warmor deploy/helm/warmor/
```

`image.tag` currently defaults to `latest`; use `image.digest=sha256:<64 lowercase
hex characters>` for immutable deployment (also `controller.image.digest` when
enabled). Digest overrides tag for daemon, validator and controller images.

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
| `daemon.auditMode` | `true` | Pass `--audit`: no termination or blocking; contradictory enforcement flags are rejected |
| `daemon.lsmEnforce` | `false` | Pass `--lsm-enforce`: kernel-level blocking (EPERM) for cached exec/connect denies. Requires `CONFIG_BPF_LSM=y` and `bpf` in `/sys/kernel/security/lsm` on the nodes |
| `daemon.requireLSM` | `false` | Pass `--require-lsm`: fail to start unless BPF-LSM enforcement can be loaded |
| `daemon.defaultDeny` | `false` | Pass `--default-deny`: preload the policy's static allow rules and refuse (EPERM) exec/connect the policy does not allow. Requires `daemon.lsmEnforce` and an allowlist policy (`default_action: deny` + exact `eq` rules); misses stay allowed when the policy is not eligible. See [the design](https://github.com/yasindce1998/warmor/blob/main/docs/design/kernel-default-deny.md) |
| `daemon.cgroupFilter` | `auto` | Continuously discover exact pod/descendant container IDs; empty sets cover nobody. Explicit paths are exact IDs, not recursive selectors |
| `daemon.cgroupReconcileInterval` | `1s` | Polling lag before new cgroups are covered |
| `daemon.confirmNodeWidePolicy` | `false` | Required to disable audit or watch all namespaces; auto scope includes Warmor/system pods |
| `daemon.metricsBindAddress` | `""` | All interfaces by default; loopback breaks kubelet HTTP probes |
| `hostPaths.cgroup` / `.cgroupMount` / `.kernel` | `/sys/fs/cgroup` / `/host/sys/fs/cgroup` / `/sys/kernel` | Host cgroup/kernel sources and container cgroup mount passed to the daemon |
| `policy.existingConfigMap` | `""` | ConfigMap (with a `policy.wasm` key) mounted over `/etc/warmor`; empty = use the policy baked into the image |
| `resources` | requests 100m/128Mi, limits 500m/256Mi | Daemon container resources |
| `tolerations` / `nodeSelector` / `affinity` | Linux amd64 nodes | Keep mandatory OS/architecture selectors for current images |
| `serviceAccount.create` / `.name` / `.annotations` | `true` / auto / `{}` | Service account for the daemon |
| `podAnnotations` / `podSecurityContext` | — | Pod-level annotations / security context |
| `priorityClass.*` | enabled, value 1000000000 | PriorityClass for the daemon pods (1000000000 is the K8s maximum for user-defined classes) |
| `updateStrategy` | `RollingUpdate`, `maxUnavailable: 10%` | DaemonSet update strategy |
| `networkPolicy.enabled` / `.extraEgress` | `true` / `[]` | Restrict daemon egress |
| `podDisruptionBudget.*` | enabled, `maxUnavailable: 1` | PDB for the daemon |
| `serviceMonitor.*` | disabled | Prometheus Operator ServiceMonitor |
| `grafana.dashboardEnabled` | `false` | ConfigMap with the Grafana dashboard |
| `alerting.*` | disabled | PrometheusRule with deny-rate, daemon-down, error-rate, loader-failure, dropped-events, WASM-error and map-sync alerts |
| `webhook.enabled` | `false` | Enabling is rejected: no functional admission handler exists |

## Optional controller and upgrades

`controller.enabled=true` compiles WarmorPolicy resources and publishes a single
node-wide effective policy. Its HTTP probes and pod-annotated metrics use port
9091, separate from the daemon metrics Service. Controller `/ready` means a
recent successful **local reconciliation**, including last-good retention after
invalid edits; it does not attest node application. CR publication is
`phase=Published` with `Published=True`, while `Applied` stays `Unknown`.

Apply `crds/warmorpolicy-crd.yaml` explicitly before controller upgrades: Helm
does not upgrade schemas under `crds/`. The additive status schema retains old
fields for compatibility but does not fabricate node counts or `lastApplied`.
See [runtime safety](RUNTIME-SAFETY.md) and the
[controller contract](../../../../docs/design/warmorpolicy-controller.md) for
recovery, signing and selector limits.

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
  `--default-deny`, `--cgroup-filter`, log level, stats interval, metrics
  port

## Known issues

To opt into enforcement after validating policy and scope, explicitly set
`daemon.auditMode=false,daemon.confirmNodeWidePolicy=true`. Kernel blocking needs
`daemon.lsmEnforce=true,daemon.requireLSM=true` and suitable nodes; it refuses an
unsupported node. Policies remain node-wide unless cgroup filtering restricts
them; disabling audit can affect host processes as well as pods.

Everything below is open on `main`; see
[Feature Status](https://github.com/yasindce1998/warmor/blob/main/docs/STATUS.md)
for the tracked items.

1. **No kernel enforcement on most clusters.** Kind nodes and typical
   hosted clusters lack `CONFIG_BPF_LSM`, so the daemon degrades to
   tracepoint-only monitoring (or detect-then-`SIGKILL` if audit is explicitly disabled). Set
   `daemon.lsmEnforce: true` on BPF-LSM nodes for kernel blocking;
   `daemon.requireLSM: true` makes the daemon refuse to start without it.
2. **Pod selectors are not executed.** The optional controller publishes one
   node policy; selector-bearing resources (including `selector: {}`) remain
   Pending. Omit the selector only for intended node-wide publication. Unsupported webhook
   enablement is rejected instead of deploying a handler-less admission hook.
3. **No policy-server integration.** The chart runs a standalone daemon
   with a ConfigMap policy; there is no `warmor-server` deployment,
   mTLS or agent registration in the chart.

Static manifests in `deploy/kubernetes/` are an audit-first policy-server example
requiring certificates and a deployed server. Prefer the validated chart for
standalone/ConfigMap deployments. No live enforcement test was run for this
runtime-safety unit/render test suite; see the isolated capability matrix.
