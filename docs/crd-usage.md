# WarmorPolicy CRD Usage

The `WarmorPolicy` custom resource manages security policies as native
Kubernetes objects. With the controller enabled (`controller.enabled=true`
in the Helm chart), applying a `WarmorPolicy` compiles it and rolls it out
to every node — without restarting any agent. See
[the controller design](design/warmorpolicy-controller.md) for the
architecture.

> Without `controller.enabled` the CRD is schema only: resources are
> stored and never applied. The chart's `ValidatingWebhookConfiguration`
> still has no handler behind it (it is disabled by default with
> `failurePolicy: Ignore`) — do not rely on it for validation; the
> controller validates on reconcile and reports on `status`.

## Prerequisites

- Warmor Helm chart installed (the CRD installs automatically from
  `crds/`)
- Enable the controller:

```bash
helm upgrade warmor deploy/helm/warmor --set controller.enabled=true
```

By default the controller watches `WarmorPolicy` resources in the
chart's own namespace. `controller.watchAllNamespaces=true` merges CRs
from every namespace instead — single-tenant clusters only, since any
namespace can then affect every node's policy.

## Create a Policy

```yaml
apiVersion: warmor.io/v1alpha1
kind: WarmorPolicy
metadata:
  name: block-miners
spec:
  name: block-crypto-miners
  version: 1
  description: "Block cryptocurrency miners"
  rules:
    - name: block-known-miners
      event: process
      conditions:
        all:
          - comm: { any_of: ["xmrig", "minerd", "cpuminer"] }
      action: deny
      reason: "Cryptocurrency miner blocked"
    - name: block-mining-ports
      event: network
      conditions:
        all:
          - remote_port: { any_of: [3333, 4444, 14444] }
      action: deny
      reason: "Connection to mining pool blocked"
  defaultAction: allow
```

```bash
kubectl apply -f policy.yaml
```

The controller validates the CR with the same parser the daemon uses at
load time, compiles it, publishes the module in a ConfigMap the DaemonSet
mounts, and agents hot-reload it through their policy-file watcher.
Agents must not run `--verify-key` in this mode: controller-compiled
policies are unsigned (the same stance as `--policy-fallback`).

## Check Status

```bash
# List all policies (the Status column is the phase)
kubectl get warmorpolicies
# or shorthand:
kubectl get wp

# Describe a specific policy
kubectl describe wp block-miners
```

| Field | Description |
|-------|-------------|
| `phase` | `Active` (compiled and published), `Error` (invalid — see the `Ready` condition's message) or `Pending` (held back, e.g. it carries a selector) |
| `observedGeneration` | The generation the status describes |
| `lastApplied` | When this CR last contributed to a newly published policy |
| `conditions` | A `Ready` condition with the reason (`Compiled`, `InvalidPolicy`, `SelectorNotSupported`) |

An invalid CR is reported on itself and **excluded** from the effective
policy; the remaining CRs keep syncing. One bad policy never blocks the
fleet.

## Multiple Policies

All `Active` CRs merge into one effective policy per node:

- **Rule order**: most-restrictive-first (`deny`, then `audit`, then
  `allow`), because the compiled module is first-match-wins — an `allow`
  from one policy can never shadow another policy's `deny`. A single CR
  keeps its own rule order exactly as written.
- **Default action**: the strictest across the merged CRs
  (`deny` > `audit` > `allow`).
- **Variables** are namespaced per CR, so identical variable names in
  two policies never bleed into each other.
- **Rule names** are prefixed with the CR name, so deny reasons stay
  attributable.

CRs fully define the effective policy: applying your first CR *replaces*
the baked cluster default (`deploy/default-policy.yaml`), it does not
extend it. With no CRs at all, the controller syncs the baked default.

## Selectors (not yet honored)

`spec.selector` is accepted by the schema but cannot be enforced yet:
the daemon enforces node-wide, and applying a pod-scoped policy beyond
its intended scope would be wrong in both directions. A CR carrying a
selector is held `Pending` with a `SelectorNotSupported` condition
instead of being silently mis-applied. Selectors become meaningful when
per-workload policies land.

## Update a Policy

Edit the resource and apply. Every spec change (whether or not you bump
`spec.version`) triggers a recompile and rollout; the agents pick it up
within seconds through their policy-file watcher.

```bash
kubectl apply -f policy.yaml
```

## Delete a Policy

```bash
kubectl delete wp block-miners
```

The effective policy is recomputed from the remaining CRs — or reverts to
the baked cluster default when the last CR is deleted. Deletion never
leaves nodes without a policy.
