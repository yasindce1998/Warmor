# Canary Rollout

> **Status: Partial.** Percentage rollouts are **shipped**: create, ramp, complete and abort through the admin API or `warmorctl`, with consistent-hash cohorts and versioned policies. The **deny-rate `CanaryAnalyzer` and automatic rollback are library-only.** `NewCanaryAnalyzer` is never called, agents don't report per-decision data to it, and the rollout API does not accept a `CanaryConfig`. On `main` you monitor and abort manually. See [Feature Status](STATUS.md).

The policy server supports A/B canary rollouts for Wasm policies. You can gradually shift agents to a new policy version and abort back to the baseline. A canary analyzer that compares deny rates between cohorts and rolls back automatically exists as a library, but it is not wired in yet.

## How It Works

1. A rollout is created with a target percentage. Agents are assigned to the canary (new policy) or baseline (current policy) cohort via consistent hashing on `sha256(rolloutID + ":" + agentID) % 100`.
2. *(Library only, not wired.)* The `CanaryAnalyzer` is designed to record every policy decision (allow/deny) for both cohorts.
3. *(Library only, not wired.)* Once the observation window elapses and both cohorts have enough samples, it compares deny rates. If the canary deny rate exceeds baseline by more than `MaxDenyRateDelta`, the rollout is flagged as degraded or automatically rolled back.

### Verdict States

| Verdict | Meaning |
|---------|---------|
| `pending` | Not enough samples or observation time yet |
| `healthy` | Canary deny rate is within acceptable delta |
| `degraded` | Deny rate exceeded threshold (auto-rollback disabled) |
| `rolled-back` | Rollout was aborted automatically |

## Configuration (library only)

The `CanaryConfig` struct below is used by the analyzer library. **The rollout API does not accept these fields on `main`.**

| Field | Type | Description |
|-------|------|-------------|
| `max_deny_rate_delta` | float64 | Maximum allowed difference between canary and baseline deny rates (e.g., `0.05` = 5%) |
| `observation_window` | duration | Minimum time to observe before evaluating (e.g., `5m`) |
| `min_sample_size` | int | Minimum decisions per cohort before evaluation triggers |
| `auto_rollback` | bool | If true, automatically abort the rollout when degraded |

Example:
```json
{
  "max_deny_rate_delta": 0.05,
  "observation_window": "5m",
  "min_sample_size": 100,
  "auto_rollback": true
}
```

## API Endpoints

All rollout endpoints require JWT authentication (when configured).

### List rollouts

```
GET /api/v1/admin/rollouts
```

### Create a rollout

```
POST /api/v1/admin/rollouts

{
  "id": "nginx-v2-canary",
  "policy_id": "nginx-hardening",
  "target_version": 3,
  "percentage": 10
}
```

### Get rollout status

```
GET /api/v1/admin/rollouts/{id}
```

### Update rollout percentage (ramp up)

```
PUT /api/v1/admin/rollouts/{id}

{"percentage": 50}
```

Setting percentage to `100` completes the rollout.

### Abort a rollout

```
DELETE /api/v1/admin/rollouts/{id}
```

Reverts all agents to the baseline policy version.

## Auto-Rollback Behavior (library only, not wired)

In the library, when `auto_rollback` is enabled, the `CanaryAnalyzer.Evaluate()` cycle performs:

1. Wait until both cohorts reach `min_sample_size` decisions.
2. Wait until `observation_window` has elapsed since rollout start.
3. Compute `delta = canary_deny_rate - baseline_deny_rate`.
4. If `delta > max_deny_rate_delta`, call `AbortRollout` to immediately revert all agents to the previous policy version. The verdict is set to `rolled-back`.

If `auto_rollback` is false, the verdict becomes `degraded` but the rollout continues. Operators can then manually abort or adjust percentage via the API.

## Typical Workflow

```bash
AUTH="Authorization: Bearer $ADMIN_TOKEN"   # JWT with role "admin"

# 1. Stage the new policy version (path relative to --policy-dir); "stage"
#    stores it as version 2 without serving it to any agent yet
curl -X PUT http://localhost:8443/api/v1/admin/policies/myapp -H "$AUTH" \
  -d '{"wasm_path":"myapp-v2.wasm","stage":true}'

# 2. Create rollout at 10% (target_version defaults to the latest version)
curl -X POST http://localhost:8443/api/v1/admin/rollouts -H "$AUTH" \
  -d '{"id":"v2-canary","policy_id":"myapp","target_version":2,"percentage":10}'

# 3. Monitor the canary cohort yourself (logs/metrics); if healthy, ramp up
curl -X PUT http://localhost:8443/api/v1/admin/rollouts/v2-canary -H "$AUTH" \
  -d '{"percentage":50}'

# 4. Complete rollout: version 2 becomes the policy's active version
curl -X PUT http://localhost:8443/api/v1/admin/rollouts/v2-canary -H "$AUTH" \
  -d '{"percentage":100}'

# Or abort: every agent goes back to the base version
curl -X DELETE http://localhost:8443/api/v1/admin/rollouts/v2-canary -H "$AUTH"
```

The server keeps every uploaded version. While a rollout is active the canary
cohort is served `target_version` and everyone else `base_version` (the
version that was active before the target). Completed and aborted rollouts
cannot be modified (`409 Conflict`), and a policy can have only one active
rollout at a time. Agents re-download whenever their assigned version
changes, including moving back to a lower version after an abort.
