# Receipt reconciliation onto main 971471e

## Pins and scope

* Frozen reviewed PR #57 head: `40de5eb82b3244d69f515fb7a48f14d011851c74`.
* Main merged here: `971471e2ff0b257fd58a695651aa7d67b451a3f0` (telemetry #47,
  deterministic fixtures #56, status #55 and compiler compatibility #54).
* Reconciliation branch/worktree: `fix/node-receipts-main971` /
  `.worktrees/node-receipts-main971`. Original reviewed branch remains frozen.

Old-head green checks/reviews do not establish new-head CI success or production
readiness. No live cluster, credentials, TokenRequests, push, remote configuration
or CI bypass is part of this reconciliation.

## Conflict and resolution

Only `internal/enforcer/enforcer.go` conflicted textually, at the successful
evaluator swap: the receipt branch captured its committed activation while main
replaced/sealed optional acknowledged-decision telemetry. Both operations are
retained under activationMu, event drain, decisionMu and evaluatorMu, after the
kernel prepare/durable commit succeeded. Receipt capture reads `Pool.Identity`,
never the supplied telemetry snapshot. Main's new four-argument activation
transaction and `ActivateAssignment(..., nil)` telemetry handling are retained.

No assignment-checker conflict occurred. The canonical pool identity checks,
signed trust/clock/journal and startup cross-mode guard remain unchanged from the
reviewed receipt head. New main fixture deadlines remain test-only.

## Invariants and regression delta

* Receipt daemon mode still allocates **no** telemetry collector or fleet lease.
  `--receipt-controller` plus `--server`/`--signed-assignments` still fails before
  trust files, TLS or capture. No download/telemetry-derived controller Applied.
* Owned fake-HTTPS activation test runs with and without an embedded collector.
  The collector path supplies a deliberately different telemetry hash and still
  requires the committed pool's real signed digest/ABI/build claims. It exercises
  signature failure, drift withdrawal, failed kernel rollback, failed durable
  commit, fresh recovery, telemetry sealing on generic reload and publication ABA.
  A blocking durable-commit callback also proves ActiveReceipt readers cannot
  escape the activation lock before committed pool capture, for both entrypoints.
  Failed candidates do not advance either the collector revision or the active
  evaluator identity; kernel rollback failure invalidates receipt acknowledgement.
* `internal/nodereceipt`, controller publication epochs, RBAC/Helm trust gates,
  `Pool.Identity` and compiler-7 artifact claims remain unchanged. Sequence/session
  validation still precedes withdrawal; epochs remain durable and no-op stable.
* Current status tables now qualify opt-in receipts and merged telemetry APIs,
  retaining Partial/no-attestation/no-production/no-automatic-rollback boundaries.
  They explicitly require new-head evidence, not the prior green PR head.

Review production delta with `git diff 40de5eb -- internal/enforcer/enforcer.go
internal/enforcer/signed_assignment.go internal/enforcer/receipt_test.go` and
compare inherited telemetry to pinned main. The complete feature relative to
main is `git diff 971471e`.

The earlier `docs/design/node-receipts-integration-review.md` records the original
`40de5eb` reconciliation onto `ce1d5ab`; its pins and validation are historical,
not a validation claim for this later main merge.

## Local validation of this reconciliation

Sequentially under `GOTOOLCHAIN=go1.26.11 GOMAXPROCS=2`:

* `go test -p=2 -count=1 ./...` — passed, including Helm contract tests.
* `go test -p=2 -race -count=1 ./...` — passed, no race reports.
* `golangci-lint run --allow-serial-runners --concurrency=2 --timeout=10m ./...`
  — passed, empty diagnostics.
* `helm lint deploy/helm/warmor` — passed (icon recommendation only).
* Ten repeated race runs of actual receipt activation (both collector modes),
  telemetry commit failure/sealing and signed-mode refusal — passed.
* `git diff --check`, unmerged-path check, and byte-preservation comparisons for
  reviewed receipt code and inherited main telemetry/fixture code — passed.

Logs: `/tmp/opencode/node-receipts-main971-{targeted,full,race,lint,repeat-race}-go1.26.11.log`.
These are local test results, not fresh remote CI, a live-cluster outcome gate,
attestation or production readiness clearance. No CI/settings were changed.
