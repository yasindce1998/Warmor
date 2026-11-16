# Node receipt integration review delta

## Pinned inputs and scope

* Frozen receipt source: `8b149eee3aad1ad90978bf1c344250fbb7f189ce`.
* Merged main: `ce1d5abd5a5ad8d78829c3001ff5eb8228964a57`.
* Integration branch: `feat/node-receipts-integration`; persistent worktree
  `.worktrees/node-receipts-integration`.

This integrates the default-disabled receipt path with main's signed assignments,
compiler 7 and exact artifact metadata. No fleet/controller combined-mode support,
new token privileges, workload selector application, live-cluster acceptance or
attestation claim is added. The source branch/worktree remains untouched.

## Textual conflicts and resolutions

1. `internal/enforcer/enforcer.go`: retain main's signed-assignment startup checks,
   kernelEnforce posture and shared activation transaction. Keep receipt capture
   only at the committed evaluator swap/startup boundary, invalidating after
   failed kernel rollback. Keep the receipt's loaded-vs-enabled LSM distinction.
2. `internal/wasm/pool.go`: retain main's moduleDigest/buildMetadata capture,
   ABI consistency checks and replacement using the captured compiled module.
   Remove the receipt branch's duplicate ABI field/getter.
3. `internal/wasm/runtime.go`: main's metadata parsing and digest assignment win;
   remove the duplicate receipt-only loadedDigest field/getter. Runtime code is
   unchanged from pinned main after resolution.
4. `internal/wasm/wasmtest/wasmtest.go`: retain main's `VersionedConstPolicy` and
   default-deny fixtures; receipt tests use this existing fixture builder.

## Semantic integration changes requiring independent review

* `wasm.Pool.Identity()` returns value copies of main's captured digest, ABI,
  artifact compiler and default-action claims. Both `CheckAssignment` and
  enforcer receipt capture use this one identity; loading a candidate into the
  runtime cannot change an old pool's identity or replacement declarations.
* Receipt manifests distinguish the controller composition/compiler profile
  (`compiler`) from artifact build declarations (`artifactCompiler`,
  `defaultAction`). Both sides check declarations against the active pool. The
  controller rejects missing, compiler-6 or contradictory-default-action
  declarations before publication. Claims are not semantic/provenance proof.
  This adds required wire fields for receipt eligibility: older receipt clients
  or manifests without artifact build declarations fail closed rather than
  silently asserting compiler-7 compatibility.
* `compiler.PolicyABIVersion` merely exposes the existing codegen decision. It
  does not change generated Rust or add a second ABI export; a regression asserts
  controller prediction and the single generated export agree for ABI 3/5.
  Compiler version/identity, Build metadata emission, generated Rust behavior,
  runtime metadata parsing and pool instantiation remain pinned-main behavior.
* Reject `--receipt-controller` with `--server` or `--signed-assignments` at the
  first statement of `runDaemon`, before privilege checks, trust files, TLS or
  capture. Child-process tests use missing trust paths to assert ordering. Library
  `ActiveReceipt` independently refuses signed-assignment mode. Standalone
  detached artifact verification remains tested with real New/Start/ActivatePolicy
  and HTTPS receipt transport (only platform/Kubernetes backends faked).
* The publication-epoch logic from reviewed source is retained: a random epoch
  commits atomically only with a changed publication, remains stable on no-op
  reconcile/restart, and failed writes never become a durable epoch. ABA and
  exact-generation tests now publish real metadata-bearing tiny WASM fixtures.
* Withdrawal's bound principal/challenge/boot/sequence/freshness checks still
  precede clearing evidence. New compiler/default-action contradictions use that
  same withdrawal behavior; identity authentication itself is unchanged.

## Review boundaries

Review `git diff ce1d5ab` for the complete receipt feature relative to main and
`git diff 8b149ee` for main plus the integration resolutions. In particular,
check unchanged main runtime/pool initialization, signed-intent checks and
compiler-7 metadata generation against the pins above. Helm manifests/RBAC stay
default-disabled and unchanged from reviewed receipt source. No real cluster,
TokenRequest, host capture backend or privilege infrastructure is used by the
integration tests.

## Validation

Run sequentially with `GOTOOLCHAIN=go1.26.11 GOMAXPROCS=2`:

* `go test -p=2 -count=1 ./...` — passed (including Helm contracts).
* `go test -p=2 -race -count=1 ./...` — passed, no race reports.
* `golangci-lint run --allow-serial-runners --concurrency=2 --timeout=10m ./...`
  — passed, empty diagnostics.
* `helm lint deploy/helm/warmor` — passed; icon recommendation only.
* `git diff --check` and resolved-conflict checks — passed.

Logs are in `/tmp/opencode/node-receipts-integration-{full,race,lint}-go1.26.11.log`.
The owned-fake HTTPS test covers signed-artifact activation drift/rollback/ABA;
pool tests retain identity across runtime reload and pool replacement. There was
one corrected test-only flag typo (`--assignment-clock` versus main's existing
`--assignment-clock-health`) in an initial targeted run; final full and race
runs above include the corrected early-rejection test. No main trust flag was
renamed. These tests do not establish real-cluster or privileged kernel outcomes.
