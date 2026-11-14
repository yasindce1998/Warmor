# Signed assignment integration onto main

This standalone integration starts at main `9297209` (PR38 durable activation,
PR45 supervised policy host/FD bootstrap, and PR42 release gates) and applies
only the reviewed assignment commits `17b7adf`, `f54480a`, and `3d3e78d`.
Generation-atomic activation and the independent shared-metadata branch are
**not enabled or imported**. See [the operator contract](../SIGNED_POLICY_ASSIGNMENTS.md).

Conflicts were limited to compiler version/identity, runtime load admission,
and pool initialization/replacement. Resolution preserves main's preflight
complexity limits before build-section parsing/compilation; debug-info decoding
remains disabled. Bounded initialization, actual allocation validation,
strict ABI/action/UTF-8 semantics, pool deadline/closed checks, anonymous
instances and captured compiled-module replacement remain in place. Pool build
claims/digest are captured alongside that same compiled module, not looked up
from a runtime that might later load another module. A regression test reloads
the runtime then replaces an old pool member and verifies its original identity.

The default-deny test fixture now allocates declaration tables separately from
its persistent event buffer, satisfying main's strict nonaliasing allocator
contract instead of weakening it. The compiler cache identity advances from
main's version 6 to 7 because signed build sections change final WASM bytes;
main's UTF-8, identifier, input and allocator code generation is retained.

`assignment.json` remains signed mode's **sole** durable publication/startup
authority. No independent PR38 `current` pointer commit is chained. Artifact
and assignment keys remain separate, unsigned defaults remain unchanged, and
clock health/declaration trust are explicit local requirements. Legacy kernel
map activation is still not generation-atomic; no new kernel guarantees or
policy-host routing are claimed. The policy-host implementation, descriptor
bootstrap, coordinator, dependency manifests and release workflows are unchanged
from this main baseline. Shared runtime metadata/API unification belongs to the
main coordinator, preserving the trust distinction between observations and
artifact-author build claims.

Signed daemon SIGHUP is refused before invoking any reload callback, and generic
enforcer activation is disabled in signed mode. Later generation combination
must also retain that owner's `359c75c` fleet out-of-band-reload prohibition;
this standalone branch does not cherry-pick or enable generation activation.

## Local integration validation

Using Go **1.26.11**, with build/test parallelism limited to `-p 2`:

- `go test -p 2 ./...` and `go test -race -p 2 ./...` passed.
- Full `go vet -p 2 ./...`, repository-configured golangci-lint v1.64.8
  (`GOFLAGS=-p=2`, concurrency 2), changed-file gofmt and diff checks passed.
- Repeated signed/assignment-focused daemon/enforcer/runtime/server race tests
  passed with count 3. Cargo input/unknown-posture/temporal semantics and all
  initialization-deadline entry-point checks ran and passed, not skipped.
- Every `cmd/...` command built natively and cross-compiled for Darwin arm64
  and Windows amd64 with CGO disabled. Darwin/Windows daemon test binaries also
  cross-compiled. This is not native macOS/Windows execution or a live BPF test.
- Standalone staticcheck 2026.2.2 passed for affected library/signer packages;
  its full-tree run reports 16 findings in unchanged main files (one unused
  eBPF field, coordinator error capitalization, and a test HTTP status literal).
  Repository-configured lint is green; these unrelated findings were not edited.

No dependency manifests, coordinator/policy-host code, release workflows,
external infrastructure, or real key material were changed for this validation.

## PR40/main refresh (from signed checkpoint `8634b22`)

The subsequent merge imports main `09fdce9`, containing reviewed PR40
`061685e`. It does not rewrite the reviewed signed source or cherry-pick a new
activation backend. Conflicts are confined to these three files:

- `cmd/warmor-daemon/main.go`: retain one `enforcerOpts` shared by ordinary,
  signed bootstrap/recovery, and restored-state startup, adding PR40's cgroup
  root/reconciliation interval and metrics-bind fields. Signed config validation,
  pre-start trust/time checks, sole-agentstore commit and SIGHUP refusal remain.
- `internal/enforcer/enforcer.go`: retain signed candidate validation and test
  platform injection while forwarding dynamic cgroup settings to the real
  platform constructor. Preserve PR40's active-loop flag, capture readiness and
  metrics readiness callback. Signed startup/update readiness still reflects
  local capture/scope health, not desired CR-generation acknowledgement.
- `internal/compiler/build.go`: retain cancellable toolchain checks/Cargo
  subprocesses, wait bounds, context propagation and failed-crate cleanup, then
  append signed build claims before returning a successful result. Recheck
  cancellation before metadata processing/output. Compiler cache identity stays
  7; safe crate identifier and strict input/codegen semantics remain unchanged.

Controller selector-Pending behavior (including an explicit empty selector),
last-known-good recovery/publication, dynamic cgroup discovery and its failure
readiness, chart probes and deploy preflight are imported unchanged from PR40.
Neither controller publication nor signed relay claims automatic per-workload
signed activation. No kernel-generation or policy-host routing combination is
enabled. No competing `current` pointer is added to signed mode.

New overlap regression tests exercise signed startup forwarding cgroup options,
capture-not-ready and failed reconciliation states, failed signed commit keeping
the healthy last-known-good evaluator, generic reload rejection, and a real
context-aware Cargo build with an unsafe display name that still loads with ABI
3, compiler identity `warmor-yaml/7`, and matching build metadata/digest. Existing
PR40 cancellation/cleanup and controller selector/recovery tests are retained.

Validation for this merge used Go 1.26.11 with `-p 2`: full repository tests,
full race tests, vet, configured golangci-lint (concurrency 2), module verification,
and native builds of every command passed. All commands also cross-compiled
for Darwin arm64 and Windows amd64 (CGO disabled), as did both daemon test
binaries. Focused compiler/controller/enforcer/runtime/daemon tests ran with
`WARMOR_REQUIRE_CARGO=1`, including the real context-aware signed-metadata build.
Changed-file gofmt and diff whitespace checks passed. Logs are local validation
artifacts only; no native macOS/Windows execution, live cluster, kernel-generation
guarantee, real keys, push or publication is implied.
