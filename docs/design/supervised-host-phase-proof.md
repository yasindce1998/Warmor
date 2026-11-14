# Held-load concurrency proof (follow-up to 399f605)

This follow-up preserves the frozen packaging checkpoint **399f605**. It fixes
its P2 oracle gap: the old fixture allowed 20 seconds to observe an uncached
ALLOW while candidate loading timed out in 500ms. Dispatch blocked for the
entire load could therefore pass after rejection. PID visibility and an eventual
ALLOW were not concurrency evidence.

## Explicit test profile, not a production bypass

Only `run-outcomes.sh --policy-host` builds daemon and helper with
`-tags policyhost_phaseproof`. Normal builds, release archives and Docker builds
omit this profile. The fixture checks both binaries' embedded tags as well as
revision/toolchain/architecture and installed helper digest. Production builds
do not read phase-control environment variables, open a phase socket or speak
the extra handshake. Tagged/untagged pairs fail protocol validation rather than
falling back. No production deadline, signature check, resource limit, action,
cache eligibility rule, kernel map or enforcement oracle changes.

The tagged real worker acknowledges the signed module upload and sends a
`test-load-held` receipt over its owned anonymous pipe, then waits for a matching
release **before compilation**. The tagged supervisor forwards a receipt bound
to its owned child PID, exact module digest and limits over a guest-local Unix
socket. Only the selected compile-heavy/init-loop digest is externally held;
startup and other loads are immediately released through the same paired IPC.
The worker still receives no environment or filesystem capability.

The fixture completes its uid-65534 helper, observes its PID/path-attributed,
uncached file ALLOW, and only then requests a fresh held-load confirmation. It
releases the worker only after that confirmation. Rejection, process exit, EOF,
wrong receipt or missing ALLOW fails. A blocked dispatcher cannot pass later:
once rejected, the load's socket is closed and cannot supply a fresh receipt.
Timeouts bound failures; a narrow elapsed-time comparison never proves success.
Receipts are retained as `*-phase-proof.txt` alongside the actual event record.

The existing 10s total initialization deadline/cancellation watch remains active
through the hold. The existing 500ms child-load budget starts after release;
real compiler/initialization work must still reach that deadline, reject and
reap. The test does **not** claim an ALLOW observed during native SSA execution:
it proves dispatch progress while activation owns a verified, still-loading
candidate, then independently verifies real compile/init deadline failures.
Original eventual LKG allow and exact-deny checks after rejection remain.
Malformed framing has only eventual-LKG assertions, not a concurrency claim.

## Negative and bounded-lifetime probes

- Shared offline oracle forces `eventMu`-until-rejection ordering and rejects
  eventual success without a fresh phase receipt.
- Enforcer probe in both map modes holds the **real eventMu**, rejects a real
  artifact-signed initialization-loop candidate, then unlocks and observes a real uncached LKG
  ALLOW. The concurrency oracle must reject it by EOF, not by a wall timeout.
- Tagged real-worker test checks explicit release, caller cancellation, total
  initialization deadline, mismatched release rejection, capacity release and
  owned-child reaping. Post-reject
  ALLOW cannot validate a stale receipt.
- Normal-build test checks the test environment is inert; workflow contracts
  check no profile enters release/Docker packaging.

The VM workflow is pinned to **Go 1.26.11** (the 399f605 checkpoint used 1.26.2).
“Artifact-signed” means detached module signatures, **not signed deployment**.
No actual VM result or broad-green claim is supplied by these offline probes.
Both legacy/atomic VM runs remain for CI after the coordinator combines reviewed
PR53 source/unsupported-combination guards and private VM recording changes.

## Focused validation

Go 1.26.11, `GOMAXPROCS=2`, `-p 2`: focused normal/race tests for the shared
oracle, workflow contracts, daemon configuration, production-build inertness and
real-eventMu negative probe; tagged real-worker release/cancel/deadline/reaping
tests; affected normal/tagged golangci-lint; integration test-binary compilation;
shell syntax and actionlint. Build-only preparation validates the paired profile
and exact helper pin without starting a daemon/VM. No broad/full suite result is
claimed; frozen 399f605's older 1.26.2 evidence remains historical, not upgraded
by this narrower validation.
