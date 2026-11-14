# Supervised evaluator shutdown integration

Status: **experimental/off by default; no production sandbox or VM readiness claim**.

Persistent worktree `.worktrees/supervised-evaluator-shutdown`, branch
`feat/supervised-evaluator-shutdown`, begins at review pin `9d7183f` and merges
`5aa4556` (including reviewed idle-reader fix `9c3d201` and PR41 transport fix
`0e3a2e3`). Merge checkpoint `7c2bcbc` has those two parents. The reviewed
`feat/supervised-evaluator-main` branch remains unchanged at `9d7183f`.
Security re-review fixes arriving later must be separately scoped commits; this
integration does not claim that review is complete.

## Actual conflict and retained behavior

Only `internal/platform/linux.go` conflicted. The resolution combines
`tracepointMonitor`/error-returning `StopReaders` with existing generation capture,
single-reader flush/fence state, exact cgroup scope and initialized `LSMBlocking`
status. The existing LSM reader seam gains `StopReaders`; production uses the
same `LSMLoader`, not a second reader. Stop closes tracepoint and LSM readers
**before** monitor join, but only resource `Close` detaches maps/hooks. Errors
from reader interruption remain available on repeated platform Stop.

`5aa4556` also imports VM harness closed-stdin protection, the strict real-ring
idle-reader fixture/oracle, and compiler version 7. The compiler-version change
is imported as-is, not a new metadata contract. Existing 127-byte process-path,
288-byte exact-key, protocol-v2 host metadata and signed/atomic combination gates
remain unchanged. No BPF C/object or dependency-file changes are introduced.

## Additional shutdown ordering fixes

- `Enforcer.Close` now cancels and interrupts readers before taking
  `activationMu`. Previously an activation could own that mutex while waiting for
  its own context/drain, delaying shutdown until the grace timeout. One
  `stopProcessing` owner also serializes concurrent Stop/Close and queued-lease
  cleanup, avoiding races on platform teardown.
- Stop does not retire healthy idle evaluators or detach maps. Close waits for
  event processing and the event lifetime barrier, then closes/reaps every
  retained backend before platform resource Close. A guest in an active IPC
  request can be killed/reaped by context cancellation; this does not bypass a
  still-active post-evaluation action/outcome lease.
- Canceled/stopped generation drains do not start another flush or acknowledge
  a ready queue fence as success after known cancellation. Cancellation is also
  rechecked before kernel drain acknowledgment/old-backend retirement. A live
  commit interrupted during shutdown remains `ErrActivationPending`, not an old
  or new successful durable acknowledgment.
- New activations after cancellation are refused. The existing single-reader
  normal flush behavior, original pending flush ownership, old-event routing,
  and host fail-closed/noncached-error behavior are retained.

## Unprivileged test evidence

Tests build the real `cmd/warmor-policy-host` and use fake platform/kernel
boundaries. No BPF/security hooks, live daemon, arbitrary process action or host
enforcement is installed. Action-delay tests replace termination with an inert
test callback; no process is signaled.

- Normal Stop in both legacy and generation mode interrupts a context-ignoring
  fake idle reader, joins it once, and leaves the host/maps usable until Close.
- Close while activation waits for a canceled reader drain does not wait on
  activationMu before cancellation; retained old/current hosts are reaped before
  fake map teardown and no old drain is acknowledged.
- Concurrent Stop/Close during an old-generation post-evaluation action keeps
  both real hosts and fake maps alive until the action completes. An additional
  queued old-generation lease is completed during shutdown; no state retains
  outstanding references afterward.
- An actual endless WASM request is canceled through the real host backend;
  the owned child is reaped before map teardown and its error is not cached.
- Platform tests cover blocked idle LSM reads and blocked channel delivery
  during a concurrent outstanding generation flush, lease release on canceled
  delivery, no fresh flush after Stop, and no flush for an already canceled call.
- Imported PR41 tests separately cover tracepoint reader close-before-join and
  preserved errors. Its real-ring VM fixture is included, not executed locally.

## Remaining gates and limits

The eventual whole-daemon Host VM shutdown gate must include this merged reader
fix and assert clean SIGTERM completion; cleanup SIGKILL is not a successful
shutdown or workload outcome. No VM run is claimed here. Hooks/maps remain alive
until Close but do not survive daemon death. Durable filesystem callbacks are
administrator-owned synchronous functions with no cancellation interface; a
callback that itself never returns remains outside this shutdown bound. Likewise
an intentionally blocked outcome must complete before lifetime retirement;
there is no forced lease timeout that silently closes evaluators under work.

Initial local tests caught two fixture issues: minimal Close needs a nil-cancel
guard, and PID zero deliberately refuses actions before reaching a fake delayed
termination callback. The production guard was retained and the fixture uses an
inert injected callback with a nonzero synthetic PID. Neither failure was hidden
by skipping tests or relaxing shutdown/resource assertions.

## Local validation checkpoint

Code checkpoint `c9cbb7c`, Linux unprivileged, **Go 1.26.11**, `GOMAXPROCS=2`,
package parallelism **`-p 2`**:

- `WARMOR_REQUIRE_CARGO=1 go test -count=1 -p 2 ./...`: pass on the settled tree,
  including actual compiled-policy tests (Cargo absence would fail, not skip).
- `WARMOR_REQUIRE_CARGO=1 go test -race -count=1 -p 2 ./...`: pass on the same
  checkpoint, including real-host compiler deadlines and shutdown cancellation.
- Focused shutdown/platform tests under `-race -count=5`: pass after the queued
  lease and real guest cancellation assertions were added. The preceding merge
  checkpoint also passed ten focused race repetitions.
- `go vet -p 2 ./...`: pass.
- `golangci-lint v1.64.8 run --concurrency 2 --timeout 5m ./...`: pass with Go
  1.26.11 selected; the lint executable reports it was built using Go 1.27.2.
- Windows amd64 enforcer and Darwin arm64 daemon test binaries cross-compiled:
  pass; no native non-Linux execution is claimed.
- Integration-tagged ebpf/outcome packages built using `-run '^$'`: pass. This
  includes the imported VM reader fixture, not execution of enforcing tests.
- `git diff --check`: pass. No BPF C/embedded object or `go.mod`/`go.sum` delta
  from `9d7183f`. Both review branches remain at their original pins.

Logs: `/tmp/opencode/supervised-shutdown-{full,race,focused,repeated-race,vet,`
`lint,integration-build,cross-windows,cross-darwin}.log`. No pushes, PR actions,
source-branch edits, live VM, cluster, or host-wide enforcement runs were made.
