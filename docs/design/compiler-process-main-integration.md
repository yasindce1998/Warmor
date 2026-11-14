# Compiler subprocess / signed-main integration

## Review scope

This integration merges `origin/main` at `98d2b90` into compiler-process branch
tip `33151a5`. It does not replace the independent reviews of `a5ca745` and
`d05496b`, or their native CI results. The controller-main integration remains
in the history at `178367c`.

The only textual conflict was the import block of `internal/compiler/build.go`:
retain `policybuild` from main, and omit the old `time` import because process
ownership and pipe deadlines live in the subprocess helper. The signed-main
metadata append body merged without a conflict and is retained unchanged.

## Preserved contracts

- `BuildOptions.Context`, bounded target discovery, the shared captured-output
  budget, and the pre-publication cancellation check remain active. A timed-out
  or over-output Cargo process cannot become a successful artifact merely by
  writing a valid WASM file and exiting zero.
- `Build` appends `policybuild.Metadata{Compiler: Identity, DefaultAction: ...}`
  after Cargo succeeds and before returning success. Main's context checks
  around metadata append/write are retained. `Version` is `7` and `Identity` is
  `warmor-yaml/7`; code generation and safe crate naming are unchanged.
- All production subprocess helper files are byte-for-byte unchanged from
  `33151a5`: Linux/Darwin own a fresh process group, use non-reaping `waitid`,
  check ownership before signaling, and signal before reaping. Darwin's
  zombie-only `EPERM` evidence and auto-reap checks remain intact. Windows
  remains explicitly parent-only; no stronger platform/sandbox claim is added.
- Signed assignment verification, allowed compiler/digest checks, durable
  authorization, activation/publication, and pool-captured artifact identity
  come from main without integration-specific edits. In particular, metadata
  is an artifact-signed declaration, not proof of trusted compiler provenance.

## Integration-specific test adjustment

The injected fake Cargo formerly emitted the string `fake wasm`. That is not a
WASM artifact and is correctly rejected by signed-main's metadata parser. It
now emits a valid empty WASM module. Its successful build test reads the final
metadata and checks compiler identity/default action. The actual-Cargo context
test now checks the final metadata too. Flood/slow-output fixtures also write
valid WASM, preserving the stronger assertion that their preexisting destination
is untouched despite a syntactically valid intermediate artifact.

Main's real-Cargo
`TestCompiledAssignmentRetainsBuildContextSafeIdentifierAndMetadata` independently
loads the built artifact, constructs a pool, and checks its digest, ABI 3,
compiler 7 identity, and deny posture against an assignment. Signed activation
and workload composition tests run without being replaced by fake tool tests.

## Validation commands

Use Go 1.26.11 with `GOMAXPROCS=2` and package parallelism 2 on this shared host:

```sh
GOTOOLCHAIN=go1.26.11 GOMAXPROCS=2 WARMOR_REQUIRE_CARGO=1 go test -p 2 -count=1 ./...
GOTOOLCHAIN=go1.26.11 GOMAXPROCS=2 WARMOR_REQUIRE_CARGO=1 go test -race -p 2 -count=1 ./...
GOTOOLCHAIN=go1.26.11 GOMAXPROCS=2 GOFLAGS=-p=2 golangci-lint run --concurrency=2 --timeout=5m
```

Native Darwin regressions and actual Cargo/WASM contracts passed for `d05496b`;
all 26 checks completed without failures for `33151a5` before this main merge.
Those results are historical evidence, not a claim that this new merge commit
has already passed native-platform CI. No CI tests or production limits are
disabled or weakened by this resolution.

The focused signed/Cargo/metadata selection passed three times with actual
Cargo required on Go 1.26.11. It includes both the unchanged main assignment
test and the merged compiler artifact checks. An initial run without a
`GOMAXPROCS` cap hit unrelated 30/50ms WASM initialization/evaluation deadlines
under host load; no deadline settings were changed. Full test/race and lint
results are reported in the integration handoff rather than inferred from the
earlier branch CI.

## Main-side compatibility blocker discovered by full tests

At `98d2b90`, `internal/workload/manifest/manifest.go` deliberately pins
`SupportedCompilerVersion = "6"` and requires it to equal `compiler.Version`.
Signed main has bumped the latter to `7`. Consequently the full manifest suite,
including its real-Cargo cases, rejects setup with `unsupported manifest
version, generation, compiler, composition or posture`. This reproduces from
the main sources without changing any subprocess behavior. This integration
does not weaken that fail-closed check or silently approve compiler-7 workload
composition; the workload owner/controller must reconcile the explicit pin.

The full non-race run also encountered `TestHandleEvent_PolicyLog`'s 50ms
evaluation deadline and `TestCPURlimitKillsOwnedWorker`'s wall-clock deadline
under shared-host load. No production/test deadlines or CPU limits were edited.
