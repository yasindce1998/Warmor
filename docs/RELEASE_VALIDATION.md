# Release gate validation — 2026-11-14

Local validation on Linux AMD64, based on `5b32b66`, before any remote
publication. This is a change-validation record, not a successful release.

## Passed

- 10 Python release regressions: deterministic tar/zip output, checksum
  verification, safe extraction, executable modes, symlink/traversal rejection,
  stale-output rejection, pinned actions/images, sole-publisher gate shape and
  packaged chart version/image invariants.
- `actionlint v1.7.12` on `release.yml`, `binaries.yml`, `macos-ci.yml` (shellcheck
  unavailable locally; Bash syntax checked separately).
- Go **1.26.11** full `go test -mod=readonly -race -count=1 ./...` with both
  `WARMOR_REQUIRE_CARGO=1` and `WARMOR_REQUIRE_POLICY_CRATES=1`; all policy crates
  built first. `go mod verify` passed. The earlier portable `CGO_ENABLED=0`
  short suite also passed.
- Linux AMD64 release archive built; its extracted binaries passed version and
  policy-validation checks. Repackaging the same payload produced identical
  archive bytes (separate packaging reproducibility check).
- Windows AMD64 and macOS ARM64 **cross-compilation** of the selected release
  commands passed. These are not native runtime/backend tests.
- Staged prerelease Helm package passed lint/render checks and did not modify
  the source chart; daemon/controller images used the staged version.

## Blocked / not verified

- The reachable Go vulnerability gate reports `GO-2026-6865`
  (`github.com/klauspost/compress v1.18.0`, fixed version reported: `v1.20.2`)
  and `GO-2026-6497` / `GO-2026-6499` (`oras.land/oras-go/v2 v2.6.1`, fixed:
  `v2.6.2`). **Publication must remain blocked** pending dependency fixes and
  a clean rescan. No ignore or dependency edit was made by this workflow task.
- Local pinned Docker-base pulls and the Trivy binary download timed out.
  Full container build/smoke tests, image/Rust vulnerability scans and SBOM
  generation therefore remain unverified locally. Do not interpret a valid
  workflow or a passing source test as a passing image security scan.
- GitHub Actions native ARM64, Windows and macOS jobs, registry promotion,
  GitHub OIDC attestations/verification, GitHub release creation and Helm OCI
  publication have not been executed. No push, PR, tag, release or deployment
  was made. Repository/plan attestation support must be confirmed remotely.
- macOS cgo/ESF SDK compilation, Apple signing/notarization and native Windows
  SDK/WDK driver build/signing/outcome tests still need external native
  infrastructure. macOS archives intentionally omit the daemon. Windows
  archives contain the experimental ETW Go daemon, no `.sys` artifacts.
- BPF regeneration parity and privileged AMD64/ARM64 Kubernetes workload
  enforcement outcomes remain separate Plan H readiness work, not claims
  established by the release smoke tests.

`ci.yml` was intentionally not changed; source chart versions/defaults are
owned by the coordinating chart task. Re-run packaged-chart tests after those
changes are integrated.

## Independent-review follow-up

All four requested findings are covered by local regression tests:

- **Windows CRLF archive path:** `release-build.sh` constructs `.zip`/`.tar.gz`
  filenames in Bash instead of capturing Python `print`. A Windows-target
  packaging smoke test uses a Python shim that emits actual CRLF and executes
  the extraction/checksum/CLI steps with tiny executable payload stubs. It is
  not a native Windows runtime test, but reproduces the shell-path failure.
- **Independent artifact integrity:** producers expose upload IDs and ZIP
  SHA-256 digests through job outputs, rather than inside downloaded manifests.
  Publishers verify raw ZIP bytes before extracting/loading/signing/pushing.
  Tests replace both payload and its self-consistent checksum file and require
  a hard failure with no published extraction directory; missing/duplicate
  receipts and partial transfer failures also fail closed. ZIPs are requested
  by immutable producer ID, not a mutable artifact name or most-recent run.
- **Maintained branch matching:** full ref-name tests reject misleading nested
  `origin/feature/origin/main` and `origin/feature/origin/release-*` refs while
  accepting the exact maintained refs.
- **Moved tag:** local bare-remote tests verify both lightweight and annotated
  tags, then move or delete them and require failure. The remote peeled tag is
  checked again at publication/signing boundaries. Immutable protected tag
  rules remain mandatory to close the unavoidable check-to-use race; no remote
  ruleset or release was changed by these tests.

The updated 19-test Python suite, actionlint (including the extracted reusable
`release-image.yml`), Bash syntax, `git diff --check`, and the full
`GOMAXPROCS=2 GOTOOLCHAIN=go1.26.11 go test -mod=readonly -race -count=1 ./...`
suite pass. Native Windows,
macOS/ARM64 hosted runs, raw GitHub artifact transfer, OIDC/registry publication,
and the external SDK/driver infrastructure remain unverified here. The separate
dependency-fix branch is not modified or silently folded into this release
branch; integration and a passing rescan remain the coordinator's responsibility.

## Main-based release integration

Persistent worktree `.worktrees/release-integration`, branch
`ci/tested-release-artifacts`, starts at `origin/main` **`78471f6`** and
cherry-picks only `5915d3f`, `f0fb5ba`, `2be9737` and `0f7bd1b` from the release
task. The validation above is historical source-branch evidence, not a claim
that the full runtime suite was rerun on this integration. Separate review
follow-ups to `0f7bd1b` are not folded in here.

Integration-only changes make security/build validation run on every PR (not
only selected manifest/workflow paths) and weekly Monday 04:17 UTC. These runs
retain read-only repository permissions and cannot enter either publisher;
both publishers still require a `push` event on `refs/tags/v*`. Vulnerability
findings, scanner errors and download failures remain hard failures.

Local checks on this integration:

- **21 Python release regressions pass**, including source-chart byte snapshots
  before/after packaging stable, prerelease and CI versions. Chart sources are
  untouched; the pending chart-agent changes are not integrated.
- **actionlint v1.7.12 passes** for `release.yml`, `binaries.yml`,
  `release-image.yml` and `macos-ci.yml`, with `-shellcheck=` because shellcheck
  is unavailable. `bash -n` passes on all four release shell scripts.
- **CI-configured errcheck passes on both this branch and `78471f6`**, using
  local golangci-lint v1.64.8, Go 1.26.11, the unchanged `.golangci.yml`, and
  `golangci-lint run --disable-all --enable errcheck --out-format=line-number
  --timeout=5m`. The baseline is an isolated `git archive 78471f6`, not a feature
  branch. This checks errcheck only, not the complete CI linter suite.
- Standalone `errcheck -asserts ./...` exits nonzero with **385 byte-for-byte
  identical diagnostics** on baseline and integration. Those additional raw
  findings must not be described as new feature regressions or as a clean raw
  errcheck run.
- `git diff --check` passes; `git diff 78471f6 -- deploy/helm go.mod go.sum` is
  empty. Dependency PR #36 is deliberately not combined; integrate it through
  main after merge and require fresh successful vulnerability scans before any
  publication.

Not revalidated here: full Go/Rust runtime suites, live vulnerability databases,
Docker/Trivy image builds and scans, native hosted ARM64/Windows/macOS jobs,
GitHub artifact API ZIP transfer, GHCR/Helm OCI promotion, OIDC attestations,
immutable tag rulesets, privileged Kubernetes/BPF outcomes or native SDK/driver
infrastructure. No remote push, PR, tag, release, deployment or merge was made.

## PR #42 hosted failure triage (head `049204b`)

Inspected existing logs for Release run **43607491228** and Windows CI run
**43607491182** without rerunning jobs. Release checked out the PR merge commit
`012e91a45009dc8f29918a3795e2617d1a5cdac6`, not just the head commit. No scanner
download, checksum, database-download, unsupported-flag, workflow-rule or action
pin failure was found in the requested jobs.

| Job | Actual failure / disposition |
| --- | --- |
| Release tests `132485185572` | Go regression/race tests and Rust policy builds passed. govulncheck completed and blocked on `GO-2026-6865` (compress v1.18.0; reports fix v1.20.2) and `GO-2026-6497`/`GO-2026-6499` (ORAS v2.6.1; fix v2.6.2). Rust Trivy steps were **skipped**, not passed. Keep blocked pending PR #36 through main and a clean rescan. |
| Daemon AMD64/ARM64 `132485216504` / `132485216633` | Native Docker builds, image CLI/default-policy smoke tests and pinned Trivy installation passed. Both completed scans found one fixable HIGH `CVE-2026-63209` in compress v1.18.0 (Trivy reports fix 1.18.7). This is a dependency finding, not scanner infrastructure failure; PR #36 must satisfy both scanners. |
| Controller AMD64/ARM64 `132485216580` / `132485216586` | Native builds, smoke tests and pinned scanner installation passed. Both completed scans found eight fixable HIGH Debian findings: six in `linux-libc-dev` 6.12.116-1 (fix 6.12.117-1) and two in `zlib1g` 1:1.3.dfsg+really1.3.1-1+b1 (fix 1:1.3.dfsg+really1.3.1-1+deb13u1). The Rust base needs security maintenance and fresh native scans; Go-only PR #36 does **not** fix these OS packages. No exceptions/ignore rules were added. |
| Darwin AMD64 `132485216542` | `TestReloadPolicy_Errors/invalid_wasm` failed its cache/old-policy assertions after setup evaluation exceeded the 50 ms default (`malloc failed: module closed with context deadline exceeded`). Failed reload returns before changing the active runtime/cache. The test now uses a bounded five-second evaluation budget only for this reload-atomicity scenario, requires a successful cached ALLOW **before** reload, checks unchanged evaluator/pool/runtime/cache afterward, requires a real cache hit, and distinguishes a cacheable policy DENY from an evaluation-error DENY. Production deadlines and dedicated timeout tests are unchanged. |
| Windows CI `132485184776` | `TestPolicyEvaluator_Evaluate_Allow` required latency > 0. A fast evaluation can measure zero within a Windows clock tick. The assertion now accepts zero but still rejects negative/impossible elapsed durations and missing timestamps; production timing is not fabricated. Race testing, coverage and ETW gates are not removed or bypassed. |

The same Release run successfully built/smoke-tested/uploaded portable archives
on Linux AMD64/ARM64, Windows AMD64 and Darwin ARM64, and packaged the staged
chart. Darwin AMD64 archive creation was skipped after its test failure. Image
SBOM/save/upload steps were not reached after vulnerability failures. Both
publishers were skipped; there was no release/tag publication. These are results
for that existing PR merge commit, not green evidence for the follow-up patch.

Local follow-up validation (Linux AMD64, Go 1.26.11, `GOMAXPROCS=2`):

- Reload error regression passes **30 race-enabled repetitions**, evaluator
  ALLOW timing test passes **100 race-enabled repetitions**.
- Both affected packages pass `go test -mod=readonly -race -short -count=1 -p=1
  ./internal/enforcer ./internal/wasm`, including existing timeout/fail-closed
  regressions.
- All **21 Python release regressions** pass; actionlint v1.7.12 passes for the
  four release-owned workflows plus `windows-ci.yml` (`-shellcheck=`), release
  shell scripts pass `bash -n`, CI-configured errcheck passes, and
  `git diff --check` passes.

Only tests and this validation record change. Required security/native gates,
workflow permissions, production evaluation limits, dependency manifests,
Docker base digests and source chart are unchanged. No native Windows/macOS
follow-up run, old-job rerun, push, PR update, merge, tag or release was requested
or performed. Security findings remain release blockers, not unverified scans;
OIDC/registry publication, artifact consumption and privileged/native driver
infrastructure still need coordinating validation.
