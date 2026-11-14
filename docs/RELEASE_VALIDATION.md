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
