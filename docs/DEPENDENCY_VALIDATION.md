# Dependency security validation — 2026-11-14

Initially validated on branch `fix/vulnerability-dependency-updates`, created from a fresh
fetch of `origin/main` at `9ea4594`. This task changes dependency pins/checksums
and this record only; no release-workflow documents or source code are changed.

## Initial standalone validation (historical; superseded by integrated results)

The pins, toolchain requirements and scan/build results in this section describe
the original standalone source, not the final integrated graph. The integrated
CRI validation below is authoritative for the current branch; its `x/*` modules
require Go 1.26.0, not the Go 1.25 minimum of the initial five upgrades.

### Verified advisories and least fixed versions

The following exact module paths and fixed-version events were read directly
from the Go vulnerability database, not inferred from similarly named packages:

| Advisory | Module | Previous pin | New pin | Evidence |
| --- | --- | --- | --- | --- |
| GO-2026-6865 | `github.com/klauspost/compress` | `v1.18.0` | `v1.20.2` | [Go advisory](https://vuln.go.dev/ID/GO-2026-6865.json), [upstream release](https://github.com/klauspost/compress/releases/tag/v1.20.2) |
| GO-2026-6497, GO-2026-6499 | `oras.land/oras-go/v2` | `v2.6.1` | `v2.6.2` | [6497](https://vuln.go.dev/ID/GO-2026-6497.json), [6499](https://vuln.go.dev/ID/GO-2026-6499.json), [upstream release](https://github.com/oras-project/oras-go/releases/tag/v2.6.2) |
| GO-2026-5024 | `golang.org/x/sys` | `v0.43.0` | `v0.44.0` | [Go advisory](https://vuln.go.dev/ID/GO-2026-5024.json) — Windows `NewNTUnicodeString` integer overflow |
| GO-2026-5970, GO-2026-6629 | `golang.org/x/text` | `v0.16.0` | `v0.41.0` | [5970](https://vuln.go.dev/ID/GO-2026-5970.json) fixed in `v0.39.0`; [6629](https://vuln.go.dev/ID/GO-2026-6629.json) fixed in `v0.41.0` |

ORAS `v2.6.2` requires `golang.org/x/sync v0.22.0`, so minimal version
selection also updates that indirect dependency from `v0.20.0`. No unrelated
dependency was upgraded, no module was replaced, and no vulnerability was
suppressed. `go mod tidy` replaced obsolete checksums with the selected versions.
The repository's `go 1.26.0` directive is unchanged; all five selected modules
require Go 1.25 or 1.25.0, compatible with the tested Go 1.26.11 toolchain.

Published versions were independently confirmed with `go list -m -json` and
upstream GitHub release APIs. Module origin commits reported by Go:

- compress `v1.20.2`: `7f5d8528720c895a6106f201719f87eb030a565d`;
- ORAS `v2.6.2`: `105715ee12eac6895ec736a075285c34d9f2eeb6`;
- x/sys `v0.44.0`: `fb1facd76f95fa87c151018200ea5e4892ff115d`;
- x/text `v0.41.0`: `acdba6655fd45cdb5ab73c9d6a8981333bd65a39`.

### Toolchain, scan scope and results

- Test/analyzed Go toolchain: **go1.26.11**, Linux AMD64.
- Scanner: **golang.org/x/vuln/cmd/govulncheck v1.9.0**, installed with that
  toolchain into a persistent user cache.
- Database: `https://vuln.go.dev`, reported update
  **2026-11-11 02:51:11 UTC**, queried on 2026-11-14.
- Go commands used `GOMAXPROCS=2 GOTOOLCHAIN=go1.26.11` and persistent defaults
  `/home/yasin/.cache/go-build`, `/home/yasin/go/pkg/mod`; Rust builds used
  `CARGO_BUILD_JOBS=2`, Rust **1.99.0**, and the installed WASM target.

Final `govulncheck -show verbose ./...` on Linux AMD64 and Windows AMD64
(`CGO_ENABLED=0` for the Windows analysis) returned **“No vulnerabilities
found”**, with no remaining module-only findings. Darwin ARM64 cgo-disabled
source analysis also returned **“No vulnerabilities found.”** The original
three findings disappeared after the compress/ORAS upgrades; the Linux verbose
scan then exposed GO-2026-5024 at module level, and Windows analysis exposed
GO-2026-5970/6629 at module level. Those were fixed rather than ignored even
though the scans did not show a reachable call to them in this source tree.

For cross-target analysis, install/run the scanner as a **host executable** and
set `GOOS`/`GOARCH` only when executing it. `GOOS=windows go run ...` builds a
Windows scanner executable and cannot run it on Linux. This source analysis is
not a native Windows runtime test, macOS cgo/ESF test, or kernel-driver test.

Reproduction (with the Go 1.26.11 toolchain already installed):

```bash
export GOMAXPROCS=2 GOTOOLCHAIN=go1.26.11
GOBIN="$HOME/.cache/warmor-dependency-tools" \
  go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
scanner="$HOME/.cache/warmor-dependency-tools/govulncheck"
"$scanner" -version
"$scanner" -show verbose ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 "$scanner" -show verbose ./...
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 "$scanner" ./...
```

### Build/test results

All passed with the final five dependency pins:

- `go mod verify` and `go mod tidy -diff` (no diff);
- `go vet -mod=readonly ./...`;
- `CARGO_BUILD_JOBS=2 bash scripts/build-rust-policies.sh` (all ten Rust crates);
- `WARMOR_REQUIRE_CARGO=1 WARMOR_REQUIRE_POLICY_CRATES=1 go test -mod=readonly -race -count=1 ./...`;
- `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -mod=readonly ./...`;
- `CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -mod=readonly ./...`.

Passing scans only describe the database/toolchain/targets above. They do not
certify image/OS dependencies, production enforcement, native driver builds or
future advisories. No native macOS ESF or Windows driver infrastructure was used.

## Initial isolated workload dependency union (historical)

Inspected dependency-only commit
`9924c17eced30cf56bf557755aba67f5a8a817f9` and the workload branch's manifest.
An isolated copy of that commit's `go.mod`/`go.sum` was updated with the new
compress, ORAS and x/text pins. An exact manifest comparison confirmed **only**:

| Module | Workload pin | Union pin |
| --- | --- | --- |
| `github.com/klauspost/compress` | `v1.18.0` | `v1.20.2` |
| `oras.land/oras-go/v2` | `v2.6.1` | `v2.6.2` |
| `golang.org/x/sync` | `v0.21.0` | `v0.22.0` |
| `golang.org/x/text` | `v0.39.0` | `v0.41.0` |

The union retained **x/sys `v0.46.0`**, gRPC `v1.72.2`, `k8s.io/api`,
`k8s.io/apimachinery`, `k8s.io/cri-api` all `v0.35.10`, and protobuf
`v1.36.12-0.20260120151049-f2248ac996af`, plus every other workload pin unchanged.
Do **not** overwrite the workload `go.mod` with this standalone branch's lower
x/sys pin or run a later `go get ...@v0.44.0` when resolving the union: retain
`v0.46.0` or newer. Conversely retain x/sync `v0.22.0` and x/text `v0.41.0` from
this security patch rather than reverting to the workload commit's older pins.

With the union manifest in an isolated copy of this branch's source,
`govulncheck ./...` and a module-only scan (run from `cmd/warmor-daemon`, since
the repository root has no Go source files) both reported no vulnerabilities.
This validates the dependency graph, **not** all workload feature code or the
eventual merged source. The coordinator must resolve textual go.mod/go.sum
conflicts with these maxima and rerun full tests/scans on the integrated tree.

## Integrated CRI source validation

After PR #35 and #37 merged, the actual integrated source was rescanned, not
only an isolated manifest. The earlier union result above did not exercise
the new CRI imports. That scan found six reachable advisories in `x/net` and
gRPC, plus package/module findings; the earlier clean result must not be used
as evidence for this integrated source.

The final union retains all Kubernetes pins and protobuf, and selects:

| Module | Integrated pin | Reason |
| --- | --- | --- |
| `google.golang.org/grpc` | `v1.83.2` | Fixes GO-2026-6348/6061/4762/6441; GO-2026-6443 also affects `v1.83.1`, so that intermediate candidate was rejected |
| `golang.org/x/net` | `v0.62.0` | Fixes GO-2026-6617/6612/6611/6603/6610 and module findings GO-2026-6866/6860 |
| `golang.org/x/sync` | `v0.24.0` | Required minimum selected by the fixed dependency graph |
| `golang.org/x/sys` | `v0.49.0` | Required minimum; newer than the CRI branch's `v0.46.0`, not a downgrade |
| `golang.org/x/text` | `v0.43.0` | Required minimum, retaining the prior security fixes |
| `google.golang.org/genproto/googleapis/rpc` | `v0.0.0-20260526163538-3dc84a4a5aaa` | Required gRPC dependency |

Published fixed versions were verified with `go list -m -json` and the Go
advisories, including [GO-2026-6348](https://vuln.go.dev/ID/GO-2026-6348.json),
[GO-2026-6443](https://vuln.go.dev/ID/GO-2026-6443.json) and
[GO-2026-6866](https://vuln.go.dev/ID/GO-2026-6866.json). All are compatible with
the tested Go 1.26.11 toolchain.

On the final integrated source (main through `d3b057a` plus these pins), Linux
AMD64, Windows AMD64 and portable Darwin ARM64 verbose source scans report
**No vulnerabilities found**, including package/module-only findings. The full
required-Cargo race suite passes. No findings were suppressed. Scanner/database
versions are the same as recorded above; these results do not replace image/OS
or native-platform validation. PR #36 requires fresh CI for this changed head.

No tags, releases or deployments were performed.
