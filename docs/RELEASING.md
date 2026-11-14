# Release integrity

`Release` is the sole publisher. It runs on `vMAJOR.MINOR.PATCH[-prerelease]`
tags pointing at a commit contained in `main` or `release-*`; branch pushes no
longer publish `latest`, moving minor tags or a repeatedly overwritten chart.
Do not use a tag as an instruction to deploy or upgrade any production cluster.
The workflow performs **no deployment**.

## Gates and artifact identity

The tag's exact commit is checked out explicitly in every build. Publication
requires all of these jobs from the **same run**, not a previous green branch:

- Linux race tests, required Rust policy builds and compiled WASM contracts;
- Go reachable-vulnerability checks and Rust resolved-lockfile vulnerability scans;
- native portable Go tests and archive smoke tests on Linux AMD64/ARM64,
  Windows AMD64 and macOS AMD64/ARM64 (macOS **tools only**);
- native Linux AMD64/ARM64 container builds, CLI/default-policy smoke tests and
  image vulnerability scans;
- lint/render checks on the **packaged** chart with release-specific
  `version`, `appVersion`, daemon and controller image tags.

Container images are saved and uploaded only after testing; publishing downloads
and verifies those saved files and image IDs rather than rebuilding. Final
multi-architecture manifests refer to the tested architectures. Archive and
chart downloads are the same retained artifacts. Actions are pinned to commit
IDs; Go/Rust/Helm/Buildx are fixed versions, BuildKit/base images are index-digest
pinned, and Trivy binary downloads are SHA-256 checked. Dependency downloads use
Go checksums (`go mod verify`); generated controller policies compile offline.
Archive timestamps, ownership and ordering are normalized; Go uses `-trimpath`,
`-buildvcs=false` and no build ID. This reduces nondeterminism, **not** a claim
that an independent party has reproduced the entire container image byte-for-byte.

The source chart is not modified during packaging. The release staging script
overrides both image repositories/tags and verifies rendered images. Existing
release/image/chart versions are rejected, not overwritten. Failed partial
publication may leave run-scoped staging images or final registry objects;
registry/chart/GitHub publication is not atomic. Investigate and use a new
version rather than deleting artifacts or silently forcing an overwrite.

## Vulnerability policy

`govulncheck` blocks reachable Go vulnerabilities. Trivy blocks **fixable HIGH
and CRITICAL** Rust dependency and image vulnerabilities; unfixed/lower-severity
findings remain visible via SBOMs but are not a release blocker. Scanner jobs
have ten-minute scan timeouts and bounded job timeouts; failed downloads/scans
fail closed. There is no blanket ignore file or invented credential. Vulnerability
databases intentionally track upstream updates, so a rerun can discover new
findings. Upgrade vulnerable dependencies/base digests; do not bypass a gate to
make a release green. Example Rust crates currently lack committed lockfiles;
their CI build resolves and scans dependencies, **not** a reproducibility claim
for those examples. The shipped generated policies are dependency-free.

## Signatures, SBOMs and verification

GitHub artifact attestations use OIDC and the existing `GITHUB_TOKEN`, with
`id-token: write` and `attestations: write` only in the tag publisher. No signing
secret, Apple credential or external private infrastructure is assumed. This
requires repository/plan support for GitHub attestations; unsupported attestation
publication is a blocker, not a reason to skip signing.

SPDX SBOMs are generated from the extracted binary archive payloads and the
published image digests. The combined binary SBOM is bound to each archive by a
signed SBOM attestation. Provenance covers archives, chart, SBOM files,
`IMAGES.txt`, platform support note and the top-level `SHA256SUMS`. The workflow
verifies provenance against its exact repository, workflow path, commit and tag
before publishing chart/downloads. `provenance.sigstore.json` is the detached
keyless signature bundle, **not** a PGP/minisign signature. Image provenance is
also pushed to GHCR and verified. Inner archive checksums cover binary payloads;
the top-level manifest covers the downloads, excluding the subsequently copied
attestation bundle itself.

After downloading assets from a chosen release:

```bash
repo=yasindce1998/warmor
tag=vX.Y.Z
commit=FULL_EXPECTED_COMMIT_SHA
gh attestation verify SHA256SUMS --repo "$repo" \
  --signer-workflow "$repo/.github/workflows/release.yml" \
  --source-ref "refs/tags/$tag" --source-digest "$commit"
sha256sum -c SHA256SUMS
gh attestation verify "warmor-${tag#v}-linux-amd64.tar.gz" --repo "$repo" \
  --signer-workflow "$repo/.github/workflows/release.yml" \
  --source-ref "refs/tags/$tag" --source-digest "$commit"
# Or add --bundle provenance.sigstore.json for offline bundle verification.
# Registry authentication is needed for OCI verification:
gh attestation verify oci://ghcr.io/yasindce1998/warmor@sha256:EXPECTED_DIGEST \
  --repo "$repo" --signer-workflow "$repo/.github/workflows/release.yml" \
  --source-ref "refs/tags/$tag" --source-digest "$commit"
```

Use `--predicate-type https://spdx.dev/Document` to verify a binary archive's
SBOM attestation. Compare `IMAGES.txt` digests before deployment. Keyless
provenance establishes workflow/source identity and digest integrity; it does
not prove the absence of vulnerabilities or certify enforcement behavior.

## Remaining release-support blockers

See [platform support](RELEASE_SUPPORT.md). Native macOS cgo/ESF, signed/notarized
System Extensions, Windows SDK/WDK native drivers and driver outcome tests are
not validated by hosted portable builds. ARM64 smoke tests run on ARM64 hosts,
but are **not** BPF-LSM workload-outcome tests on ARM64 Kubernetes nodes. Exact
BPF regeneration parity with committed objects still needs a pinned compiler
and a verified regeneration job. These workflow changes do not substitute for
Plan H's privileged Linux/Kubernetes release-readiness gates.

## Local checks

```bash
python3 -m unittest discover -s tests/release -v
actionlint .github/workflows/{release,binaries,macos-ci}.yml
VERSION=9.8.7-rc.1 IMAGE_REPOSITORY=ghcr.io/example/warmor bash scripts/release-chart.sh
```

Changes to release workflows, packaging or Dockerfile run the build-only gates
on pull requests without package/release/signing write permissions. Actual
registry/OIDC publication and non-Linux native runners must still be verified
by the coordinating maintainer in GitHub Actions; never simulate these as green.
