#!/usr/bin/env bash
# Build on the target OS/architecture; macOS packages are tools-only.
set -euo pipefail
: "${VERSION:?set VERSION}"
: "${GOOS:?set GOOS}"
: "${GOARCH:?set GOARCH}"
export CGO_ENABLED=0
out="dist/warmor-${VERSION}-${GOOS}-${GOARCH}"
mkdir -p "$out"
ext=""
if [[ "$GOOS" == windows ]]; then ext=.exe; fi
tools=(warmorctl warmor-server warmor-compile warmor-learn warmor-simulate
  warmor-policy-gen warmor-policy-merge warmor-policy-diff warmor-policy-bundle
  warmor-integrity-scan warmor-sbom-policy)
if [[ "$GOOS" != darwin ]]; then tools+=(warmor-daemon); fi
if [[ "$GOOS" == linux ]]; then tools+=(warmor-oci-hook); fi
for tool in "${tools[@]}"; do
  go build -mod=readonly -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid= -X github.com/yasindce1998/warmor/internal/version.Version=${VERSION}" \
    -o "$out/$tool$ext" "./cmd/$tool"
done
cp LICENSE "$out/"
cp docs/RELEASE_SUPPORT.md "$out/RELEASE_SUPPORT.md"
# No root, drivers, entitlements or production cluster needed.
"$out/warmor-compile$ext" --version | grep -F -- "$VERSION"
"$out/warmor-compile$ext" --validate deploy/default-policy.yaml
if [[ "$GOOS" != darwin ]]; then
  "$out/warmor-daemon$ext" --version 2>&1 | grep -F -- "$VERSION"
else
  test ! -e "$out/warmor-daemon"
fi
python3 scripts/release-package.py "$out" "${SOURCE_DATE_EPOCH:?set SOURCE_DATE_EPOCH}" "$GOOS"
