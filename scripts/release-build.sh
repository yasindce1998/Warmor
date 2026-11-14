#!/usr/bin/env bash
# Build on the target OS/architecture; macOS packages are tools-only.
set -euo pipefail
: "${VERSION:?set VERSION}"
: "${GOOS:?set GOOS}"
: "${GOARCH:?set GOARCH}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || exit 1
case "$GOOS/$GOARCH" in
  linux/amd64|linux/arm64|windows/amd64|darwin/amd64|darwin/arm64) ;;
  *) echo "unsupported release target: $GOOS/$GOARCH" >&2; exit 1 ;;
esac
export CGO_ENABLED=0
out="dist/warmor-${VERSION}-${GOOS}-${GOARCH}"
# Never package stale binaries (particularly an old macOS daemon) on reruns.
test ! -e "$out" || { echo "release output already exists: $out" >&2; exit 1; }
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
# Test the extracted bytes of the final archive, not just build-directory files.
# Python's print uses CRLF on Windows. Never derive a shell filename from it.
python3 scripts/release-package.py "$out" "${SOURCE_DATE_EPOCH:?set SOURCE_DATE_EPOCH}" "$GOOS"
archive="${out}.tar.gz"
if [[ "$GOOS" == windows ]]; then archive="${out}.zip"; fi
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/archives"
cp "$archive" "$stage/archives/"
python3 scripts/release-extract.py "$stage/archives" "$stage/extracted"
out="$stage/extracted/$(basename "$out")"
python3 - "$out" <<'PY'
import hashlib
from pathlib import Path
import sys

root = Path(sys.argv[1])
for line in (root / "SHA256SUMS").read_text().splitlines():
    checksum, name = line.split("  ", 1)
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != checksum:
        raise SystemExit(f"release checksum mismatch: {name}")
PY
# No root, drivers, entitlements or production cluster needed.
"$out/warmor-compile$ext" --version | grep -F -- "$VERSION"
"$out/warmor-compile$ext" --validate deploy/default-policy.yaml
if [[ "$GOOS" != darwin ]]; then
  "$out/warmor-daemon$ext" --version 2>&1 | grep -F -- "$VERSION"
else
  test ! -e "$out/warmor-daemon"
fi
echo "$archive"
