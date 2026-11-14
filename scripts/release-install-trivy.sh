#!/usr/bin/env bash
# Pin binary bytes; no default-branch installer or invented credentials.
set -euo pipefail
version=0.76.2
case "$(uname -m)" in
  x86_64) asset=Linux-64bit; checksum=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf ;;
  aarch64) asset=Linux-ARM64; checksum=ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3 ;;
  *) echo 'unsupported scanner architecture' >&2; exit 1 ;;
esac
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
archive="trivy_${version}_${asset}.tar.gz"
curl --fail --silent --show-error --location --retry 3 --max-time 180 \
  "https://github.com/aquasecurity/trivy/releases/download/v${version}/${archive}" -o "$stage/$archive"
echo "$checksum  $stage/$archive" | sha256sum -c -
tar -xzf "$stage/$archive" -C "$stage" trivy
mkdir -p "$HOME/.local/bin"
install -m 0755 "$stage/trivy" "$HOME/.local/bin/trivy"
if [[ -n "${GITHUB_PATH:-}" ]]; then echo "$HOME/.local/bin" >> "$GITHUB_PATH"; fi
