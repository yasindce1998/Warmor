#!/usr/bin/env bash
# Build every Rust policy crate under policies/ for wasm32-unknown-unknown.
#
# Output: policies/<crate>/target/wasm32-unknown-unknown/release/<lib>.wasm
# These artifacts are what internal/wasm/crates_test.go loads.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="wasm32-unknown-unknown"

status=0
for manifest in "$root"/policies/*/Cargo.toml; do
	crate="$(basename "$(dirname "$manifest")")"
	echo "==> building policies/$crate"
	if ! cargo build --release --target "$target" --manifest-path "$manifest"; then
		echo "FAILED: policies/$crate" >&2
		status=1
	fi
done
exit "$status"
