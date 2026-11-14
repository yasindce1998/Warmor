#!/usr/bin/env bash
# Compatibility entry point. Enforcement is deliberately restricted to a VM.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/integration/run-outcomes.sh" "$@"
