#!/usr/bin/env bash
# Remote state is checked again at every publication boundary, not just at
# metadata time. Protected immutable tag rules are still required (TOCTOU).
set -euo pipefail
case "${1:?use branch or tag}" in
  branch)
    : "${GITHUB_SHA:?set GITHUB_SHA}"
    git for-each-ref --format='%(refname)' --contains "$GITHUB_SHA" refs/remotes/origin/ \
      | grep -Eq '^refs/remotes/origin/(main|release-[^/]+)$'
    ;;
  tag)
    : "${GITHUB_SHA:?set GITHUB_SHA}"
    : "${GITHUB_REF:?set GITHUB_REF}"
    [[ "$GITHUB_REF" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]
    # Explicit patterns return both forms; annotated tags must be peeled to
    # their commit, while lightweight tags use the direct object ID.
    remote="$(git ls-remote origin "$GITHUB_REF" "${GITHUB_REF}^{}")"
    python3 - "$GITHUB_REF" "$GITHUB_SHA" "$remote" <<'PY'
import re
import sys

ref, expected, output = sys.argv[1:]
objects = {}
for line in output.splitlines():
    digest, name = line.split("\t")
    if name not in (ref, ref + "^{}") or name in objects or not re.fullmatch(r"[0-9a-f]{40}", digest):
        raise SystemExit("unexpected remote tag response")
    objects[name] = digest
if ref not in objects or objects.get(ref + "^{}", objects[ref]) != expected:
    raise SystemExit("remote tag missing or moved away from the tested commit")
PY
    ;;
  *) exit 1 ;;
esac
