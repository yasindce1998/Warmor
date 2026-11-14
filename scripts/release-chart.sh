#!/usr/bin/env bash
# Stage, version, test and package without changing chart sources.
set -euo pipefail
: "${VERSION:?set VERSION without v prefix}"
: "${IMAGE_REPOSITORY:?set lowercase image repository}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || exit 1
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp -R deploy/helm/warmor "$stage/warmor"
# helm package --app-version alone does not change values.yaml image tags.
python3 - "$stage/warmor/values.yaml" "$VERSION" "$IMAGE_REPOSITORY" <<'PY'
import re
import sys
from pathlib import Path

path, version, repository = sys.argv[1:]
text = Path(path).read_text()
text, tags = re.subn(r'(?m)^(\s+)tag:.*$', lambda m: f'{m[1]}tag: "{version}"', text)
text, repos = re.subn(r'(?m)^(\s+)repository:.*$', lambda m: f'{m[1]}repository: {repository}' + ('-controller' if len(m[1]) == 4 else ''), text)
if (tags, repos) != (2, 2):
    raise SystemExit("chart image layout changed: update release-chart.sh")
Path(path).write_text(text)
PY
mkdir -p dist
helm package "$stage/warmor" --version "$VERSION" --app-version "$VERSION" --destination dist
package="dist/warmor-${VERSION}.tgz"
helm lint "$package"
helm template warmor "$package" --set controller.enabled=true > "$stage/rendered.yaml"
python3 - "$stage/rendered.yaml" "$VERSION" "$IMAGE_REPOSITORY" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
version, repository = sys.argv[2:]
images = re.findall(r'(?m)^\s+image: ["\']?([^"\'\s]+)', text)
expected = {f"{repository}:{version}", f"{repository}-controller:{version}"}
if set(images) != expected:
    raise SystemExit(f"unexpected rendered release images: {images}")
PY
