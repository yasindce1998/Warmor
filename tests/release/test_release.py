"""Release invariants, without network, publishing credentials or native SDKs."""

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


packager = load("release-package")
extractor = load("release-extract")


class ArchiveTests(unittest.TestCase):
    def test_reproducible_archives_checksums_and_extraction(self):
        for goos in ("linux", "darwin", "windows"):
            with self.subTest(goos=goos), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                payload = root / f"warmor-1.2.3-{goos}-amd64"
                payload.mkdir()
                name = "warmor-compile.exe" if goos == "windows" else "warmor-compile"
                (payload / name).write_bytes(b"binary\x00contents")
                (payload / "LICENSE").write_text("license\n")
                archive = packager.package(payload, 1700000000, goos)
                first = archive.read_bytes()
                os.utime(payload / name, (1800000000, 1800000000))
                packager.package(payload, 1700000000, goos)
                self.assertEqual(first, archive.read_bytes())
                extractor.extract(root, root / "extracted")
                extracted = root / "extracted" / payload.name
                self.assertEqual((extracted / name).read_bytes(), b"binary\x00contents")
                for line in (extracted / "SHA256SUMS").read_text().splitlines():
                    checksum, filename = line.split("  ", 1)
                    self.assertEqual(checksum, hashlib.sha256((extracted / filename).read_bytes()).hexdigest())

    def test_archive_rejects_symlink_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "link").symlink_to("missing")
            with self.assertRaises(ValueError):
                packager.package(root, 1700000000, "linux")

    def test_extraction_rejects_tar_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with tarfile.open(root / "bad.tar.gz", "w:gz") as out:
                info = tarfile.TarInfo("../escape")
                info.size = 3
                out.addfile(info, io.BytesIO(b"bad"))
            with self.assertRaises(ValueError):
                extractor.extract(root, root / "out")
            self.assertFalse((root / "escape").exists())

    def test_extraction_rejects_zip_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with zipfile.ZipFile(root / "bad.zip", "w") as out:
                info = zipfile.ZipInfo("link")
                info.create_system = 3
                info.external_attr = 0o120777 << 16
                out.writestr(info, "../../elsewhere")
            with self.assertRaises(ValueError):
                extractor.extract(root, root / "out")


class WorkflowTests(unittest.TestCase):
    def test_all_owned_external_actions_are_immutable(self):
        for filename in ("release.yml", "binaries.yml", "macos-ci.yml"):
            text = (ROOT / ".github/workflows" / filename).read_text()
            for action in re.findall(r"(?m)^\s+(?:- )?uses: (\S+)", text):
                if action.startswith("./"):
                    continue
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_only_one_publisher_and_all_gates_required(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        binaries = (ROOT / ".github/workflows/binaries.yml").read_text()
        self.assertNotIn("push:", binaries)
        self.assertNotIn("contents: write", binaries)
        self.assertIn("needs: [metadata, tests, binaries, chart, images]", workflow)
        self.assertIn("needs: [metadata, tests, binaries, chart, images, publish-images]", workflow)
        self.assertNotIn("value=latest", workflow)
        self.assertNotIn("branches:", workflow)
        self.assertIn("--source-digest", workflow)
        self.assertIn("--signer-workflow", workflow)
        self.assertIn("--source-ref", workflow)
        self.assertNotIn("pull_request_target", workflow)

    def test_macos_daemon_is_explicitly_omitted(self):
        text = (ROOT / "scripts/release-build.sh").read_text()
        self.assertIn('if [[ "$GOOS" != darwin ]]; then tools+=(warmor-daemon); fi', text)
        macos = (ROOT / ".github/workflows/macos-ci.yml").read_text()
        self.assertNotIn("go test -race", macos)
        self.assertIn("**No — tools only**", (ROOT / "docs/RELEASE_SUPPORT.md").read_text())

    def test_pinned_multiplatform_base_images_and_reproducible_flags(self):
        dockerfile = (ROOT / "deploy/Dockerfile").read_text()
        for image in re.findall(r"(?m)^FROM (\S+)", dockerfile):
            if image == "rust-base":
                continue
            self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")
        self.assertIn("-trimpath -buildvcs=false", dockerfile)
        self.assertIn("CARGO_NET_OFFLINE=true", dockerfile)


@unittest.skipUnless(shutil.which("helm"), "helm required for packaged chart regression")
class ChartTests(unittest.TestCase):
    def test_packaged_chart_uses_release_version_not_source_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "deploy/helm").mkdir(parents=True)
            shutil.copytree(ROOT / "deploy/helm/warmor", root / "deploy/helm/warmor")
            source = (root / "deploy/helm/warmor/values.yaml").read_bytes()
            env = dict(os.environ, VERSION="9.8.7-rc.1", IMAGE_REPOSITORY="ghcr.io/example/warmor")
            subprocess.run(["bash", str(ROOT / "scripts/release-chart.sh")], cwd=root, env=env, check=True, capture_output=True)
            archive = root / "dist/warmor-9.8.7-rc.1.tgz"
            with tarfile.open(archive) as stream:
                chart = stream.extractfile("warmor/Chart.yaml").read().decode()
                values = stream.extractfile("warmor/values.yaml").read().decode()
            self.assertRegex(chart, r"(?m)^version: 9\.8\.7-rc\.1$")
            self.assertIn("appVersion: 9.8.7-rc.1", chart)
            self.assertEqual(values.count('tag: "9.8.7-rc.1"'), 2)
            self.assertNotIn('tag: "latest"', values)
            self.assertEqual(source, (root / "deploy/helm/warmor/values.yaml").read_bytes())


if __name__ == "__main__":
    unittest.main()
