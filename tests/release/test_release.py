"""Release invariants, without network, publishing credentials or native SDKs."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
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
artifacts = load("release-artifacts")


class ArchiveTests(unittest.TestCase):
    def test_windows_packager_crlf_stdout_does_not_enter_archive_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "docs").mkdir()
            (root / "bin").mkdir()
            for name in ("release-package.py", "release-extract.py"):
                shutil.copy2(ROOT / "scripts" / name, root / "scripts" / name)
            (root / "LICENSE").write_text("license")
            (root / "docs/RELEASE_SUPPORT.md").write_text("support")
            # Simulate native Windows Python's print translation while using
            # tiny executable stubs instead of cross-compiling actual tools.
            shim = root / "bin/python3"
            shim.write_text(f'#!{sys.executable}\nimport os,subprocess,sys\n'
                            f'python={sys.executable!r}\n'
                            'if sys.argv[1].endswith("release-package.py"):\n'
                            ' r=subprocess.run([python]+sys.argv[1:],capture_output=True)\n'
                            ' sys.stdout.buffer.write(r.stdout.replace(b"\\n",b"\\r\\n"))\n'
                            ' sys.exit(r.returncode)\n'
                            'os.execv(python,[python]+sys.argv[1:])\n')
            shim.chmod(0o755)
            go = root / "bin/go"
            go.write_text(f'#!{sys.executable}\nimport pathlib,sys\n'
                          'out=pathlib.Path(sys.argv[sys.argv.index("-o")+1])\n'
                          'out.write_text("#!/usr/bin/env bash\\necho 1.2.3\\n")\n'
                          'out.chmod(0o755)\n')
            go.chmod(0o755)
            env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                       VERSION="1.2.3", GOOS="windows", GOARCH="amd64", SOURCE_DATE_EPOCH="1700000000")
            result = subprocess.run(["bash", str(ROOT / "scripts/release-build.sh")], cwd=root, env=env, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(b".zip\r\n", result.stdout)
            self.assertTrue((root / "dist/warmor-1.2.3-windows-amd64.zip").is_file())

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
                self.assertTrue((extracted / name).stat().st_mode & 0o111)
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
        for filename in ("release.yml", "binaries.yml", "release-image.yml", "macos-ci.yml"):
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
        self.assertNotIn("actions/download-artifact@", workflow)
        self.assertIn("ARTIFACT_RECEIPTS: ${{ needs.images.outputs.receipts }}", workflow)
        self.assertIn("toJSON(needs.chart.outputs)", workflow)
        self.assertIn("toJSON(needs.publish-images.outputs)", workflow)
        self.assertLess(workflow.index("python3 scripts/release-artifacts.py verified-downloads"), workflow.index("subject-path: release/*"))
        self.assertIn('bash scripts/release-check-ref.sh tag\n          helm push', workflow)
        self.assertIn('bash scripts/release-check-ref.sh tag\n          gh release create', workflow)

    def test_macos_daemon_is_explicitly_omitted(self):
        text = (ROOT / "scripts/release-build.sh").read_text()
        self.assertIn('if [[ "$GOOS" != darwin ]]; then tools+=(warmor-daemon); fi', text)
        macos = (ROOT / ".github/workflows/macos-ci.yml").read_text()
        self.assertNotIn("go test -race", macos)
        self.assertIn("**No — tools only**", (ROOT / "docs/RELEASE_SUPPORT.md").read_text())

    def test_rebuild_refuses_stale_payload_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "dist/warmor-1.2.3-darwin-arm64"
            output.mkdir(parents=True)
            (output / "warmor-daemon").write_text("old nonfunctional daemon")
            env = dict(os.environ, VERSION="1.2.3", GOOS="darwin", GOARCH="arm64")
            result = subprocess.run(["bash", str(ROOT / "scripts/release-build.sh")], cwd=root, env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"release output already exists", result.stderr)

    def test_pinned_multiplatform_base_images_and_reproducible_flags(self):
        dockerfile = (ROOT / "deploy/Dockerfile").read_text()
        for image in re.findall(r"(?m)^FROM (\S+)", dockerfile):
            if image == "rust-base":
                continue
            self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")
        self.assertIn("-trimpath -buildvcs=false", dockerfile)
        self.assertIn("CARGO_NET_OFFLINE=true", dockerfile)
        self.assertIn("GOTOOLCHAIN=local", dockerfile)


class ArtifactTransferTests(unittest.TestCase):
    @staticmethod
    def archive(path, contents):
        with zipfile.ZipFile(path, "w") as out:
            for name, data in contents.items():
                out.writestr(name, data)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_producer_id_is_used_and_digest_verified_before_extract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "payload.zip"
            digest = self.archive(archive, {"binary.tar.gz": b"tested"})
            receipts = [{"name": "binaries-linux-amd64", "id": "123", "digest": digest}]
            calls = []
            def fetch(identity, destination):
                calls.append(identity)
                shutil.copyfile(archive, destination)
            artifacts.download(receipts, root / "out", "owner/repo", fetch)
            self.assertEqual(calls, ["123"])
            self.assertEqual((root / "out/binaries-linux-amd64/binary.tar.gz").read_bytes(), b"tested")

    def test_replaced_payload_and_self_consistent_checksums_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "payload.zip"
            expected = self.archive(archive, {"image.tar": b"tested", "IMAGE_SHA256SUMS": b"old checksums"})
            # An attacker updates the payload AND all self-reported metadata.
            changed = b"replaced"
            self.archive(archive, {"image.tar": changed, "IMAGE_SHA256SUMS": hashlib.sha256(changed).hexdigest().encode()})
            receipts = [{"name": "image-daemon-amd64", "id": "123", "digest": expected}]
            with self.assertRaisesRegex(ValueError, "differs from producer"):
                artifacts.download(receipts, root / "out", "owner/repo", lambda identity, dest: shutil.copyfile(archive, dest))
            self.assertFalse((root / "out").exists())

    def test_missing_duplicate_and_malformed_receipts_rejected(self):
        good = {"name": "chart", "id": "123", "digest": "a" * 64}
        for receipts in ([], [good, good], [dict(good, id="")], [dict(good, digest="")], [dict(good, digest="sha256:bad")]):
            with self.subTest(receipts=receipts), self.assertRaises(ValueError):
                artifacts.validate_receipts(receipts)

    def test_partial_transfer_does_not_publish_any_verified_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "payload.zip"
            digest = self.archive(archive, {"chart.tgz": b"tested"})
            receipts = [{"name": "first", "id": "123", "digest": digest},
                        {"name": "second", "id": "456", "digest": "0" * 64}]
            with self.assertRaises(ValueError):
                artifacts.download(receipts, root / "out", "owner/repo", lambda identity, dest: shutil.copyfile(archive, dest))
            self.assertFalse((root / "out").exists())

    def test_even_correctly_hashed_zip_cannot_escape_verified_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "payload.zip"
            digest = self.archive(archive, {"../escape": b"bad"})
            with self.assertRaises(ValueError):
                artifacts.verify_and_extract(archive, digest, root / "out")
            self.assertFalse((root / "out").exists())
            self.assertFalse((root / "escape").exists())

    def test_collector_requires_successful_direct_producer_outputs(self):
        good = {"name": "chart", "id": "123", "digest": "a" * 64}
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            for result in ("failure", "skipped", "success"):
                env = dict(os.environ, GITHUB_OUTPUT=str(output), PRODUCERS=json.dumps({"chart": {"result": result, "outputs": good}}))
                run = subprocess.run([sys.executable, str(ROOT / "scripts/release-receipts.py")], env=env, capture_output=True)
                if result != "success":
                    self.assertNotEqual(run.returncode, 0)
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(run.returncode, 0, run.stderr.decode())
                    self.assertEqual(json.loads(output.read_text().removeprefix("receipts=")), [good])


class RefTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "release-test@example.invalid")
        self.git("config", "user.name", "Release test")
        self.git("commit", "--allow-empty", "-qm", "tested")
        self.sha = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True, stderr=subprocess.DEVNULL)

    def check(self, mode):
        env = dict(os.environ, GITHUB_SHA=self.sha, GITHUB_REF="refs/tags/v1.2.3")
        return subprocess.run(["bash", str(ROOT / "scripts/release-check-ref.sh"), mode], cwd=self.root, env=env, capture_output=True)

    def test_branch_full_ref_match_rejects_embedded_origin_main(self):
        for ref in ("refs/remotes/origin/feature/origin/main", "refs/remotes/origin/feature/origin/release-1", "refs/remotes/other/main"):
            self.git("update-ref", ref, self.sha)
        self.assertNotEqual(self.check("branch").returncode, 0)
        self.git("update-ref", "refs/remotes/origin/main", self.sha)
        self.assertEqual(self.check("branch").returncode, 0)
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        self.git("update-ref", "refs/remotes/origin/release-1", self.sha)
        self.assertEqual(self.check("branch").returncode, 0)

    def test_lightweight_and_annotated_remote_tag_move_or_delete_rejected(self):
        remote = self.root / "remote.git"
        self.git("init", "--bare", "-q", str(remote))
        self.git("remote", "add", "origin", str(remote))
        for annotated in (False, True):
            with self.subTest(annotated=annotated):
                self.git("tag", "-f", *( ["-a", "-m", "release"] if annotated else []), "v1.2.3", self.sha)
                self.git("push", "-qf", "origin", "refs/tags/v1.2.3")
                self.assertEqual(self.check("tag").returncode, 0)
                self.git("commit", "--allow-empty", "-qm", "different")
                self.git("tag", "-f", *( ["-a", "-m", "moved"] if annotated else []), "v1.2.3")
                self.git("push", "-qf", "origin", "refs/tags/v1.2.3")
                self.assertNotEqual(self.check("tag").returncode, 0)
                self.git("push", "-q", "origin", ":refs/tags/v1.2.3")
                self.assertNotEqual(self.check("tag").returncode, 0)


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
