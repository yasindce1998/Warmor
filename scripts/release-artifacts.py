#!/usr/bin/env python3
"""Fail-closed transfer of uploaded artifacts using independent job receipts.

ARTIFACT_RECEIPTS is JSON passed through producer job outputs, NOT downloaded
alongside the payload. Each entry contains name/id/digest from upload-artifact.
We fetch by immutable ID and verify the ZIP hash before inspecting/extracting it.
"""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile


def validate_receipts(receipts):
    if not isinstance(receipts, list) or not receipts:
        raise ValueError("missing producer artifact receipts")
    names, ids = set(), set()
    for receipt in receipts:
        name, identity, digest = (receipt[key] for key in ("name", "id", "digest"))
        if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
            raise ValueError("invalid artifact name")
        if not re.fullmatch(r"[1-9][0-9]*", str(identity)):
            raise ValueError("missing/invalid producer artifact ID")
        if not isinstance(digest, str) or not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", digest):
            raise ValueError("missing/invalid producer artifact SHA-256")
        if name in names or str(identity) in ids:
            raise ValueError("duplicate artifact receipt")
        names.add(name)
        ids.add(str(identity))


def verify_and_extract(archive, expected_digest, destination):
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != expected_digest.removeprefix("sha256:"):
        raise ValueError("artifact ZIP digest differs from producer job output")
    with zipfile.ZipFile(archive) as stream:
        seen = set()
        members = stream.infolist()
        if not members:
            raise ValueError("empty artifact")
        # Validate every member before writing any of them. Release uploads
        # are deliberately flat; no links, directories or hidden files needed.
        for member in members:
            path = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if (len(path.parts) != 1 or path.name in (".", "..") or path.name.startswith(".")
                    or "\\" in member.filename or path.is_absolute() or member.is_dir()
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or path.name in seen):
                raise ValueError(f"unsafe/duplicate artifact member: {member.filename}")
            seen.add(path.name)
        destination.mkdir()
        for member in members:
            (destination / member.filename).write_bytes(stream.read(member))


def download(receipts, destination, repository, fetch=None):
    validate_receipts(receipts)
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+", repository):
        raise ValueError("invalid GitHub repository")
    if destination.exists():
        raise ValueError("artifact destination already exists")

    def fetch_from_github(identity, archive):
        # gh follows GitHub's signed archive redirect without forwarding the
        # API token to an arbitrary download host. Never resolve by name/latest.
        with archive.open("wb") as out:
            subprocess.run(["gh", "api", f"repos/{repository}/actions/artifacts/{identity}/zip"], stdout=out, check=True)

    fetch = fetch or fetch_from_github
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as tmp:
        stage = Path(tmp)
        verified = stage / "verified"
        verified.mkdir()
        for receipt in receipts:
            archive = stage / (receipt["name"] + ".zip")
            fetch(str(receipt["id"]), archive)
            verify_and_extract(archive, receipt["digest"], verified / receipt["name"])
        # No partial result reaches a publisher if any receipt or digest fails.
        shutil.move(str(verified), destination)


if __name__ == "__main__":
    download(json.loads(os.environ["ARTIFACT_RECEIPTS"]), Path(sys.argv[1]), os.environ["GITHUB_REPOSITORY"])
