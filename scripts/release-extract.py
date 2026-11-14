#!/usr/bin/env python3
"""Extract only regular files from our release archives for binary SBOM scans."""

from pathlib import Path, PurePosixPath
import sys
import tarfile
import zipfile


def destination(root: Path, name: str) -> Path:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError(f"unsafe archive path: {name}")
    out = root.joinpath(*path.parts)
    out.parent.mkdir(parents=True, exist_ok=True)
    return out


def extract(source: Path, root: Path) -> None:
    for archive in sorted(source.iterdir()):
        if archive.name.endswith(".tar.gz"):
            with tarfile.open(archive) as stream:
                for member in stream:
                    if not member.isfile():
                        raise ValueError(f"non-regular release member: {member.name}")
                    destination(root, member.name).write_bytes(stream.extractfile(member).read())
        elif archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as stream:
                for member in stream.infolist():
                    if member.is_dir() or (member.external_attr >> 16) & 0o170000 != 0o100000:
                        raise ValueError(f"non-regular release member: {member.filename}")
                    destination(root, member.filename).write_bytes(stream.read(member))


if __name__ == "__main__":
    extract(Path(sys.argv[1]), Path(sys.argv[2]))
