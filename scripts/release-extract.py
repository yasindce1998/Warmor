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
                    out = destination(root, member.name)
                    out.write_bytes(stream.extractfile(member).read())
                    out.chmod(member.mode & 0o777)
        elif archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as stream:
                for member in stream.infolist():
                    if member.is_dir() or (member.external_attr >> 16) & 0o170000 != 0o100000:
                        raise ValueError(f"non-regular release member: {member.filename}")
                    out = destination(root, member.filename)
                    out.write_bytes(stream.read(member))
                    out.chmod((member.external_attr >> 16) & 0o777)


if __name__ == "__main__":
    extract(Path(sys.argv[1]), Path(sys.argv[2]))
