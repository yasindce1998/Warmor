#!/usr/bin/env python3
"""Deterministic release archives with an internal checksum manifest."""

import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import zipfile


def package(directory: Path, epoch: int, goos: str) -> Path:
    files = sorted(p for p in directory.iterdir() if p.name != "SHA256SUMS")
    if not files or any(not p.is_file() or p.is_symlink() for p in files):
        raise ValueError("release directory must contain only regular files")
    checksums = "".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files
    )
    (directory / "SHA256SUMS").write_text(checksums, encoding="utf-8", newline="\n")
    files = sorted(directory.iterdir())
    archive = directory.with_name(directory.name + (".zip" if goos == "windows" else ".tar.gz"))
    if goos == "windows":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as out:
            for path in files:
                info = zipfile.ZipInfo(f"{directory.name}/{path.name}", (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (0o100755 if path.suffix == ".exe" else 0o100644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                out.writestr(info, path.read_bytes())
    else:
        with archive.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as out:
                for path in files:
                    data = path.read_bytes()
                    info = tarfile.TarInfo(f"{directory.name}/{path.name}")
                    info.size = len(data)
                    info.mode = 0o755 if path.name.startswith("warmor") else 0o644
                    info.mtime = epoch
                    out.addfile(info, io.BytesIO(data))
    return archive


if __name__ == "__main__":
    print(package(Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3]))
