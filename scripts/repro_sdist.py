#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rewrite an sdist (.tar.gz) so that two builds of the same commit give the same bytes (15/11/2026).

setuptools writes the files' modification times into the tar and the build time into the gzip header, so two builds
with the same SOURCE_DATE_EPOCH differed. This keeps every member's name, content, type and executable bit, and sets:
member order sorted by name, mtime = SOURCE_DATE_EPOCH (required), uid/gid 0, empty owner names, mode 0644 or 0755
(directories and executables), PAX format, gzip header mtime 0 and no file name. The content is checked unchanged.
Usage: SOURCE_DATE_EPOCH=<seconds> python3 scripts/repro_sdist.py dist/<name>.tar.gz
"""
import gzip
import hashlib
import io
import os
import sys
import tarfile


def rewrite(path: str, epoch: int) -> None:
    with tarfile.open(path, "r:gz") as src:
        members = [(m, src.extractfile(m).read() if m.isfile() else None) for m in src.getmembers()]
    for m, _ in members:
        if not (m.isfile() or m.isdir()):
            raise ValueError(f"{m.name}: only regular files and directories are expected in an sdist")
    before = {m.name: hashlib.sha256(d).hexdigest() for m, d in members if d is not None}
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as dst:
        for m, data in sorted(members, key=lambda x: x[0].name):
            m.mtime, m.uid, m.gid, m.uname, m.gname = epoch, 0, 0, "", ""
            m.mode = 0o755 if (m.isdir() or m.mode & 0o111) else 0o644
            m.pax_headers = {}
            dst.addfile(m, io.BytesIO(data) if data is not None else None)
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    with tarfile.open(fileobj=io.BytesIO(out.getvalue()), mode="r:gz") as chk:
        after = {m.name: hashlib.sha256(chk.extractfile(m).read()).hexdigest() for m in chk.getmembers() if m.isfile()}
    if after != before:
        raise RuntimeError("the rewritten sdist does not hold the same files")
    with open(path + ".tmp", "wb") as f:
        f.write(out.getvalue())
    os.replace(path + ".tmp", path)


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].endswith(".tar.gz"):
        print("usage: SOURCE_DATE_EPOCH=<seconds> repro_sdist.py <sdist.tar.gz>", file=sys.stderr)
        return 2
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    if not epoch.isdigit():
        print("SOURCE_DATE_EPOCH must be set to an integer number of seconds", file=sys.stderr)
        return 2
    rewrite(sys.argv[1], int(epoch))
    return 0


if __name__ == "__main__":
    sys.exit(main())
