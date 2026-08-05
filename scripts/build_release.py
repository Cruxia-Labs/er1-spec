#!/usr/bin/env python3
"""Build the PyPI distributions and scrub the sdist's tar headers.

`python -m build` writes the builder's OS account into every sdist tar member (uname/gname and
uid/gid) — invisible to any content audit, permanent on PyPI, and a cross-package fingerprint of
whoever built the release. The pre-publish audit found it in the headers of an sdist whose
unpacked CONTENTS were clean, which is exactly why this is a script and not a checklist item.

    python scripts/build_release.py            # build into dist/, scrub, verify
    python scripts/build_release.py <pkg_dir>  # same, for another package directory

The scrub rewrites every member to uid=0 gid=0 uname='' gname='' and re-gzips with mtime=0 so the
gzip header carries no build timestamp either. It then VERIFIES the result — a scrub that silently
failed to apply would be indistinguishable from one that worked.
"""
from __future__ import annotations

import glob
import gzip
import io
import subprocess
import sys
import tarfile
from pathlib import Path


def scrub_sdist(path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(path, "r:gz") as tin, tarfile.open(fileobj=buf, mode="w") as tout:
        for m in tin.getmembers():
            m.uid = m.gid = 0
            m.uname = m.gname = ""
            tout.addfile(m, tin.extractfile(m) if m.isreg() else None)
    with open(path, "wb") as f:
        with gzip.GzipFile(fileobj=f, mode="wb", mtime=0) as gz:
            gz.write(buf.getvalue())


def verify_clean(path: Path) -> None:
    with tarfile.open(path, "r:gz") as t:
        dirty = [m.name for m in t.getmembers()
                 if m.uid or m.gid or m.uname or m.gname]
    if dirty:
        raise SystemExit(f"SCRUB FAILED — members still carry ownership: {dirty[:3]}")


def main() -> int:
    pkg = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    subprocess.run([sys.executable, "-m", "build", "--outdir", "dist", "."], cwd=pkg, check=True)
    sdists = [Path(p) for p in glob.glob(str(pkg / "dist" / "*.tar.gz"))]
    if not sdists:
        raise SystemExit("no sdist produced")
    for s in sdists:
        scrub_sdist(s)
        verify_clean(s)
        print(f"scrubbed + verified: {s.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
