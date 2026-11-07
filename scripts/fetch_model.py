"""Download and verify the injection-classifier weights (used by the Docker build).

    python scripts/fetch_model.py <url> <sha256> <dest-dir>

Downloads a .tar.gz, refuses it unless its SHA-256 matches, and extracts it into <dest-dir> with the
tarfile "data" filter (no absolute paths, links outside the target or device files).
"""

from __future__ import annotations

import hashlib
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path


def main(url: str, sha256: str, dest: Path) -> None:
    if not url.startswith("https://"):
        raise SystemExit("model URL must be https")
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "model.tar.gz"
        with urllib.request.urlopen(url, timeout=120) as resp, archive.open("wb") as out:  # noqa: S310 (https checked)
            while chunk := resp.read(1 << 20):
                out.write(chunk)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != sha256.lower():
            raise SystemExit(f"model checksum mismatch: expected {sha256}, got {digest}")
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive) as tar:
            tar.extractall(dest, filter="data")
    print(f"model {digest[:12]} extracted to {dest}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2], Path(sys.argv[3]))
