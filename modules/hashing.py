"""Evidence hashing with SHA-256 and SHA-3-256."""

import hashlib
from pathlib import Path

HASH_ALGORITHMS = ("sha256", "sha3_256")
CHUNK_SIZE = 65536


def hash_file(path):
    """Return SHA-256 and SHA-3-256 digests for a file."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    digests = {alg: hashlib.new(alg) for alg in HASH_ALGORITHMS}
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            for digest in digests.values():
                digest.update(chunk)

    stat = path.stat()
    return {
        "path": str(path),
        "name": path.name,
        "size": stat.st_size,
        "sha256": digests["sha256"].hexdigest(),
        "sha3_256": digests["sha3_256"].hexdigest(),
    }
