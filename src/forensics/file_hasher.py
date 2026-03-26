"""SHA-256 file hashing for forensic integrity."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from src.core.exceptions import ForensicError

logger = logging.getLogger(__name__)

HASH_BUFFER_SIZE = 65536  # 64KB read chunks


def compute_sha256(file_path: str | Path) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        file_path: Path to the file to hash.

    Returns:
        Hexadecimal SHA-256 hash string.

    Raises:
        ForensicError: If the file cannot be read.
        ValueError: If file_path is empty.
    """
    if not file_path:
        raise ValueError("file_path must not be empty")

    path = Path(file_path)
    if not path.is_file():
        raise ForensicError(f"File not found: {path}")

    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                data = fh.read(HASH_BUFFER_SIZE)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()
    except OSError as exc:
        raise ForensicError(f"Failed to hash file {path}: {exc}") from exc


def compute_sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of raw bytes.

    Args:
        data: Bytes to hash.

    Returns:
        Hexadecimal SHA-256 hash string.
    """
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes, got {type(data).__name__}")
    return hashlib.sha256(data).hexdigest()
