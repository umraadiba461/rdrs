"""Shannon entropy helpers (FR-3)."""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of data: 0.0 (predictable) to 8.0 (random)."""
    if not data:
        return 0.0
    total = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def file_entropy(path: str | Path, sample_bytes: int = 65536) -> float:
    """Entropy of the first `sample_bytes` of a file. Returns 0.0 if unreadable."""
    try:
        with open(path, "rb") as fh:
            return shannon_entropy(fh.read(sample_bytes))
    except (OSError, PermissionError):
        return 0.0
