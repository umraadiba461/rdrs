"""Threat scoring (FR-7): add up the weight of every signal that is firing."""
from __future__ import annotations

from typing import Any, Iterable


def calculate_score(signals: Iterable[str], weights: Any) -> int:
    """Sum the weights of the signals, capped at 100. Unknown signals count 0."""
    total = sum(getattr(weights, name, 0) for name in set(signals))
    return min(int(total), 100)


def classify(score: int, levels: Any) -> str:
    """Turn a score into Normal / Warning / Critical."""
    if score >= levels.critical:
        return "Critical"
    if score >= levels.warning:
        return "Warning"
    return "Normal"