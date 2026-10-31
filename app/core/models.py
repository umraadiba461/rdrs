"""Shared data models for RDRS."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class FileEvent:
    """One file-system change, in RDRS's own format (FR-2)."""

    event_type: str            # created / modified / moved / deleted
    path: str                  # file path (the old path for a rename)
    timestamp: datetime
    extension: str             # extension of the file AFTER the event, e.g. ".locked"
    dest_path: Optional[str] = None   # new path, only for renames
    entropy: Optional[float] = None   # filled in during Phase 3