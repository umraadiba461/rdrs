"""Sliding-window ransomware behaviour detection (FR-6)."""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Deque, Dict, Optional, Set

from app.core.models import FileEvent

if TYPE_CHECKING:  # only needed for type hints
    from app.core.config import DetectionConfig

MIN_ENTROPY_SAMPLES = 5   # need at least this many files before judging entropy


class DetectionEngine:
    """Keeps the last `window_seconds` of events and reports suspicious signals."""

    def __init__(self, cfg: "DetectionConfig") -> None:
        self.cfg = cfg
        self._events: Deque[FileEvent] = deque()
        self._lock = threading.Lock()

    # ---- feeding events -------------------------------------------------
    def add_event(self, ev: FileEvent) -> None:
        with self._lock:
            self._events.append(ev)
            self._prune(ev.timestamp)

    def _prune(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.cfg.window_seconds)
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()

    # ---- measuring ------------------------------------------------------
    def stats(self, now: Optional[datetime] = None) -> Dict[str, float]:
        """Counters for the current window."""
        with self._lock:
            self._prune(now or datetime.now())
            events = list(self._events)

        # Count DISTINCT files: Windows reports several 'modified' events per write
        modified_files = {e.path for e in events if e.event_type == "modified"}
        moves = [e for e in events if e.event_type == "moved"]
        ext_changes = [e for e in moves if Path(e.path).suffix.lower() != e.extension]

        # Latest entropy per file, for modified or renamed files only
        latest: Dict[str, float] = {}
        for e in events:
            if e.event_type in ("modified", "moved") and e.entropy is not None:
                latest[e.dest_path or e.path] = e.entropy
        avg = sum(latest.values()) / len(latest) if latest else 0.0

        return {
            "files_modified": len(modified_files),
            "renames": len(moves),
            "extension_changes": len(ext_changes),
            "entropy_samples": len(latest),
            "avg_entropy": round(avg, 2),
        }

    # ---- deciding -------------------------------------------------------
    def signals(self, now: Optional[datetime] = None) -> Set[str]:
        """Names of the signals that are currently firing."""
        s = self.stats(now)
        fired: Set[str] = set()
        if s["files_modified"] >= self.cfg.files_modified_per_minute:
            fired.add("rapid_encryption")
        if (s["renames"] >= self.cfg.renames_threshold
                or s["extension_changes"] >= self.cfg.extension_changes_threshold):
            fired.add("mass_rename")
        if (s["entropy_samples"] >= MIN_ENTROPY_SAMPLES
                and s["avg_entropy"] >= self.cfg.avg_entropy_threshold):
            fired.add("high_entropy")
        return fired