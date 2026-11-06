"""The detection pipeline: one file event in, threat score and response out."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from app.core.entropy import file_entropy
from app.core.models import FileEvent
from app.database.db import Database
from app.detectors.detection_engine import DetectionEngine
from app.detectors.response import ResponseEngine
from app.detectors.scoring import calculate_score, classify

CPU_SPIKE_PERCENT = 80.0


class Pipeline:
    """Connects entropy, storage, detection, scoring and response."""

    def __init__(self, settings: Any, db: Database, engine: DetectionEngine,
                 responder: ResponseEngine) -> None:
        self.settings = settings
        self.db = db
        self.engine = engine
        self.responder = responder
        self.signals: Set[str] = set()
        self.processes: List[Dict[str, Any]] = []
        self.score = 0
        self.level = "Normal"

    def on_processes(self, timestamp: str, rows: List[Dict[str, Any]]) -> None:
        """Called with every process snapshot."""
        self.db.save_processes(timestamp, rows)
        # pid 0 is Windows' "System Idle Process": high CPU there means the PC is idle
        self.processes = [r for r in rows if r["pid"] != 0]

    def process(self, ev: FileEvent) -> Optional[int]:
        """Handle one file event. Returns an incident id if a new incident was opened."""
        size = self.settings.entropy.sample_bytes
        if ev.event_type in ("created", "modified"):
            ev.entropy = file_entropy(ev.path, size)
        elif ev.event_type == "moved" and ev.dest_path:
            ev.entropy = file_entropy(ev.dest_path, size)
        self.db.save_event(ev)

        self.engine.add_event(ev)
        signals = set(self.engine.signals())
        if any(p["cpu"] >= CPU_SPIKE_PERCENT for p in self.processes):
            signals.add("cpu_spike")

        incident_id = None
        if signals != self.signals:          # only react when something changes
            self.signals = signals
            self.score = calculate_score(signals, self.settings.weights)
            self.level = classify(self.score, self.settings.levels)
            suspect = self.processes[0] if self.processes else None   # busiest process
            incident_id = self.responder.handle(self.score, self.level, signals,
                                                self.engine.stats(), suspect)
        return incident_id