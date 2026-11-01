"""Automatic incident response (FR-8). Copies evidence, never deletes anything."""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from app.core.logger import get_logger
from app.database.db import Database

alert_log = get_logger("alerts")
audit_log = get_logger("audit")

MAX_QUARANTINE_FILES = 200


class ResponseEngine:
    """Decides what to do for each threat level."""

    def __init__(self, db: Database, quarantine_dir: str | Path,
                 simulation_mode: bool = True, cooldown_seconds: int = 60,
                 window_seconds: int = 60) -> None:
        self.db = db
        self.quarantine_dir = Path(quarantine_dir)
        self.simulation_mode = simulation_mode
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.window = timedelta(seconds=window_seconds)
        self._last_incident: Optional[datetime] = None

    # ---- helpers --------------------------------------------------------
    def _affected_files(self, now: datetime) -> List[str]:
        """Files modified or renamed inside the detection window that still exist."""
        found: List[str] = []
        seen = set()
        for row in self.db.recent("events", 1000):
            if datetime.fromisoformat(row["timestamp"]) < now - self.window:
                continue
            if row["event_type"] not in ("modified", "moved"):
                continue
            path = row["dest_path"] or row["path"]
            if path not in seen and Path(path).exists():
                seen.add(path)
                found.append(path)
        return found

    def _quarantine(self, incident_id: int, files: Iterable[str]) -> int:
        """COPY files into data/quarantine/incident_<id>/. Originals stay untouched."""
        target = self.quarantine_dir / f"incident_{incident_id}"
        target.mkdir(parents=True, exist_ok=True)
        copied = 0
        for src in list(files)[:MAX_QUARANTINE_FILES]:
            dest = target / Path(src).name
            n = 1
            while dest.exists():                 # avoid overwriting a same-named file
                dest = target / f"{Path(src).stem}_{n}{Path(src).suffix}"
                n += 1
            try:
                shutil.copy2(src, dest)
                copied += 1
            except OSError as exc:
                audit_log.warning("Could not quarantine {}: {}", src, exc)
        return copied

    def _terminate(self, suspect: Optional[Dict[str, Any]]) -> str:
        if not suspect:
            return "no suspect process identified"
        label = f"{suspect.get('name')} (pid {suspect.get('pid')})"
        if self.simulation_mode:
            audit_log.warning("SIMULATION: would terminate {}", label)
            return f"SIMULATION: would terminate {label}"
        audit_log.warning("Live termination is not implemented in this build: {}", label)
        return f"termination not implemented: {label}"

    # ---- main entry -----------------------------------------------------
    def handle(self, score: int, level: str, signals: Iterable[str],
               stats: Dict[str, Any], suspect: Optional[Dict[str, Any]] = None,
               now: Optional[datetime] = None) -> Optional[int]:
        """Record the score and react. Returns the incident id for Critical, else None."""
        now = now or datetime.now()
        ts = now.isoformat()
        signals = sorted(set(signals))
        self.db.save_score(ts, score, level, signals)

        if level == "Normal":
            alert_log.info("Threat level Normal (score {})", score)
            return None

        message = f"{level}: score {score} | signals {signals} | {stats}"
        self.db.save_alert(ts, level, score, message)
        if level == "Warning":
            alert_log.warning(message)
            return None

        # ---- Critical ----
        alert_log.critical(message)
        if self._last_incident and now - self._last_incident < self.cooldown:
            audit_log.info("Critical alert inside cooldown: no new incident")
            return None
        self._last_incident = now

        files = self._affected_files(now)
        suspect_name = f"{suspect.get('name')} (pid {suspect.get('pid')})" if suspect else "unknown"
        incident_id = self.db.save_incident(ts, score, suspect_name, json.dumps(files), "open")
        copied = self._quarantine(incident_id, files)
        action = self._terminate(suspect)
        audit_log.warning("Incident {} opened | {} files affected, {} copied to quarantine | {}",
                          incident_id, len(files), copied, action)
        return incident_id