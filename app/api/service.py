"""Logic behind the REST API. Plain functions, so they are easy to test."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml

from app.core.entropy import file_entropy
from app.database.db import Database

MAX_SCAN_FILES = 500

# Settings the API is allowed to change: name -> (type, minimum value)
EDITABLE_DETECTION = {
    "window_seconds": (int, 1),
    "files_modified_per_minute": (int, 1),
    "renames_threshold": (int, 1),
    "extension_changes_threshold": (int, 1),
    "avg_entropy_threshold": (float, 0.0),
}


def get_status(db: Database, simulation_mode: bool) -> Dict[str, Any]:
    """Current threat level plus a few counters."""
    latest = db.recent("scores", 1)
    score = latest[0] if latest else {"score": 0, "level": "Normal", "signals": "", "timestamp": None}
    return {
        "level": score["level"],
        "score": score["score"],
        "signals": [s for s in (score["signals"] or "").split(",") if s],
        "last_update": score["timestamp"],
        "simulation_mode": simulation_mode,
        "totals": {t: db.count(t) for t in ("events", "alerts", "incidents")},
    }


def get_recent(db: Database, table: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Newest rows of events / alerts / incidents / scores / processes."""
    limit = max(1, min(int(limit), 500))
    return db.recent(table, limit)


def list_reports(reports_dir: str | Path) -> List[str]:
    folder = Path(reports_dir)
    if not folder.exists():
        return []
    return sorted(p.name for p in folder.iterdir() if p.is_file())


def run_scan(settings: Any) -> Dict[str, Any]:
    """One-time check: how many files in the watched folders look encrypted?"""
    scanned = 0
    suspicious: List[Dict[str, Any]] = []
    for folder in settings.watch_folders:
        base = Path(folder)
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if scanned >= MAX_SCAN_FILES:
                break
            if not path.is_file():
                continue
            scanned += 1
            ent = file_entropy(path, settings.entropy.sample_bytes)
            if ent >= settings.entropy.high_threshold:
                suspicious.append({"path": str(path), "entropy": round(ent, 2)})
    return {"files_scanned": scanned, "suspicious_count": len(suspicious), "suspicious": suspicious[:100]}


def validate_detection_update(updates: Dict[str, Any]) -> Dict[str, Any]:
    """Check new threshold values. Raises ValueError for anything not allowed."""
    clean: Dict[str, Any] = {}
    for key, value in updates.items():
        if value is None:
            continue
        if key not in EDITABLE_DETECTION:
            raise ValueError(f"'{key}' cannot be changed")
        kind, minimum = EDITABLE_DETECTION[key]
        try:
            value = kind(value)
        except (TypeError, ValueError):
            raise ValueError(f"'{key}' must be a {kind.__name__}")
        if value < minimum:
            raise ValueError(f"'{key}' must be at least {minimum}")
        clean[key] = value
    if not clean:
        raise ValueError("No settings given")
    return clean


def update_detection_settings(config_path: str | Path, updates: Dict[str, Any]) -> Dict[str, Any]:
    """Save new detection thresholds to config.yaml (takes effect on next start)."""
    clean = validate_detection_update(updates)
    path = Path(config_path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    data.setdefault("detection", {}).update(clean)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return data["detection"]