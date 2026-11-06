"""Incident reports (FR-11): a JSON report and a CSV list of affected files.

Run for the newest incident:   python -m app.reports.generator
Run for a specific incident:   python -m app.reports.generator --incident 2
"""
from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.database.db import Database

REPORTS_DIR = "data/reports"
MAX_TIMELINE = 200


def build_recommendations(signals: List[str], suspect: str) -> List[str]:
    """Plain-language next steps, chosen from the signals that fired."""
    tips = [
        "Disconnect the affected computer from the network (unplug the cable / turn off Wi-Fi) "
        "so the activity cannot spread.",
        "Do NOT pay any ransom. Report the incident to your security team.",
        "Keep the quarantine copies for evidence; they are copies, the originals were not changed.",
    ]
    if "rapid_encryption" in signals or "high_entropy" in signals:
        tips.append("Files were rewritten with random-looking data. Restore them from a clean, "
                    "offline backup after the cause is removed.")
    if "mass_rename" in signals:
        tips.append("Many files changed extension. Look for a new extension (such as .locked) "
                    "and for a ransom note in the affected folders.")
    if "cpu_spike" in signals:
        tips.append("A process used unusually high CPU. Check it in Task Manager.")
    if suspect and suspect != "unknown":
        tips.append(f"Investigate the suspect process: {suspect}. Confirm it is really the "
                    "source before stopping it (it is the busiest process, which is a good "
                    "hint but not proof).")
    return tips


def build_report(db: Database, incident_id: int, quarantine_dir: str | Path,
                 window_seconds: int = 60, simulation_mode: bool = True) -> Dict[str, Any]:
    """Collect everything about one incident into a dictionary."""
    incident = next((r for r in db.recent("incidents", 1000) if r["id"] == incident_id), None)
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    detected = datetime.fromisoformat(incident["timestamp"])
    files: List[str] = json.loads(incident["affected_files"] or "[]")

    # The score row was saved with the same timestamp as the incident
    signals: List[str] = []
    for row in db.recent("scores", 1000):
        if row["timestamp"] == incident["timestamp"]:
            signals = [s for s in (row["signals"] or "").split(",") if s]
            break

    events = list(reversed(db.recent("events", 5000)))          # oldest first
    start = detected - timedelta(seconds=window_seconds)
    timeline = [
        {"time": e["timestamp"], "event": e["event_type"],
         "file": e["dest_path"] or e["path"], "entropy": e["entropy"]}
        for e in events
        if start <= datetime.fromisoformat(e["timestamp"]) <= detected
    ][:MAX_TIMELINE]

    latest_entropy: Dict[str, float] = {}
    for e in events:                                            # later events overwrite earlier
        if e["entropy"] is not None:
            latest_entropy[e["dest_path"] or e["path"]] = e["entropy"]

    quarantine_folder = Path(quarantine_dir) / f"incident_{incident_id}"
    affected = []
    for f in files:
        ent = latest_entropy.get(f)
        affected.append({
            "file": f,
            "entropy": round(ent, 2) if ent is not None else None,
            "quarantined": (quarantine_folder / Path(f).name).exists(),
        })

    return {
        "incident_id": incident_id,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "detected_at": incident["timestamp"],
        "threat_score": incident["score"],
        "status": incident["status"],
        "simulation_mode": simulation_mode,
        "signals": signals,
        "suspect_process": incident["suspect_process"],
        "affected_file_count": len(affected),
        "quarantine_folder": str(quarantine_folder),
        "affected_files": affected,
        "timeline": timeline,
        "recommendations": build_recommendations(signals, incident["suspect_process"]),
    }


def write_report(report: Dict[str, Any], reports_dir: str | Path = REPORTS_DIR) -> Tuple[Path, Path]:
    """Save the report as JSON and the affected files as CSV. Returns both paths."""
    folder = Path(reports_dir)
    folder.mkdir(parents=True, exist_ok=True)
    stem = f"incident_{report['incident_id']}_report"

    json_path = folder / f"{stem}.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    csv_path = folder / f"{stem}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["file", "entropy", "quarantined"])
        writer.writeheader()
        writer.writerows(report["affected_files"])
    return json_path, csv_path


def main() -> None:
    from app.core.config import load_config      # imported here so tests need no extra libraries

    parser = argparse.ArgumentParser(description="Create an RDRS incident report")
    parser.add_argument("--incident", type=int, help="Incident id (default: the newest)")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--out", default=REPORTS_DIR, help="Folder for the report files")
    args = parser.parse_args()

    settings = load_config(args.config)
    db = Database(settings.database_path)
    incident_id = args.incident
    if incident_id is None:
        newest = db.recent("incidents", 1)
        if not newest:
            print("No incidents in the database yet.")
            return
        incident_id = newest[0]["id"]

    report = build_report(db, incident_id, settings.quarantine_dir,
                          settings.detection.window_seconds, settings.simulation_mode)
    json_path, csv_path = write_report(report, args.out)
    print(f"Report for incident {incident_id} saved:")
    print(f"  {json_path}")
    print(f"  {csv_path}")
    db.close()


if __name__ == "__main__":
    main()