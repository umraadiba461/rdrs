import csv
import json
from datetime import datetime

import pytest

from app.core.models import FileEvent
from app.database.db import Database
from app.reports.generator import build_recommendations, build_report, write_report


def make_incident(tmp_path):
    db = Database(tmp_path / "t.db")
    quarantine = tmp_path / "quarantine"
    f1, f2 = str(tmp_path / "a.locked"), str(tmp_path / "b.locked")
    now = datetime.now()
    db.save_event(FileEvent("modified", f1, now, ".locked", None, 7.99))
    db.save_event(FileEvent("moved", str(tmp_path / "b.bin"), now, ".locked", f2, 7.95))
    ts = now.isoformat()
    db.save_score(ts, 95, "Critical", ["rapid_encryption", "mass_rename"])
    incident_id = db.save_incident(ts, 95, "evil.exe (pid 7)", json.dumps([f1, f2]), "open")
    (quarantine / f"incident_{incident_id}").mkdir(parents=True)
    (quarantine / f"incident_{incident_id}" / "a.locked").write_bytes(b"x")   # only a.locked was copied
    return db, quarantine, incident_id


def test_report_contents(tmp_path):
    db, quarantine, iid = make_incident(tmp_path)
    r = build_report(db, iid, quarantine)
    assert r["suspect_process"] == "evil.exe (pid 7)"
    assert r["threat_score"] == 95
    assert set(r["signals"]) == {"rapid_encryption", "mass_rename"}
    assert r["affected_file_count"] == 2
    by_name = {a["file"].split("\\")[-1].split("/")[-1]: a for a in r["affected_files"]}
    assert by_name["a.locked"]["quarantined"] is True
    assert by_name["b.locked"]["quarantined"] is False
    assert by_name["a.locked"]["entropy"] == 7.99
    assert len(r["timeline"]) == 2


def test_files_are_written(tmp_path):
    db, quarantine, iid = make_incident(tmp_path)
    json_path, csv_path = write_report(build_report(db, iid, quarantine), tmp_path / "reports")
    assert json.loads(json_path.read_text(encoding="utf-8"))["incident_id"] == iid
    with csv_path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 2 and set(rows[0]) == {"file", "entropy", "quarantined"}


def test_unknown_incident(tmp_path):
    db = Database(tmp_path / "t.db")
    with pytest.raises(ValueError):
        build_report(db, 99, tmp_path)


def test_recommendations_follow_signals():
    tips = " ".join(build_recommendations(["mass_rename"], "evil.exe (pid 7)"))
    assert "extension" in tips and "evil.exe" in tips and "ransom" in tips
    assert "backup" not in " ".join(build_recommendations([], "unknown"))