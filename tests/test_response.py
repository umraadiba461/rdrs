from datetime import datetime

from app.core.models import FileEvent
from app.database.db import Database
from app.detectors.response import ResponseEngine

SUSPECT = {"name": "evil.exe", "pid": 123}


def setup(tmp_path, n_files=3):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    db = Database(tmp_path / "t.db")
    for i in range(n_files):
        f = sandbox / f"f{i}.locked"
        f.write_bytes(b"x" * 100)
        db.save_event(FileEvent("modified", str(f), datetime.now(), ".locked", None, 7.9))
    return db, ResponseEngine(db, tmp_path / "quarantine", simulation_mode=True)


def test_normal_only_saves_score(tmp_path):
    db, resp = setup(tmp_path)
    assert resp.handle(0, "Normal", set(), {}) is None
    assert db.count("scores") == 1 and db.count("alerts") == 0


def test_warning_creates_alert_not_incident(tmp_path):
    db, resp = setup(tmp_path)
    assert resp.handle(40, "Warning", {"rapid_encryption"}, {}) is None
    assert db.count("alerts") == 1 and db.count("incidents") == 0


def test_critical_creates_incident_and_quarantine_copy(tmp_path):
    db, resp = setup(tmp_path, n_files=3)
    incident_id = resp.handle(95, "Critical", {"rapid_encryption", "mass_rename"}, {}, SUSPECT)
    assert incident_id == 1
    assert db.count("incidents") == 1
    copies = list((tmp_path / "quarantine" / "incident_1").iterdir())
    assert len(copies) == 3
    # originals must still exist
    assert len(list((tmp_path / "sandbox").iterdir())) == 3


def test_cooldown_prevents_duplicate_incidents(tmp_path):
    db, resp = setup(tmp_path)
    assert resp.handle(95, "Critical", {"mass_rename"}, {}, SUSPECT) == 1
    assert resp.handle(95, "Critical", {"mass_rename"}, {}, SUSPECT) is None
    assert db.count("incidents") == 1