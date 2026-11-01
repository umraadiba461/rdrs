from datetime import datetime
from types import SimpleNamespace

import pytest

from app.api import service
from app.core.models import FileEvent
from app.database.db import Database


def test_status_when_empty(tmp_path):
    db = Database(tmp_path / "t.db")
    s = service.get_status(db, True)
    assert s["level"] == "Normal" and s["score"] == 0 and s["signals"] == []


def test_status_uses_latest_score(tmp_path):
    db = Database(tmp_path / "t.db")
    db.save_score("2026-01-01T00:00:00", 40, "Warning", ["rapid_encryption"])
    db.save_score("2026-01-01T00:01:00", 95, "Critical", ["rapid_encryption", "mass_rename"])
    s = service.get_status(db, True)
    assert s["level"] == "Critical" and s["score"] == 95
    assert "mass_rename" in s["signals"]


def test_recent_limit(tmp_path):
    db = Database(tmp_path / "t.db")
    for i in range(5):
        db.save_event(FileEvent("created", f"f{i}", datetime.now(), ".txt"))
    assert len(service.get_recent(db, "events", 3)) == 3


def test_reports_listing(tmp_path):
    assert service.list_reports(tmp_path / "missing") == []
    (tmp_path / "a.json").write_text("{}")
    assert service.list_reports(tmp_path) == ["a.json"]


def test_scan_finds_random_file(tmp_path):
    import os
    (tmp_path / "plain.txt").write_text("hello hello hello")
    (tmp_path / "random.bin").write_bytes(os.urandom(20000))
    settings = SimpleNamespace(
        watch_folders=[str(tmp_path)],
        entropy=SimpleNamespace(sample_bytes=65536, high_threshold=7.5))
    result = service.run_scan(settings)
    assert result["files_scanned"] == 2
    assert result["suspicious_count"] == 1


def test_validate_rejects_bad_values():
    with pytest.raises(ValueError):
        service.validate_detection_update({"nonsense": 1})
    with pytest.raises(ValueError):
        service.validate_detection_update({"renames_threshold": 0})
    with pytest.raises(ValueError):
        service.validate_detection_update({})
    assert service.validate_detection_update({"renames_threshold": "20"}) == {"renames_threshold": 20}


def test_update_writes_config(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("detection:\n  renames_threshold: 15\n  window_seconds: 60\n")
    saved = service.update_detection_settings(cfg, {"renames_threshold": 25})
    assert saved["renames_threshold"] == 25 and saved["window_seconds"] == 60
    assert "25" in cfg.read_text()