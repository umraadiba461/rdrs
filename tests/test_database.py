from datetime import datetime

import pytest

from app.core.models import FileEvent
from app.database.db import Database


def make_event(t="created", path="a.txt", ent=None):
    return FileEvent(t, path, datetime.now(), ".txt", None, ent)


def test_save_and_count_events(tmp_path):
    db = Database(tmp_path / "t.db")
    db.save_event(make_event())
    db.save_event(make_event("modified", ent=7.9))
    assert db.count("events") == 2
    latest = db.recent("events", 1)[0]
    assert latest["event_type"] == "modified"
    assert latest["entropy"] == 7.9
    db.close()


def test_save_processes(tmp_path):
    db = Database(tmp_path / "t.db")
    db.save_processes("2026-01-01T00:00:00", [{"pid": 1, "name": "x", "cpu": 5.0}])
    assert db.count("processes") == 1
    db.close()


def test_unknown_table_rejected(tmp_path):
    db = Database(tmp_path / "t.db")
    with pytest.raises(ValueError):
        db.count("users; DROP TABLE events")
    db.close()