from datetime import datetime, timedelta
from types import SimpleNamespace

from app.core.models import FileEvent
from app.detectors.detection_engine import DetectionEngine


def cfg():
    return SimpleNamespace(
        window_seconds=60, files_modified_per_minute=20, renames_threshold=15,
        extension_changes_threshold=15, avg_entropy_threshold=7.0)


def modified(i, entropy=None, when=None):
    return FileEvent("modified", f"f{i}.txt", when or datetime.now(), ".txt", None, entropy)


def renamed(i):
    return FileEvent("moved", f"f{i}.txt", datetime.now(), ".locked", f"f{i}.locked", 8.0)


def test_normal_activity_is_quiet():
    eng = DetectionEngine(cfg())
    for i in range(3):
        eng.add_event(modified(i, 4.5))
    assert eng.signals() == set()


def test_burst_of_modifications_fires_rapid_encryption():
    eng = DetectionEngine(cfg())
    for i in range(25):
        eng.add_event(modified(i))
    assert "rapid_encryption" in eng.signals()


def test_repeated_events_for_one_file_count_once():
    eng = DetectionEngine(cfg())
    for _ in range(40):
        eng.add_event(modified(1))
    assert eng.stats()["files_modified"] == 1
    assert "rapid_encryption" not in eng.signals()


def test_mass_rename_fires():
    eng = DetectionEngine(cfg())
    for i in range(16):
        eng.add_event(renamed(i))
    assert "mass_rename" in eng.signals()


def test_high_entropy_needs_enough_samples():
    eng = DetectionEngine(cfg())
    for i in range(4):
        eng.add_event(modified(i, 7.9))
    assert "high_entropy" not in eng.signals()
    eng.add_event(modified(4, 7.9))
    assert "high_entropy" in eng.signals()


def test_old_events_leave_the_window():
    eng = DetectionEngine(cfg())
    old = datetime.now() - timedelta(seconds=120)
    for i in range(25):
        eng.add_event(modified(i, when=old))
    assert eng.signals() == set()