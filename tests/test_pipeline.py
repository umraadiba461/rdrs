"""End-to-end test: real files -> entropy -> detection -> score -> incident -> report."""
import os
from datetime import datetime
from types import SimpleNamespace

from app.core.models import FileEvent
from app.database.db import Database
from app.detectors.detection_engine import DetectionEngine
from app.detectors.response import ResponseEngine
from app.pipeline import Pipeline
from app.reports.generator import build_report

SETTINGS = SimpleNamespace(
    entropy=SimpleNamespace(sample_bytes=65536),
    weights=SimpleNamespace(rapid_encryption=40, mass_rename=30, high_entropy=25, cpu_spike=15, unknown_program=10),
    levels=SimpleNamespace(warning=40, critical=70),
)
DETECTION = SimpleNamespace(window_seconds=60, files_modified_per_minute=20, renames_threshold=15,
                            extension_changes_threshold=15, avg_entropy_threshold=7.0)


def make(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    db = Database(tmp_path / "t.db")
    engine = DetectionEngine(DETECTION)
    responder = ResponseEngine(db, tmp_path / "quarantine", simulation_mode=True)
    pipe = Pipeline(SETTINGS, db, engine, responder)
    pipe.on_processes(datetime.now().isoformat(),
                      [{"pid": 0, "name": "System Idle Process", "cpu": 99.0},
                       {"pid": 7, "name": "evil.exe", "cpu": 50.0}])
    return pipe, db, sandbox


def event(kind, path, dest=None):
    ext = os.path.splitext(dest or path)[1].lower()
    return FileEvent(kind, str(path), datetime.now(), ext, str(dest) if dest else None)


def test_normal_activity_stays_normal(tmp_path):
    pipe, db, sandbox = make(tmp_path)
    for i in range(3):
        f = sandbox / f"note{i}.txt"
        f.write_text("just some ordinary text " * 20)
        assert pipe.process(event("modified", f)) is None
    assert pipe.level == "Normal"
    assert db.count("incidents") == 0


def test_idle_process_is_ignored(tmp_path):
    pipe, _db, _sandbox = make(tmp_path)
    assert [p["pid"] for p in pipe.processes] == [7]


def test_ransomware_burst_opens_one_incident_and_a_report(tmp_path):
    pipe, db, sandbox = make(tmp_path)
    files = []
    for i in range(50):                                   # 50 files get "encrypted"
        f = sandbox / f"doc{i}.txt"
        f.write_bytes(os.urandom(20000))
        files.append(f)
        pipe.process(event("modified", f))
    assert pipe.level == "Warning"                        # rapid_encryption + high_entropy = 65

    incident_ids = []
    for f in files:                                       # ...and renamed to .locked
        locked = f.with_suffix(".locked")
        f.rename(locked)
        incident_ids.append(pipe.process(event("moved", f, locked)))

    opened = [i for i in incident_ids if i]
    assert len(opened) == 1                               # cooldown: exactly one incident
    assert pipe.level == "Critical" and pipe.score >= 70
    assert db.count("incidents") == 1 and db.count("alerts") >= 2

    # evidence was copied, originals untouched
    copies = list((tmp_path / "quarantine" / f"incident_{opened[0]}").iterdir())
    assert len(copies) >= 15
    assert len(list(sandbox.iterdir())) == 50

    # the suspect is the busiest REAL process, not the idle process
    report = build_report(db, opened[0], tmp_path / "quarantine")
    assert report["suspect_process"] == "evil.exe (pid 7)"
    assert "mass_rename" in report["signals"]
    assert report["affected_file_count"] >= 15


def test_event_entropy_is_saved(tmp_path):
    pipe, db, sandbox = make(tmp_path)
    f = sandbox / "random.bin"
    f.write_bytes(os.urandom(20000))
    pipe.process(event("modified", f))
    assert db.recent("events", 1)[0]["entropy"] > 7.9