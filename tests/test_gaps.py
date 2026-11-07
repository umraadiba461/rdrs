"""Small tests for error paths and edge cases."""
import json
import os
import sys
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

import psutil
import pytest

import app.core.logger as lg
from app.api import service
from app.core.config import LoggingConfig
from app.core.models import FileEvent
from app.database.db import Database
from app.detectors.process_monitor import ProcessMonitor
from app.detectors.response import ResponseEngine
from app.reports import generator
from tests.test_pipeline import event, make


# ---------- response ----------
def test_affected_files_skips_old_and_irrelevant_events(tmp_path):
    db = Database(tmp_path / "t.db")
    old_file, new_file, created_file = tmp_path / "old.txt", tmp_path / "new.txt", tmp_path / "c.txt"
    for f in (old_file, new_file, created_file):
        f.write_text("x")
    now = datetime.now()
    db.save_event(FileEvent("modified", str(old_file), now - timedelta(seconds=300), ".txt"))
    db.save_event(FileEvent("created", str(created_file), now, ".txt"))
    db.save_event(FileEvent("modified", str(new_file), now, ".txt"))
    resp = ResponseEngine(db, tmp_path / "q")
    assert resp._affected_files(now) == [str(new_file)]


def test_quarantine_handles_same_names_and_missing_files(tmp_path):
    db = Database(tmp_path / "t.db")
    resp = ResponseEngine(db, tmp_path / "q")
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "same.txt").write_text("1")
    (tmp_path / "b" / "same.txt").write_text("2")
    copied = resp._quarantine(1, [str(tmp_path / "a" / "same.txt"),
                                  str(tmp_path / "b" / "same.txt"),
                                  str(tmp_path / "gone.txt")])      # this one does not exist
    assert copied == 2
    assert sorted(p.name for p in (tmp_path / "q" / "incident_1").iterdir()) == ["same.txt", "same_1.txt"]


def test_terminate_messages(tmp_path):
    db = Database(tmp_path / "t.db")
    assert "no suspect" in ResponseEngine(db, tmp_path)._terminate(None)
    live = ResponseEngine(db, tmp_path, simulation_mode=False)._terminate({"name": "x.exe", "pid": 5})
    assert "not implemented" in live          # real killing is deliberately not built


# ---------- process monitor ----------
class FakeProc:
    def __init__(self, pid, name="p", cpu=1.0, io_error=None, exe_error=None, name_error=None):
        self.pid, self._name, self._cpu = pid, name, cpu
        self._io_error, self._exe_error, self._name_error = io_error, exe_error, name_error

    def io_counters(self):
        if self._io_error:
            raise self._io_error
        return SimpleNamespace(write_bytes=10)

    def exe(self):
        if self._exe_error:
            raise self._exe_error
        return "C:/x.exe"

    def ppid(self):
        return 1

    def name(self):
        if self._name_error:
            raise self._name_error
        return self._name

    def cpu_percent(self, _=None):
        return self._cpu

    def memory_percent(self):
        return 1.234


def test_snapshot_survives_unreadable_processes(monkeypatch):
    fakes = [FakeProc(1, "ok", 5.0),
             FakeProc(2, "guarded", 9.0, io_error=psutil.AccessDenied(2), exe_error=psutil.AccessDenied(2)),
             FakeProc(3, "vanishes", name_error=psutil.NoSuchProcess(3))]
    monkeypatch.setattr(psutil, "process_iter", lambda: fakes)
    rows = ProcessMonitor(lambda ts, r: None).snapshot()
    assert [r["name"] for r in rows] == ["guarded", "ok"]          # sorted by CPU, vanished one skipped
    assert rows[0]["disk_write"] == 0 and rows[0]["exe"] == ""


def test_monitor_thread_survives_a_failing_callback(monkeypatch):
    monkeypatch.setattr(psutil, "process_iter", lambda: [])
    calls = []

    def bad_callback(ts, rows):
        calls.append(1)
        raise RuntimeError("boom")

    pm = ProcessMonitor(bad_callback, interval=0.05)
    pm.start()
    time.sleep(0.5)
    pm.stop()
    assert len(calls) >= 2                  # kept running after the first error


# ---------- pipeline, logger, database ----------
def test_cpu_spike_signal(tmp_path):
    pipe, _db, sandbox = make(tmp_path)
    pipe.on_processes(datetime.now().isoformat(), [{"pid": 9, "name": "busy.exe", "cpu": 95.0}])
    f = sandbox / "a.txt"
    f.write_text("hello")
    pipe.process(event("modified", f))
    assert "cpu_spike" in pipe.signals and pipe.score == 15


def test_setup_logging_only_runs_once(tmp_path):
    lg._configured = True
    lg.setup_logging(LoggingConfig(dir=str(tmp_path / "never_created")))
    assert not (tmp_path / "never_created").exists()
    lg._configured = False


def test_recent_rejects_unknown_table(tmp_path):
    with pytest.raises(ValueError):
        Database(tmp_path / "t.db").recent("users")


# ---------- api service ----------
def make_settings(folder, limit=7.5):
    return SimpleNamespace(watch_folders=[str(folder)],
                           entropy=SimpleNamespace(sample_bytes=65536, high_threshold=limit))


def test_scan_ignores_missing_folders_and_subfolders(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "f.txt").write_text("hello")
    settings = SimpleNamespace(watch_folders=[str(tmp_path / "missing"), str(tmp_path)],
                               entropy=SimpleNamespace(sample_bytes=65536, high_threshold=7.5))
    assert service.run_scan(settings)["files_scanned"] == 1


def test_scan_stops_at_the_limit(tmp_path, monkeypatch):
    for i in range(5):
        (tmp_path / f"{i}.txt").write_text("x")
    monkeypatch.setattr(service, "MAX_SCAN_FILES", 2)
    assert service.run_scan(make_settings(tmp_path))["files_scanned"] == 2


def test_validate_skips_none_and_rejects_text():
    assert service.validate_detection_update({"renames_threshold": 5, "window_seconds": None}) == {"renames_threshold": 5}
    with pytest.raises(ValueError):
        service.validate_detection_update({"renames_threshold": "abc"})


# ---------- report command line ----------
def test_report_recommends_checking_cpu():
    assert "CPU" in " ".join(generator.build_recommendations(["cpu_spike"], "unknown"))


def write_config(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f'database_path: "{(tmp_path / "r.db").as_posix()}"\n'
                   f'quarantine_dir: "{(tmp_path / "q").as_posix()}"\n', encoding="utf-8")
    return cfg


def test_report_command_with_no_incidents(tmp_path, monkeypatch, capsys):
    cfg = write_config(tmp_path)
    monkeypatch.setattr(sys, "argv", ["generator", "--config", str(cfg), "--out", str(tmp_path / "out")])
    generator.main()
    assert "No incidents" in capsys.readouterr().out


def test_report_command_writes_files_for_newest_incident(tmp_path, monkeypatch, capsys):
    cfg = write_config(tmp_path)
    db = Database(tmp_path / "r.db")
    ts = datetime.now().isoformat()
    db.save_score(ts, 95, "Critical", ["mass_rename"])
    db.save_incident(ts, 95, "evil.exe (pid 1)", json.dumps([]), "open")
    db.close()
    out = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["generator", "--config", str(cfg), "--out", str(out)])
    generator.main()
    assert "saved" in capsys.readouterr().out
    assert (out / "incident_1_report.json").exists() and (out / "incident_1_report.csv").exists()