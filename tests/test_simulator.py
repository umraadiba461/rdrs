import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "simulate_ransomware", Path(__file__).resolve().parent.parent / "scripts" / "simulate_ransomware.py")
sim = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sim)


def test_refuses_folders_not_named_sandbox(tmp_path):
    with pytest.raises(SystemExit):
        sim.simulate(tmp_path / "documents", count=2, delay=0)
    with pytest.raises(SystemExit):
        sim.cleanup(tmp_path / "documents")


def test_creates_locked_files_and_cleans_up(tmp_path):
    folder = tmp_path / "sandbox"
    folder.mkdir()
    (folder / "keep_me.txt").write_text("my real file")
    assert sim.simulate(folder, count=5, size=1000, delay=0) == 5
    assert len(list(folder.glob("*.locked"))) == 5
    assert sim.cleanup(folder) == 5
    assert [p.name for p in folder.iterdir()] == ["keep_me.txt"]      # real file untouchedimport importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "simulate_ransomware", Path(__file__).resolve().parent.parent / "scripts" / "simulate_ransomware.py")
sim = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sim)


def test_refuses_folders_not_named_sandbox(tmp_path):
    with pytest.raises(SystemExit):
        sim.simulate(tmp_path / "documents", count=2, delay=0)
    with pytest.raises(SystemExit):
        sim.cleanup(tmp_path / "documents")


def test_creates_locked_files_and_cleans_up(tmp_path):
    folder = tmp_path / "sandbox"
    folder.mkdir()
    (folder / "keep_me.txt").write_text("my real file")
    assert sim.simulate(folder, count=5, size=1000, delay=0) == 5
    assert len(list(folder.glob("*.locked"))) == 5
    assert sim.cleanup(folder) == 5
    assert [p.name for p in folder.iterdir()] == ["keep_me.txt"]      # real file untouched