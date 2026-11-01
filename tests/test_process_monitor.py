import time

from app.detectors.process_monitor import ProcessMonitor


def test_snapshot_returns_rows():
    pm = ProcessMonitor(lambda ts, rows: None, top_n=5)
    pm.snapshot()                 # first call primes cpu_percent
    rows = pm.snapshot()
    assert 0 < len(rows) <= 5
    for key in ("pid", "name", "cpu", "memory", "disk_write"):
        assert key in rows[0]


def test_start_stop_calls_back():
    got = []
    pm = ProcessMonitor(lambda ts, rows: got.append(rows), interval=0.1)
    pm.start()
    deadline = time.time() + 30   # one snapshot can take several seconds on Windows
    while not got and time.time() < deadline:
        time.sleep(0.2)
    pm.stop()
    assert len(got) >= 1