"""Uses the real watchdog observer on a temporary folder."""
import time

from app.detectors.file_monitor import start_monitor


def test_monitor_sees_a_real_new_file(tmp_path):
    seen = []
    observer, _handler = start_monitor([str(tmp_path)], seen.append)
    try:
        (tmp_path / "hello.txt").write_text("hi")
        deadline = time.time() + 15
        while time.time() < deadline and not any(e.path.endswith("hello.txt") for e in seen):
            time.sleep(0.2)
    finally:
        observer.stop()
        observer.join()
    assert any(e.event_type == "created" and e.path.endswith("hello.txt") for e in seen)