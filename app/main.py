"""RDRS entry point."""
from __future__ import annotations

import argparse
import time

from app.core.config import load_config
from app.core.entropy import file_entropy
from app.core.logger import get_logger, setup_logging
from app.core.models import FileEvent
from app.database.db import Database
from app.detectors.detection_engine import DetectionEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="Ransomware Detection and Response System")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--watch", help="Folder to watch (overrides config)")
    args = parser.parse_args()

    settings = load_config(args.config)
    setup_logging(settings.logging)
    log = get_logger("system")
    alert_log = get_logger("alerts")
    log.info("RDRS started | simulation_mode={}", settings.simulation_mode)
    if args.watch:
        settings.watch_folders = [args.watch]

    db = Database(settings.database_path)
    engine = DetectionEngine(settings.detection)
    last_signals: set[str] = set()

    # Imported here so config/logging work even if a library is missing
    from app.detectors.file_monitor import start_monitor
    from app.detectors.process_monitor import ProcessMonitor

    def on_event(ev: FileEvent) -> None:
        nonlocal last_signals
        # Entropy only makes sense for files that were written or renamed
        if ev.event_type in ("created", "modified"):
            ev.entropy = file_entropy(ev.path, settings.entropy.sample_bytes)
        elif ev.event_type == "moved" and ev.dest_path:
            ev.entropy = file_entropy(ev.dest_path, settings.entropy.sample_bytes)
        db.save_event(ev)

        engine.add_event(ev)
        signals = engine.signals()
        if signals != last_signals:          # only report when something changes
            stats = engine.stats()
            if signals:
                alert_log.warning("SIGNALS: {} | {}", sorted(signals), stats)
            else:
                alert_log.info("Signals cleared | {}", stats)
            last_signals = signals
        # Phase 5 will turn these signals into a threat score and a response.

    observer, _handler = start_monitor(settings.watch_folders, on_event)
    proc_monitor = ProcessMonitor(db.save_processes, interval=5.0)
    proc_monitor.start()

    print(f"Monitoring {settings.watch_folders}  (press Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        log.info("RDRS stopped by user")
    finally:
        proc_monitor.stop()
        observer.stop()
        observer.join()
        print(f"Saved {db.count('events')} events and {db.count('processes')} process rows to {settings.database_path}")
        db.close()


if __name__ == "__main__":
    main()