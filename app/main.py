"""RDRS entry point."""
from __future__ import annotations

import argparse
import time

from app.core.config import load_config
from app.core.logger import get_logger, setup_logging
from app.core.models import FileEvent


def main() -> None:
    parser = argparse.ArgumentParser(description="Ransomware Detection and Response System")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--watch", help="Folder to watch (overrides config)")
    args = parser.parse_args()

    settings = load_config(args.config)
    setup_logging(settings.logging)
    log = get_logger("system")
    log.info("RDRS started | simulation_mode={}", settings.simulation_mode)
    if args.watch:
        settings.watch_folders = [args.watch]

    # Imported here so the config/logging work even if watchdog is missing
    from app.detectors.file_monitor import start_monitor

    def on_event(ev: FileEvent) -> None:
        # Phase 3 will save to the database; Phase 4 will feed the detection engine.
        pass

    observer, _handler = start_monitor(settings.watch_folders, on_event)
    print(f"Monitoring {settings.watch_folders}  (press Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        log.info("RDRS stopped by user")
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()