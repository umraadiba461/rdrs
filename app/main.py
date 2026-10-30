"""RDRS entry point."""
from __future__ import annotations

import argparse

from app.core.config import load_config
from app.core.logger import get_logger, setup_logging


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
    log.info("Watching: {}", settings.watch_folders)


if __name__ == "__main__":
    main()
