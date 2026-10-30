"""Rotating log files: system, events, alerts, errors, audit."""
from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

from app.core.config import LoggingConfig

CHANNELS = ("system", "events", "alerts", "errors", "audit")
_configured = False


def setup_logging(cfg: LoggingConfig) -> None:
    """Configure loguru with one rotating file per channel plus console."""
    global _configured
    if _configured:
        return
    log_dir = Path(cfg.dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    logger.remove()
    logger.add(sys.stderr, level="INFO")
    for ch in CHANNELS:
        if ch == "errors":
            logger.add(log_dir / "errors.log", level="ERROR",
                       rotation=cfg.rotation, retention=cfg.retention)
        elif ch == "system":
            logger.add(log_dir / "system.log", level="INFO",
                       rotation=cfg.rotation, retention=cfg.retention,
                       filter=lambda r: r["extra"].get("channel") in (None, "system"))
        else:
            logger.add(log_dir / f"{ch}.log", level="INFO",
                       rotation=cfg.rotation, retention=cfg.retention,
                       filter=lambda r, c=ch: r["extra"].get("channel") == c)
    _configured = True


def get_logger(channel: str = "system"):
    """Return a logger bound to a channel (system/events/alerts/errors/audit)."""
    return logger.bind(channel=channel)
