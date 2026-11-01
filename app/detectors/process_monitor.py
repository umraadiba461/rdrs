"""Process monitoring with psutil (FR-5)."""
from __future__ import annotations

import threading
from datetime import datetime
from typing import Any, Callable, Dict, List

import psutil

from app.core.logger import get_logger

log = get_logger("system")


class ProcessMonitor:
    """Takes a snapshot of the busiest processes every few seconds."""

    def __init__(self, callback: Callable[[str, List[Dict[str, Any]]], None],
                 interval: float = 5.0, top_n: int = 10) -> None:
        self.callback = callback
        self.interval = interval
        self.top_n = top_n
        self._cache: Dict[int, psutil.Process] = {}   # keep objects so cpu_percent works
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def snapshot(self) -> List[Dict[str, Any]]:
        """Return the top_n processes by CPU. Skips processes we may not read."""
        rows: List[Dict[str, Any]] = []
        for p in psutil.process_iter():
            try:
                proc = self._cache.setdefault(p.pid, p)
                try:
                    disk = proc.io_counters().write_bytes
                except (psutil.AccessDenied, AttributeError, NotImplementedError):
                    disk = 0
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    exe = ""
                rows.append({
                    "pid": proc.pid,
                    "ppid": proc.ppid(),
                    "name": proc.name(),
                    "exe": exe,
                    "cpu": proc.cpu_percent(None),
                    "memory": round(proc.memory_percent(), 2),
                    "disk_write": disk,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                self._cache.pop(p.pid, None)
                continue
        rows.sort(key=lambda r: r["cpu"], reverse=True)
        return rows[: self.top_n]

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.callback(datetime.now().isoformat(), self.snapshot())
            except Exception as exc:  # never let the thread die
                log.error("Process snapshot failed: {}", exc)
            self._stop.wait(self.interval)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info("Process monitor started (every {}s)", self.interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)