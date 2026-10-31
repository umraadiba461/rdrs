"""Real-time file monitoring using watchdog (FR-2)."""
from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.core.logger import get_logger
from app.core.models import FileEvent

log = get_logger("events")


class EventHandler(FileSystemEventHandler):
    """Turns raw watchdog events into FileEvent objects and counts them."""

    def __init__(self, callback: Callable[[FileEvent], None], show_count: bool = True) -> None:
        super().__init__()
        self.callback = callback
        self.show_count = show_count
        self.count = 0
        self._lock = threading.Lock()

    def _emit(self, event_type: str, src: str, dest: str | None = None) -> None:
        ext = Path(dest or src).suffix.lower()
        ev = FileEvent(event_type, src, datetime.now(), ext, dest)
        with self._lock:
            self.count += 1
            n = self.count
        log.info("{} | {}{}", event_type, src, f" -> {dest}" if dest else "")
        self.callback(ev)
        if self.show_count:
            print(f"\rEvents seen: {n}   (last: {event_type} {Path(dest or src).name})".ljust(70), end="", flush=True)

    def on_created(self, event) -> None:
        if not event.is_directory:
            self._emit("created", event.src_path)

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self._emit("modified", event.src_path)

    def on_deleted(self, event) -> None:
        if not event.is_directory:
            self._emit("deleted", event.src_path)

    def on_moved(self, event) -> None:
        if not event.is_directory:
            self._emit("moved", event.src_path, event.dest_path)


def start_monitor(folders: Iterable[str], callback: Callable[[FileEvent], None]):
    """Start watching folders. Returns (observer, handler)."""
    observer = Observer()
    handler = EventHandler(callback)
    for folder in folders:
        Path(folder).mkdir(parents=True, exist_ok=True)
        observer.schedule(handler, str(folder), recursive=True)
        log.info("Watching folder: {}", folder)
    observer.start()
    return observer, handler