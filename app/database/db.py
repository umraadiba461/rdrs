"""SQLite storage for events, processes, scores, alerts and incidents (FR-4)."""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List

from app.core.models import FileEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    path TEXT NOT NULL,
    dest_path TEXT,
    extension TEXT,
    entropy REAL
);
CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    pid INTEGER, ppid INTEGER, name TEXT, exe TEXT,
    cpu REAL, memory REAL, disk_write INTEGER
);
CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    score INTEGER NOT NULL,
    level TEXT NOT NULL,
    signals TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    level TEXT NOT NULL,
    score INTEGER,
    message TEXT
);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    score INTEGER,
    suspect_process TEXT,
    affected_files TEXT,
    status TEXT
);
"""


class Database:
    """Small thread-safe wrapper around one SQLite file."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # watchdog and the process monitor run in other threads
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def save_event(self, ev: FileEvent) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events (timestamp, event_type, path, dest_path, extension, entropy) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (ev.timestamp.isoformat(), ev.event_type, ev.path, ev.dest_path, ev.extension, ev.entropy),
            )
            self._conn.commit()

    def save_processes(self, timestamp: str, rows: Iterable[Dict[str, Any]]) -> None:
        data = [
            (timestamp, r["pid"], r.get("ppid"), r.get("name"), r.get("exe"),
             r.get("cpu"), r.get("memory"), r.get("disk_write"))
            for r in rows
        ]
        with self._lock:
            self._conn.executemany(
                "INSERT INTO processes (timestamp, pid, ppid, name, exe, cpu, memory, disk_write) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", data)
            self._conn.commit()

    def count(self, table: str) -> int:
        if table not in {"events", "processes", "scores", "alerts", "incidents"}:
            raise ValueError(f"Unknown table: {table}")
        with self._lock:
            return self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def recent(self, table: str, limit: int = 50) -> List[Dict[str, Any]]:
        if table not in {"events", "processes", "scores", "alerts", "incidents"}:
            raise ValueError(f"Unknown table: {table}")
        with self._lock:
            cur = self._conn.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

    def close(self) -> None:
        with self._lock:
            self._conn.close()