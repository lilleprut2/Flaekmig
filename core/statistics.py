"""SQLite-backed scan history and score calculations."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional


@dataclass(frozen=True)
class ScanHistoryRecord:
    target: str
    timestamp: str
    latency: Optional[float]
    packet_loss: float
    batch_size: int
    timeout: int
    scan_duration: float
    open_ports_found: int
    network_quality: str
    score: float
    network_type: str = "unknown"


def scan_score(open_ports_found: int, scan_duration_seconds: float, packet_loss_percent: float) -> float:
    """Score discovery yield against elapsed time and packet loss."""
    return (open_ports_found * 10.0) - scan_duration_seconds - (packet_loss_percent * 5.0)


class ScanHistoryManager:
    """Persist RustScan executions and provide records for adaptive decisions."""

    def __init__(self, database_path: str = "data/scan_history.db"):
        self.database_path = str(Path(database_path))
        parent = Path(self.database_path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.database_path)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                latency REAL,
                packet_loss REAL NOT NULL,
                batch_size INTEGER NOT NULL,
                timeout INTEGER NOT NULL,
                scan_duration REAL NOT NULL,
                open_ports_found INTEGER NOT NULL,
                network_quality TEXT NOT NULL,
                score REAL NOT NULL,
                network_type TEXT NOT NULL DEFAULT 'unknown'
            )
            """
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_history_target ON scan_history(target)"
        )
        self._connection.commit()

    def record_scan(
        self,
        target: str,
        latency: Optional[float],
        packet_loss: float,
        batch_size: int,
        timeout: int,
        scan_duration: float,
        open_ports_found: int,
        network_quality: str,
        network_type: str = "unknown",
        timestamp: Optional[str] = None,
    ) -> ScanHistoryRecord:
        timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        score = scan_score(open_ports_found, scan_duration, packet_loss)
        self._connection.execute(
            """
            INSERT INTO scan_history (
                target, timestamp, latency, packet_loss, batch_size, timeout,
                scan_duration, open_ports_found, network_quality, score, network_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """ ,
            (target, timestamp, latency, packet_loss, batch_size, timeout,
             scan_duration, open_ports_found, network_quality, score, network_type),
        )
        self._connection.commit()
        return ScanHistoryRecord(
            target, timestamp, latency, packet_loss, batch_size, timeout,
            scan_duration, open_ports_found, network_quality, score, network_type,
        )

    def count(self, target: Optional[str] = None) -> int:
        if target is None:
            row = self._connection.execute("SELECT COUNT(*) AS count FROM scan_history").fetchone()
        else:
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM scan_history WHERE target = ?", (target,)
            ).fetchone()
        return int(row["count"])

    def recent(self, target: Optional[str] = None, limit: int = 100) -> List[ScanHistoryRecord]:
        if limit < 1:
            return []
        if target is None:
            rows = self._connection.execute(
                "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT * FROM scan_history WHERE target = ? ORDER BY id DESC LIMIT ?",
                (target, limit),
            ).fetchall()
        return [self._record_from_row(row) for row in rows]

    def by_quality(self, quality: str, limit: int = 100) -> List[ScanHistoryRecord]:
        rows = self._connection.execute(
            "SELECT * FROM scan_history WHERE network_quality = ? ORDER BY id DESC LIMIT ?",
            (quality, limit),
        ).fetchall()
        return [self._record_from_row(row) for row in rows]

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> ScanHistoryRecord:
        return ScanHistoryRecord(
            target=row["target"], timestamp=row["timestamp"], latency=row["latency"],
            packet_loss=row["packet_loss"], batch_size=row["batch_size"],
            timeout=row["timeout"], scan_duration=row["scan_duration"],
            open_ports_found=row["open_ports_found"], network_quality=row["network_quality"],
            score=row["score"], network_type=row["network_type"],
        )

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "ScanHistoryManager":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
