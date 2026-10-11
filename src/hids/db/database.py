"""SQLite database persistence engine for events, alerts, and FIM baselines."""

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from hids.models.enums import EventCategory, MitreTactic, Severity
from hids.models.telemetry import Alert, FileIntegrityRecord, HostEvent


class DatabaseManager:
    """Thread-safe SQLite database manager running in WAL mode."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Create database tables and indices from schema definition."""
        schema_path = Path(__file__).parent / "schema.sql"
        schema_sql = schema_path.read_text(encoding="utf-8")
        with self._get_connection() as conn:
            conn.executescript(schema_sql)

    # Host Events
    def save_event(self, event: HostEvent) -> None:
        """Insert a telemetry event record."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO host_events (
                    event_id, timestamp, category, host_id, action, source_component, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.category.value,
                    event.host_id,
                    event.action,
                    event.source_component,
                    json.dumps(event.details),
                ),
            )

    def list_events(self, limit: int = 100, offset: int = 0) -> list[HostEvent]:
        """Fetch chronological list of host events."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM host_events ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [
                HostEvent(
                    event_id=r["event_id"],
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    category=EventCategory(r["category"]),
                    host_id=r["host_id"],
                    action=r["action"],
                    source_component=r["source_component"],
                    details=json.loads(r["details"]),
                )
                for r in rows
            ]

    # Alerts
    def save_alert(self, alert: Alert) -> None:
        """Insert a generated security alert."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, rule_id, rule_name, severity, mitre_tactic,
                    mitre_technique, category, description, matched_event_id, host_id,
                    evidence, acknowledged
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.timestamp.isoformat(),
                    alert.rule_id,
                    alert.rule_name,
                    alert.severity.value,
                    alert.mitre_tactic.value,
                    alert.mitre_technique,
                    alert.category.value,
                    alert.description,
                    alert.matched_event_id,
                    alert.host_id,
                    json.dumps(alert.evidence),
                    1 if alert.acknowledged else 0,
                ),
            )

    def list_alerts(
        self,
        severity: Severity | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Alert]:
        """Retrieve alerts optionally filtered by severity."""
        with self._get_connection() as conn:
            if severity:
                query = (
                    "SELECT * FROM alerts WHERE severity = ? "
                    "ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                )
                rows = conn.execute(query, (severity.value, limit, offset)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()

            return [
                Alert(
                    alert_id=r["alert_id"],
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    rule_id=r["rule_id"],
                    rule_name=r["rule_name"],
                    severity=Severity(r["severity"]),
                    mitre_tactic=MitreTactic(r["mitre_tactic"]),
                    mitre_technique=r["mitre_technique"],
                    category=EventCategory(r["category"]),
                    description=r["description"],
                    matched_event_id=r["matched_event_id"],
                    host_id=r["host_id"],
                    evidence=json.loads(r["evidence"]),
                    acknowledged=bool(r["acknowledged"]),
                )
                for r in rows
            ]

    # FIM Baselines
    def save_fim_baseline(self, records: dict[str, FileIntegrityRecord]) -> None:
        """Persist or update file integrity records."""
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            for rec in records.values():
                conn.execute(
                    """
                    INSERT INTO fim_baselines (
                        file_path, sha256_hash, size_bytes, mode_permissions,
                        owner_uid, group_gid, modified_time, is_directory, last_scanned
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(file_path) DO UPDATE SET
                        sha256_hash = excluded.sha256_hash,
                        size_bytes = excluded.size_bytes,
                        mode_permissions = excluded.mode_permissions,
                        owner_uid = excluded.owner_uid,
                        group_gid = excluded.group_gid,
                        modified_time = excluded.modified_time,
                        last_scanned = excluded.last_scanned
                    """,
                    (
                        str(rec.file_path),
                        rec.sha256_hash,
                        rec.size_bytes,
                        rec.mode_permissions,
                        rec.owner_uid,
                        rec.group_gid,
                        rec.modified_time.isoformat(),
                        1 if rec.is_directory else 0,
                        now,
                    ),
                )

    def load_fim_baseline(self) -> dict[str, FileIntegrityRecord]:
        """Load stored baseline file records from database."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM fim_baselines").fetchall()
            baseline: dict[str, FileIntegrityRecord] = {}
            for r in rows:
                baseline[r["file_path"]] = FileIntegrityRecord(
                    file_path=Path(r["file_path"]),
                    sha256_hash=r["sha256_hash"],
                    size_bytes=r["size_bytes"],
                    mode_permissions=r["mode_permissions"],
                    owner_uid=r["owner_uid"],
                    group_gid=r["group_gid"],
                    modified_time=datetime.fromisoformat(r["modified_time"]),
                    is_directory=bool(r["is_directory"]),
                )
            return baseline
