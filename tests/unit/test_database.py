"""Unit tests for SQLite WAL database manager."""

from datetime import UTC, datetime
from pathlib import Path

from hids.db.database import DatabaseManager
from hids.models.enums import EventCategory, MitreTactic, Severity
from hids.models.telemetry import Alert, FileIntegrityRecord, HostEvent


def test_database_init_and_event_persistence(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)
    db.init_db()

    event = HostEvent(
        category=EventCategory.PROCESS_ACTIVITY,
        action="PROCESS_SPAWNED",
        source_component="test_suite",
        details={"pid": 111, "name": "test"},
    )
    db.save_event(event)

    events = db.list_events()
    assert len(events) == 1
    assert events[0].event_id == event.event_id
    assert events[0].details["pid"] == 111


def test_alert_persistence_and_filtering(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)
    db.init_db()

    a1 = Alert(
        rule_id="R-1",
        rule_name="High finding",
        severity=Severity.HIGH,
        mitre_tactic=MitreTactic.DEFENSE_EVASION,
        mitre_technique="T1036",
        category=EventCategory.PROCESS_ACTIVITY,
        description="desc1",
        matched_event_id="e1",
    )
    a2 = Alert(
        rule_id="R-2",
        rule_name="Critical finding",
        severity=Severity.CRITICAL,
        mitre_tactic=MitreTactic.CREDENTIAL_ACCESS,
        mitre_technique="T1003",
        category=EventCategory.FILE_INTEGRITY,
        description="desc2",
        matched_event_id="e2",
    )

    db.save_alert(a1)
    db.save_alert(a2)

    all_alerts = db.list_alerts()
    assert len(all_alerts) == 2

    crit_alerts = db.list_alerts(severity=Severity.CRITICAL)
    assert len(crit_alerts) == 1
    assert crit_alerts[0].rule_id == "R-2"


def test_fim_baseline_persistence_and_loading(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)
    db.init_db()

    rec1 = FileIntegrityRecord(
        file_path=Path("/etc/hosts"),
        sha256_hash="abc123456789",
        size_bytes=256,
        mode_permissions="-rw-r--r--",
        owner_uid=0,
        group_gid=0,
        modified_time=datetime.now(UTC),
    )

    db.save_fim_baseline({str(rec1.file_path): rec1})

    loaded = db.load_fim_baseline()
    assert str(rec1.file_path) in loaded
    assert loaded[str(rec1.file_path)].sha256_hash == "abc123456789"
