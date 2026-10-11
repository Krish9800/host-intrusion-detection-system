"""Unit tests for telemetry domain models."""

from datetime import UTC, datetime
from pathlib import Path

from hids.models.enums import EventCategory, MitreTactic, Severity
from hids.models.telemetry import (
    Alert,
    AuthLogRecord,
    DetectionRule,
    FileIntegrityRecord,
    ProcessRecord,
)


def test_file_integrity_record_model() -> None:
    rec = FileIntegrityRecord(
        file_path=Path("/etc/shadow"),
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size_bytes=1024,
        mode_permissions="-rw-r-----",
        owner_uid=0,
        group_gid=42,
        modified_time=datetime.now(UTC),
    )
    assert rec.file_path == Path("/etc/shadow")
    assert rec.owner_uid == 0
    assert not rec.is_directory


def test_process_record_model() -> None:
    proc = ProcessRecord(
        pid=1234,
        name="nc",
        exe_path="/bin/nc",
        cmdline=["nc", "-lvnp", "4444"],
        username="www-data",
    )
    assert proc.pid == 1234
    assert proc.name == "nc"
    assert "4444" in proc.cmdline


def test_auth_log_record_model() -> None:
    auth = AuthLogRecord(
        timestamp=datetime.now(UTC),
        service="sshd",
        event_type="login_failed",
        username="root",
        source_ip="192.168.1.100",
        source_port=54321,
        message="Failed password for root from 192.168.1.100 port 54321 ssh2",
        raw_log="Oct 11 12:00:00 server sshd[123]: Failed password for root",
    )
    assert auth.service == "sshd"
    assert auth.username == "root"


def test_alert_generation_from_rule() -> None:
    rule = DetectionRule(
        rule_id="RULE-001",
        name="Process Executed from /tmp",
        description="Detects binary execution out of /tmp directory",
        category=EventCategory.PROCESS_ACTIVITY,
        severity=Severity.HIGH,
        mitre_tactic=MitreTactic.DEFENSE_EVASION,
        mitre_technique="T1036.005",
    )
    alert = Alert(
        rule_id=rule.rule_id,
        rule_name=rule.name,
        severity=rule.severity,
        mitre_tactic=rule.mitre_tactic,
        mitre_technique=rule.mitre_technique,
        category=rule.category,
        description=rule.description,
        matched_event_id="evt-1234",
    )
    assert alert.rule_id == "RULE-001"
    assert alert.severity == Severity.HIGH
    assert not alert.acknowledged
