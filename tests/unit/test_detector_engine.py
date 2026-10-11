"""Unit tests for detection and rule correlation engine."""

from hids.engine.detector import DetectionEngine
from hids.models.enums import EventCategory, Severity
from hids.models.telemetry import HostEvent


def test_evaluate_critical_fim_event() -> None:
    engine = DetectionEngine()
    event = HostEvent(
        category=EventCategory.FILE_INTEGRITY,
        action="MODIFIED",
        source_component="fim_scanner",
        details={
            "file_path": "/etc/shadow",
            "action": "MODIFIED",
        },
    )

    alerts = engine.evaluate_event(event)
    assert len(alerts) >= 1
    assert alerts[0].rule_id == "HIDS-RULE-001"
    assert alerts[0].severity == Severity.CRITICAL
    assert alerts[0].mitre_technique == "T1003.008"


def test_evaluate_persistence_crontab_event() -> None:
    engine = DetectionEngine()
    event = HostEvent(
        category=EventCategory.FILE_INTEGRITY,
        action="CREATED",
        source_component="fim_scanner",
        details={
            "file_path": "/etc/cron.d/malicious_job",
            "action": "CREATED",
        },
    )

    alerts = engine.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "HIDS-RULE-002"
    assert alerts[0].mitre_technique == "T1053.003"


def test_evaluate_process_anomaly_reverse_shell() -> None:
    engine = DetectionEngine()
    event = HostEvent(
        category=EventCategory.PROCESS_ACTIVITY,
        action="UNAUTHORIZED_CHILD_SHELL",
        source_component="process_monitor",
        details={
            "action": "UNAUTHORIZED_CHILD_SHELL",
            "pid": 4321,
        },
    )

    alerts = engine.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "HIDS-RULE-005"
    assert alerts[0].severity == Severity.CRITICAL


def test_evaluate_auth_failed_login() -> None:
    engine = DetectionEngine()
    event = HostEvent(
        category=EventCategory.AUTHENTICATION,
        action="login_failed",
        source_component="auth_log_parser",
        details={
            "service": "sshd",
            "username": "root",
            "source_ip": "10.0.0.99",
        },
    )

    alerts = engine.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "HIDS-RULE-006"
    assert alerts[0].severity == Severity.HIGH
