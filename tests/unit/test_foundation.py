"""Unit tests for settings and domain enumerations."""

from hids.config.settings import Settings
from hids.models.enums import EventCategory, FIMAction, MitreTactic, Severity


def test_settings_initialization() -> None:
    s = Settings(agent_id="test-agent")
    assert s.agent_id == "test-agent"
    assert s.failed_login_threshold == 5
    assert len(s.suspicious_exec_directories) >= 3


def test_domain_enums() -> None:
    assert Severity.CRITICAL.value == "CRITICAL"
    assert EventCategory.FILE_INTEGRITY.value == "FILE_INTEGRITY"
    assert FIMAction.MODIFIED.value == "MODIFIED"
    assert MitreTactic.PERSISTENCE.value == "TA0003"
