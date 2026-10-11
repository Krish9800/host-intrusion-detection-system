"""Integration tests for FastAPI REST control plane."""

from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hids.api.app import create_app
from hids.config.settings import Settings
from hids.db.database import DatabaseManager
from hids.models.enums import EventCategory, MitreTactic, Severity
from hids.models.telemetry import Alert, FileIntegrityRecord, HostEvent


@pytest.fixture
def test_db(tmp_path: Path) -> Generator[DatabaseManager, None, None]:
    """Provide a fresh SQLite test database."""
    db_file = tmp_path / "test_api_hids.db"
    db = DatabaseManager(db_file)
    db.init_db()
    yield db


@pytest.fixture
def client(test_db: DatabaseManager, tmp_path: Path) -> Generator[TestClient, None, None]:
    """Provide FastAPI test client."""
    settings = Settings(db_path=tmp_path / "test_api_hids.db")
    app = create_app(settings=settings, db=test_db)
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client: TestClient) -> None:
    """Test health status endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "host-intrusion-detection-system"
    assert data["database_connected"] is True


def test_alerts_endpoints(client: TestClient, test_db: DatabaseManager) -> None:
    """Test listing and fetching alert endpoints."""
    # Initially empty
    response = client.get("/alerts")
    assert response.status_code == 200
    assert response.json() == []

    # Insert test alerts
    alert1 = Alert(
        rule_id="RULE-001",
        rule_name="Unauthorized SSH Access",
        severity=Severity.HIGH,
        mitre_tactic=MitreTactic.INITIAL_ACCESS,
        mitre_technique="T1110.001",
        category=EventCategory.AUTHENTICATION,
        description="Brute force detected",
        matched_event_id="evt-001",
    )
    alert2 = Alert(
        rule_id="RULE-002",
        rule_name="File Modification",
        severity=Severity.LOW,
        mitre_tactic=MitreTactic.DEFENSE_EVASION,
        mitre_technique="T1070",
        category=EventCategory.FILE_INTEGRITY,
        description="File changed in /etc",
        matched_event_id="evt-002",
    )
    test_db.save_alert(alert1)
    test_db.save_alert(alert2)

    # List all alerts
    response = client.get("/alerts")
    assert response.status_code == 200
    assert len(response.json()) == 2

    # Filter by severity
    resp_high = client.get("/alerts?severity=high")
    assert resp_high.status_code == 200
    assert len(resp_high.json()) == 1
    assert resp_high.json()[0]["rule_id"] == "RULE-001"

    # Invalid severity query
    resp_invalid = client.get("/alerts?severity=unknown")
    assert resp_invalid.status_code == 400

    # Get alert by ID
    resp_by_id = client.get(f"/alerts/{alert1.alert_id}")
    assert resp_by_id.status_code == 200
    assert resp_by_id.json()["alert_id"] == alert1.alert_id

    # Non-existent alert ID
    resp_missing = client.get("/alerts/non-existent-id")
    assert resp_missing.status_code == 404


def test_events_endpoints(client: TestClient, test_db: DatabaseManager) -> None:
    """Test querying host events."""
    event1 = HostEvent(
        category=EventCategory.PROCESS_ACTIVITY,
        action="PROCESS_SPAWNED",
        source_component="process_monitor",
        details={"pid": 1234, "cmdline": "/bin/bash"},
    )
    event2 = HostEvent(
        category=EventCategory.AUTHENTICATION,
        action="SSH_AUTH_FAILED",
        source_component="auth_monitor",
        details={"user": "root", "ip": "10.0.0.1"},
    )
    test_db.save_event(event1)
    test_db.save_event(event2)

    # List all events
    response = client.get("/events")
    assert response.status_code == 200
    assert len(response.json()) == 2

    # Filter by category
    resp_filtered = client.get("/events?category=process_activity")
    assert resp_filtered.status_code == 200
    assert len(resp_filtered.json()) == 1
    assert resp_filtered.json()[0]["category"] == "PROCESS_ACTIVITY"

    # Invalid category query
    resp_invalid = client.get("/events?category=invalid_cat")
    assert resp_invalid.status_code == 400


def test_fim_endpoints(client: TestClient, test_db: DatabaseManager) -> None:
    """Test querying FIM baseline records."""
    rec = FileIntegrityRecord(
        file_path=Path("/etc/passwd"),
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size_bytes=1024,
        mode_permissions="644",
        owner_uid=0,
        group_gid=0,
        modified_time=datetime.now(UTC),
    )
    test_db.save_fim_baseline({str(rec.file_path): rec})

    # List baselines
    resp_list = client.get("/fim/baselines")
    assert resp_list.status_code == 200
    assert len(resp_list.json()) == 1
    assert resp_list.json()[0]["file_path"] == "/etc/passwd"

    # Get specific baseline
    resp_item = client.get("/fim/baselines/etc/passwd")
    assert resp_item.status_code == 200
    assert resp_item.json()["file_path"] == "/etc/passwd"

    # Missing baseline
    resp_missing = client.get("/fim/baselines/etc/nonexistent")
    assert resp_missing.status_code == 404
