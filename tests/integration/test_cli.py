"""Integration tests for Typer CLI administration tool."""

from pathlib import Path

from typer.testing import CliRunner

from hids.cli.main import app
from hids.db.database import DatabaseManager
from hids.models.enums import EventCategory, MitreTactic, Severity
from hids.models.telemetry import Alert, HostEvent

runner = CliRunner()


def test_cli_help() -> None:
    """Test main CLI help command."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Host Intrusion Detection System" in result.output
    assert "fim-scan" in result.output
    assert "alerts" in result.output
    assert "events" in result.output
    assert "rules" in result.output


def test_cli_init_db(tmp_path: Path) -> None:
    """Test database initialization command."""
    db_file = tmp_path / "custom_init.db"
    result = runner.invoke(app, ["init-db", "--db-path", str(db_file)])
    assert result.exit_code == 0
    assert "Database successfully initialized" in result.output
    assert db_file.exists()


def test_cli_rules() -> None:
    """Test display of active detection rules."""
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "Active Detection Rules" in result.output
    assert "HIDS-RULE-001" in result.output
    assert "HIDS-RULE-003" in result.output


def test_cli_alerts_and_events(tmp_path: Path) -> None:
    """Test listing alerts and telemetry events via CLI."""
    db_file = tmp_path / "cli_test.db"
    db = DatabaseManager(db_file)
    db.init_db()

    # Empty states
    res_empty_alerts = runner.invoke(app, ["alerts", "--db-path", str(db_file)])
    assert res_empty_alerts.exit_code == 0
    assert "No alerts found" in res_empty_alerts.output

    res_empty_events = runner.invoke(app, ["events", "--db-path", str(db_file)])
    assert res_empty_events.exit_code == 0
    assert "No events found" in res_empty_events.output

    # Insert test data
    event = HostEvent(
        category=EventCategory.PROCESS_ACTIVITY,
        action="SUSPICIOUS_PATH",
        source_component="process_monitor",
        details={"pid": 9999, "path": "/tmp/evil"},
    )
    db.save_event(event)

    alert = Alert(
        rule_id="HIDS-PROC-001",
        rule_name="Binary in Suspicious Directory",
        severity=Severity.HIGH,
        mitre_tactic=MitreTactic.DEFENSE_EVASION,
        mitre_technique="T1036",
        category=EventCategory.PROCESS_ACTIVITY,
        description="Binary executed from /tmp",
        matched_event_id=event.event_id,
    )
    db.save_alert(alert)

    # Populate and check alerts
    res_alerts = runner.invoke(app, ["alerts", "--db-path", str(db_file)])
    assert res_alerts.exit_code == 0
    assert "HIDS-PROC-001" in res_alerts.output
    assert "Binary" in res_alerts.output

    # Test severity filtering
    res_high = runner.invoke(app, ["alerts", "--db-path", str(db_file), "--severity", "high"])
    assert res_high.exit_code == 0
    assert "HIDS-PROC-001" in res_high.output

    # Invalid severity
    res_invalid_sev = runner.invoke(
        app, ["alerts", "--db-path", str(db_file), "--severity", "bogus"]
    )
    assert res_invalid_sev.exit_code == 1

    # Check events listing
    res_events = runner.invoke(app, ["events", "--db-path", str(db_file)])
    assert res_events.exit_code == 0
    assert "SUSPICIOUS" in res_events.output


def test_cli_fim_scan(tmp_path: Path) -> None:
    """Test FIM scanning commands via CLI."""
    db_file = tmp_path / "fim_cli.db"
    scan_dir = tmp_path / "watch_target"
    scan_dir.mkdir()
    target_file = scan_dir / "monitored.conf"
    target_file.write_text("secret_config=true", encoding="utf-8")

    # Establish baseline with --update
    res_baseline = runner.invoke(
        app,
        ["fim-scan", str(scan_dir), "--db-path", str(db_file), "--update"],
    )
    assert res_baseline.exit_code == 0
    assert "Successfully saved baseline" in res_baseline.output

    # Scan unchanged
    res_unchanged = runner.invoke(
        app,
        ["fim-scan", str(scan_dir), "--db-path", str(db_file)],
    )
    assert res_unchanged.exit_code == 0
    assert "No changes detected" in res_unchanged.output

    # Modify file and detect changes
    target_file.write_text("tampered_config=false", encoding="utf-8")
    res_modified = runner.invoke(
        app,
        ["fim-scan", str(scan_dir), "--db-path", str(db_file)],
    )
    assert res_modified.exit_code == 0
    assert "MODIFIED" in res_modified.output
