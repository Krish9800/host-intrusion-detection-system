"""Unit tests for Linux auth.log parsing and SSH brute-force detection."""

from datetime import UTC, datetime
from pathlib import Path

from hids.collectors.auth_log import AuthLogParser
from hids.models.enums import EventCategory


def test_parse_sshd_failed_login() -> None:
    line = (
        "Oct 11 14:22:01 web01 sshd[12345]: Failed password for invalid user admin "
        "from 198.51.100.23 port 54321 ssh2"
    )
    rec = AuthLogParser.parse_line(line, reference_year=2026)

    assert rec is not None
    assert rec.service == "sshd"
    assert rec.event_type == "login_failed"
    assert rec.username == "admin"
    assert rec.source_ip == "198.51.100.23"
    assert rec.source_port == 54321


def test_parse_sshd_accepted_login() -> None:
    line = (
        "Oct 11 14:25:30 web01 sshd[12349]: Accepted publickey for ubuntu "
        "from 198.51.100.55 port 42100 ssh2"
    )
    rec = AuthLogParser.parse_line(line, reference_year=2026)

    assert rec is not None
    assert rec.service == "sshd"
    assert rec.event_type == "login_success"
    assert rec.username == "ubuntu"
    assert rec.source_ip == "198.51.100.55"


def test_parse_sudo_command() -> None:
    line = (
        "Oct 11 14:30:00 web01 sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; "
        "USER=root ; COMMAND=/bin/cat /etc/shadow"
    )
    rec = AuthLogParser.parse_line(line, reference_year=2026)

    assert rec is not None
    assert rec.service == "sudo"
    assert rec.event_type == "sudo_command"
    assert rec.username == "ubuntu"
    assert "/etc/shadow" in rec.message


def test_detect_ssh_brute_force_sliding_window() -> None:
    now = datetime.now(UTC)
    records = []

    # 6 failed attempts from 203.0.113.1 within 30 seconds
    for i in range(6):
        raw = (
            f"Oct 11 15:00:{10 + i:02d} web01 sshd[100{i}]: "
            f"Failed password for root from 203.0.113.1 port 5000{i} ssh2"
        )
        records.append(AuthLogParser.parse_line(raw, reference_year=now.year))

    # 2 failed attempts from 198.51.100.2 (below threshold 5)
    for i in range(2):
        raw = (
            f"Oct 11 15:00:{10 + i:02d} web01 sshd[200{i}]: "
            f"Failed password for test from 198.51.100.2 port 4000{i} ssh2"
        )
        records.append(AuthLogParser.parse_line(raw, reference_year=now.year))

    valid_records = [r for r in records if r is not None]
    attacks = AuthLogParser.detect_ssh_brute_force(valid_records, threshold=5, window_seconds=60)

    assert len(attacks) == 1
    assert attacks[0]["source_ip"] == "203.0.113.1"
    assert attacks[0]["failed_attempts"] == 6


def test_parse_file_stream(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Oct 11 14:00:00 srv sshd[1]: Failed password for root from 1.1.1.1 port 111 ssh2\n"
        "Oct 11 14:00:05 srv sshd[2]: Accepted password for user from 2.2.2.2 port 222 ssh2\n"
        "Oct 11 14:00:10 srv kernel: Some kernel noise\n"
    )

    parsed = list(AuthLogParser.parse_file(log_file))
    assert len(parsed) == 2
    assert parsed[0].source_ip == "1.1.1.1"
    assert parsed[1].source_ip == "2.2.2.2"

    # Test event conversion
    event = AuthLogParser.create_host_event(parsed[0])
    assert event.category == EventCategory.AUTHENTICATION
    assert event.action == "login_failed"
