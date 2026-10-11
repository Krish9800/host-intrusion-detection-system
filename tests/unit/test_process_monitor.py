"""Unit tests for process telemetry monitor and anomaly detector."""

from hids.collectors.process import ProcessMonitor
from hids.models.enums import EventCategory
from hids.models.telemetry import ProcessRecord


def test_detect_suspicious_directory_execution() -> None:
    monitor = ProcessMonitor()
    proc_data = {
        "pid": 5555,
        "name": "miner",
        "exe": "/tmp/miner",  # nosec B108
        "cmdline": ["/tmp/miner", "--daemon"],  # nosec B108
    }

    anomalies = monitor.analyze_process(proc_data)
    assert len(anomalies) >= 1
    types = [a.anomaly_type for a in anomalies]
    assert "SUSPICIOUS_DIRECTORY_EXECUTION" in types


def test_detect_process_masquerading() -> None:
    monitor = ProcessMonitor()
    proc_data = {
        "pid": 9999,
        "name": "systemd",
        "exe": "/home/user/.hidden/systemd",
        "cmdline": ["systemd"],
    }

    anomalies = monitor.analyze_process(proc_data)
    types = [a.anomaly_type for a in anomalies]
    assert "PROCESS_MASQUERADING" in types


def test_detect_unauthorized_child_shell_from_web_daemon() -> None:
    monitor = ProcessMonitor()
    proc_data = {
        "pid": 8888,
        "name": "sh",
        "exe": "/bin/sh",
        "cmdline": ["sh", "-i"],
        "ppid_name": "nginx",
    }

    anomalies = monitor.analyze_process(proc_data)
    types = [a.anomaly_type for a in anomalies]
    assert "UNAUTHORIZED_CHILD_SHELL" in types
    assert "REVERSE_SHELL_DETECTED" in types


def test_create_host_event_from_process_anomaly() -> None:
    monitor = ProcessMonitor()
    rec = ProcessRecord(
        pid=123,
        name="malware",
        exe_path="/dev/shm/payload",  # nosec B108
        cmdline=["/dev/shm/payload"],  # nosec B108
    )
    anomalies = monitor.analyze_process(
        {
            "pid": rec.pid,
            "name": rec.name,
            "exe": rec.exe_path,
            "cmdline": rec.cmdline,
        }
    )
    event = monitor.create_host_event(rec, anomalies[0])

    assert event.category == EventCategory.PROCESS_ACTIVITY
    assert event.action == "SUSPICIOUS_DIRECTORY_EXECUTION"
    assert event.details["pid"] == 123


def test_collect_live_processes() -> None:
    monitor = ProcessMonitor()
    procs = monitor.collect_live_processes()

    # The running test runner itself should appear in live processes
    assert len(procs) > 0
    names = [p.name for p in procs]
    assert any("python" in n.lower() or "pytest" in n.lower() for n in names)
