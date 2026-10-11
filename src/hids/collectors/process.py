"""Process telemetry collector and suspicious behavior detector."""

from datetime import UTC, datetime
from typing import Any

import psutil
from pydantic import BaseModel, Field

from hids.models.enums import EventCategory
from hids.models.telemetry import HostEvent, ProcessRecord


class ProcessAnomaly(BaseModel):
    """Identified process anomaly or suspicious indicator."""

    pid: int
    name: str
    anomaly_type: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class ProcessMonitor:
    """Monitors live host processes for masquerading, reverse shells, and anomalous paths."""

    def __init__(
        self,
        suspicious_directories: list[str] | None = None,
        masquerading_targets: list[str] | None = None,
    ) -> None:
        self.suspicious_directories = suspicious_directories or [
            "/tmp",  # nosec B108
            "/var/tmp",  # nosec B108
            "/dev/shm",  # nosec B108
        ]
        self.masquerading_targets = set(
            masquerading_targets or ["systemd", "sshd", "cron", "bash", "sh"]
        )

    @staticmethod
    def _is_suspicious_parent_child(ppid_name: str | None, name: str) -> bool:
        """Detect abnormal shells spawned by web daemons or database servers."""
        if not ppid_name:
            return False

        web_servers = {"apache2", "httpd", "nginx", "php-fpm", "caddy", "uwsgi"}
        shells = {"bash", "sh", "dash", "zsh", "python", "python3", "perl", "nc", "ncat", "netcat"}

        return bool(ppid_name in web_servers and name in shells)

    @staticmethod
    def _detect_reverse_shell_cmdline(cmdline: list[str]) -> bool:
        """Detect common reverse shell commands and one-liners."""
        joined = " ".join(cmdline).lower()
        indicators = [
            "/dev/tcp/",
            "nc -e",
            "ncat -e",
            "netcat -e",
            "sh -i",
            "bash -i",
            "pty.spawn",
            "socket.socket",
            "mkfifo /tmp",  # nosec B108
        ]
        return any(ind in joined for ind in indicators)

    def analyze_process(self, proc_data: dict[str, Any]) -> list[ProcessAnomaly]:
        """Analyze a process dictionary representation for anomalies."""
        anomalies: list[ProcessAnomaly] = []
        pid = proc_data.get("pid", 0)
        name = proc_data.get("name", "")
        exe = proc_data.get("exe") or ""
        cmdline = proc_data.get("cmdline") or []
        ppid_name = proc_data.get("ppid_name")

        # 1. Check execution out of suspicious / world-writable directories
        for s_dir in self.suspicious_directories:
            if exe.startswith(s_dir):
                anomalies.append(
                    ProcessAnomaly(
                        pid=pid,
                        name=name,
                        anomaly_type="SUSPICIOUS_DIRECTORY_EXECUTION",
                        description=f"Process executed out of untrusted directory '{s_dir}'",
                        evidence={"exe": exe, "cmdline": cmdline},
                    )
                )

        # 2. Check process masquerading (e.g. 'systemd' executed from /home or /tmp)
        if name in self.masquerading_targets and exe:
            valid_system_prefixes = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/")
            if not exe.startswith(valid_system_prefixes):
                anomalies.append(
                    ProcessAnomaly(
                        pid=pid,
                        name=name,
                        anomaly_type="PROCESS_MASQUERADING",
                        description=(
                            f"Process '{name}' executed from non-standard path '{exe}' "
                            f"(potential impersonation)"
                        ),
                        evidence={"exe": exe, "cmdline": cmdline},
                    )
                )

        # 3. Check web daemon spawning interactive shell
        if self._is_suspicious_parent_child(ppid_name, name):
            anomalies.append(
                ProcessAnomaly(
                    pid=pid,
                    name=name,
                    anomaly_type="UNAUTHORIZED_CHILD_SHELL",
                    description=(
                        f"Interactive shell '{name}' spawned by web daemon '{ppid_name}' "
                        f"(possible Remote Code Execution / Web Shell)"
                    ),
                    evidence={"ppid_name": ppid_name, "cmdline": cmdline},
                )
            )

        # 4. Check reverse shell payload signatures in cmdline
        if self._detect_reverse_shell_cmdline(cmdline):
            anomalies.append(
                ProcessAnomaly(
                    pid=pid,
                    name=name,
                    anomaly_type="REVERSE_SHELL_DETECTED",
                    description=f"Interactive reverse shell command string observed in PID {pid}",
                    evidence={"cmdline": cmdline},
                )
            )

        return anomalies

    def collect_live_processes(self) -> list[ProcessRecord]:
        """Scan active host processes via psutil."""
        records: list[ProcessRecord] = []
        for p in psutil.process_iter(
            attrs=["pid", "ppid", "name", "exe", "cmdline", "username", "status", "create_time"]
        ):
            try:
                info = p.info
                conns: list[dict[str, Any]] = []
                try:
                    for c in p.connections(kind="inet"):
                        conns.append(
                            {
                                "fd": c.fd,
                                "family": str(c.family),
                                "type": str(c.type),
                                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                                "status": c.status,
                            }
                        )
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                create_dt = (
                    datetime.fromtimestamp(info["create_time"], tz=UTC)
                    if info.get("create_time")
                    else datetime.now(UTC)
                )

                records.append(
                    ProcessRecord(
                        pid=info["pid"],
                        ppid=info.get("ppid"),
                        name=info.get("name") or "unknown",
                        exe_path=info.get("exe"),
                        cmdline=info.get("cmdline") or [],
                        username=info.get("username"),
                        status=info.get("status") or "running",
                        created_time=create_dt,
                        connections=conns,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return records

    def create_host_event(
        self, record: ProcessRecord, anomaly: ProcessAnomaly | None = None
    ) -> HostEvent:
        """Create a standardized HostEvent for a process observation or detected anomaly."""
        action = anomaly.anomaly_type if anomaly else "PROCESS_SPAWNED"
        details: dict[str, Any] = {
            "pid": record.pid,
            "name": record.name,
            "exe": record.exe_path,
            "cmdline": record.cmdline,
        }
        if anomaly:
            details["anomaly"] = anomaly.model_dump()

        return HostEvent(
            category=EventCategory.PROCESS_ACTIVITY,
            action=action,
            source_component="process_monitor",
            process_record=record,
            details=details,
        )
