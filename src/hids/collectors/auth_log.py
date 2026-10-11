"""Linux system and authentication log collector and parser."""

import re
from collections import defaultdict
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hids.models.enums import EventCategory
from hids.models.telemetry import AuthLogRecord, HostEvent


class AuthLogParser:
    """Parses Linux /var/log/auth.log or secure logs into structured AuthLogRecord events."""

    # Regex patterns for SSH and sudo log events
    SSHD_FAILED_PATTERN = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
        r"sshd\[(?P<pid>\d+)\]:\s+Failed password for (?:invalid user )?(?P<user>\S+)\s+"
        r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port (?P<port>\d+)"
    )

    SSHD_ACCEPTED_PATTERN = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
        r"sshd\[(?P<pid>\d+)\]:\s+Accepted (?:password|publickey) for (?P<user>\S+)\s+"
        r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port (?P<port>\d+)"
    )

    SUDO_CMD_PATTERN = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
        r"sudo:\s+(?P<user>\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(?P<target_user>\S+)\s+;\s+"
        r"COMMAND=(?P<command>.*)$"
    )

    @classmethod
    def parse_line(cls, line: str, reference_year: int | None = None) -> AuthLogRecord | None:
        """Parse a single raw auth log entry into structured AuthLogRecord."""
        clean_line = line.strip()
        if not clean_line:
            return None

        now = datetime.now(UTC)
        year = reference_year or now.year

        # 1. Match failed SSH login
        m_failed = cls.SSHD_FAILED_PATTERN.match(clean_line)
        if m_failed:
            d = m_failed.groupdict()
            dt_str = f"{year} {d['month']} {d['day']} {d['time']}"
            try:
                dt = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
            except ValueError:
                dt = now

            return AuthLogRecord(
                timestamp=dt,
                service="sshd",
                event_type="login_failed",
                username=d["user"],
                source_ip=d["ip"],
                source_port=int(d["port"]),
                message=clean_line,
                raw_log=clean_line,
            )

        # 2. Match successful SSH login
        m_accepted = cls.SSHD_ACCEPTED_PATTERN.match(clean_line)
        if m_accepted:
            d = m_accepted.groupdict()
            dt_str = f"{year} {d['month']} {d['day']} {d['time']}"
            try:
                dt = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
            except ValueError:
                dt = now

            return AuthLogRecord(
                timestamp=dt,
                service="sshd",
                event_type="login_success",
                username=d["user"],
                source_ip=d["ip"],
                source_port=int(d["port"]),
                message=clean_line,
                raw_log=clean_line,
            )

        # 3. Match sudo command execution
        m_sudo = cls.SUDO_CMD_PATTERN.match(clean_line)
        if m_sudo:
            d = m_sudo.groupdict()
            dt_str = f"{year} {d['month']} {d['day']} {d['time']}"
            try:
                dt = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
            except ValueError:
                dt = now

            return AuthLogRecord(
                timestamp=dt,
                service="sudo",
                event_type="sudo_command",
                username=d["user"],
                message=f"sudo executed command: {d['command']} as {d['target_user']}",
                raw_log=clean_line,
            )

        return None

    @classmethod
    def parse_file(cls, log_file: Path) -> Iterator[AuthLogRecord]:
        """Stream and parse lines from a system log file."""
        if not log_file.is_file():
            return

        try:
            with open(log_file, encoding="utf-8", errors="replace") as f:
                for line in f:
                    rec = cls.parse_line(line)
                    if rec:
                        yield rec
        except (PermissionError, OSError):
            return

    @classmethod
    def detect_ssh_brute_force(
        cls,
        records: list[AuthLogRecord],
        threshold: int = 5,
        window_seconds: int = 60,
    ) -> list[dict[str, Any]]:
        """Identify IP addresses exceeding failed login threshold in a time window."""
        failed_by_ip: dict[str, list[datetime]] = defaultdict(list)

        for r in records:
            if r.service == "sshd" and r.event_type == "login_failed" and r.source_ip:
                failed_by_ip[r.source_ip].append(r.timestamp)

        attacks: list[dict[str, Any]] = []
        for ip, times in failed_by_ip.items():
            sorted_times = sorted(times)
            if len(sorted_times) >= threshold:
                # Sliding window check
                for i in range(len(sorted_times) - threshold + 1):
                    delta = (sorted_times[i + threshold - 1] - sorted_times[i]).total_seconds()
                    if delta <= window_seconds:
                        attacks.append(
                            {
                                "source_ip": ip,
                                "failed_attempts": len(sorted_times),
                                "window_seconds": window_seconds,
                                "first_seen": sorted_times[i].isoformat(),
                                "last_seen": sorted_times[i + threshold - 1].isoformat(),
                            }
                        )
                        break

        return attacks

    @classmethod
    def create_host_event(cls, record: AuthLogRecord) -> HostEvent:
        """Wrap an AuthLogRecord into a unified HostEvent."""
        return HostEvent(
            category=EventCategory.AUTHENTICATION,
            action=record.event_type,
            source_component="auth_log_parser",
            auth_record=record,
            details={
                "service": record.service,
                "username": record.username,
                "source_ip": record.source_ip,
                "event_type": record.event_type,
            },
        )
