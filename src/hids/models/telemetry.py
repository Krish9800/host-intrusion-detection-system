"""Host telemetry events, alerts, and detection rule models."""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from hids.models.enums import EventCategory, MitreTactic, Severity


class FileIntegrityRecord(BaseModel):
    """Cryptographic baseline or observed record for a monitored host file."""

    file_path: Path
    sha256_hash: str
    size_bytes: int
    mode_permissions: str
    owner_uid: int
    group_gid: int
    modified_time: datetime
    is_directory: bool = False


class ProcessRecord(BaseModel):
    """Snapshot of an active or spawned process observed on the host."""

    pid: int
    ppid: int | None = None
    name: str
    exe_path: str | None = None
    cmdline: list[str] = Field(default_factory=list)
    username: str | None = None
    status: str = "running"
    created_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    connections: list[dict[str, Any]] = Field(default_factory=list)


class AuthLogRecord(BaseModel):
    """Parsed structured security authentication event from system logs."""

    timestamp: datetime
    service: str  # sshd, sudo, su, login
    event_type: str  # login_failed, login_success, sudo_command
    username: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    message: str
    raw_log: str


class HostEvent(BaseModel):
    """Unified telemetry observation event emitted by collectors."""

    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    category: EventCategory
    host_id: str = "localhost"
    action: str
    source_component: str
    details: dict[str, Any] = Field(default_factory=dict)
    fim_record: FileIntegrityRecord | None = None
    process_record: ProcessRecord | None = None
    auth_record: AuthLogRecord | None = None


class DetectionRule(BaseModel):
    """Sigma-inspired signature or heuristic detection rule."""

    rule_id: str
    name: str
    description: str
    category: EventCategory
    severity: Severity
    mitre_tactic: MitreTactic
    mitre_technique: str  # e.g., T1036.005, T1110
    enabled: bool = True
    conditions: dict[str, Any] = Field(default_factory=dict)


class Alert(BaseModel):
    """High-fidelity security finding generated when an event matches a detection rule."""

    alert_id: str = Field(default_factory=lambda: f"alt-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    rule_id: str
    rule_name: str
    severity: Severity
    mitre_tactic: MitreTactic
    mitre_technique: str
    category: EventCategory
    description: str
    matched_event_id: str
    host_id: str = "localhost"
    evidence: dict[str, Any] = Field(default_factory=dict)
    acknowledged: bool = False
