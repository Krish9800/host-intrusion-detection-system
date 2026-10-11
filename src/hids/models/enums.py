"""Core domain enumerations for HIDS."""

from enum import StrEnum


class Severity(StrEnum):
    """Detection alert severity classification."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EventCategory(StrEnum):
    """Host telemetry event category."""

    FILE_INTEGRITY = "FILE_INTEGRITY"
    PROCESS_ACTIVITY = "PROCESS_ACTIVITY"
    AUTHENTICATION = "AUTHENTICATION"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    SYSTEM_CONFIGURATION = "SYSTEM_CONFIGURATION"


class FIMAction(StrEnum):
    """File integrity modification actions."""

    CREATED = "CREATED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"


class MitreTactic(StrEnum):
    """MITRE ATT&CK Enterprise Tactics."""

    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"
