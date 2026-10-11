from hids.models.enums import EventCategory, MitreTactic, Severity
from hids.models.telemetry import Alert, DetectionRule, HostEvent

BUILTIN_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="HIDS-RULE-001",
        name="Critical System File Modified",
        description="Detects modification to sensitive authentication or system configuration",
        category=EventCategory.FILE_INTEGRITY,
        severity=Severity.CRITICAL,
        mitre_tactic=MitreTactic.CREDENTIAL_ACCESS,
        mitre_technique="T1003.008",
        conditions={
            "paths": ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/pam.d"],
            "actions": ["MODIFIED", "DELETED"],
        },
    ),
    DetectionRule(
        rule_id="HIDS-RULE-002",
        name="Persistence via Crontab or Systemd",
        description="Detects creation or modification of cron tasks or systemd service units",
        category=EventCategory.FILE_INTEGRITY,
        severity=Severity.HIGH,
        mitre_tactic=MitreTactic.PERSISTENCE,
        mitre_technique="T1053.003",
        conditions={
            "path_prefixes": ["/etc/cron", "/var/spool/cron", "/etc/systemd/system"],
            "actions": ["CREATED", "MODIFIED"],
        },
    ),
    DetectionRule(
        rule_id="HIDS-RULE-003",
        name="Suspicious Directory Execution",
        description="Detects processes executing out of temporary or world-writable directories",
        category=EventCategory.PROCESS_ACTIVITY,
        severity=Severity.HIGH,
        mitre_tactic=MitreTactic.DEFENSE_EVASION,
        mitre_technique="T1036.005",
        conditions={
            "action": "SUSPICIOUS_DIRECTORY_EXECUTION",
        },
    ),
    DetectionRule(
        rule_id="HIDS-RULE-004",
        name="Process Masquerading Detected",
        description="Detects critical system daemon names executed outside valid PATH directories",
        category=EventCategory.PROCESS_ACTIVITY,
        severity=Severity.CRITICAL,
        mitre_tactic=MitreTactic.DEFENSE_EVASION,
        mitre_technique="T1036.004",
        conditions={
            "action": "PROCESS_MASQUERADING",
        },
    ),
    DetectionRule(
        rule_id="HIDS-RULE-005",
        name="Unauthorized Interactive Web Shell",
        description="Detects interactive shells spawned by web server daemons",
        category=EventCategory.PROCESS_ACTIVITY,
        severity=Severity.CRITICAL,
        mitre_tactic=MitreTactic.EXECUTION,
        mitre_technique="T1059.004",
        conditions={
            "action": "UNAUTHORIZED_CHILD_SHELL",
        },
    ),
    DetectionRule(
        rule_id="HIDS-RULE-006",
        name="SSH Brute Force Attack",
        description="Detects SSH credential stuffing or password brute force attempts",
        category=EventCategory.AUTHENTICATION,
        severity=Severity.HIGH,
        mitre_tactic=MitreTactic.CREDENTIAL_ACCESS,
        mitre_technique="T1110.001",
        conditions={
            "action": "login_failed",
            "service": "sshd",
        },
    ),
]


class DetectionEngine:
    """Evaluates telemetry events against loaded signature and correlation rules."""

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self.rules: dict[str, DetectionRule] = {}
        initial_rules = rules or BUILTIN_RULES
        for r in initial_rules:
            self.register_rule(r)

    def register_rule(self, rule: DetectionRule) -> None:
        """Register or update a detection rule."""
        self.rules[rule.rule_id] = rule

    def evaluate_event(self, event: HostEvent) -> list[Alert]:
        """Evaluate a single HostEvent against all enabled rules."""
        generated_alerts: list[Alert] = []

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            if rule.category != event.category:
                continue

            if self._matches_rule_conditions(rule, event):
                alert = Alert(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    category=rule.category,
                    description=f"{rule.description} [Observed: {event.action}]",
                    matched_event_id=event.event_id,
                    host_id=event.host_id,
                    evidence=event.details,
                )
                generated_alerts.append(alert)

        return generated_alerts

    def _matches_rule_conditions(self, rule: DetectionRule, event: HostEvent) -> bool:
        conds = rule.conditions

        # Category 1: FILE_INTEGRITY conditions
        if rule.category == EventCategory.FILE_INTEGRITY:
            file_path = event.details.get("file_path", "")
            action = event.action

            if "actions" in conds and action not in conds["actions"]:
                return False

            if "paths" in conds and any(
                file_path.endswith(p) or p in file_path for p in conds["paths"]
            ):
                return True

            return bool(
                "path_prefixes" in conds
                and any(file_path.startswith(prefix) for prefix in conds["path_prefixes"])
            )

        # Category 2: PROCESS_ACTIVITY conditions
        if rule.category == EventCategory.PROCESS_ACTIVITY:
            target_action = conds.get("action")
            return bool(target_action and event.action == target_action)

        # Category 3: AUTHENTICATION conditions
        if rule.category == EventCategory.AUTHENTICATION:
            target_action = conds.get("action")
            target_service = conds.get("service")
            event_service = event.details.get("service")

            if target_action and event.action != target_action:
                return False
            return not (target_service and event_service != target_service)

        return False
