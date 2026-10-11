# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-11

### Added
- **Core Architecture & Models**: Unified telemetry observation events, MITRE ATT&CK tactics, and severity levels.
- **Cryptographic File Integrity Monitoring (FIM)**: SHA-256 baseline hashing, permission tracking, recursive scanning, and baseline delta detection.
- **Process Anomaly Heuristics**: Detection of binaries executing from `/tmp`, masqueraded system binaries (`kworker`, `sshd`), and interactive shells spawned by web server daemons (`nginx`, `apache2`).
- **Linux Auth.log Parser**: Regex-based syslog parsing for sshd login failures/successes, sudo elevation, and sliding-window SSH brute-force detection.
- **Detection & Correlation Engine**: Sigma-inspired rules with ATT&CK matrix tagging (Credential Access, Defense Evasion, Execution, Persistence).
- **SQLite WAL Persistence**: Thread-safe database engine storing host events, security alerts, and FIM file baselines.
- **FastAPI Control Plane**: REST endpoints for health checks, alert triage, telemetry querying, and FIM baselines.
- **Typer CLI Administration Tool**: Command-line interface with `init-db`, `fim-scan`, `alerts`, `events`, and `rules` commands.
- **Hardening & Threat Model**: Multi-stage rootless Dockerfile (UID 10001), STRIDE threat model, and adversarial testbed.
