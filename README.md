# Host Intrusion Detection System (HIDS)

[![HIDS Continuous Integration](https://github.com/krish/host-intrusion-detection-system/actions/workflows/ci.yml/badge.svg)](https://github.com/krish/host-intrusion-detection-system/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![Coverage](https://img.shields.io/badge/coverage-94%25-brightgreen.svg)]()
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: mypy](https://img.shields.io/badge/type%20checked-mypy%20strict-blue.svg)](https://mypy-lang.org/)

Production-grade, lightweight Host Intrusion Detection System (HIDS) agent written in Python 3.12, providing cryptographic file integrity monitoring, real-time process anomaly heuristics, Linux authentication log correlation, and MITRE ATT&CK-mapped alert triage.

---

## Key Features

1. **Cryptographic File Integrity Monitoring (FIM)**:
   - Chunked SHA-256 baseline hashing of monitored paths (`/etc`, `/bin`, `/sbin`).
   - Tracks file size, Unix permissions mode, ownership UID/GID, and modification timestamps.
   - Computes state deltas for added, modified, deleted, and permission-altered files.

2. **Process Anomaly & Threat Heuristics**:
   - Detects suspicious execution paths (`/tmp`, `/var/tmp`, `/dev/shm`).
   - Identifies masqueraded processes mimicking kernel threads (`[kworker]`, `[ksoftirqd]`).
   - Flags reverse shells spawned from web daemons (`apache2`, `nginx`, `www-data`).

3. **Authentication Log Correlation**:
   - Real-time regex parser for Linux `/var/log/auth.log` and `/var/log/secure`.
   - Stateful sliding-window SSH brute-force attack detection.
   - Sudo command auditing and privilege escalation tracking.

4. **Detection Engine & Correlation**:
   - Sigma-inspired rule definitions mapped directly to MITRE ATT&CK tactics (TA0001–TA0040).
   - Real-time event scoring and high-fidelity alert generation.

5. **Local Persistence Engine**:
   - High-throughput SQLite storage operating in Write-Ahead Logging (WAL) mode.
   - Indices on timestamps, severity, and event categories.

6. **REST Control Plane & CLI**:
   - FastAPI monitoring endpoints (`/health`, `/alerts`, `/events`, `/fim/baselines`).
   - Rich Typer CLI interface for operators and administrators.

---

## Architecture

```
[ Collectors (FIM, Process, Auth.log) ]
                 │
                 ▼ (HostEvent)
       [ Detection Engine ] ──(Sigma Rules)──► [ MITRE ATT&CK Alerts ]
                 │                                    │
                 └──────────────┬─────────────────────┘
                                ▼
                      [ SQLite WAL Store ]
                                │
                 ┌──────────────┴──────────────┐
                 ▼                             ▼
       [ FastAPI Control Plane ]      [ Typer CLI Agent ]
```

---

## Quickstart

### 1. Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. Initialize Database & Establish FIM Baseline
```bash
# Initialize SQLite database
hids init-db

# Establish baseline for target directory
hids fim-scan /etc --update

# Verify integrity
hids fim-scan /etc
```

### 3. Query Security Alerts & Telemetry
```bash
# View alerts
hids alerts --severity high

# View recent host events
hids events --limit 10

# Display detection rules
hids rules
```

### 4. Run REST Control Plane
```bash
uvicorn hids.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

---

## Security & Hardening
- **Rootless Container:** Executes as non-root UID 10001 with dropped Linux capabilities.
- **Threat Model:** Comprehensive STRIDE threat model available in [`docs/threat_model.md`](docs/threat_model.md).
- **SAST Verified:** Zero Bandit security findings and 100% strict Mypy compliance.

---

## License
MIT License - see `LICENSE` for details.
