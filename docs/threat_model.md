# STRIDE Threat Model: Host Intrusion Detection System (HIDS)

## 1. System Overview
The Host Intrusion Detection System (HIDS) is designed to run on endpoint Linux servers to monitor file system integrity, process lifecycles, and authentication logs, evaluating all signals against Sigma and heuristic rules mapped to the MITRE ATT&CK framework.

```
+-----------------------------------------------------------------------------------------+
|                                    Monitored Host                                       |
|                                                                                         |
|  +--------------------+   +---------------------+   +--------------------------------+  |
|  | File Integrity Mon |   | Process Anomaly Mon |   | Linux Auth.log Parser         |  |
|  | (SHA-256 Hashes)   |   | (psutil / procfs)   |   | (SSH Brute Force Correlator)   |  |
|  +---------+----------+   +----------+----------+   +---------------+----------------+  |
|            |                         |                              |                   |
|            +-------------------------+------------------------------+                   |
|                                      | Host Events                                      |
|                                      v                                                  |
|                       +-----------------------------+                                   |
|                       |   Detection Engine (Sigma)  |                                   |
|                       +--------------+--------------+                                   |
|                                      | High-Fidelity Alerts                             |
|                                      v                                                  |
|                       +-----------------------------+                                   |
|                       |   SQLite WAL Store (Local)  |                                   |
|                       +--------------+--------------+                                   |
|                                      |                                                  |
|                      +---------------+---------------+                                  |
|                      v                               v                                  |
|         +-------------------------+     +-------------------------+                     |
|         |  FastAPI Control Plane  |     |  Typer CLI Admin Tool   |                     |
|         |  (Port 8000, Read-Only) |     |  (`hids` command)       |                     |
|         +-------------------------+     +-------------------------+                     |
+-----------------------------------------------------------------------------------------+
```

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Potential Attack Vector | Impact | Mitigation Mechanism |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker injects fake authentication log lines to frame other users or induce alert fatigue. | High | Regex parsers validate timestamp sequences; syslog permissions prevent unprivileged log tampering. |
| **Tampering** | Attacker overwrites FIM baseline in SQLite database to conceal malware drop. | Critical | SQLite runs with strict file permissions (`600`); agent Docker container runs read-only filesystem with non-root UID 10001. |
| **Repudiation** | Attacker modifies critical files (`/etc/shadow`) and deletes logs. | High | Cryptographic SHA-256 baselines capture exact delta and timestamp prior to log purge. |
| **Information Disclosure** | Unauthorized users query REST API to view sensitive host file structures or alerts. | Medium | API binds to localhost (`127.0.0.1`) by default; container drops all capabilities (`cap_drop: ALL`). |
| **Denial of Service** | Process flooding or massive auth log generation exhausts agent memory / CPU. | Medium | Sliding window limits brute force cache size (max 10,000 IPs); WAL mode prevents database lock contention. |
| **Elevation of Privilege** | Vulnerability in HIDS agent exploited to gain root shell. | Critical | Agent operates with `no-new-privileges: true`, non-root user UID 10001, and read-only host mounts. |

---

## 3. Security Hardening Controls
- **Rootless Containerization:** Dockerfile provisions dedicated unprivileged user (`hids`, UID 10001).
- **WAL Persistence:** SQLite Write-Ahead Logging ensures crash resilience and concurrent reads without blocking writes.
- **Strict Typing & Linting:** 100% strictly typed (`mypy --strict`), PEP 8 compliant, automated SAST scan (`bandit`).
