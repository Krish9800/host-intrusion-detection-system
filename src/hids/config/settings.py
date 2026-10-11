"""Runtime configuration settings for HIDS agent."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application and detection agent operational settings."""

    model_config = SettingsConfigDict(
        env_prefix="HIDS_",
        env_file=".env",
        extra="ignore",
    )

    # General agent configuration
    agent_id: str = "hids-agent-01"
    environment: str = "production"
    log_level: str = "INFO"

    # Persistent Storage
    db_path: Path = Path("data/hids.db")

    # File Integrity Monitoring (FIM)
    fim_paths_to_watch: list[Path] = [
        Path("/etc"),
        Path("/bin"),
        Path("/sbin"),
        Path("/usr/bin"),
        Path("/usr/sbin"),
    ]
    fim_scan_interval_seconds: int = 60
    fim_ignore_patterns: list[str] = [
        "*.swp",
        "*.tmp",
        "*~",
        "/etc/mtab",
        "/etc/resolv.conf",
    ]

    # Process Anomaly Detection
    process_scan_interval_seconds: int = 10
    suspicious_exec_directories: list[str] = [
        "/tmp",  # nosec B108
        "/var/tmp",  # nosec B108
        "/dev/shm",  # nosec B108
    ]

    masquerading_targets: list[str] = [
        "systemd",
        "sshd",
        "cron",
        "bash",
        "sh",
    ]

    # Auth Log Parsing
    auth_log_path: Path = Path("/var/log/auth.log")
    failed_login_threshold: int = 5
    failed_login_window_seconds: int = 60

    # API Control Plane
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    cors_origins: list[str] = ["*"]


settings = Settings()
