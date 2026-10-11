"""Typer CLI command-line administration tool for HIDS."""

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from hids.collectors.fim import FileIntegrityScanner
from hids.config.settings import Settings
from hids.db.database import DatabaseManager
from hids.engine.detector import DetectionEngine
from hids.models.enums import Severity

app = typer.Typer(
    name="hids",
    help="Host Intrusion Detection System (HIDS) Command-Line Utility.",
    no_args_is_help=True,
)
console = Console()


def get_db(db_path: Path | None = None) -> DatabaseManager:
    """Instantiate and initialize database manager."""
    path = db_path or Settings().db_path
    db = DatabaseManager(path)
    db.init_db()
    return db


@app.command("init-db")
def init_database(
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database file path"),
) -> None:
    """Initialize database tables and indices."""
    db = get_db(db_path)
    console.print(f"[bold green]Database successfully initialized at:[/] {db.db_path}")


@app.command("fim-scan")
def fim_scan(
    watch_path: Path = typer.Argument(..., help="Directory or file path to scan"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database path"),
    update_baseline: bool = typer.Option(
        False, "--update", "-u", help="Store scanned files as baseline"
    ),
) -> None:
    """Scan directory and check against existing baseline or create baseline."""
    db = get_db(db_path)
    settings = Settings()
    scanner = FileIntegrityScanner(ignore_patterns=settings.fim_ignore_patterns)

    if update_baseline:
        records = scanner.scan_directory(watch_path)
        db.save_fim_baseline(records)
        console.print(
            f"[bold green]Successfully saved baseline with {len(records)} files to database.[/]"
        )
        return

    stored_baseline = db.load_fim_baseline()
    if not stored_baseline:
        console.print("[yellow]No baseline found in database. Establishing initial baseline.[/]")
        records = scanner.scan_directory(watch_path)
        db.save_fim_baseline(records)
        console.print(f"[green]Initialized baseline with {len(records)} files.[/]")
        return

    current_records = scanner.scan_directory(watch_path)
    changes = scanner.compare_baselines(stored_baseline, current_records)
    if not changes:
        console.print("[bold green]FIM check complete: No changes detected.[/]")
        return

    table = Table(title="File Integrity Monitoring Changes Detected")
    table.add_column("Action", style="bold red")
    table.add_column("Path", style="cyan")
    table.add_column("SHA-256 Hash", style="magenta")
    table.add_column("Size (Bytes)", justify="right")

    for c in changes:
        rec = c.current_record or c.previous_record
        sha_str = rec.sha256_hash[:16] + "..." if (rec and rec.sha256_hash) else "DELETED"
        size_str = str(rec.size_bytes) if rec else "0"
        table.add_row(
            c.action.value,
            str(c.file_path),
            sha_str,
            size_str,
        )

    console.print(table)


@app.command("alerts")
def list_alerts(
    severity: str = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    limit: int = typer.Option(50, "--limit", "-l", help="Max alerts to display"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database path"),
) -> None:
    """List intrusion alerts recorded in the database."""
    db = get_db(db_path)
    sev_filter = None
    if severity:
        try:
            sev_filter = Severity(severity.upper())
        except ValueError:
            console.print(f"[red]Error: Invalid severity '{severity}'.[/]")
            raise typer.Exit(code=1) from None

    alerts = db.list_alerts(severity=sev_filter, limit=limit)
    if not alerts:
        console.print("[dim]No alerts found matching criteria.[/]")
        return

    table = Table(title=f"Recorded Intrusion Alerts (Showing {len(alerts)})")
    table.add_column("Timestamp", style="dim")
    table.add_column("Severity", style="bold")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("MITRE Tactic", style="magenta")

    for a in alerts:
        sev_color = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "bright_red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "green",
        }.get(a.severity, "white")

        table.add_row(
            a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            f"[{sev_color}]{a.severity.value}[/{sev_color}]",
            a.rule_id,
            a.description,
            f"{a.mitre_tactic.value} ({a.mitre_technique})",
        )

    console.print(table)


@app.command("events")
def list_events(
    limit: int = typer.Option(20, "--limit", "-l", help="Number of recent events to display"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database path"),
) -> None:
    """View recent telemetry events captured on the host."""
    db = get_db(db_path)
    events = db.list_events(limit=limit)
    if not events:
        console.print("[dim]No events found in database.[/]")
        return

    table = Table(title=f"Recent Telemetry Events ({len(events)})")
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("Category", style="cyan")
    table.add_column("Action", style="bold yellow")
    table.add_column("Source", style="magenta")
    table.add_column("Details", style="white")

    for e in events:
        details_str = json.dumps(e.details)
        if len(details_str) > 60:
            details_str = details_str[:57] + "..."
        table.add_row(
            e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            e.category.value,
            e.action,
            e.source_component,
            details_str,
        )

    console.print(table)


@app.command("rules")
def show_rules() -> None:
    """Display installed Sigma and heuristic detection rules."""
    engine = DetectionEngine()
    table = Table(title=f"Active Detection Rules ({len(engine.rules)})")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Name", style="bold white")
    table.add_column("Severity", style="bold")
    table.add_column("MITRE Tactic", style="magenta")
    table.add_column("Technique", style="yellow")

    for r in engine.rules.values():
        sev_color = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "bright_red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "green",
        }.get(r.severity, "white")
        table.add_row(
            r.rule_id,
            r.name,
            f"[{sev_color}]{r.severity.value}[/{sev_color}]",
            r.mitre_tactic.value,
            r.mitre_technique,
        )

    console.print(table)


if __name__ == "__main__":
    app()
