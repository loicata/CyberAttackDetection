"""Rich-based console dashboard for real-time alert monitoring."""

from __future__ import annotations

import logging
from typing import Any

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.core.enums import AlertSeverity, AlertStatus, DetectorState

logger = logging.getLogger(__name__)

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

STATUS_COLORS = {
    "new": "bold white",
    "investigating": "yellow",
    "resolved": "green",
    "false_positive": "dim",
}


def print_banner() -> None:
    """Display the application startup banner."""
    banner = Text()
    banner.append("  Cyber Attack Detection v1.0.1\n", style="bold red")
    banner.append("  Real-time intrusion detection & response\n", style="dim")
    console.print(Panel(banner, border_style="red"))


def print_alert(alert_data: dict[str, Any]) -> None:
    """Display a new alert notification.

    Args:
        alert_data: Alert information dictionary.
    """
    severity = alert_data.get("severity", "INFO")
    color = SEVERITY_COLORS.get(severity, "white")

    table = Table(show_header=False, border_style=color, expand=True)
    table.add_column("Field", style="bold")
    table.add_column("Value")

    table.add_row("Alert", alert_data.get("title", "Unknown"))
    table.add_row("Severity", Text(severity, style=color))
    table.add_row("Score", f"{alert_data.get('score', 0)}/100")
    table.add_row("Type", alert_data.get("alert_type", "Unknown"))

    if alert_data.get("source_ip"):
        src = f"{alert_data['source_ip']}"
        if alert_data.get("source_port"):
            src += f":{alert_data['source_port']}"
        table.add_row("Source", src)

    if alert_data.get("dest_ip"):
        dst = f"{alert_data['dest_ip']}"
        if alert_data.get("dest_port"):
            dst += f":{alert_data['dest_port']}"
        table.add_row("Destination", dst)

    if alert_data.get("process_name"):
        table.add_row(
            "Process",
            f"{alert_data['process_name']} (PID {alert_data.get('process_pid', '?')})",
        )

    table.add_row("Description", alert_data.get("description", ""))

    console.print(Panel(table, title=f"[{color}]ALERT[/{color}]", border_style=color))


def print_alert_table(alerts: list[dict[str, Any]]) -> None:
    """Display a table of recent alerts.

    Args:
        alerts: List of alert dictionaries.
    """
    table = Table(title="Recent Alerts", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Score", width=6)
    table.add_column("Title", min_width=30)
    table.add_column("Source IP", width=16)
    table.add_column("Status", width=14)
    table.add_column("Time", width=20)

    for idx, alert in enumerate(alerts, 1):
        severity = alert.get("severity", "INFO")
        status = alert.get("status", "new")
        sev_color = SEVERITY_COLORS.get(severity, "white")
        stat_color = STATUS_COLORS.get(status, "white")

        table.add_row(
            str(idx),
            Text(severity, style=sev_color),
            str(alert.get("score", 0)),
            alert.get("title", "Unknown")[:50],
            alert.get("source_ip", "-"),
            Text(status, style=stat_color),
            alert.get("created_at", "")[:19],
        )

    console.print(table)


def print_detector_status(detectors: list[dict[str, object]]) -> None:
    """Display detector health status.

    Args:
        detectors: List of detector health check results.
    """
    table = Table(title="Detector Status")
    table.add_column("Detector", style="bold")
    table.add_column("State")
    table.add_column("Cycles", justify="right")
    table.add_column("Errors", justify="right")

    state_colors = {
        "running": "green",
        "stopped": "dim",
        "error": "red",
        "starting": "yellow",
    }

    for det in detectors:
        state = str(det.get("state", "unknown"))
        color = state_colors.get(state, "white")
        table.add_row(
            str(det.get("name", "unknown")),
            Text(state, style=color),
            str(det.get("cycle_count", 0)),
            str(det.get("error_count", 0)),
        )

    console.print(table)


def print_response_menu(actions: list[dict[str, str]]) -> None:
    """Display available response actions.

    Args:
        actions: List of action type/description pairs.
    """
    table = Table(title="Available Response Actions")
    table.add_column("#", style="bold", width=4)
    table.add_column("Action")
    table.add_column("Description")

    for idx, action in enumerate(actions, 1):
        table.add_row(str(idx), action["type"], action["description"])

    console.print(table)
    console.print("[bold]Enter action number (0 to skip):[/bold]")


def print_intel_report(intel_data: dict[str, Any]) -> None:
    """Display threat intelligence results.

    Args:
        intel_data: Intel report data.
    """
    table = Table(title=f"Threat Intelligence: {intel_data.get('ip_address', '?')}")
    table.add_column("Source", style="bold")
    table.add_column("Result")

    if intel_data.get("reverse_dns"):
        table.add_row("Reverse DNS", ", ".join(intel_data["reverse_dns"]))

    if intel_data.get("whois_org"):
        table.add_row("WHOIS Org", intel_data["whois_org"])
    if intel_data.get("whois_country"):
        table.add_row("WHOIS Country", intel_data["whois_country"])

    if intel_data.get("geoip_country"):
        geo = f"{intel_data['geoip_country']}"
        if intel_data.get("geoip_city"):
            geo += f", {intel_data['geoip_city']}"
        table.add_row("GeoIP", geo)

    if intel_data.get("abuse_score") is not None:
        score = intel_data["abuse_score"]
        color = "red" if score > 50 else "yellow" if score > 20 else "green"
        table.add_row("AbuseIPDB Score", Text(f"{score}/100", style=color))
        table.add_row("AbuseIPDB Reports", str(intel_data.get("abuse_reports", 0)))

    if intel_data.get("virustotal_malicious") is not None:
        vt = intel_data["virustotal_malicious"]
        color = "red" if vt > 5 else "yellow" if vt > 0 else "green"
        table.add_row(
            "VirusTotal",
            Text(f"{vt} malicious / {intel_data.get('virustotal_total', '?')} total", style=color),
        )

    console.print(table)


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[bold green][OK][/bold green] {message}")


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"[bold red][ERROR][/bold red] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[bold yellow][WARN][/bold yellow] {message}")


def get_user_choice(prompt: str, max_option: int) -> int:
    """Get a numeric choice from the user.

    Args:
        prompt: Prompt message.
        max_option: Maximum valid option number.

    Returns:
        Selected option number (0 = skip).
    """
    while True:
        try:
            choice = console.input(f"[bold]{prompt}[/bold] ")
            num = int(choice.strip())
            if 0 <= num <= max_option:
                return num
            console.print(f"[red]Please enter 0-{max_option}[/red]")
        except (ValueError, EOFError):
            console.print("[red]Please enter a valid number[/red]")
