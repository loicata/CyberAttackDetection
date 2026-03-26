"""Response tab — execute response actions and manage rollbacks."""

from __future__ import annotations

from typing import Any

import customtkinter as ctk

from src.ui.bridge import ThreadBridge
from src.ui.theme import (
    BG_CARD, BG_DARK, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY,
    SEVERITY_COLORS, ACCENT_BLUE, ACCENT_GREEN, ACCENT_RED, ACCENT_ORANGE,
    FONT_TITLE, FONT_HEADING, FONT_BODY, FONT_SMALL,
    PAD_SECTION, PAD_WIDGET,
)
from src.ui.widgets.confirmation_dialog import ConfirmationDialog
from src.ui.widgets.severity_badge import SeverityBadge


class ResponseTab(ctk.CTkFrame):
    """Execute response actions for alerts and manage rollback history.

    Args:
        master: Parent widget.
        bridge: Thread communication bridge.
    """

    def __init__(
        self, master: ctk.CTkBaseClass, bridge: ThreadBridge, **kwargs: object
    ) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self._bridge = bridge
        self._alerts: list[dict[str, Any]] = []
        self._selected_alert: dict[str, Any] | None = None
        self._response_history: list[dict[str, Any]] = []

        self._build_ui()

    def _build_ui(self) -> None:
        ctk.CTkLabel(
            self, text="Response", font=FONT_TITLE, text_color=TEXT_PRIMARY, anchor="w",
        ).pack(fill="x", padx=PAD_SECTION, pady=(PAD_SECTION, 5))

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=PAD_SECTION, pady=PAD_WIDGET)
        content.columnconfigure(0, weight=1)
        content.columnconfigure(1, weight=2)
        content.rowconfigure(0, weight=1)

        # Left: alert selector
        left = ctk.CTkFrame(content, fg_color=BG_CARD, border_color=BORDER_COLOR, border_width=1, corner_radius=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, PAD_WIDGET))

        ctk.CTkLabel(left, text="Actionable Alerts", font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(padx=5, pady=5)

        self._alert_scroll = ctk.CTkScrollableFrame(left, fg_color="transparent")
        self._alert_scroll.pack(fill="both", expand=True, padx=2, pady=2)

        # Right: actions + history
        right = ctk.CTkFrame(content, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        # Actions panel
        actions_panel = ctk.CTkFrame(right, fg_color=BG_CARD, border_color=BORDER_COLOR, border_width=1, corner_radius=8)
        actions_panel.grid(row=0, column=0, sticky="nsew", pady=(0, PAD_WIDGET))

        ctk.CTkLabel(actions_panel, text="Available Actions", font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(padx=5, pady=5)

        self._actions_frame = ctk.CTkScrollableFrame(actions_panel, fg_color="transparent")
        self._actions_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self._no_action_label = ctk.CTkLabel(
            self._actions_frame, text="Select an alert to see available actions",
            font=FONT_BODY, text_color=TEXT_SECONDARY,
        )
        self._no_action_label.pack(pady=20)

        # History panel
        history_panel = ctk.CTkFrame(right, fg_color=BG_CARD, border_color=BORDER_COLOR, border_width=1, corner_radius=8)
        history_panel.grid(row=1, column=0, sticky="nsew")

        ctk.CTkLabel(history_panel, text="Response History", font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(padx=5, pady=5)

        self._history_frame = ctk.CTkScrollableFrame(history_panel, fg_color="transparent")
        self._history_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Status bar
        self._status_label = ctk.CTkLabel(
            self, text="", font=FONT_SMALL, text_color=TEXT_SECONDARY,
        )
        self._status_label.pack(fill="x", padx=PAD_SECTION, pady=(0, PAD_WIDGET))

    def add_alert(self, alert_data: dict[str, Any]) -> None:
        """Add an alert to the selector (only HIGH/CRITICAL).

        Args:
            alert_data: Alert dictionary.
        """
        severity = alert_data.get("severity", "INFO")
        if severity not in ("HIGH", "CRITICAL"):
            return

        self._alerts.insert(0, alert_data)
        self._render_alert_button(alert_data)

    def _render_alert_button(self, alert: dict[str, Any]) -> None:
        """Render an alert selection button."""
        severity = alert.get("severity", "INFO")
        sev_color = SEVERITY_COLORS.get(severity, TEXT_SECONDARY)

        btn = ctk.CTkButton(
            self._alert_scroll,
            text=f"[{severity}] {alert.get('title', '')[:40]}",
            font=FONT_SMALL,
            text_color=sev_color,
            fg_color=BG_DARK, hover_color=BORDER_COLOR,
            anchor="w",
            command=lambda a=alert: self._select_alert(a),
        )
        btn.pack(fill="x", pady=1)

    def _select_alert(self, alert: dict[str, Any]) -> None:
        """Show available actions for the selected alert."""
        self._selected_alert = alert

        for w in self._actions_frame.winfo_children():
            w.destroy()

        # Alert info
        info = ctk.CTkLabel(
            self._actions_frame,
            text=f"{alert.get('title', 'N/A')} (Score: {alert.get('score', 0)}/100)",
            font=FONT_BODY, text_color=TEXT_PRIMARY, anchor="w",
        )
        info.pack(fill="x", pady=(0, 10))

        # Action buttons
        actions = self._get_available_actions(alert)
        for action in actions:
            color_map = {
                "block_ip": ACCENT_RED,
                "kill_process": ACCENT_RED,
                "quarantine_file": ACCENT_ORANGE,
                "isolate_network": ACCENT_RED,
                "report_only": ACCENT_BLUE,
            }
            color = color_map.get(action["type"], ACCENT_BLUE)

            btn = ctk.CTkButton(
                self._actions_frame,
                text=action["description"],
                font=FONT_BODY,
                fg_color=color, hover_color=color,
                anchor="w", height=40,
                command=lambda a=action: self._confirm_action(a),
            )
            btn.pack(fill="x", pady=3)

    def _get_available_actions(self, alert: dict[str, Any]) -> list[dict[str, str]]:
        """Determine available actions for an alert."""
        actions: list[dict[str, str]] = []

        ip = alert.get("source_ip") or alert.get("dest_ip")
        if ip:
            actions.append({"type": "block_ip", "description": f"Block IP {ip} via Firewall", "ip": ip})

        if alert.get("process_pid"):
            actions.append({
                "type": "kill_process",
                "description": f"Kill {alert.get('process_name', '?')} (PID {alert['process_pid']})",
                "pid": str(alert["process_pid"]),
            })

        if alert.get("file_path"):
            actions.append({
                "type": "quarantine_file",
                "description": f"Quarantine {alert['file_path']}",
                "file_path": alert["file_path"],
            })

        actions.append({"type": "isolate_network", "description": "Emergency: Disable Network Adapter"})
        actions.append({"type": "report_only", "description": "Generate Report Only (no action)"})

        return actions

    def _confirm_action(self, action: dict[str, str]) -> None:
        """Show confirmation dialog before executing."""
        danger = action["type"] in ("kill_process", "isolate_network", "block_ip")

        ConfirmationDialog(
            master=self.winfo_toplevel(),
            title=f"Confirm: {action['type'].replace('_', ' ').title()}",
            message=action["description"],
            on_confirm=lambda: self._execute_action(action),
            danger=danger,
        )

    def _execute_action(self, action: dict[str, str]) -> None:
        """Send the action command to the engine."""
        if not self._selected_alert:
            return

        params: dict[str, Any] = {}
        if action.get("ip"):
            params["ip"] = action["ip"]
        if action.get("pid"):
            params["pid"] = int(action["pid"])
        if action.get("file_path"):
            params["file_path"] = action["file_path"]

        self._bridge.send_command("execute_response", {
            "alert_uid": self._selected_alert.get("alert_uid"),
            "response_type": action["type"],
            "params": params,
        })

        self._add_history_entry(action["type"], "pending")
        self._status_label.configure(text=f"Executing: {action['type']}...", text_color=ACCENT_BLUE)

    def _add_history_entry(self, action_type: str, status: str) -> None:
        """Add an entry to the response history display."""
        row = ctk.CTkFrame(self._history_frame, fg_color="transparent")
        row.pack(fill="x", pady=1)

        status_colors = {"pending": ACCENT_BLUE, "executed": ACCENT_GREEN, "failed": ACCENT_RED, "rolled_back": ACCENT_ORANGE}
        color = status_colors.get(status, TEXT_SECONDARY)

        ctk.CTkLabel(row, text=action_type, font=FONT_SMALL, text_color=TEXT_PRIMARY, width=130, anchor="w").pack(side="left", padx=2)
        ctk.CTkLabel(row, text=status, font=FONT_SMALL, text_color=color, width=80, anchor="w").pack(side="left", padx=2)

    def update_response_result(self, data: dict[str, Any]) -> None:
        """Update display after a response action completes.

        Args:
            data: Result dict with success, message.
        """
        success = data.get("success", False)
        message = data.get("message", "")
        if success:
            self._status_label.configure(text=f"Success: {message}", text_color=ACCENT_GREEN)
        else:
            self._status_label.configure(text=f"Failed: {message}", text_color=ACCENT_RED)
