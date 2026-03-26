"""Alerts tab — filterable alert list with detail panel."""

from __future__ import annotations

from typing import Any, Callable

import customtkinter as ctk

from src.ui.bridge import ThreadBridge
from src.ui.theme import (
    BG_CARD, BG_DARK, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY,
    SEVERITY_COLORS, STATUS_COLORS, FONT_TITLE, FONT_HEADING,
    FONT_BODY, FONT_SMALL, FONT_MONO, PAD_SECTION, PAD_WIDGET,
    ACCENT_BLUE, ACCENT_GREEN, ACCENT_RED, ACCENT_ORANGE,
)
from src.ui.widgets.severity_badge import SeverityBadge


class AlertsTab(ctk.CTkFrame):
    """Filterable alert table with expandable detail panel.

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

        self._build_header()
        self._build_filter_bar()
        self._build_alert_list()
        self._build_detail_panel()

    def _build_header(self) -> None:
        ctk.CTkLabel(
            self, text="Alerts", font=FONT_TITLE, text_color=TEXT_PRIMARY, anchor="w",
        ).pack(fill="x", padx=PAD_SECTION, pady=(PAD_SECTION, 5))

    def _build_filter_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x", padx=PAD_SECTION, pady=PAD_WIDGET)

        ctk.CTkLabel(bar, text="Severity:", font=FONT_SMALL, text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 5))
        self._sev_filter = ctk.CTkOptionMenu(
            bar, values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            command=lambda v: self._apply_filters(), width=110,
        )
        self._sev_filter.pack(side="left", padx=(0, 15))
        self._sev_filter.set("All")

        ctk.CTkLabel(bar, text="Status:", font=FONT_SMALL, text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 5))
        self._status_filter = ctk.CTkOptionMenu(
            bar, values=["All", "new", "investigating", "resolved", "false_positive"],
            command=lambda v: self._apply_filters(), width=110,
        )
        self._status_filter.pack(side="left", padx=(0, 15))
        self._status_filter.set("All")

        ctk.CTkLabel(bar, text="Search:", font=FONT_SMALL, text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 5))
        self._search_var = ctk.StringVar()
        self._search_var.trace_add("write", lambda *a: self._apply_filters())
        ctk.CTkEntry(bar, textvariable=self._search_var, width=200, placeholder_text="Filter by title, IP...").pack(side="left")

    def _build_alert_list(self) -> None:
        # Column headers
        hdr = ctk.CTkFrame(self, fg_color=BG_CARD, height=30)
        hdr.pack(fill="x", padx=PAD_SECTION, pady=(PAD_WIDGET, 0))
        for text, w in [("Sev", 80), ("Score", 50), ("Title", 350), ("Source IP", 130), ("Status", 100), ("Time", 160)]:
            ctk.CTkLabel(hdr, text=text, font=FONT_SMALL, text_color=TEXT_SECONDARY, width=w, anchor="w").pack(side="left", padx=2)

        self._list_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._list_frame.pack(fill="both", expand=True, padx=PAD_SECTION, pady=0)

    def _build_detail_panel(self) -> None:
        self._detail_frame = ctk.CTkFrame(self, fg_color=BG_CARD, border_color=BORDER_COLOR, border_width=1, corner_radius=8, height=200)
        self._detail_frame.pack(fill="x", padx=PAD_SECTION, pady=PAD_WIDGET)
        self._detail_frame.pack_propagate(False)

        self._detail_label = ctk.CTkLabel(
            self._detail_frame, text="Click an alert to view details",
            font=FONT_BODY, text_color=TEXT_SECONDARY,
        )
        self._detail_label.pack(pady=20)

        # Action buttons (hidden until alert selected)
        self._action_frame = ctk.CTkFrame(self._detail_frame, fg_color="transparent")

        self._btn_fp = ctk.CTkButton(
            self._action_frame, text="Mark False Positive", font=FONT_SMALL,
            fg_color=ACCENT_ORANGE, hover_color="#b8860b", width=160,
            command=self._mark_false_positive,
        )
        self._btn_fp.pack(side="left", padx=5)

        self._btn_respond = ctk.CTkButton(
            self._action_frame, text="Respond", font=FONT_SMALL,
            fg_color=ACCENT_RED, hover_color="#cc0033", width=100,
            command=self._respond_to_alert,
        )
        self._btn_respond.pack(side="left", padx=5)

    def add_alert(self, alert_data: dict[str, Any]) -> None:
        """Add a new alert to the list.

        Args:
            alert_data: Alert dictionary.
        """
        self._alerts.insert(0, alert_data)
        self._render_row(alert_data, position=0)

    def _apply_filters(self) -> None:
        """Rerender list based on current filters."""
        # Clear existing rows
        for widget in self._list_frame.winfo_children():
            widget.destroy()

        sev = self._sev_filter.get()
        status = self._status_filter.get()
        search = self._search_var.get().lower()

        for alert in self._alerts:
            if sev != "All" and alert.get("severity") != sev:
                continue
            if status != "All" and alert.get("status") != status:
                continue
            if search:
                searchable = f"{alert.get('title', '')} {alert.get('source_ip', '')} {alert.get('process_name', '')}".lower()
                if search not in searchable:
                    continue
            self._render_row(alert)

    def _render_row(self, alert: dict[str, Any], position: int | None = None) -> None:
        """Render a single alert row.

        Args:
            alert: Alert dictionary.
            position: Insert position (0=top). None=append.
        """
        existing_children = self._list_frame.winfo_children()

        row = ctk.CTkFrame(self._list_frame, fg_color="transparent", height=30, cursor="hand2")

        severity = alert.get("severity", "INFO")
        sev_color = SEVERITY_COLORS.get(severity, "#8b949e")

        SeverityBadge(row, severity).pack(side="left", padx=2)
        ctk.CTkLabel(row, text=str(alert.get("score", 0)), font=FONT_SMALL, text_color=sev_color, width=50, anchor="w").pack(side="left", padx=2)
        ctk.CTkLabel(row, text=alert.get("title", "")[:55], font=FONT_BODY, text_color=TEXT_PRIMARY, width=350, anchor="w").pack(side="left", padx=2)
        ctk.CTkLabel(row, text=alert.get("source_ip", "-"), font=FONT_SMALL, text_color=TEXT_SECONDARY, width=130, anchor="w").pack(side="left", padx=2)

        st = alert.get("status", "new")
        st_color = STATUS_COLORS.get(st, TEXT_SECONDARY)
        ctk.CTkLabel(row, text=st, font=FONT_SMALL, text_color=st_color, width=100, anchor="w").pack(side="left", padx=2)
        ctk.CTkLabel(row, text=alert.get("created_at", "")[:19], font=FONT_SMALL, text_color=TEXT_SECONDARY, width=160, anchor="w").pack(side="left", padx=2)

        row.bind("<Button-1>", lambda e, a=alert: self._select_alert(a))
        for child in row.winfo_children():
            child.bind("<Button-1>", lambda e, a=alert: self._select_alert(a))

        if position == 0 and existing_children:
            try:
                row.pack(fill="x", pady=1, before=existing_children[0])
            except Exception:
                row.pack(fill="x", pady=1)
        else:
            row.pack(fill="x", pady=1)

    def _select_alert(self, alert: dict[str, Any]) -> None:
        """Show alert details in the detail panel."""
        self._selected_alert = alert
        self._detail_label.configure(text="")

        for w in self._detail_frame.winfo_children():
            if w not in (self._detail_label, self._action_frame):
                w.destroy()

        info_frame = ctk.CTkFrame(self._detail_frame, fg_color="transparent")
        info_frame.pack(fill="x", padx=PAD_SECTION, pady=5)

        text_parts = [
            f"Title: {alert.get('title', 'N/A')}",
            f"Severity: {alert.get('severity')} | Score: {alert.get('score')}/100",
            f"Description: {alert.get('description', 'N/A')}",
        ]
        if alert.get("source_ip"):
            text_parts.append(f"Source: {alert['source_ip']}:{alert.get('source_port', '?')}")
        if alert.get("dest_ip"):
            text_parts.append(f"Dest: {alert['dest_ip']}:{alert.get('dest_port', '?')}")
        if alert.get("process_name"):
            text_parts.append(f"Process: {alert['process_name']} (PID {alert.get('process_pid', '?')})")

        detail_text = ctk.CTkTextbox(info_frame, font=FONT_MONO, height=100, fg_color=BG_DARK)
        detail_text.pack(fill="x")
        detail_text.insert("1.0", "\n".join(text_parts))
        detail_text.configure(state="disabled")

        self._action_frame.pack(fill="x", padx=PAD_SECTION, pady=5)

    def _mark_false_positive(self) -> None:
        """Mark the selected alert as false positive."""
        if not self._selected_alert:
            return
        self._bridge.send_command("mark_false_positive", {
            "alert_uid": self._selected_alert.get("alert_uid"),
        })

    def _respond_to_alert(self) -> None:
        """Switch to the response tab for the selected alert."""
        # This could emit an event to switch tabs — simplified for now
        if not self._selected_alert:
            return
        self._bridge.send_command("execute_response", {
            "alert_uid": self._selected_alert.get("alert_uid"),
            "response_type": "report_only",
            "params": {},
        })
