"""Dashboard tab — real-time overview of detection status."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

import customtkinter as ctk

from src.ui.theme import (
    BG_DARK, BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY,
    SEVERITY_COLORS, FONT_TITLE, FONT_HEADING, FONT_BODY, FONT_SMALL,
    FONT_MONO, PAD_SECTION, PAD_WIDGET, ACCENT_GREEN, ACCENT_BLUE,
    ACCENT_RED, ACCENT_ORANGE, ACCENT_CYAN,
)
from src.ui.widgets.stat_counter import StatCounter
from src.ui.widgets.detector_indicator import DetectorIndicator
from src.ui.widgets.alert_card import AlertCard

MAX_RECENT_ALERTS = 30
MAX_LOG_LINES = 100


class DashboardTab(ctk.CTkFrame):
    """Real-time dashboard showing detectors, counters, recent alerts, and live log.

    Args:
        master: Parent widget.
    """

    def __init__(self, master: ctk.CTkBaseClass, **kwargs: object) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self._start_time = time.time()
        self._alert_list: list[dict[str, Any]] = []
        self._detector_indicators: dict[str, DetectorIndicator] = {}
        self._log_count = 0

        self._build_header()
        self._build_counters()

        # Middle section: detectors + live log side by side
        middle = ctk.CTkFrame(self, fg_color="transparent")
        middle.pack(fill="x", padx=PAD_SECTION, pady=PAD_WIDGET)
        middle.columnconfigure(0, weight=1)
        middle.columnconfigure(1, weight=2)
        middle.rowconfigure(0, weight=1)

        self._build_detectors(middle)
        self._build_live_log(middle)

        self._build_recent_alerts()
        self._build_status_bar()

    def _build_header(self) -> None:
        """Build the top header row."""
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=PAD_SECTION, pady=(PAD_SECTION, 5))

        ctk.CTkLabel(
            header, text="Dashboard", font=FONT_TITLE, text_color=TEXT_PRIMARY,
        ).pack(side="left")

        self._uptime_label = ctk.CTkLabel(
            header, text="Uptime: 0m 0s", font=FONT_SMALL, text_color=TEXT_SECONDARY,
        )
        self._uptime_label.pack(side="right")

        self._status_led = ctk.CTkLabel(
            header, text="● MONITORING", font=FONT_BODY, text_color=ACCENT_GREEN,
        )
        self._status_led.pack(side="right", padx=20)

    def _build_counters(self) -> None:
        """Build the severity counter cards."""
        counter_frame = ctk.CTkFrame(self, fg_color="transparent")
        counter_frame.pack(fill="x", padx=PAD_SECTION, pady=PAD_WIDGET)
        counter_frame.columnconfigure((0, 1, 2, 3, 4), weight=1)

        self._counter_total = StatCounter(
            counter_frame, title="Total Alerts", color=TEXT_PRIMARY,
        )
        self._counter_total.grid(row=0, column=0, padx=PAD_WIDGET, sticky="nsew")

        self._counter_critical = StatCounter(
            counter_frame, title="Critical", color=SEVERITY_COLORS["CRITICAL"],
        )
        self._counter_critical.grid(row=0, column=1, padx=PAD_WIDGET, sticky="nsew")

        self._counter_high = StatCounter(
            counter_frame, title="High", color=SEVERITY_COLORS["HIGH"],
        )
        self._counter_high.grid(row=0, column=2, padx=PAD_WIDGET, sticky="nsew")

        self._counter_medium = StatCounter(
            counter_frame, title="Medium", color=SEVERITY_COLORS["MEDIUM"],
        )
        self._counter_medium.grid(row=0, column=3, padx=PAD_WIDGET, sticky="nsew")

        self._counter_events = StatCounter(
            counter_frame, title="Events/min", color=ACCENT_CYAN,
        )
        self._counter_events.grid(row=0, column=4, padx=PAD_WIDGET, sticky="nsew")

    def _build_detectors(self, parent: ctk.CTkFrame) -> None:
        """Build detector status indicators."""
        det_panel = ctk.CTkFrame(
            parent, fg_color=BG_CARD, border_color=BORDER_COLOR,
            border_width=1, corner_radius=8,
        )
        det_panel.grid(row=0, column=0, sticky="nsew", padx=(0, PAD_WIDGET))

        ctk.CTkLabel(
            det_panel, text="Detectors", font=FONT_HEADING,
            text_color=TEXT_PRIMARY, anchor="w",
        ).pack(fill="x", padx=PAD_WIDGET, pady=(PAD_WIDGET, 2))

        for name in ["process_detector", "network_detector", "eventlog_detector",
                      "filesystem_detector", "suricata_detector"]:
            indicator = DetectorIndicator(det_panel, name=name)
            indicator.pack(fill="x", padx=PAD_WIDGET, pady=1)
            self._detector_indicators[name] = indicator

        # Integration status indicators
        status_frame = ctk.CTkFrame(det_panel, fg_color="transparent")
        status_frame.pack(fill="x", padx=PAD_WIDGET, pady=(5, PAD_WIDGET))

        self._sysmon_label = ctk.CTkLabel(
            status_frame, text="● Sysmon: checking...",
            font=FONT_SMALL, text_color=TEXT_SECONDARY,
        )
        self._sysmon_label.pack(anchor="w")

        self._suricata_label = ctk.CTkLabel(
            status_frame, text="● Suricata: checking...",
            font=FONT_SMALL, text_color=TEXT_SECONDARY,
        )
        self._suricata_label.pack(anchor="w")

    def _build_live_log(self, parent: ctk.CTkFrame) -> None:
        """Build the live activity log panel."""
        log_panel = ctk.CTkFrame(
            parent, fg_color=BG_CARD, border_color=BORDER_COLOR,
            border_width=1, corner_radius=8,
        )
        log_panel.grid(row=0, column=1, sticky="nsew")

        ctk.CTkLabel(
            log_panel, text="Live Activity", font=FONT_HEADING,
            text_color=TEXT_PRIMARY, anchor="w",
        ).pack(fill="x", padx=PAD_WIDGET, pady=(PAD_WIDGET, 2))

        self._log_textbox = ctk.CTkTextbox(
            log_panel, font=FONT_MONO, fg_color=BG_DARK,
            text_color=TEXT_SECONDARY, height=150,
        )
        self._log_textbox.pack(fill="both", expand=True, padx=PAD_WIDGET, pady=(0, PAD_WIDGET))
        self._log_textbox.configure(state="disabled")

    def _build_recent_alerts(self) -> None:
        """Build the recent alerts scrollable list."""
        section_label = ctk.CTkLabel(
            self, text="Recent Alerts", font=FONT_HEADING,
            text_color=TEXT_PRIMARY, anchor="w",
        )
        section_label.pack(fill="x", padx=PAD_SECTION, pady=(PAD_SECTION, 2))

        self._alerts_scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
        )
        self._alerts_scroll.pack(fill="both", expand=True, padx=PAD_SECTION, pady=PAD_WIDGET)

    def _build_status_bar(self) -> None:
        """Build the bottom status bar."""
        bar = ctk.CTkFrame(self, fg_color="transparent", height=25)
        bar.pack(fill="x", padx=PAD_SECTION, pady=(0, PAD_WIDGET))

        self._events_label = ctk.CTkLabel(
            bar, text="Events processed: 0", font=FONT_SMALL, text_color=TEXT_SECONDARY,
        )
        self._events_label.pack(side="left", padx=10)

        self._queue_label = ctk.CTkLabel(
            bar, text="Queue: 0", font=FONT_SMALL, text_color=TEXT_SECONDARY,
        )
        self._queue_label.pack(side="left", padx=10)

    # ------------------------------------------------------------------
    # Public update methods
    # ------------------------------------------------------------------

    def add_alert(self, alert_data: dict[str, Any]) -> None:
        """Add a new alert to the dashboard.

        Args:
            alert_data: Alert dictionary.
        """
        self._alert_list.insert(0, alert_data)
        if len(self._alert_list) > MAX_RECENT_ALERTS:
            self._alert_list = self._alert_list[:MAX_RECENT_ALERTS]

        # Get existing cards BEFORE creating the new one
        existing_children = self._alerts_scroll.winfo_children()

        card = AlertCard(self._alerts_scroll, alert_data)

        # Pack at top (before the first existing card) or just pack
        if existing_children:
            try:
                card.pack(fill="x", pady=1, before=existing_children[0])
            except Exception:
                card.pack(fill="x", pady=1)
        else:
            card.pack(fill="x", pady=1)

        # Trim old cards
        children = self._alerts_scroll.winfo_children()
        while len(children) > MAX_RECENT_ALERTS:
            children[-1].destroy()
            children = self._alerts_scroll.winfo_children()

        self._update_counters()

        # Also log it
        sev = alert_data.get("severity", "?")
        title = alert_data.get("title", "?")
        self.add_log(f"ALERT [{sev}] {title}", level=sev)

    def _get_first_card(self) -> ctk.CTkBaseClass | None:
        """Get the first child widget for insert-before positioning."""
        children = self._alerts_scroll.winfo_children()
        return children[0] if children else None

    def update_detectors(self, statuses: list[dict[str, object]]) -> None:
        """Update detector indicators.

        Args:
            statuses: List of detector health check dicts.
        """
        sysmon_active = False
        suricata_active = False
        for status in statuses:
            name = str(status.get("name", ""))
            indicator = self._detector_indicators.get(name)
            if indicator:
                indicator.update_status(
                    state=str(status.get("state", "stopped")),
                    cycle_count=int(status.get("cycle_count", 0)),
                    error_count=int(status.get("error_count", 0)),
                )
            if name == "eventlog_detector" and status.get("state") == "running":
                sysmon_active = True
            if name == "suricata_detector" and status.get("state") == "running":
                suricata_active = True

        self._update_integration_indicators(sysmon_active, suricata_active)

    def update_engine_stats(self, stats: dict[str, Any]) -> None:
        """Update engine statistics display.

        Args:
            stats: Dict with event_count, queue_size.
        """
        event_count = stats.get("event_count", 0)
        self._events_label.configure(text=f"Events processed: {event_count}")
        self._queue_label.configure(text=f"Queue: {stats.get('queue_size', 0)}")

        # Calculate events per minute
        elapsed_min = max((time.time() - self._start_time) / 60, 0.1)
        epm = int(event_count / elapsed_min)
        self._counter_events.set_value(epm)

    def update_uptime(self) -> None:
        """Update the uptime display."""
        elapsed = int(time.time() - self._start_time)
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            text = f"Uptime: {hours}h {minutes}m"
        else:
            text = f"Uptime: {minutes}m {seconds}s"
        self._uptime_label.configure(text=text)

    def add_log(self, message: str, level: str = "INFO") -> None:
        """Add a line to the live activity log.

        Args:
            message: Log message.
            level: Log level for color coding.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}\n"

        self._log_textbox.configure(state="normal")
        self._log_textbox.insert("end", line)
        self._log_count += 1

        # Trim old lines
        if self._log_count > MAX_LOG_LINES:
            self._log_textbox.delete("1.0", "2.0")
            self._log_count -= 1

        self._log_textbox.see("end")
        self._log_textbox.configure(state="disabled")

    def _update_counters(self) -> None:
        """Recalculate severity counters from alert list."""
        total = len(self._alert_list)
        critical = sum(1 for a in self._alert_list if a.get("severity") == "CRITICAL")
        high = sum(1 for a in self._alert_list if a.get("severity") == "HIGH")
        medium = sum(1 for a in self._alert_list if a.get("severity") == "MEDIUM")

        self._counter_total.set_value(total)
        self._counter_critical.set_value(critical)
        self._counter_high.set_value(high)
        self._counter_medium.set_value(medium)

    def _update_integration_indicators(
        self, eventlog_running: bool, suricata_running: bool
    ) -> None:
        """Update the Sysmon and Suricata status indicators.

        Args:
            eventlog_running: Whether the eventlog detector is running.
            suricata_running: Whether the suricata detector is running.
        """
        # Sysmon indicator
        if not eventlog_running:
            self._sysmon_label.configure(
                text="● Sysmon: waiting for eventlog detector",
                text_color=TEXT_SECONDARY,
            )
        else:
            try:
                from src.core.subprocess_utils import run_silent
                result = run_silent(
                    ["wevtutil", "gl", "Microsoft-Windows-Sysmon/Operational"],
                    timeout=3,
                )
                if result.returncode == 0:
                    self._sysmon_label.configure(
                        text="● Sysmon: active (16 event types)",
                        text_color=ACCENT_GREEN,
                    )
                else:
                    self._sysmon_label.configure(
                        text="● Sysmon: not installed (run install_sysmon.ps1)",
                        text_color=ACCENT_ORANGE,
                    )
            except Exception:
                self._sysmon_label.configure(
                    text="● Sysmon: status unknown",
                    text_color=TEXT_SECONDARY,
                )

        # Suricata indicator
        if suricata_running:
            self._suricata_label.configure(
                text="● Suricata: active (eve.json ingestion)",
                text_color=ACCENT_GREEN,
            )
        else:
            # Check if Suricata is installed but not yet started
            from pathlib import Path
            eve_paths = [
                r"C:\Program Files\Suricata\log\eve.json",
                r"C:\Program Files\Suricata\eve.json",
            ]
            found = any(Path(p).exists() for p in eve_paths)
            if found:
                self._suricata_label.configure(
                    text="● Suricata: installed (detector starting...)",
                    text_color=ACCENT_BLUE,
                )
            else:
                self._suricata_label.configure(
                    text="● Suricata: not installed (run install_suricata.ps1)",
                    text_color=ACCENT_ORANGE,
                )
