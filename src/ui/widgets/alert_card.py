"""Compact alert card widget for dashboard and alert lists."""

from __future__ import annotations

from typing import Any, Callable

import customtkinter as ctk

from src.ui.theme import (
    BG_CARD, BG_CARD_HOVER, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY,
    SEVERITY_COLORS, FONT_BODY, FONT_SMALL, PAD_WIDGET,
)


class AlertCard(ctk.CTkFrame):
    """A compact card showing alert summary info.

    Args:
        master: Parent widget.
        alert_data: Alert dictionary with title, severity, score, etc.
        on_click: Optional callback when card is clicked.
    """

    def __init__(
        self,
        master: ctk.CTkBaseClass,
        alert_data: dict[str, Any],
        on_click: Callable[[dict[str, Any]], None] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(
            master,
            fg_color=BG_CARD,
            border_color=BORDER_COLOR,
            border_width=1,
            corner_radius=6,
            **kwargs,
        )
        self._alert_data = alert_data
        self._on_click = on_click

        severity = alert_data.get("severity", "INFO")
        sev_color = SEVERITY_COLORS.get(severity, "#8b949e")

        # Left color bar
        self._color_bar = ctk.CTkFrame(
            self, fg_color=sev_color, width=4, corner_radius=0,
        )
        self._color_bar.pack(side="left", fill="y", padx=(0, PAD_WIDGET))

        # Content frame
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(side="left", fill="both", expand=True, padx=PAD_WIDGET, pady=2)

        # Top row: severity + title + score
        top_row = ctk.CTkFrame(content, fg_color="transparent")
        top_row.pack(fill="x")

        ctk.CTkLabel(
            top_row, text=severity, font=FONT_SMALL, text_color=sev_color, width=70, anchor="w",
        ).pack(side="left")

        title = alert_data.get("title", "Unknown")[:60]
        ctk.CTkLabel(
            top_row, text=title, font=FONT_BODY, text_color=TEXT_PRIMARY, anchor="w",
        ).pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            top_row, text=f"{alert_data.get('score', 0)}/100",
            font=FONT_SMALL, text_color=sev_color, width=60, anchor="e",
        ).pack(side="right")

        # Bottom row: source IP + process + time
        bottom_row = ctk.CTkFrame(content, fg_color="transparent")
        bottom_row.pack(fill="x")

        details_parts: list[str] = []
        if alert_data.get("source_ip"):
            details_parts.append(f"Src: {alert_data['source_ip']}")
        if alert_data.get("process_name"):
            details_parts.append(f"Proc: {alert_data['process_name']}")
        timestamp = alert_data.get("created_at", "")[:19]
        details_parts.append(timestamp)

        ctk.CTkLabel(
            bottom_row, text=" | ".join(details_parts),
            font=FONT_SMALL, text_color=TEXT_SECONDARY, anchor="w",
        ).pack(side="left", fill="x", expand=True)

        # Click binding
        if self._on_click:
            self.bind("<Button-1>", lambda e: self._on_click(self._alert_data))
            for child in self.winfo_children():
                child.bind("<Button-1>", lambda e: self._on_click(self._alert_data))
