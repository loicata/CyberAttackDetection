"""Colored badge widget displaying alert severity."""

from __future__ import annotations

import customtkinter as ctk

from src.ui.theme import SEVERITY_COLORS, FONT_SMALL, BG_CARD


class SeverityBadge(ctk.CTkLabel):
    """A small colored label showing severity level.

    Args:
        master: Parent widget.
        severity: Severity string (CRITICAL, HIGH, MEDIUM, LOW, INFO).
    """

    def __init__(self, master: ctk.CTkBaseClass, severity: str, **kwargs: object) -> None:
        color = SEVERITY_COLORS.get(severity, "#8b949e")
        super().__init__(
            master,
            text=f" {severity} ",
            font=FONT_SMALL,
            text_color="white" if severity in ("CRITICAL", "HIGH") else "#000000",
            fg_color=color,
            corner_radius=4,
            height=22,
            **kwargs,
        )
