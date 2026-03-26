"""Detector status indicator with LED and stats."""

from __future__ import annotations

import customtkinter as ctk

from src.ui.theme import (
    BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY,
    DETECTOR_COLORS, FONT_BODY, FONT_SMALL, PAD_WIDGET,
)


class DetectorIndicator(ctk.CTkFrame):
    """Shows detector name, state LED, cycle count, and errors.

    Args:
        master: Parent widget.
        name: Detector display name.
    """

    def __init__(self, master: ctk.CTkBaseClass, name: str, **kwargs: object) -> None:
        super().__init__(
            master,
            fg_color=BG_CARD,
            border_color=BORDER_COLOR,
            border_width=1,
            corner_radius=6,
            height=40,
            **kwargs,
        )

        self._name = name

        self._led = ctk.CTkLabel(
            self, text="●", font=FONT_BODY, text_color=DETECTOR_COLORS["stopped"], width=20,
        )
        self._led.pack(side="left", padx=(PAD_WIDGET, 2))

        self._name_label = ctk.CTkLabel(
            self, text=name, font=FONT_BODY, text_color=TEXT_PRIMARY, anchor="w", width=120,
        )
        self._name_label.pack(side="left", padx=2)

        self._state_label = ctk.CTkLabel(
            self, text="stopped", font=FONT_SMALL, text_color=TEXT_SECONDARY, width=70,
        )
        self._state_label.pack(side="left", padx=2)

        self._cycles_label = ctk.CTkLabel(
            self, text="0 cycles", font=FONT_SMALL, text_color=TEXT_SECONDARY, width=80,
        )
        self._cycles_label.pack(side="left", padx=2)

        self._errors_label = ctk.CTkLabel(
            self, text="0 err", font=FONT_SMALL, text_color=TEXT_SECONDARY, width=50,
        )
        self._errors_label.pack(side="left", padx=2)

    def update_status(self, state: str, cycle_count: int = 0, error_count: int = 0) -> None:
        """Update the indicator display.

        Args:
            state: Detector state string.
            cycle_count: Number of completed cycles.
            error_count: Number of errors.
        """
        color = DETECTOR_COLORS.get(state, TEXT_SECONDARY)
        self._led.configure(text_color=color)
        self._state_label.configure(text=state, text_color=color)
        self._cycles_label.configure(text=f"{cycle_count} cycles")

        err_color = "#f85149" if error_count > 0 else TEXT_SECONDARY
        self._errors_label.configure(text=f"{error_count} err", text_color=err_color)
