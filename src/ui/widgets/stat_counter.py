"""Counter widget displaying a number with a label."""

from __future__ import annotations

import customtkinter as ctk

from src.ui.theme import (
    BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY,
    FONT_COUNTER, FONT_COUNTER_LABEL, PAD_WIDGET,
)


class StatCounter(ctk.CTkFrame):
    """A card showing a large number with a descriptive label.

    Args:
        master: Parent widget.
        title: Label text below the number.
        initial_value: Starting value.
        color: Color for the number text.
    """

    def __init__(
        self,
        master: ctk.CTkBaseClass,
        title: str,
        initial_value: int = 0,
        color: str = TEXT_PRIMARY,
        **kwargs: object,
    ) -> None:
        super().__init__(
            master,
            fg_color=BG_CARD,
            border_color=BORDER_COLOR,
            border_width=1,
            corner_radius=8,
            **kwargs,
        )

        self._value_label = ctk.CTkLabel(
            self,
            text=str(initial_value),
            font=FONT_COUNTER,
            text_color=color,
        )
        self._value_label.pack(pady=(PAD_WIDGET, 0))

        self._title_label = ctk.CTkLabel(
            self,
            text=title,
            font=FONT_COUNTER_LABEL,
            text_color=TEXT_SECONDARY,
        )
        self._title_label.pack(pady=(0, PAD_WIDGET))

    def set_value(self, value: int) -> None:
        """Update the displayed number.

        Args:
            value: New value to display.
        """
        self._value_label.configure(text=str(value))
