"""Collapsible configuration section widget."""

from __future__ import annotations

import customtkinter as ctk

from src.ui.theme import BG_CARD, BORDER_COLOR, TEXT_PRIMARY, ACCENT_BLUE, FONT_HEADING, PAD_SECTION


class ConfigSection(ctk.CTkFrame):
    """A collapsible section for grouping config options.

    Args:
        master: Parent widget.
        title: Section title.
        expanded: Whether to start expanded.
    """

    def __init__(
        self,
        master: ctk.CTkBaseClass,
        title: str,
        expanded: bool = True,
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
        self._expanded = expanded

        # Header bar (clickable)
        self._header = ctk.CTkFrame(self, fg_color="transparent", cursor="hand2")
        self._header.pack(fill="x", padx=PAD_SECTION, pady=(PAD_SECTION, 0))

        self._arrow = ctk.CTkLabel(
            self._header, text="▼" if expanded else "▶",
            font=FONT_HEADING, text_color=ACCENT_BLUE, width=20,
        )
        self._arrow.pack(side="left")

        ctk.CTkLabel(
            self._header, text=title, font=FONT_HEADING, text_color=TEXT_PRIMARY,
        ).pack(side="left", padx=5)

        self._header.bind("<Button-1>", lambda e: self.toggle())
        for child in self._header.winfo_children():
            child.bind("<Button-1>", lambda e: self.toggle())

        # Content area
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        if expanded:
            self.content.pack(fill="x", padx=PAD_SECTION, pady=(5, PAD_SECTION))

    def toggle(self) -> None:
        """Toggle the section open/closed."""
        self._expanded = not self._expanded
        if self._expanded:
            self.content.pack(fill="x", padx=PAD_SECTION, pady=(5, PAD_SECTION))
            self._arrow.configure(text="▼")
        else:
            self.content.pack_forget()
            self._arrow.configure(text="▶")
