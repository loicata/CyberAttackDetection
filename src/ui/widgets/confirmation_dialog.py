"""Modal confirmation dialog."""

from __future__ import annotations

from typing import Callable

import customtkinter as ctk

from src.ui.theme import (
    BG_DARK, BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY,
    ACCENT_RED, ACCENT_GREEN, FONT_HEADING, FONT_BODY, PAD_SECTION,
)


class ConfirmationDialog(ctk.CTkToplevel):
    """A modal dialog asking user to confirm an action.

    Args:
        master: Parent window.
        title: Dialog title.
        message: Description of the action.
        on_confirm: Callback if user confirms.
        on_cancel: Callback if user cancels.
        danger: If True, use red styling for confirm button.
    """

    def __init__(
        self,
        master: ctk.CTk,
        title: str,
        message: str,
        on_confirm: Callable[[], None],
        on_cancel: Callable[[], None] | None = None,
        danger: bool = False,
    ) -> None:
        super().__init__(master)
        self._on_confirm = on_confirm
        self._on_cancel = on_cancel

        self.title(title)
        self.geometry("450x220")
        self.resizable(False, False)
        self.configure(fg_color=BG_DARK)

        # Grab focus
        self.grab_set()
        self.focus_force()

        # Icon + message
        icon_text = "⚠" if danger else "?"
        icon_color = ACCENT_RED if danger else TEXT_PRIMARY

        ctk.CTkLabel(
            self, text=icon_text, font=("Segoe UI", 36), text_color=icon_color,
        ).pack(pady=(PAD_SECTION, 5))

        ctk.CTkLabel(
            self, text=message, font=FONT_BODY, text_color=TEXT_SECONDARY,
            wraplength=400, justify="center",
        ).pack(pady=5, padx=PAD_SECTION)

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=PAD_SECTION)

        confirm_color = ACCENT_RED if danger else ACCENT_GREEN
        ctk.CTkButton(
            btn_frame, text="Confirm", font=FONT_BODY,
            fg_color=confirm_color, hover_color=confirm_color,
            command=self._confirm, width=120,
        ).pack(side="left", padx=10)

        ctk.CTkButton(
            btn_frame, text="Cancel", font=FONT_BODY,
            fg_color=BORDER_COLOR, hover_color="#484f58",
            command=self._cancel, width=120,
        ).pack(side="left", padx=10)

        # Escape to cancel
        self.bind("<Escape>", lambda e: self._cancel())

    def _confirm(self) -> None:
        """Handle confirm button click."""
        self.grab_release()
        self.destroy()
        self._on_confirm()

    def _cancel(self) -> None:
        """Handle cancel button click."""
        self.grab_release()
        self.destroy()
        if self._on_cancel:
            self._on_cancel()
