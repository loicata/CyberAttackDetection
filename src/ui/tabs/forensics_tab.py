"""Forensics tab — browse evidence, verify integrity, generate reports."""

from __future__ import annotations

import json
import webbrowser
from pathlib import Path
from typing import Any

import customtkinter as ctk

from src.ui.bridge import ThreadBridge
from src.ui.theme import (
    BG_CARD, BG_DARK, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY,
    SEVERITY_COLORS, ACCENT_BLUE, ACCENT_GREEN, ACCENT_RED,
    FONT_TITLE, FONT_HEADING, FONT_BODY, FONT_SMALL, FONT_MONO,
    PAD_SECTION, PAD_WIDGET,
)


class ForensicsTab(ctk.CTkFrame):
    """Browse forensic evidence, verify integrity, generate reports.

    Args:
        master: Parent widget.
        bridge: Thread communication bridge.
        evidence_dir: Path to evidence directory.
        report_dir: Path to reports directory.
    """

    def __init__(
        self,
        master: ctk.CTkBaseClass,
        bridge: ThreadBridge,
        evidence_dir: str = "./data/evidence",
        report_dir: str = "./data/reports",
        **kwargs: object,
    ) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self._bridge = bridge
        self._evidence_dir = Path(evidence_dir)
        self._report_dir = Path(report_dir)
        self._selected_alert_uid: str | None = None

        import logging
        _logger = logging.getLogger(__name__)
        _logger.info("Forensics tab evidence_dir: %s (exists=%s)", self._evidence_dir, self._evidence_dir.exists())

        self._build_ui()

    def _build_ui(self) -> None:
        ctk.CTkLabel(
            self, text="Forensics", font=FONT_TITLE, text_color=TEXT_PRIMARY, anchor="w",
        ).pack(fill="x", padx=PAD_SECTION, pady=(PAD_SECTION, 5))

        # Main split
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=PAD_SECTION, pady=PAD_WIDGET)
        content.columnconfigure(0, weight=1)
        content.columnconfigure(1, weight=3)
        content.rowconfigure(0, weight=1)

        # Left: alert list
        left = ctk.CTkFrame(content, fg_color=BG_CARD, border_color=BORDER_COLOR, border_width=1, corner_radius=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, PAD_WIDGET))

        ctk.CTkLabel(left, text="Alerts with Evidence", font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(padx=5, pady=5)

        self._alert_list = ctk.CTkScrollableFrame(left, fg_color="transparent")
        self._alert_list.pack(fill="both", expand=True, padx=2, pady=2)

        # Auto-refresh on tab switch — no manual button needed

        # Right: evidence viewer
        right = ctk.CTkFrame(content, fg_color=BG_CARD, border_color=BORDER_COLOR, border_width=1, corner_radius=8)
        right.grid(row=0, column=1, sticky="nsew")

        # File list + viewer
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        self._evidence_header = ctk.CTkLabel(
            right, text="Select an alert to view evidence", font=FONT_HEADING, text_color=TEXT_SECONDARY,
        )
        self._evidence_header.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        viewer_frame = ctk.CTkFrame(right, fg_color="transparent")
        viewer_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        viewer_frame.columnconfigure(0, weight=1)
        viewer_frame.columnconfigure(1, weight=3)
        viewer_frame.rowconfigure(0, weight=1)

        # File list
        self._file_list = ctk.CTkScrollableFrame(viewer_frame, fg_color=BG_DARK, width=200)
        self._file_list.grid(row=0, column=0, sticky="nsew", padx=(0, 2))

        # JSON viewer
        self._json_viewer = ctk.CTkTextbox(viewer_frame, font=FONT_MONO, fg_color=BG_DARK, state="disabled")
        self._json_viewer.grid(row=0, column=1, sticky="nsew")

        # Action bar
        action_bar = ctk.CTkFrame(self, fg_color="transparent")
        action_bar.pack(fill="x", padx=PAD_SECTION, pady=PAD_WIDGET)

        ctk.CTkButton(
            action_bar, text="Verify Integrity", font=FONT_BODY,
            fg_color=ACCENT_BLUE, width=150, command=self._verify_integrity,
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            action_bar, text="Generate Report", font=FONT_BODY,
            fg_color=ACCENT_GREEN, width=150, command=self._generate_report,
        ).pack(side="left", padx=5)


        self._status_label = ctk.CTkLabel(action_bar, text="", font=FONT_SMALL, text_color=TEXT_SECONDARY)
        self._status_label.pack(side="left", padx=15)

    def _refresh_alerts(self) -> None:
        """Refresh the list of alerts with evidence, showing date/severity/title."""
        for w in self._alert_list.winfo_children():
            w.destroy()

        if not self._evidence_dir.exists():
            return

        # Read alert metadata from DB for display
        alert_meta: dict[str, dict[str, str]] = {}
        try:
            import sqlite3
            import os
            db_path = os.path.join(
                os.environ.get("LOCALAPPDATA", ""),
                "CyberAttackDetection", "alerts.db",
            )
            if not os.path.exists(db_path):
                db_path = str(Path("./data/alerts.db"))
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT alert_uid, severity, title, created_at FROM alerts"
            ).fetchall()
            conn.close()
            for row in rows:
                alert_meta[row["alert_uid"]] = {
                    "severity": row["severity"] or "?",
                    "title": row["title"] or "Unknown",
                    "created_at": row["created_at"] or "",
                }
        except Exception:
            pass

        for alert_dir in sorted(self._evidence_dir.iterdir(), reverse=True):
            if not alert_dir.is_dir():
                continue
            uid = alert_dir.name
            file_count = len(list(alert_dir.glob("*.json")))

            meta = alert_meta.get(uid, {})
            severity = meta.get("severity", "?")
            title = meta.get("title", uid[:12])
            created = meta.get("created_at", "")

            # Format: "25/03 22:48 [CRITICAL] ET SCAN Nmap..."
            date_display = ""
            if created:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(created)
                    date_display = dt.strftime("%d/%m %H:%M")
                except Exception:
                    date_display = created[:16]

            # Shorten title for display
            title_short = title[:40] + "..." if len(title) > 40 else title
            label = f"{date_display}  [{severity}]  {title_short}"

            btn = ctk.CTkButton(
                self._alert_list,
                text=label,
                font=FONT_SMALL, fg_color=BG_DARK, hover_color=BORDER_COLOR,
                text_color="#ffffff", anchor="w",
                command=lambda u=uid: self._select_alert(u),
            )
            btn.pack(fill="x", pady=1)

    def _select_alert(self, alert_uid: str) -> None:
        """Load evidence files for the selected alert."""
        self._selected_alert_uid = alert_uid

        # Build a readable label matching the alert list display
        display_label = alert_uid[:16] + "..."
        try:
            import sqlite3
            import os
            from datetime import datetime as _dt
            db_path = os.path.join(
                os.environ.get("LOCALAPPDATA", ""),
                "CyberAttackDetection", "alerts.db",
            )
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT severity, title, created_at FROM alerts WHERE alert_uid = ?",
                    (alert_uid,),
                ).fetchone()
                conn.close()
                if row:
                    sev = row["severity"] or "?"
                    title = row["title"] or "Unknown"
                    title_short = title[:40] + "..." if len(title) > 40 else title
                    date_str = ""
                    try:
                        dt = _dt.fromisoformat(row["created_at"])
                        date_str = dt.strftime("%d/%m %H:%M")
                    except Exception:
                        pass
                    display_label = f"{date_str}  [{sev}]  {title_short}"
        except Exception:
            pass

        self._selected_alert_label = display_label
        self._evidence_header.configure(text=f"Evidence: {display_label}")

        # Clear file list
        for w in self._file_list.winfo_children():
            w.destroy()

        alert_dir = self._evidence_dir / alert_uid
        if not alert_dir.exists():
            return

        for file_path in sorted(alert_dir.glob("*.json")):
            btn = ctk.CTkButton(
                self._file_list,
                text=file_path.name, font=FONT_SMALL,
                fg_color="transparent", hover_color=BORDER_COLOR, anchor="w",
                command=lambda p=file_path: self._show_file(p),
            )
            btn.pack(fill="x", pady=1)

    def _show_file(self, file_path: Path) -> None:
        """Display file contents in the JSON viewer."""
        try:
            content = file_path.read_text(encoding="utf-8")
            try:
                parsed = json.loads(content)
                content = json.dumps(parsed, indent=2)
            except json.JSONDecodeError:
                pass
        except OSError as exc:
            content = f"Error reading file: {exc}"

        self._json_viewer.configure(state="normal")
        self._json_viewer.delete("1.0", "end")
        self._json_viewer.insert("1.0", content)
        self._json_viewer.configure(state="disabled")

    def _verify_integrity(self) -> None:
        """Send verify integrity command for selected alert."""
        if not self._selected_alert_uid:
            self._status_label.configure(text="No alert selected", text_color=ACCENT_RED)
            return
        self._bridge.send_command("verify_integrity", {"alert_uid": self._selected_alert_uid})
        self._status_label.configure(text="Verifying...", text_color=ACCENT_BLUE)

    def _generate_report(self) -> None:
        """Ask where to save, then generate the forensic ZIP archive."""
        if not self._selected_alert_uid:
            self._status_label.configure(text="No alert selected", text_color=ACCENT_RED)
            return

        from tkinter import filedialog
        from datetime import datetime

        # Read alert metadata from database
        severity = "UNKNOWN"
        title_raw = "alert"
        source_ip = "unknown"
        try:
            import sqlite3
            import os
            db_path = os.path.join(
                os.environ.get("LOCALAPPDATA", ""),
                "CyberAttackDetection", "alerts.db",
            )
            if not os.path.exists(db_path):
                db_path = str(Path("./data/alerts.db"))
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT severity, title, source_ip FROM alerts WHERE alert_uid = ?",
                (self._selected_alert_uid,),
            ).fetchone()
            conn.close()
            if row:
                severity = row["severity"] or "UNKNOWN"
                title_raw = row["title"] or "alert"
                source_ip = row["source_ip"] or "unknown"
        except Exception:
            pass
        date_str = datetime.now().strftime("%d-%m-%Y_%Hh%M")

        # Sanitize title for filename (remove special chars)
        import re
        title_clean = re.sub(r'[^\w\s-]', '', title_raw).strip()
        title_clean = re.sub(r'\s+', '_', title_clean)
        if len(title_clean) > 60:
            title_clean = title_clean[:60]

        default_name = (
            f"Rapport_Forensique_{date_str}_"
            f"[{severity}]_{title_clean}.zip"
        )

        save_path = filedialog.asksaveasfilename(
            title="Save Forensic Archive",
            defaultextension=".zip",
            filetypes=[("ZIP Archive", "*.zip"), ("All Files", "*.*")],
            initialfile=default_name,
            initialdir=str(Path.home() / "Desktop"),
        )

        if not save_path:
            return  # User cancelled

        self._bridge.send_command("generate_report", {
            "alert_uid": self._selected_alert_uid,
            "save_path": save_path,
        })
        self._status_label.configure(text="Generating report...", text_color=ACCENT_BLUE)

    def update_status(self, message: str, success: bool = True) -> None:
        """Update the status label.

        Args:
            message: Status message.
            success: Whether to show as success or error.
        """
        color = ACCENT_GREEN if success else ACCENT_RED
        self._status_label.configure(text=message, text_color=color)
