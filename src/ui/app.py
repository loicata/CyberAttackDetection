"""Main CustomTkinter application window with system tray support."""

from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any

import customtkinter as ctk

from src.ui.bridge import ThreadBridge
from src.ui.theme import (
    WINDOW_TITLE, WINDOW_WIDTH, WINDOW_HEIGHT,
    APPEARANCE_MODE, COLOR_THEME,
    BG_DARK, POLL_INTERVAL_MS,
)
from src.ui.tabs.dashboard_tab import DashboardTab
from src.ui.tabs.alerts_tab import AlertsTab
from src.ui.tabs.config_tab import ConfigTab
from src.ui.tabs.forensics_tab import ForensicsTab
from src.ui.tabs.response_tab import ResponseTab

logger = logging.getLogger(__name__)


def _get_icon_path() -> Path | None:
    """Locate the application icon file.

    Returns:
        Path to icon.ico if found, None otherwise.
    """
    candidates = []
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        candidates.append(exe_dir / "icon.ico")
        candidates.append(exe_dir / "assets" / "icon.ico")
    base = Path(__file__).resolve().parent.parent.parent
    candidates.append(base / "assets" / "icon.ico")

    for path in candidates:
        if path.is_file():
            return path
    return None


class CyberAttackDetectionApp(ctk.CTk):
    """Main application window with tabbed interface.

    Args:
        bridge: Thread communication bridge.
        config_data: Raw configuration dict for the config editor.
        evidence_dir: Path to evidence directory.
        report_dir: Path to reports directory.
    """

    def __init__(
        self,
        bridge: ThreadBridge,
        config_data: dict[str, Any],
        evidence_dir: str = "./data/evidence",
        report_dir: str = "./data/reports",
    ) -> None:
        ctk.set_appearance_mode(APPEARANCE_MODE)
        ctk.set_default_color_theme(COLOR_THEME)

        super().__init__()
        self._bridge = bridge

        self.title(WINDOW_TITLE)
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.minsize(1000, 600)
        self.configure(fg_color=BG_DARK)

        # Tab view
        self._tabview = ctk.CTkTabview(self, fg_color=BG_DARK)
        self._tabview.pack(fill="both", expand=True, padx=5, pady=5)

        # Create tabs
        self._tabview.add("Dashboard")
        self._tabview.add("Alerts")
        self._tabview.add("Config")
        self._tabview.add("Forensics")
        self._tabview.add("Response")

        # Tab contents
        self._dashboard = DashboardTab(self._tabview.tab("Dashboard"))
        self._dashboard.pack(fill="both", expand=True)

        self._alerts_tab = AlertsTab(self._tabview.tab("Alerts"), bridge=bridge)
        self._alerts_tab.pack(fill="both", expand=True)

        self._config_tab = ConfigTab(
            self._tabview.tab("Config"), bridge=bridge, config_data=config_data,
        )
        self._config_tab.pack(fill="both", expand=True)

        self._forensics_tab = ForensicsTab(
            self._tabview.tab("Forensics"), bridge=bridge,
            evidence_dir=evidence_dir, report_dir=report_dir,
        )
        self._forensics_tab.pack(fill="both", expand=True)

        self._response_tab = ResponseTab(self._tabview.tab("Response"), bridge=bridge)
        self._response_tab.pack(fill="both", expand=True)

        # Start dashboard on launch
        self._tabview.set("Dashboard")

        # Auto-refresh forensics when switching to that tab
        self._tabview.configure(command=self._on_tab_changed)

        # Set window icon
        icon_path = _get_icon_path()
        if icon_path:
            try:
                self.iconbitmap(str(icon_path))
            except Exception:
                logger.debug("Could not set window icon from %s", icon_path)

        # Window close handler — minimize to tray
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # System tray
        self._tray_icon = None
        self._tray_thread = None
        self._setup_tray(icon_path)

        # Start queue polling
        self.after(POLL_INTERVAL_MS, self._poll_queues)

        logger.info("GUI initialized: %dx%d", WINDOW_WIDTH, WINDOW_HEIGHT)

    def _on_tab_changed(self, tab_name: str = "") -> None:
        """Auto-refresh data when switching tabs."""
        if tab_name == "Forensics":
            self._forensics_tab._refresh_alerts()

    def _poll_queues(self) -> None:
        """Drain incoming queues and update GUI widgets."""
        self._drain_alert_queue()
        self._drain_status_queue()
        self._dashboard.update_uptime()
        self.after(POLL_INTERVAL_MS, self._poll_queues)

    def _drain_alert_queue(self) -> None:
        """Process all pending alert messages.

        Behavior based on severity when window is minimized to tray:
        - CRITICAL / HIGH: restore window + tray notification
        - MEDIUM: tray balloon notification only
        - LOW / INFO: silent (logged only)
        """
        count = 0
        q_size = self._bridge.alert_queue.qsize()
        if q_size > 0:
            logger.info("Alert queue has %d messages to drain", q_size)

        while not self._bridge.alert_queue.empty() and count < 50:
            try:
                msg = self._bridge.alert_queue.get_nowait()
            except Exception:
                break
            count += 1

            msg_type = msg.get("type")
            data = msg.get("data", {})

            if msg_type == "new_alert":
                logger.info(
                    "GUI received alert: severity=%s score=%s title='%s'",
                    data.get("severity"), data.get("score"), data.get("title", "?"),
                )
                try:
                    self._dashboard.add_alert(data)
                    logger.info("Dashboard add_alert OK")
                except Exception:
                    logger.exception("Dashboard add_alert FAILED")
                try:
                    self._alerts_tab.add_alert(data)
                    logger.info("Alerts tab add_alert OK")
                except Exception:
                    logger.exception("Alerts tab add_alert FAILED")
                try:
                    self._response_tab.add_alert(data)
                except Exception:
                    logger.exception("Response tab add_alert FAILED")
                self._handle_alert_notification(data)
            elif msg_type == "alert_updated":
                pass

        if count > 0:
            logger.info("Drained %d alert messages from queue", count)

    def _handle_alert_notification(self, alert_data: dict[str, Any]) -> None:
        """Show notification and/or restore window based on alert severity.

        Args:
            alert_data: Alert dictionary with 'severity' and 'title' keys.
        """
        severity = alert_data.get("severity", "").upper()
        title = alert_data.get("title", "Alert detected")
        score = alert_data.get("score", 0)

        is_minimized = not self.winfo_viewable()

        if severity in ("CRITICAL", "HIGH"):
            # Always notify via tray
            self._send_tray_notification(
                f"[{severity}] {title}",
                f"Score: {score} — Click tray icon to view details.",
            )
            # Restore window if minimized
            if is_minimized:
                self._restore_window()
                self._tabview.set("Alerts")
                logger.info(
                    "Window restored for %s alert: %s (score=%d)",
                    severity, title, score,
                )

        elif severity == "MEDIUM":
            # Tray notification only, don't restore window
            if is_minimized:
                self._send_tray_notification(
                    f"[MEDIUM] {title}",
                    f"Score: {score} — Open app to investigate.",
                )

    def _send_tray_notification(self, title: str, message: str) -> None:
        """Send a balloon notification via the system tray icon.

        Args:
            title: Notification title.
            message: Notification body text.
        """
        if not self._tray_icon:
            return
        try:
            self._tray_icon.notify(title=title, message=message)
        except Exception:
            logger.debug("Failed to send tray notification: %s", title)

    def _drain_status_queue(self) -> None:
        """Process all pending status messages."""
        count = 0
        while not self._bridge.status_queue.empty() and count < 50:
            try:
                msg = self._bridge.status_queue.get_nowait()
            except Exception:
                break
            count += 1

            msg_type = msg.get("type")
            data = msg.get("data", {})

            if msg_type == "detector_status":
                self._dashboard.update_detectors(data)
            elif msg_type == "engine_stats":
                self._dashboard.update_engine_stats(data)
            elif msg_type == "log_message":
                level = data.get("level", "INFO")
                message = data.get("message", "")
                self._dashboard.add_log(f"[{level}] {message}", level=level)
            elif msg_type == "forensic_complete":
                self._forensics_tab.update_status(
                    f"Forensics collected: {data.get('evidence_count', 0)} files",
                    success=True,
                )
                self._forensics_tab._refresh_alerts()
            elif msg_type == "intel_complete":
                pass  # Could show toast
            elif msg_type == "response_result":
                self._response_tab.update_response_result(data)
                # Also update forensics tab status
                msg = data.get("message", "")
                success = data.get("success", False)
                if "Integrity" in msg or "Archive" in msg or "Report" in msg:
                    self._forensics_tab.update_status(msg, success=success)
            elif msg_type == "log_message":
                pass  # Could show in a log panel

    def _setup_tray(self, icon_path: Path | None) -> None:
        """Create the system tray icon with menu.

        Args:
            icon_path: Path to the .ico file, or None to generate a fallback.
        """
        try:
            import pystray
            from PIL import Image as PILImage
        except ImportError:
            logger.warning("pystray or Pillow not available — no tray icon")
            return

        try:
            if icon_path and icon_path.is_file():
                tray_image = PILImage.open(str(icon_path))
            else:
                # Fallback: generate a simple colored square
                tray_image = PILImage.new("RGB", (64, 64), "#00d4ff")
        except Exception:
            tray_image = PILImage.new("RGB", (64, 64), "#00d4ff")

        menu = pystray.Menu(
            pystray.MenuItem("Show", self._tray_show, default=True),
            pystray.MenuItem("Hide", self._tray_hide),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._tray_quit),
        )

        self._tray_icon = pystray.Icon(
            name="CyberAttackDetection",
            icon=tray_image,
            title="Cyber Attack Detection — Monitoring",
            menu=menu,
        )

        self._tray_thread = threading.Thread(
            target=self._tray_icon.run,
            daemon=True,
            name="TrayIcon",
        )
        self._tray_thread.start()
        logger.info("System tray icon started")

    def _tray_show(self, _icon: Any = None, _item: Any = None) -> None:
        """Restore the window from tray."""
        self.after(0, self._restore_window)

    def _restore_window(self) -> None:
        """Restore window on the main thread."""
        self.deiconify()
        self.lift()
        self.focus_force()

    def _tray_hide(self, _icon: Any = None, _item: Any = None) -> None:
        """Minimize to tray."""
        self.after(0, self.withdraw)

    def _tray_quit(self, _icon: Any = None, _item: Any = None) -> None:
        """Quit from tray menu."""
        self.after(0, self._full_quit)

    def _full_quit(self) -> None:
        """Shutdown engine, stop tray, and close window."""
        self._bridge.send_command("shutdown")
        if self._tray_icon:
            try:
                self._tray_icon.stop()
            except Exception:
                pass
        self.quit()
        self.destroy()

    def _on_close(self) -> None:
        """Handle window close — minimize to tray instead of quitting."""
        if self._tray_icon:
            self.withdraw()  # Hide window, keep running in tray
        else:
            self._full_quit()
