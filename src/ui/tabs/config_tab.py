"""Configuration tab — full settings editor with TOML save."""

from __future__ import annotations

import logging
from pathlib import Path
from tkinter import filedialog
from typing import Any

import customtkinter as ctk

from src.ui.bridge import ThreadBridge
from src.ui.theme import (
    BG_CARD, BG_DARK, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY,
    ACCENT_BLUE, ACCENT_GREEN, ACCENT_RED, FONT_TITLE, FONT_HEADING,
    FONT_BODY, FONT_SMALL, FONT_MONO, PAD_SECTION, PAD_WIDGET,
)
from src.ui.widgets.config_section import ConfigSection

logger = logging.getLogger(__name__)

LOCAL_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent.parent / "config" / "local.toml"


class ConfigTab(ctk.CTkFrame):
    """Full configuration editor with save to local.toml.

    Args:
        master: Parent widget.
        bridge: Thread communication bridge.
        config_data: Initial configuration dictionary (raw TOML data).
    """

    def __init__(
        self,
        master: ctk.CTkBaseClass,
        bridge: ThreadBridge,
        config_data: dict[str, Any],
        **kwargs: object,
    ) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self._bridge = bridge
        self._config = config_data
        self._widgets: dict[str, Any] = {}

        self._build_header()
        self._scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._scroll.pack(fill="both", expand=True, padx=PAD_SECTION, pady=PAD_WIDGET)

        self._build_detectors_section()
        self._build_scoring_section()
        self._build_whitelist_section()
        self._build_detection_section()
        self._build_suricata_section()
        self._build_intel_section()
        self._build_response_section()
        self._build_save_bar()

    def _build_header(self) -> None:
        ctk.CTkLabel(
            self, text="Configuration", font=FONT_TITLE, text_color=TEXT_PRIMARY, anchor="w",
        ).pack(fill="x", padx=PAD_SECTION, pady=(PAD_SECTION, 5))

    def _build_detectors_section(self) -> None:
        section = ConfigSection(self._scroll, "Detectors")
        section.pack(fill="x", pady=PAD_WIDGET)

        detection = self._config.get("detection", {})
        enabled = detection.get("enabled_detectors", [])

        for det_name in ["eventlog", "network", "process", "filesystem"]:
            row = ctk.CTkFrame(section.content, fg_color="transparent")
            row.pack(fill="x", pady=2)
            switch = ctk.CTkSwitch(row, text=det_name.capitalize(), font=FONT_BODY)
            if det_name in enabled:
                switch.select()
            switch.pack(side="left", padx=5)
            self._widgets[f"det_{det_name}"] = switch

        row = ctk.CTkFrame(section.content, fg_color="transparent")
        row.pack(fill="x", pady=5)
        ctk.CTkLabel(row, text="Polling interval (sec):", font=FONT_SMALL, text_color=TEXT_SECONDARY).pack(side="left", padx=5)
        interval_entry = ctk.CTkEntry(row, width=60, font=FONT_SMALL)
        interval_entry.insert(0, str(detection.get("polling_interval_seconds", 5)))
        interval_entry.pack(side="left", padx=5)
        self._widgets["polling_interval"] = interval_entry

    def _build_scoring_section(self) -> None:
        section = ConfigSection(self._scroll, "Scoring")
        section.pack(fill="x", pady=PAD_WIDGET)

        analysis = self._config.get("analysis", {})

        # Threshold slider
        row = ctk.CTkFrame(section.content, fg_color="transparent")
        row.pack(fill="x", pady=5)
        ctk.CTkLabel(row, text="Score threshold:", font=FONT_BODY, text_color=TEXT_PRIMARY).pack(side="left", padx=5)
        threshold_val = analysis.get("score_threshold", 40)
        self._threshold_label = ctk.CTkLabel(row, text=str(threshold_val), font=FONT_BODY, text_color=ACCENT_BLUE, width=40)
        self._threshold_label.pack(side="right", padx=5)
        slider = ctk.CTkSlider(
            row, from_=0, to=100, number_of_steps=100,
            command=lambda v: self._threshold_label.configure(text=str(int(v))),
        )
        slider.set(threshold_val)
        slider.pack(side="left", fill="x", expand=True, padx=5)
        self._widgets["score_threshold"] = slider

        # Rule weights
        weights = analysis.get("scoring_weights", {})
        ctk.CTkLabel(section.content, text="Rule weights:", font=FONT_SMALL, text_color=TEXT_SECONDARY, anchor="w").pack(fill="x", padx=5, pady=(10, 2))
        for rule, weight in weights.items():
            row = ctk.CTkFrame(section.content, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(row, text=rule, font=FONT_SMALL, text_color=TEXT_SECONDARY, width=220, anchor="w").pack(side="left", padx=5)
            entry = ctk.CTkEntry(row, width=60, font=FONT_SMALL)
            entry.insert(0, str(weight))
            entry.pack(side="left")
            self._widgets[f"weight_{rule}"] = entry

    def _build_whitelist_section(self) -> None:
        section = ConfigSection(self._scroll, "Whitelist")
        section.pack(fill="x", pady=PAD_WIDGET)

        defaults = self._config.get("analysis", {}).get("whitelist_defaults", {})

        for wl_type, label in [("trusted_processes", "Trusted Processes"), ("trusted_ip_ranges", "Trusted IP Ranges")]:
            ctk.CTkLabel(section.content, text=label, font=FONT_SMALL, text_color=TEXT_SECONDARY, anchor="w").pack(fill="x", padx=5, pady=(8, 2))
            textbox = ctk.CTkTextbox(section.content, height=60, font=FONT_MONO, fg_color=BG_DARK)
            textbox.pack(fill="x", padx=5, pady=2)
            items = defaults.get(wl_type, [])
            textbox.insert("1.0", "\n".join(items))
            self._widgets[f"whitelist_{wl_type}"] = textbox

        # Add entry
        add_row = ctk.CTkFrame(section.content, fg_color="transparent")
        add_row.pack(fill="x", pady=5, padx=5)
        self._wl_type_var = ctk.CTkOptionMenu(add_row, values=["process", "ip", "path", "hash"], width=80)
        self._wl_type_var.pack(side="left", padx=2)
        self._wl_entry = ctk.CTkEntry(add_row, placeholder_text="Value to whitelist...", width=200)
        self._wl_entry.pack(side="left", padx=2)
        ctk.CTkButton(
            add_row, text="Add", width=60, font=FONT_SMALL,
            fg_color=ACCENT_GREEN, command=self._add_whitelist_entry,
        ).pack(side="left", padx=2)

    def _build_detection_section(self) -> None:
        section = ConfigSection(self._scroll, "Detection Rules", expanded=False)
        section.pack(fill="x", pady=PAD_WIDGET)

        det = self._config.get("detection", {})

        for key, label in [
            ("network.suspicious_ports", "Suspicious Ports (comma-separated)"),
            ("process.suspicious_process_names", "Suspicious Process Names (one per line)"),
            ("filesystem.suspicious_extensions", "Suspicious Extensions (one per line)"),
        ]:
            parts = key.split(".")
            data = det.get(parts[0], {}).get(parts[1], [])
            ctk.CTkLabel(section.content, text=label, font=FONT_SMALL, text_color=TEXT_SECONDARY, anchor="w").pack(fill="x", padx=5, pady=(8, 2))
            textbox = ctk.CTkTextbox(section.content, height=50, font=FONT_MONO, fg_color=BG_DARK)
            textbox.pack(fill="x", padx=5, pady=2)
            if "port" in key:
                textbox.insert("1.0", ", ".join(str(p) for p in data))
            else:
                textbox.insert("1.0", "\n".join(data))
            self._widgets[f"detect_{key}"] = textbox

        # Watched paths
        watched = det.get("filesystem", {}).get("watched_paths", [])
        ctk.CTkLabel(section.content, text="Watched Paths (one per line)", font=FONT_SMALL, text_color=TEXT_SECONDARY, anchor="w").pack(fill="x", padx=5, pady=(8, 2))
        wp_textbox = ctk.CTkTextbox(section.content, height=50, font=FONT_MONO, fg_color=BG_DARK)
        wp_textbox.pack(fill="x", padx=5, pady=2)
        wp_textbox.insert("1.0", "\n".join(watched))
        self._widgets["detect_watched_paths"] = wp_textbox

    def _build_suricata_section(self) -> None:
        section = ConfigSection(self._scroll, "Suricata (Optional)", expanded=False)
        section.pack(fill="x", pady=PAD_WIDGET)

        suri = self._config.get("detection", {}).get("suricata", {})

        switch = ctk.CTkSwitch(section.content, text="Enable Suricata", font=FONT_BODY)
        if suri.get("enabled"):
            switch.select()
        switch.pack(anchor="w", padx=5, pady=5)
        self._widgets["suricata_enabled"] = switch

        row = ctk.CTkFrame(section.content, fg_color="transparent")
        row.pack(fill="x", pady=2, padx=5)
        ctk.CTkLabel(row, text="Eve.json path:", font=FONT_SMALL, text_color=TEXT_SECONDARY).pack(side="left")
        eve_entry = ctk.CTkEntry(row, width=300, font=FONT_SMALL)
        eve_entry.insert(0, suri.get("eve_json_path", ""))
        eve_entry.pack(side="left", padx=5)
        ctk.CTkButton(row, text="Browse", width=70, font=FONT_SMALL, command=lambda: self._browse_file(eve_entry)).pack(side="left")
        self._widgets["suricata_eve_path"] = eve_entry

        row2 = ctk.CTkFrame(section.content, fg_color="transparent")
        row2.pack(fill="x", pady=2, padx=5)
        ctk.CTkLabel(row2, text="Syslog port:", font=FONT_SMALL, text_color=TEXT_SECONDARY).pack(side="left")
        port_entry = ctk.CTkEntry(row2, width=80, font=FONT_SMALL)
        port_entry.insert(0, str(suri.get("syslog_listen_port", 0)))
        port_entry.pack(side="left", padx=5)
        self._widgets["suricata_syslog_port"] = port_entry

    def _build_intel_section(self) -> None:
        section = ConfigSection(self._scroll, "Threat Intelligence", expanded=False)
        section.pack(fill="x", pady=PAD_WIDGET)

        intel = self._config.get("intel", {})

        switch = ctk.CTkSwitch(section.content, text="Enable Intel", font=FONT_BODY)
        if intel.get("enabled", True):
            switch.select()
        switch.pack(anchor="w", padx=5, pady=5)
        self._widgets["intel_enabled"] = switch

        for api_name, label in [("abuseipdb", "AbuseIPDB"), ("virustotal", "VirusTotal")]:
            row = ctk.CTkFrame(section.content, fg_color="transparent")
            row.pack(fill="x", pady=2, padx=5)
            api_switch = ctk.CTkSwitch(row, text=label, font=FONT_SMALL)
            if intel.get(api_name, {}).get("enabled"):
                api_switch.select()
            api_switch.pack(side="left")
            self._widgets[f"intel_{api_name}_enabled"] = api_switch

            ctk.CTkLabel(row, text="API Key:", font=FONT_SMALL, text_color=TEXT_SECONDARY).pack(side="left", padx=(15, 5))
            key_entry = ctk.CTkEntry(row, width=250, font=FONT_SMALL, show="*", placeholder_text="Enter API key...")
            key_entry.pack(side="left")
            self._widgets[f"intel_{api_name}_key"] = key_entry

        row = ctk.CTkFrame(section.content, fg_color="transparent")
        row.pack(fill="x", pady=2, padx=5)
        ctk.CTkLabel(row, text="Request timeout (sec):", font=FONT_SMALL, text_color=TEXT_SECONDARY).pack(side="left")
        timeout_entry = ctk.CTkEntry(row, width=60, font=FONT_SMALL)
        timeout_entry.insert(0, str(intel.get("request_timeout_seconds", 10)))
        timeout_entry.pack(side="left", padx=5)
        self._widgets["intel_timeout"] = timeout_entry

    def _build_response_section(self) -> None:
        section = ConfigSection(self._scroll, "Response", expanded=False)
        section.pack(fill="x", pady=PAD_WIDGET)

        resp = self._config.get("response", {})

        confirm_switch = ctk.CTkSwitch(section.content, text="Require Confirmation", font=FONT_BODY)
        if resp.get("require_confirmation", True):
            confirm_switch.select()
        confirm_switch.pack(anchor="w", padx=5, pady=5)
        self._widgets["resp_require_confirm"] = confirm_switch

        dry_switch = ctk.CTkSwitch(section.content, text="Dry Run Mode", font=FONT_BODY)
        if resp.get("dry_run", False):
            dry_switch.select()
        dry_switch.pack(anchor="w", padx=5, pady=2)
        self._widgets["resp_dry_run"] = dry_switch

        row = ctk.CTkFrame(section.content, fg_color="transparent")
        row.pack(fill="x", pady=2, padx=5)
        ctk.CTkLabel(row, text="Firewall rule prefix:", font=FONT_SMALL, text_color=TEXT_SECONDARY).pack(side="left")
        prefix_entry = ctk.CTkEntry(row, width=150, font=FONT_SMALL)
        prefix_entry.insert(0, resp.get("firewall_rule_prefix", "CAD_BLOCK_"))
        prefix_entry.pack(side="left", padx=5)
        self._widgets["resp_fw_prefix"] = prefix_entry

    def _build_save_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x", padx=PAD_SECTION, pady=PAD_WIDGET)

        self._save_status = ctk.CTkLabel(bar, text="", font=FONT_SMALL, text_color=ACCENT_GREEN)
        self._save_status.pack(side="left", padx=10)

        ctk.CTkButton(
            bar, text="Save Configuration", font=FONT_BODY,
            fg_color=ACCENT_GREEN, hover_color="#2ea043", width=180,
            command=self._save_config,
        ).pack(side="right", padx=5)

        ctk.CTkButton(
            bar, text="Reset to Defaults", font=FONT_BODY,
            fg_color=BORDER_COLOR, hover_color="#484f58", width=150,
            command=self._reset_defaults,
        ).pack(side="right", padx=5)

    def _save_config(self) -> None:
        """Collect all widget values and save to config/local.toml."""
        config = self._collect_values()
        try:
            import tomli_w
            LOCAL_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(LOCAL_CONFIG_PATH, "wb") as f:
                tomli_w.dump(config, f)
            self._save_status.configure(text="Configuration saved!", text_color=ACCENT_GREEN)
            self._bridge.send_command("reload_config")
        except Exception as exc:
            logger.error("Failed to save config: %s", exc)
            self._save_status.configure(text=f"Save failed: {exc}", text_color=ACCENT_RED)

    def _collect_values(self) -> dict[str, Any]:
        """Collect current widget values into a config dict."""
        enabled_dets = []
        for det_name in ["eventlog", "network", "process", "filesystem"]:
            switch = self._widgets.get(f"det_{det_name}")
            if switch and switch.get():
                enabled_dets.append(det_name)

        config: dict[str, Any] = {
            "detection": {
                "enabled_detectors": enabled_dets,
                "polling_interval_seconds": self._safe_int(self._widgets.get("polling_interval"), 5),
            },
            "analysis": {
                "score_threshold": int(self._widgets["score_threshold"].get()),
            },
            "response": {
                "require_confirmation": bool(self._widgets["resp_require_confirm"].get()),
                "dry_run": bool(self._widgets["resp_dry_run"].get()),
                "firewall_rule_prefix": self._widgets["resp_fw_prefix"].get(),
            },
        }

        # Scoring weights
        weights: dict[str, int] = {}
        for key, widget in self._widgets.items():
            if key.startswith("weight_"):
                rule = key[7:]
                weights[rule] = self._safe_int(widget, 0)
        if weights:
            config["analysis"]["scoring_weights"] = weights

        # Suricata
        suri_switch = self._widgets.get("suricata_enabled")
        if suri_switch:
            config.setdefault("detection", {})["suricata"] = {
                "enabled": bool(suri_switch.get()),
                "eve_json_path": self._widgets.get("suricata_eve_path", ctk.CTkEntry(self)).get(),
                "syslog_listen_port": self._safe_int(self._widgets.get("suricata_syslog_port"), 0),
            }

        # Intel
        intel_switch = self._widgets.get("intel_enabled")
        if intel_switch:
            config["intel"] = {
                "enabled": bool(intel_switch.get()),
                "request_timeout_seconds": self._safe_int(self._widgets.get("intel_timeout"), 10),
                "abuseipdb": {"enabled": bool(self._widgets.get("intel_abuseipdb_enabled", ctk.CTkSwitch(self)).get())},
                "virustotal": {"enabled": bool(self._widgets.get("intel_virustotal_enabled", ctk.CTkSwitch(self)).get())},
            }

        return config

    @staticmethod
    def _safe_int(widget: Any, default: int) -> int:
        """Safely get integer from a widget."""
        if widget is None:
            return default
        try:
            return int(widget.get())
        except (ValueError, TypeError):
            return default

    def _add_whitelist_entry(self) -> None:
        """Send a whitelist add command."""
        entry_type = self._wl_type_var.get()
        value = self._wl_entry.get().strip()
        if not value:
            return
        self._bridge.send_command("add_whitelist", {
            "entry_type": entry_type, "value": value, "reason": "User added via GUI",
        })
        self._wl_entry.delete(0, "end")

    def _browse_file(self, entry: ctk.CTkEntry) -> None:
        """Open a file browser dialog and set the entry value."""
        path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if path:
            entry.delete(0, "end")
            entry.insert(0, path)

    def _reset_defaults(self) -> None:
        """Delete local.toml and reload defaults."""
        if LOCAL_CONFIG_PATH.exists():
            LOCAL_CONFIG_PATH.unlink()
        self._bridge.send_command("reload_config")
        self._save_status.configure(text="Reset to defaults. Restart recommended.", text_color=ACCENT_BLUE)
