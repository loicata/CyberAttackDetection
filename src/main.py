"""Main entry point for Cyber Attack Detection.

Orchestrates all components: detectors, analysis pipeline,
forensic collection, response framework, and GUI/console UI.

Supports two modes:
- GUI mode (default): CustomTkinter dashboard
- Console mode (--console flag): Rich terminal output
"""

from __future__ import annotations

import asyncio
import logging
import queue
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from src.core.config import AppConfig, load_config
from src.core.database import Database
from src.core.enums import AlertSeverity, AlertStatus, AlertType, EvidenceType, ResponseType
from src.core.event_bus import EventBus
from src.core.logging_setup import setup_logging
from src.core.models import Alert, RawEvent
from src.analysis.aggregator import AlertAggregator
from src.analysis.baseline import BaselineManager
from src.analysis.correlator import EventCorrelator
from src.analysis.scorer import AlertScorer
from src.analysis.whitelist import WhitelistManager
from src.detectors.base import BaseDetector
from src.detectors.eventlog_detector import EventLogDetector
from src.detectors.filesystem_detector import FilesystemDetector
from src.detectors.network_detector import NetworkDetector
from src.detectors.process_detector import ProcessDetector
from src.detectors.suricata_detector import SuricataDetector
from src.forensics.evidence_store import EvidenceStore
from src.forensics.report_generator import generate_report
from src.forensics.snapshot import (
    capture_network_connections,
    capture_process_details,
    capture_process_list,
    capture_system_snapshot,
)
from src.forensics.registry_snapshot import capture_registry_persistence, capture_scheduled_tasks
from src.forensics.timeline import build_timeline
from src.intel.intel_aggregator import gather_intel
from src.response.response_executor import ResponseExecutor
from src.response.rollback_manager import RollbackManager
from src.ui.bridge import ThreadBridge

logger = logging.getLogger(__name__)

# Status push interval (seconds) for detector health + engine stats
STATUS_PUSH_INTERVAL = 3.0


class Application:
    """Main application orchestrator.

    Manages the lifecycle of all components and coordinates
    the detection -> analysis -> response pipeline.

    Args:
        bridge: Optional ThreadBridge for GUI communication.
            If None, falls back to console Rich output.
    """

    def __init__(self, bridge: ThreadBridge | None = None) -> None:
        self._bridge = bridge
        self._config: AppConfig | None = None
        self._db: Database | None = None
        self._event_bus: EventBus | None = None
        self._detectors: list[BaseDetector] = []
        self._scorer: AlertScorer | None = None
        self._correlator: EventCorrelator | None = None
        self._aggregator: AlertAggregator | None = None
        self._whitelist: WhitelistManager | None = None
        self._baseline: BaselineManager | None = None
        self._evidence_store: EvidenceStore | None = None
        self._response_executor: ResponseExecutor | None = None
        self._rollback_mgr: RollbackManager | None = None
        self._running = False
        self._alert_cache: dict[str, Alert] = {}

    @property
    def config(self) -> AppConfig | None:
        """Current application configuration."""
        return self._config

    @property
    def raw_config(self) -> dict[str, Any]:
        """Raw config dict for the config editor."""
        if self._config:
            return self._config.raw
        return {}

    def _initialize(self) -> None:
        """Initialize all components."""
        load_dotenv()

        self._config = load_config()
        setup_logging(level=self._config.log_level, log_dir=self._config.data_dir)
        logger.info("Configuration loaded: %s", self._config.app_name)

        self._db = Database(
            db_path=self._config.db_path,
            wal_mode=self._config.db_wal_mode,
            busy_timeout_ms=self._config.db_busy_timeout_ms,
        )
        self._db.initialize()

        for dir_path in [
            self._config.forensics.evidence_dir,
            self._config.forensics.quarantine_dir,
            self._config.forensics.report_dir,
        ]:
            Path(dir_path).mkdir(parents=True, exist_ok=True)

        self._event_bus = EventBus(max_queue_size=10000)

        self._whitelist = WhitelistManager(database=self._db, config=self._config)
        self._whitelist.initialize()
        self._baseline = BaselineManager(database=self._db, config=self._config)
        self._scorer = AlertScorer(
            config=self._config, whitelist=self._whitelist, baseline=self._baseline,
        )
        self._correlator = EventCorrelator(config=self._config)
        self._aggregator = AlertAggregator(config=self._config)

        self._evidence_store = EvidenceStore(config=self._config, database=self._db)

        self._rollback_mgr = RollbackManager(database=self._db)
        self._response_executor = ResponseExecutor(
            config=self._config, rollback_manager=self._rollback_mgr,
        )

        self._detectors = self._create_detectors()
        self._event_bus.subscribe(self._process_event)

        logger.info("All components initialized")

    def _create_detectors(self) -> list[BaseDetector]:
        """Create enabled detector instances."""
        assert self._config is not None
        assert self._event_bus is not None

        detectors: list[BaseDetector] = []
        enabled = set(self._config.enabled_detectors)

        if "process" in enabled:
            detectors.append(ProcessDetector(self._event_bus, self._config))
        if "network" in enabled:
            detectors.append(NetworkDetector(self._event_bus, self._config))
        if "eventlog" in enabled:
            detectors.append(EventLogDetector(self._event_bus, self._config))
        if "filesystem" in enabled:
            detectors.append(FilesystemDetector(self._event_bus, self._config))

        # Suricata: enabled by config OR auto-detected
        if self._config.suricata.enabled:
            detectors.append(SuricataDetector(self._event_bus, self._config))
            self._push_log("INFO", "Suricata enabled by configuration")
        else:
            # Auto-detect: check if eve.json exists in default paths
            suricata_auto = SuricataDetector(self._event_bus, self._config)
            detected_path = suricata_auto._auto_detect_eve_json()
            if detected_path:
                detectors.append(suricata_auto)
                self._push_log("INFO", f"Suricata auto-detected: {detected_path}")
            else:
                self._push_log("INFO", "Suricata not detected (optional)")

        return detectors

    # ------------------------------------------------------------------
    # Event processing pipeline
    # ------------------------------------------------------------------

    async def _process_event(self, event: RawEvent) -> None:
        """Process a raw event through the analysis pipeline."""
        assert self._scorer is not None
        assert self._aggregator is not None
        assert self._correlator is not None
        assert self._baseline is not None
        assert self._config is not None

        self._baseline.record_event(event)

        correlations = self._correlator.add_event(event)
        is_correlated = len(correlations) > 0
        has_suricata = event.event_type == AlertType.SURICATA

        score = self._scorer.score_event(
            event, is_correlated=is_correlated, has_suricata_match=has_suricata,
        )

        rule = event.data.get("rule", "unknown")
        sig = event.data.get("signature", "")
        if event.event_type == AlertType.SURICATA:
            logger.info(
                "Suricata event scored: rule=%s sig='%s' score=%d (threshold=%d)",
                rule, sig, score, self._config.analysis.score_threshold,
            )

        threshold = self._config.analysis.score_threshold
        if score < threshold:
            return

        agg_result = self._aggregator.check_duplicate(event, score)
        if not agg_result.is_new and not agg_result.is_flood:
            return

        severity = AlertSeverity.from_score(score)
        title = self._generate_title(event)
        description = self._generate_description(event, correlations)

        alert = Alert(
            alert_type=event.event_type, severity=severity, score=score,
            title=title, description=description, raw_event=event,
            source_ip=event.source_ip, source_port=event.source_port,
            dest_ip=event.dest_ip, dest_port=event.dest_port,
            process_name=event.process_name, process_pid=event.process_pid,
            file_path=event.file_path,
            correlated_event_uids=[uid for c in correlations for uid in c.involved_event_uids],
            occurrence_count=agg_result.count,
        )

        assert self._db is not None
        try:
            self._db.insert_alert(alert)
        except Exception:
            logger.exception("Failed to persist alert %s", alert.alert_uid)
            return

        self._alert_cache[alert.alert_uid] = alert
        self._push_alert(alert)

        await self._handle_forensics(alert)

        if severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
            await self._handle_intel(alert)

    # ------------------------------------------------------------------
    # Output: bridge (GUI) or console fallback
    # ------------------------------------------------------------------

    def _push_alert(self, alert: Alert) -> None:
        """Push alert to GUI bridge or print to console."""
        alert_dict = self._alert_to_dict(alert)
        logger.info(
            "Pushing alert to GUI: %s severity=%s score=%d title='%s'",
            alert.alert_uid, alert.severity.value, alert.score, alert.title,
        )
        if self._bridge:
            self._bridge.push_alert(alert_dict)
            logger.info("Alert pushed to bridge queue (size=%d)", self._bridge.alert_queue.qsize())
        else:
            from src.ui.console import print_alert
            print_alert(alert_dict)

    def _push_log(self, level: str, message: str) -> None:
        """Push log message to GUI bridge."""
        if self._bridge:
            self._bridge.push_log(level, message)

    # ------------------------------------------------------------------
    # Forensics
    # ------------------------------------------------------------------

    async def _handle_forensics(self, alert: Alert) -> None:
        """Collect forensic evidence for an alert."""
        assert self._evidence_store is not None
        assert self._config is not None

        min_severity = self._config.forensics.snapshot_on_severity
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        alert_idx = severity_order.index(alert.severity.value)
        min_idx = severity_order.index(min_severity)

        if alert_idx < min_idx:
            return

        logger.info("Collecting forensic evidence for alert %s", alert.alert_uid)
        evidence_count = 0

        try:
            snapshot = await capture_system_snapshot()
            self._evidence_store.store_evidence(
                alert.alert_uid, EvidenceType.SYSTEM_SNAPSHOT, snapshot, "system_snapshot.json",
            )
            evidence_count += 1

            processes = await capture_process_list()
            self._evidence_store.store_evidence(
                alert.alert_uid, EvidenceType.PROCESS_LIST, processes, "process_list.json",
            )
            evidence_count += 1

            connections = await capture_network_connections()
            self._evidence_store.store_evidence(
                alert.alert_uid, EvidenceType.NETWORK_CONNECTIONS, connections, "network_connections.json",
            )
            evidence_count += 1

            if alert.process_pid:
                proc_details = await capture_process_details(alert.process_pid)
                if proc_details:
                    self._evidence_store.store_evidence(
                        alert.alert_uid, EvidenceType.LOADED_DLLS, proc_details, "process_details.json",
                    )
                    evidence_count += 1

            registry = capture_registry_persistence()
            self._evidence_store.store_evidence(
                alert.alert_uid, EvidenceType.REGISTRY_PERSISTENCE, registry, "registry_persistence.json",
            )
            evidence_count += 1

            tasks = capture_scheduled_tasks()
            self._evidence_store.store_evidence(
                alert.alert_uid, EvidenceType.SERVICES_LIST, tasks, "scheduled_tasks.json",
            )
            evidence_count += 1

            timeline_data = build_timeline(alert, [])
            self._evidence_store.store_evidence(
                alert.alert_uid, EvidenceType.TIMELINE, timeline_data, "timeline.json",
            )
            evidence_count += 1

            self._evidence_store.generate_manifest(alert.alert_uid)

            if self._bridge:
                self._bridge.push_forensic_complete(alert.alert_uid, evidence_count)
            self._push_log("INFO", f"Forensics collected: {evidence_count} files for {alert.alert_uid[:8]}")

        except Exception:
            logger.exception("Forensic collection failed for alert %s", alert.alert_uid)
            self._push_log("ERROR", f"Forensic collection failed for {alert.alert_uid[:8]}")

    async def _handle_intel(self, alert: Alert) -> None:
        """Gather threat intelligence for an alert."""
        assert self._config is not None

        target_ip = alert.source_ip or alert.dest_ip
        if not target_ip or not self._config.intel.enabled:
            return

        try:
            intel = await asyncio.to_thread(gather_intel, target_ip, self._config)
            alert.intel_data = asdict(intel)
            if self._bridge:
                self._bridge.push_intel_complete(alert.alert_uid, asdict(intel))
        except Exception:
            logger.exception("Intel gathering failed for %s", target_ip)

    # ------------------------------------------------------------------
    # Command consumer (GUI -> Engine)
    # ------------------------------------------------------------------

    async def _command_consumer(self) -> None:
        """Consume commands from the GUI command queue."""
        if not self._bridge:
            return

        while self._running:
            try:
                msg = await asyncio.to_thread(
                    self._bridge.command_queue.get, True, 0.2,
                )
            except queue.Empty:
                continue
            except Exception:
                continue

            cmd_type = msg.get("type", "")
            data = msg.get("data", {})

            try:
                await self._handle_command(cmd_type, data)
            except Exception:
                logger.exception("Failed to handle command: %s", cmd_type)

    async def _handle_command(self, cmd_type: str, data: dict[str, Any]) -> None:
        """Handle a single command from the GUI.

        Args:
            cmd_type: Command type string.
            data: Command payload.
        """
        if cmd_type == "shutdown":
            self._running = False

        elif cmd_type == "execute_response":
            await self._execute_response_command(data)

        elif cmd_type == "add_whitelist":
            if self._whitelist:
                self._whitelist.add_entry(
                    data["entry_type"], data["value"], data.get("reason", "GUI"),
                )

        elif cmd_type == "mark_false_positive":
            if self._db:
                self._db.update_alert_status(
                    data["alert_uid"], AlertStatus.FALSE_POSITIVE,
                    datetime.now(timezone.utc).isoformat(),
                )
                if self._bridge:
                    self._bridge.push_alert_update(data["alert_uid"], "false_positive")

        elif cmd_type == "reload_config":
            self._config = load_config()
            logger.info("Configuration reloaded")
            if self._bridge:
                self._bridge.push_log("INFO", "Configuration reloaded successfully")

        elif cmd_type == "generate_report":
            await self._generate_report_command(data)

        elif cmd_type == "verify_integrity":
            self._verify_integrity_command(data)

    async def _execute_response_command(self, data: dict[str, Any]) -> None:
        """Execute a response action from the GUI."""
        assert self._response_executor is not None

        alert_uid = data.get("alert_uid", "")
        response_type_str = data.get("response_type", "")
        params = data.get("params", {})

        alert = self._alert_cache.get(alert_uid)
        if not alert:
            logger.error("Alert not found in cache: %s", alert_uid)
            if self._bridge:
                self._bridge.push_response_result(alert_uid, False, "Alert not found")
            return

        try:
            response_type = ResponseType(response_type_str)
        except ValueError:
            if self._bridge:
                self._bridge.push_response_result(alert_uid, False, f"Unknown response type: {response_type_str}")
            return

        if response_type == ResponseType.REPORT_ONLY:
            await self._generate_report_command({"alert_uid": alert_uid})
            return

        result = self._response_executor.execute_action(response_type, alert, params)

        if self._bridge:
            self._bridge.push_response_result(alert_uid, result.success, result.message)

    async def _generate_report_command(self, data: dict[str, Any]) -> None:
        """Generate a forensic report from a GUI command."""
        assert self._config is not None
        assert self._db is not None

        alert_uid = data.get("alert_uid", "")
        logger.info("Generating report for alert %s", alert_uid)

        # Try cache first, then database
        alert = self._alert_cache.get(alert_uid)
        if not alert:
            alert = self._db.get_alert_by_uid(alert_uid)
        if not alert:
            logger.warning("Alert %s not found in cache or database", alert_uid)
            if self._bridge:
                self._bridge.push_response_result(
                    alert_uid, False, "Alert not found. Try refreshing.",
                )
            return

        try:
            evidence_records = self._db.get_evidence_for_alert(alert_uid)
            timeline_data = build_timeline(alert, [])

            html_path, _ = generate_report(
                alert=alert, config=self._config,
                timeline=timeline_data, evidence_files=evidence_records,
                intel_data=alert.intel_data,
            )

            # Find the ZIP archive (same base name as html)
            zip_path = html_path.with_suffix(".zip")

            # Copy ZIP to user-chosen location if specified
            user_save_path = data.get("save_path")
            final_path = zip_path

            if user_save_path and zip_path.exists():
                import shutil
                shutil.copy2(str(zip_path), user_save_path)
                final_path = Path(user_save_path)
                logger.info("Forensic archive saved to: %s", final_path)

            if self._bridge:
                msg = f"Archive saved: {final_path}"
                self._bridge.push_response_result(alert_uid, True, msg)
                self._bridge.push_forensic_complete(alert_uid, len(evidence_records))

            # Open Explorer selecting the saved file
            import subprocess
            subprocess.Popen(
                ["explorer", "/select,", str(final_path)],
                creationflags=0x08000000,
            )

        except Exception as exc:
            logger.exception("Report generation failed for %s", alert_uid)
            if self._bridge:
                self._bridge.push_response_result(
                    alert_uid, False, f"Report failed: {exc}",
                )

    def _verify_integrity_command(self, data: dict[str, Any]) -> None:
        """Verify evidence integrity from a GUI command."""
        assert self._evidence_store is not None

        alert_uid = data.get("alert_uid", "")
        logger.info("Verifying integrity for alert %s", alert_uid)

        # Get alert title for user-friendly messages
        alert_label = alert_uid[:8]
        alert = self._alert_cache.get(alert_uid)
        if not alert and self._db:
            alert = self._db.get_alert_by_uid(alert_uid)
        if alert:
            alert_label = alert.title[:50] if alert.title else alert_uid[:8]

        try:
            result = self._evidence_store.verify_integrity(alert_uid)

            if isinstance(result, dict):
                total = result.get("total", 0)
                valid = result.get("valid", 0)
                msg = f"Integrity OK: {valid}/{total} files verified for {alert_label}"
            else:
                msg = f"Integrity verified for {alert_label}"

            logger.info(msg)
            if self._bridge:
                self._bridge.push_response_result(alert_uid, True, msg)
                self._bridge.push_log("INFO", msg)

        except Exception as exc:
            msg = f"Integrity FAILED for {alert_label}: {exc}"
            logger.error(msg)
            if self._bridge:
                self._bridge.push_response_result(alert_uid, False, msg)
                self._bridge.push_log("ERROR", msg)

    # ------------------------------------------------------------------
    # Status pusher
    # ------------------------------------------------------------------

    async def _status_pusher(self) -> None:
        """Periodically push detector status and engine stats to GUI."""
        if not self._bridge:
            return

        while self._running:
            statuses = [d.health_check() for d in self._detectors]
            self._bridge.push_detector_status(statuses)

            if self._event_bus:
                self._bridge.push_engine_stats({
                    "event_count": self._event_bus.event_count,
                    "queue_size": self._event_bus.queue_size,
                })

            await asyncio.sleep(STATUS_PUSH_INTERVAL)

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_title(event: RawEvent) -> str:
        """Generate an alert title from event data."""
        rule = event.data.get("rule", "unknown")
        titles = {
            # Standard detectors
            "known_malware_name": f"Malware detected: {event.process_name}",
            "suspicious_parent_child": f"Suspicious process chain: {event.process_name}",
            "suspicious_port_connection": f"Suspicious connection to port {event.dest_port}",
            "new_listening_port": f"New listening port: {event.dest_port}",
            "log_clearing": "Security log cleared",
            "new_service_installed": "New service installed",
            "multiple_failed_logins": f"Brute force from {event.source_ip}",
            "filesystem_change_system32": f"System file modified: {event.file_path}",
            "suricata_high_severity": event.data.get("signature", "Suricata Alert"),
            "suricata_medium_severity": event.data.get("signature", "Suricata Alert"),
            "connection_spike": "Connection spike detected",
            "process_high_cpu": f"High CPU: {event.process_name}",
            "process_high_memory": f"High memory: {event.process_name}",
            # Sysmon — critical
            "sysmon_process_tampering": f"SYSMON: Process tampering detected: {event.process_name}",
            "sysmon_create_remote_thread": f"SYSMON: Code injection (CreateRemoteThread): {event.process_name}",
            "sysmon_lsass_access": f"SYSMON: LSASS credential access by {event.process_name}",
            "sysmon_encoded_powershell": f"SYSMON: Encoded PowerShell command: {event.process_name}",
            "sysmon_suspicious_pipe": f"SYSMON: Suspicious named pipe: {event.data.get('PipeName', '?')}",
            "sysmon_suspicious_dns": f"SYSMON: Suspicious DNS query: {event.data.get('QueryName', '?')}",
            "sysmon_dns_tunneling": f"SYSMON: Possible DNS tunneling: {event.data.get('QueryName', '?')}",
            "sysmon_registry_persistence": f"SYSMON: Registry persistence: {event.file_path}",
            "sysmon_suspicious_dll_load": f"SYSMON: Suspicious DLL loaded by {event.process_name}",
            "sysmon_suspicious_network": f"SYSMON: Suspicious outbound: {event.process_name} -> {event.dest_ip}",
            "sysmon_startup_file_create": f"SYSMON: File created in Startup: {event.file_path}",
            "sysmon_suspicious_exec_path": f"SYSMON: Execution from suspicious path: {event.process_name}",
            "sysmon_ads_created": f"SYSMON: Alternate Data Stream created: {event.file_path}",
            "sysmon_driver_loaded": f"SYSMON: Unsigned driver loaded: {event.data.get('ImageLoaded', '?')}",
            "sysmon_unsigned_dll_load": f"SYSMON: Unsigned DLL: {event.data.get('ImageLoaded', '?')}",
        }
        return titles.get(rule, f"Detection: {rule}")

    @staticmethod
    def _generate_description(event: RawEvent, correlations: list) -> str:
        """Generate a detailed description."""
        rule = event.data.get("rule", "unknown")
        # For Suricata, show signature and category instead of internal rule name
        from src.core.enums import AlertType
        if event.event_type == AlertType.SURICATA:
            sig = event.data.get("signature", rule)
            cat = event.data.get("category", "")
            parts = [f"Suricata: {sig}"]
            if cat:
                parts.append(f"Category: {cat}")
        else:
            parts = [f"Rule: {rule}"]
        if event.process_name:
            parts.append(f"Process: {event.process_name} (PID {event.process_pid})")
        if event.source_ip:
            parts.append(f"Source: {event.source_ip}:{event.source_port or '?'}")
        if event.dest_ip:
            parts.append(f"Dest: {event.dest_ip}:{event.dest_port or '?'}")
        if event.file_path:
            parts.append(f"File: {event.file_path}")
        if correlations:
            patterns = [c.pattern_name for c in correlations]
            parts.append(f"Correlated patterns: {', '.join(patterns)}")
        return " | ".join(parts)

    @staticmethod
    def _alert_to_dict(alert: Alert) -> dict[str, Any]:
        """Convert an Alert to a display-friendly dict."""
        return {
            "alert_uid": alert.alert_uid,
            "title": alert.title,
            "severity": alert.severity.value,
            "score": alert.score,
            "alert_type": alert.alert_type.value,
            "status": alert.status.value,
            "source_ip": alert.source_ip,
            "source_port": alert.source_port,
            "dest_ip": alert.dest_ip,
            "dest_port": alert.dest_port,
            "process_name": alert.process_name,
            "process_pid": alert.process_pid,
            "description": alert.description,
            "created_at": alert.created_at,
        }

    # ------------------------------------------------------------------
    # Run loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Main application loop (runs in background thread for GUI mode)."""
        self._initialize()
        assert self._event_bus is not None

        await self._event_bus.start()

        for detector in self._detectors:
            try:
                await detector.start()
                logger.info("Detector started: %s", detector.name)
                self._push_log("INFO", f"Detector started: {detector.name}")
            except Exception:
                logger.exception("Failed to start detector: %s", detector.name)

        self._running = True
        self._push_log("INFO", f"Engine started — {len(self._detectors)} detectors active")
        sysmon_status = "enabled" if self._config.sysmon_enabled else "auto-detect at runtime"
        self._push_log("INFO", f"Sysmon: {sysmon_status}")
        self._push_log("INFO", f"Score threshold: {self._config.analysis.score_threshold}")

        # Push initial detector status
        if self._bridge:
            statuses = [d.health_check() for d in self._detectors]
            self._bridge.push_detector_status(statuses)

        # Start background tasks
        tasks: list[asyncio.Task] = []
        if self._bridge:
            tasks.append(asyncio.create_task(self._command_consumer()))
            tasks.append(asyncio.create_task(self._status_pusher()))

        try:
            while self._running:
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            pass

        # Cancel background tasks
        for task in tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        await self._shutdown()

    async def _shutdown(self) -> None:
        """Gracefully stop all components."""
        logger.info("Shutting down...")
        self._running = False

        for detector in self._detectors:
            await detector.stop()

        if self._event_bus is not None:
            await self._event_bus.stop()

        if self._db is not None:
            self._db.close()

        logger.info("Shutdown complete")


def main() -> None:
    """Console-mode entry point (--console flag)."""
    from src.ui.console import console, print_banner

    app = Application()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    print_banner()
    try:
        loop.run_until_complete(app.run())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted by user[/bold yellow]")
        loop.run_until_complete(app._shutdown())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
