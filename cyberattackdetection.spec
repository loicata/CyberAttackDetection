# -*- mode: python ; coding: utf-8 -*-

import os
import customtkinter

block_cipher = None

ctk_path = os.path.dirname(customtkinter.__file__)

a = Analysis(
    ['run.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('config/default.toml', 'config'),
        ('.env.example', '.'),
        ('assets/icon.ico', 'assets'),
        (ctk_path, 'customtkinter'),
    ],
    hiddenimports=[
        'src', 'src.core', 'src.core.config', 'src.core.database',
        'src.core.enums', 'src.core.event_bus', 'src.core.exceptions',
        'src.core.logging_setup', 'src.core.models',
        'src.detectors', 'src.detectors.base',
        'src.detectors.process_detector', 'src.detectors.network_detector',
        'src.detectors.eventlog_detector', 'src.detectors.filesystem_detector',
        'src.detectors.suricata_detector',
        'src.analysis', 'src.analysis.whitelist', 'src.analysis.baseline',
        'src.analysis.scorer', 'src.analysis.aggregator', 'src.analysis.correlator',
        'src.intel', 'src.intel.dns_lookup', 'src.intel.whois_lookup',
        'src.intel.geoip', 'src.intel.traceroute', 'src.intel.osint',
        'src.intel.intel_aggregator',
        'src.forensics', 'src.forensics.file_hasher', 'src.forensics.snapshot',
        'src.forensics.registry_snapshot', 'src.forensics.evidence_store',
        'src.forensics.timeline', 'src.forensics.report_generator',
        'src.response', 'src.response.base', 'src.response.firewall',
        'src.response.process_kill', 'src.response.quarantine',
        'src.response.network_isolate', 'src.response.rollback_manager',
        'src.response.response_executor',
        'src.ui', 'src.ui.app', 'src.ui.bridge', 'src.ui.theme',
        'src.ui.console',
        'src.ui.tabs', 'src.ui.tabs.dashboard_tab', 'src.ui.tabs.alerts_tab',
        'src.ui.tabs.config_tab', 'src.ui.tabs.forensics_tab',
        'src.ui.tabs.response_tab',
        'src.ui.widgets', 'src.ui.widgets.alert_card',
        'src.ui.widgets.severity_badge', 'src.ui.widgets.detector_indicator',
        'src.ui.widgets.stat_counter', 'src.ui.widgets.config_section',
        'src.ui.widgets.confirmation_dialog',
        'src.main',
        'psutil', 'watchdog', 'watchdog.observers', 'watchdog.events',
        'rich', 'rich.console', 'rich.table', 'rich.panel', 'rich.text',
        'rich.layout', 'jinja2', 'dotenv', 'dotenv.main',
        'dns', 'dns.resolver', 'ijson', 'requests',
        'customtkinter', 'tomli_w',
        'pystray', 'pystray._win32', 'PIL', 'PIL.Image',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CyberAttackDetection',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico',
    uac_admin=False,
)
