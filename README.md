# Cyber Attack Detection v1.0.1

Real-time intrusion detection system for Windows 10/11 with Suricata integration, forensic evidence collection, and automated response.

## Features

- **5 Detection Engines** running in parallel:
  - **Process Detector** — malicious process names, suspicious parent-child chains, abnormal resource usage
  - **Network Detector** — connections to C2 ports, new listening ports, connection flood detection
  - **EventLog / Sysmon Detector** — brute force (Event 4625), privilege escalation (4672), new services (7045), log clearing (1102), plus 16 Sysmon event types (process injection, LSASS access, encoded PowerShell, WMI persistence...)
  - **Filesystem Detector** — new executables dropped in System32/SysWOW64
  - **Suricata Detector** — real-time ingestion of `eve.json` alerts from Suricata IDS (40,000+ Emerging Threats rules)

- **False Positive Analysis** — 6-stage pipeline: whitelist filtering, behavioral baseline, confidence scoring with contextual multipliers, deduplication, multi-signal correlation, threshold gating

- **Forensic Evidence Collection** — automatic on HIGH/CRITICAL alerts: process list, network connections, registry persistence keys, scheduled tasks, system snapshot, SHA-256 integrity hashes, timeline reconstruction

- **OSINT Intelligence** — legal source identification: WHOIS, reverse DNS, GeoIP, traceroute, abuse contact lookup

- **Automated Response** — firewall rules, process termination, network isolation, file quarantine, with full rollback capability

- **Forensic Report Export** — ZIP archive with README, JSON evidence, SHA-256 checksums, chain of custody — ready for law enforcement

## Architecture

```
src/
├── core/           # Config, database, event bus, models, logging
├── detectors/      # 5 detection engines (process, network, eventlog, filesystem, suricata)
├── analysis/       # Scoring, correlation, whitelist, baseline, aggregation
├── forensics/      # Evidence store, snapshots, timeline, report generation
├── intel/          # WHOIS, DNS, GeoIP, traceroute, OSINT aggregator
├── response/       # Firewall, process kill, quarantine, network isolation, rollback
└── ui/             # GUI (CustomTkinter) with 5 tabs + system tray
```

## Requirements

- Windows 10 or 11
- Python 3.13+ (for development only — standalone `.exe` provided)
- Administrator privileges (for event log access and Suricata)

### Optional (installed automatically by the installer)

- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — enhances detection with 16 additional event types
- [Suricata](https://suricata.io/) — network IDS with 40,000+ rules
- [Npcap](https://npcap.com/) — packet capture driver (required by Suricata)

## Installation

### Option 1: Installer (recommended)

Download and run `CyberAttackDetection_1.0.1.exe` from [Releases](https://github.com/loicata/CyberAttackDetection/releases).

The installer handles everything:
- Installs the application to `C:\Program Files\Cyber Attack Detection`
- Optionally installs Sysmon with SwiftOnSecurity config
- Optionally installs Suricata + Npcap with Emerging Threats rules
- Installs VC++ Redistributable if needed
- Creates desktop shortcut and Start menu entry
- Registers as a Windows service (auto-start)

### Option 2: From source

```bash
git clone https://github.com/loicata/CyberAttackDetection.git
cd CyberAttackDetection
pip install -r requirements.txt
python run.py
```

## Usage

1. Launch **Cyber Attack Detection** (as Administrator for full functionality)
2. The dashboard shows real-time detector status and alert counters
3. Configure Suricata `eve.json` path in the **Config** tab if not auto-detected
4. Alerts appear automatically when threats are detected
5. Click an alert in **Forensics** to view collected evidence
6. Click **Generate Report** to export a forensic ZIP archive
7. Use the **Response** tab to apply countermeasures (firewall block, process kill, etc.)

## Detection Pipeline

```
Event Collection (5 detectors)
    → Whitelist Check (known-safe filtering)
    → Behavioral Baseline (anomaly vs normal)
    → Confidence Scoring (contextual multipliers)
    → Deduplication (5-min window)
    → Multi-Signal Correlation (attack pattern matching)
    → Threshold Gate (score ≥ 40 → alert)
```

### Severity Classification

| Score   | Severity | Automatic Action                      |
|---------|----------|---------------------------------------|
| 0–39    | LOW      | Logged only                           |
| 40–59   | MEDIUM   | Forensic evidence collection          |
| 60–79   | HIGH     | Forensics + OSINT intelligence        |
| 80–100  | CRITICAL | Forensics + OSINT + popup notification|

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=term-missing

# Attack simulation (requires Suricata running)
python scripts/simulate_attack.py
```

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/install_sysmon.ps1` | Install Sysmon with SwiftOnSecurity config |
| `scripts/install_suricata.ps1` | Install Suricata + Npcap + ET rules |
| `scripts/fix_suricata_rules.ps1` | Fix incompatible Suricata rules and restart |
| `scripts/simulate_attack.py` | Simulate attacks to test detection |
| `scripts/generate_icon.py` | Generate the application icon |
| `scripts/build_installer.ps1` | Build the Inno Setup installer |

## Configuration

Configuration files are in `config/`:

- `default.toml` — default settings (do not edit)
- `local.toml` — user overrides (auto-created)

Key settings:

```toml
[suricata]
enabled = true
eve_json_path = "C:\\Program Files\\Suricata\\log\\eve.json"

[scoring]
alert_threshold = 40

[detectors]
scan_interval = 5
```

## License

MIT License — see [LICENSE](LICENSE).

## Disclaimer

This software is provided for **defensive security purposes only**. The attack simulation script (`simulate_attack.py`) must only be used on networks you own or have explicit authorization to test. Unauthorized network scanning or intrusion testing is illegal.
