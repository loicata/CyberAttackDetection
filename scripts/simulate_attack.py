"""Simulate network attacks to test Suricata + Cyber Attack Detection.

This script generates traffic patterns that trigger Emerging Threats rules.
All traffic stays on the local network or targets safe test endpoints.
No actual malicious payload is sent — only signatures are triggered.

Usage (run as Administrator for best results):
    python scripts/simulate_attack.py
    python scripts/simulate_attack.py --scan-only
    python scripts/simulate_attack.py --dns-only

WARNING: This script is for TESTING PURPOSES ONLY on YOUR OWN network.
"""

from __future__ import annotations

import argparse
import logging
import socket
import struct
import sys
import time
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("attack_simulator")

# ============================================================
# Constants
# ============================================================

# Well-known malicious/test domains that trigger ET DNS rules
# These are SAFE test domains used by security tools
MALICIOUS_DNS_DOMAINS: list[str] = [
    # ET MALWARE / ET TROJAN signatures
    "wpad.localdomain",              # ET POLICY WPAD lookup
    "isatap.localdomain",            # ET POLICY ISATAP lookup
    "testmyids.com",                 # Explicit IDS test domain
    "testmynids.org",                # Explicit NIDS test domain
    # Known C2/malware beaconing patterns (domains are sinkholed/safe)
    "evil.com",
    "malware.testing.google.test",
]

# Ports commonly flagged by ET SCAN rules
SCAN_PORTS: list[int] = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    80,    # HTTP
    110,   # POP3
    135,   # MSRPC
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    993,   # IMAPS
    1433,  # MSSQL
    1723,  # PPTP
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    8080,  # HTTP Proxy
    8443,  # HTTPS Alt
]

# Suspicious ports that trigger ET POLICY rules
SUSPICIOUS_PORTS: list[int] = [
    4444,   # Metasploit default
    5555,   # Android ADB
    6666,   # IRC backdoor
    31337,  # Back Orifice
    12345,  # NetBus
]

# Known-bad User-Agent strings that trigger ET rules
MALICIOUS_USER_AGENTS: list[str] = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "Nikto/2.1.6",
    "sqlmap/1.4",
    "dirbuster",
    "Wget/1.0 (linux)",
]

# HTTP paths that trigger ET WEB_SERVER rules
SUSPICIOUS_HTTP_PATHS: list[str] = [
    "/admin/config.php",
    "/wp-login.php",
    "/phpmyadmin/",
    "/shell.php",
    "/.env",
    "/etc/passwd",
    "/cmd.exe",
    "/cgi-bin/test-cgi",
]


def _get_gateway_ip() -> str:
    """Detect the default gateway IP address.

    Returns:
        Gateway IP as string, or 192.168.1.1 as fallback.
    """
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-Command",
             "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
             "Select-Object -First 1).NextHop"],
            capture_output=True, text=True, timeout=10,
            creationflags=0x08000000,
        )
        gateway = result.stdout.strip()
        if gateway:
            socket.inet_aton(gateway)  # validate
            return gateway
    except Exception:
        pass
    return "192.168.1.1"


def _get_local_ip() -> str:
    """Get the local IP address.

    Returns:
        Local IP as string.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ============================================================
# Phase 1: Port Scanning (triggers ET SCAN rules)
# ============================================================

def simulate_port_scan(target_ip: str) -> int:
    """Perform a fast TCP SYN-like scan against common ports.

    This triggers ET SCAN rules like:
    - ET SCAN Potential VNC Scan
    - ET SCAN Suspicious inbound to MSSQL port
    - ET SCAN Potential SSH Scan
    - ET SCAN Nmap Scripting Engine User-Agent Detected

    Args:
        target_ip: IP address to scan.

    Returns:
        Number of connection attempts made.
    """
    logger.info("=" * 60)
    logger.info("PHASE 1: Port Scan Simulation")
    logger.info("  Target: %s", target_ip)
    logger.info("  Ports: %d common service ports", len(SCAN_PORTS))
    logger.info("=" * 60)

    attempts = 0
    for port in SCAN_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            status = "OPEN" if result == 0 else "closed"
            logger.info("  [SCAN] %s:%d — %s", target_ip, port, status)
            sock.close()
        except Exception as exc:
            logger.debug("  [SCAN] %s:%d — error: %s", target_ip, port, exc)
        attempts += 1
        time.sleep(0.05)  # Small delay to ensure Suricata sees each packet

    logger.info("  Scan complete: %d ports probed", attempts)
    return attempts


def simulate_suspicious_port_connections(target_ip: str) -> int:
    """Connect to ports known for malware/C2 communication.

    Triggers ET POLICY and ET TROJAN rules.

    Args:
        target_ip: IP address to connect to.

    Returns:
        Number of connection attempts.
    """
    logger.info("")
    logger.info("=" * 60)
    logger.info("PHASE 2: Suspicious Port Connections")
    logger.info("  Target: %s", target_ip)
    logger.info("  Ports: %s", SUSPICIOUS_PORTS)
    logger.info("=" * 60)

    attempts = 0
    for port in SUSPICIOUS_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((target_ip, port))
            status = "OPEN" if result == 0 else "refused"
            logger.info("  [C2] %s:%d — %s (Metasploit/RAT port)", target_ip, port, status)
            sock.close()
        except Exception as exc:
            logger.debug("  [C2] %s:%d — %s", target_ip, port, exc)
        attempts += 1
        time.sleep(0.1)

    logger.info("  Suspicious port probes complete: %d attempts", attempts)
    return attempts


# ============================================================
# Phase 3: Malicious DNS Queries (triggers ET DNS rules)
# ============================================================

def simulate_malicious_dns() -> int:
    """Send DNS queries for known-bad domains.

    Triggers ET DNS and ET MALWARE rules like:
    - ET POLICY DNS Query to .test TLD
    - ET DNS Query for testmyids.com (IDS test)
    - ET POLICY WPAD DNS Lookup

    Returns:
        Number of DNS queries sent.
    """
    logger.info("")
    logger.info("=" * 60)
    logger.info("PHASE 3: Malicious DNS Queries")
    logger.info("  Domains: %d test domains", len(MALICIOUS_DNS_DOMAINS))
    logger.info("=" * 60)

    queries = 0
    for domain in MALICIOUS_DNS_DOMAINS:
        try:
            result = socket.getaddrinfo(domain, None, socket.AF_INET)
            ip = result[0][4][0] if result else "NXDOMAIN"
            logger.info("  [DNS] %s -> %s", domain, ip)
        except socket.gaierror:
            logger.info("  [DNS] %s -> NXDOMAIN (expected)", domain)
        except Exception as exc:
            logger.info("  [DNS] %s -> error: %s", domain, exc)
        queries += 1
        time.sleep(0.2)

    logger.info("  DNS queries complete: %d sent", queries)
    return queries


# ============================================================
# Phase 4: HTTP with malicious signatures
# ============================================================

def simulate_malicious_http(target_ip: str) -> int:
    """Send HTTP requests with suspicious User-Agents and paths.

    Triggers ET WEB_SERVER and ET SCAN rules like:
    - ET SCAN Nmap Scripting Engine User-Agent
    - ET SCAN Nikto User-Agent
    - ET WEB_SERVER cmd.exe In URI
    - ET WEB_SERVER /etc/passwd In URI

    Args:
        target_ip: Target IP to send requests to.

    Returns:
        Number of HTTP requests sent.
    """
    logger.info("")
    logger.info("=" * 60)
    logger.info("PHASE 4: Malicious HTTP Requests")
    logger.info("  Target: %s:80", target_ip)
    logger.info("=" * 60)

    requests_sent = 0

    for ua in MALICIOUS_USER_AGENTS:
        for path in SUSPICIOUS_HTTP_PATHS[:3]:  # Limit combinations
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                if sock.connect_ex((target_ip, 80)) != 0:
                    sock.close()
                    continue

                http_request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
                sock.sendall(http_request.encode("utf-8"))
                logger.info("  [HTTP] GET %s (UA: %s)", path, ua[:30])
                try:
                    sock.recv(1024)
                except Exception:
                    pass
                sock.close()
                requests_sent += 1
            except Exception as exc:
                logger.debug("  [HTTP] Failed: %s", exc)
            time.sleep(0.1)

    logger.info("  HTTP requests complete: %d sent", requests_sent)
    return requests_sent


# ============================================================
# Phase 5: Testmyids.com — guaranteed Suricata alert
# ============================================================

def simulate_testmyids() -> bool:
    """Fetch testmyids.com — this page returns content that
    triggers the ET rule 'GPL ATTACK_RESPONSE id check returned root'.

    This is the MOST RELIABLE way to trigger a Suricata alert.

    Returns:
        True if the request succeeded.
    """
    logger.info("")
    logger.info("=" * 60)
    logger.info("PHASE 5: testmyids.com (Guaranteed Suricata Alert)")
    logger.info("=" * 60)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        # Resolve testmyids.com
        ip = socket.gethostbyname("testmyids.com")
        logger.info("  [TEST] Resolved testmyids.com -> %s", ip)

        sock.connect((ip, 80))
        request = (
            "GET / HTTP/1.1\r\n"
            "Host: testmyids.com\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        sock.sendall(request.encode("utf-8"))
        response = sock.recv(4096).decode("utf-8", errors="replace")
        sock.close()

        if "uid=0(root)" in response:
            logger.info("  [TEST] SUCCESS — received 'uid=0(root)' response")
            logger.info("  [TEST] This MUST trigger: GPL ATTACK_RESPONSE id check returned root")
            return True
        else:
            logger.info("  [TEST] Response received but no trigger content")
            logger.debug("  Response: %s", response[:200])
            return False

    except Exception as exc:
        logger.warning("  [TEST] testmyids.com failed: %s", exc)
        logger.info("  [TEST] Make sure you have internet connectivity")
        return False


# ============================================================
# Phase 6: Rapid connection burst (triggers flood detection)
# ============================================================

def simulate_connection_flood(target_ip: str, count: int = 50) -> int:
    """Open many connections rapidly to trigger flood/DDoS detection.

    Args:
        target_ip: Target IP.
        count: Number of rapid connections.

    Returns:
        Number of connections attempted.
    """
    logger.info("")
    logger.info("=" * 60)
    logger.info("PHASE 6: Connection Flood Simulation")
    logger.info("  Target: %s:80", target_ip)
    logger.info("  Connections: %d rapid attempts", count)
    logger.info("=" * 60)

    attempts = 0
    for i in range(count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            sock.connect_ex((target_ip, 80))
            sock.close()
            attempts += 1
        except Exception:
            pass

    logger.info("  Flood simulation complete: %d connections", attempts)
    return attempts


# ============================================================
# Main
# ============================================================

def main() -> None:
    """Run all attack simulations."""
    parser = argparse.ArgumentParser(
        description="Simulate network attacks to test Suricata + Cyber Attack Detection",
    )
    parser.add_argument(
        "--scan-only", action="store_true",
        help="Only run port scan and suspicious port phases",
    )
    parser.add_argument(
        "--dns-only", action="store_true",
        help="Only run DNS query simulation",
    )
    parser.add_argument(
        "--target", type=str, default=None,
        help="Target IP for scan (default: auto-detect gateway)",
    )
    args = parser.parse_args()

    local_ip = _get_local_ip()
    target_ip = args.target or _get_gateway_ip()

    print()
    print("=" * 60)
    print("  CYBER ATTACK DETECTION — Attack Simulator v1.0.1")
    print("  FOR TESTING PURPOSES ONLY")
    print("=" * 60)
    print(f"  Local IP:  {local_ip}")
    print(f"  Target IP: {target_ip}")
    print(f"  Time:      {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print()
    print("  This script will simulate attacks to trigger Suricata")
    print("  alerts. Ensure Suricata is running and Cyber Attack")
    print("  Detection is monitoring eve.json.")
    print()

    # Auto-start without prompt for non-interactive use
    pass
    print()

    total_events = 0
    start_time = time.time()

    if args.dns_only:
        total_events += simulate_malicious_dns()
        total_events += 1 if simulate_testmyids() else 0
    elif args.scan_only:
        total_events += simulate_port_scan(target_ip)
        total_events += simulate_suspicious_port_connections(target_ip)
        total_events += simulate_connection_flood(target_ip)
    else:
        # Full simulation
        total_events += simulate_port_scan(target_ip)
        total_events += simulate_suspicious_port_connections(target_ip)
        total_events += simulate_malicious_dns()
        total_events += simulate_malicious_http(target_ip)
        total_events += 1 if simulate_testmyids() else 0
        total_events += simulate_connection_flood(target_ip)

    elapsed = time.time() - start_time

    print()
    print("=" * 60)
    print("  SIMULATION COMPLETE")
    print("=" * 60)
    print(f"  Total events generated: {total_events}")
    print(f"  Duration:              {elapsed:.1f}s")
    print()
    print("  Expected Suricata alerts:")
    print("    - ET SCAN rules (port scanning)")
    print("    - ET POLICY rules (suspicious ports, WPAD)")
    print("    - ET DNS rules (malicious domain lookups)")
    print("    - GPL ATTACK_RESPONSE (testmyids.com)")
    print("    - ET WEB_SERVER rules (malicious HTTP)")
    print()
    print("  Check Cyber Attack Detection dashboard for alerts.")
    print("  Check Suricata eve.json:")
    print("    C:\\Program Files\\Suricata\\log\\eve.json")
    print()


if __name__ == "__main__":
    main()
