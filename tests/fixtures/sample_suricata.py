"""Fabricated Suricata eve.json entries for testing."""

from src.core.enums import AlertType
from src.core.models import RawEvent


def make_suricata_high_severity_alert() -> RawEvent:
    """Create a high-severity Suricata alert (ET MALWARE)."""
    return RawEvent(
        event_type=AlertType.SURICATA,
        data={
            "event_type": "alert",
            "timestamp": "2026-03-25T10:00:00.000000+0000",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2024792,
                "rev": 4,
                "signature": "ET MALWARE Win32/Emotet CnC Activity",
                "category": "A Network Trojan was detected",
                "severity": 1,
            },
            "proto": "TCP",
            "flow_id": 1234567890,
        },
        source_ip="192.168.1.10",
        source_port=49200,
        dest_ip="185.100.87.42",
        dest_port=443,
    )


def make_suricata_medium_severity_alert() -> RawEvent:
    """Create a medium-severity Suricata alert."""
    return RawEvent(
        event_type=AlertType.SURICATA,
        data={
            "event_type": "alert",
            "timestamp": "2026-03-25T10:05:00.000000+0000",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2100498,
                "rev": 7,
                "signature": "GPL ATTACK_RESPONSE id check returned root",
                "category": "Potentially Bad Traffic",
                "severity": 2,
            },
            "proto": "TCP",
        },
        source_ip="10.0.0.50",
        source_port=80,
        dest_ip="192.168.1.10",
        dest_port=49300,
    )


def make_suricata_flow_record() -> RawEvent:
    """Create a normal Suricata flow record (not an alert)."""
    return RawEvent(
        event_type=AlertType.SURICATA,
        data={
            "event_type": "flow",
            "timestamp": "2026-03-25T10:10:00.000000+0000",
            "proto": "TCP",
            "flow": {
                "pkts_toserver": 10,
                "pkts_toclient": 8,
                "bytes_toserver": 1200,
                "bytes_toclient": 4500,
                "start": "2026-03-25T10:09:50.000000+0000",
                "end": "2026-03-25T10:10:00.000000+0000",
            },
        },
        source_ip="192.168.1.10",
        source_port=443,
        dest_ip="93.184.216.34",
        dest_port=49400,
    )
