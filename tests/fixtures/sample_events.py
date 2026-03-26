"""Fabricated Windows event data for testing."""

from src.core.enums import AlertType
from src.core.models import RawEvent


def make_logon_success_event() -> RawEvent:
    """Create a successful Windows logon event (Event ID 4624)."""
    return RawEvent(
        event_type=AlertType.EVENTLOG,
        data={
            "event_id": 4624,
            "channel": "Security",
            "logon_type": 10,
            "target_user": "admin",
            "source_network_address": "192.168.1.50",
            "workstation_name": "WORKSTATION01",
        },
        source_ip="192.168.1.50",
        dest_ip="192.168.1.10",
    )


def make_logon_failure_event(source_ip: str = "10.0.0.99") -> RawEvent:
    """Create a failed Windows logon event (Event ID 4625).

    Args:
        source_ip: Source IP of the failed attempt.
    """
    return RawEvent(
        event_type=AlertType.EVENTLOG,
        data={
            "event_id": 4625,
            "channel": "Security",
            "logon_type": 3,
            "target_user": "admin",
            "failure_reason": "Unknown user name or bad password",
            "source_network_address": source_ip,
        },
        source_ip=source_ip,
        dest_ip="192.168.1.10",
    )


def make_process_creation_event(
    process_name: str = "cmd.exe",
    parent_name: str = "explorer.exe",
    pid: int = 5678,
) -> RawEvent:
    """Create a process creation event (Event ID 4688).

    Args:
        process_name: Name of the new process.
        parent_name: Name of the parent process.
        pid: Process ID.
    """
    return RawEvent(
        event_type=AlertType.PROCESS,
        data={
            "event_id": 4688,
            "new_process_name": process_name,
            "parent_process_name": parent_name,
            "token_elevation_type": 1,
            "command_line": f"C:\\Windows\\System32\\{process_name}",
        },
        process_name=process_name,
        process_pid=pid,
    )


def make_log_clearing_event() -> RawEvent:
    """Create a security log clearing event (Event ID 1102)."""
    return RawEvent(
        event_type=AlertType.EVENTLOG,
        data={
            "event_id": 1102,
            "channel": "Security",
            "subject_user": "admin",
            "subject_domain": "WORKSTATION01",
        },
    )


def make_service_install_event(service_name: str = "SuspiciousService") -> RawEvent:
    """Create a new service installation event (Event ID 7045).

    Args:
        service_name: Name of the new service.
    """
    return RawEvent(
        event_type=AlertType.EVENTLOG,
        data={
            "event_id": 7045,
            "channel": "System",
            "service_name": service_name,
            "service_file_name": f"C:\\Temp\\{service_name}.exe",
            "service_type": "user mode service",
            "service_start_type": "auto start",
        },
    )


def make_network_connection_event(
    dest_ip: str = "203.0.113.50",
    dest_port: int = 4444,
    process_name: str = "unknown.exe",
) -> RawEvent:
    """Create a suspicious network connection event.

    Args:
        dest_ip: Destination IP address.
        dest_port: Destination port.
        process_name: Name of the connecting process.
    """
    return RawEvent(
        event_type=AlertType.NETWORK,
        data={
            "status": "ESTABLISHED",
            "local_address": "192.168.1.10",
            "local_port": 49152,
            "remote_address": dest_ip,
            "remote_port": dest_port,
        },
        source_ip="192.168.1.10",
        source_port=49152,
        dest_ip=dest_ip,
        dest_port=dest_port,
        process_name=process_name,
        process_pid=9999,
    )


def make_filesystem_change_event(
    file_path: str = r"C:\Windows\System32\new_malware.exe",
) -> RawEvent:
    """Create a filesystem change event in a critical directory.

    Args:
        file_path: Path to the changed file.
    """
    return RawEvent(
        event_type=AlertType.FILESYSTEM,
        data={
            "event_type": "created",
            "src_path": file_path,
            "is_directory": False,
        },
        file_path=file_path,
    )
