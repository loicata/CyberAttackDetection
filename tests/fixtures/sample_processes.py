"""Fabricated process data for testing."""


def make_normal_process_list() -> list[dict]:
    """Create a typical Windows process list for baseline testing."""
    return [
        {"pid": 0, "name": "System Idle Process", "ppid": 0, "exe": None,
         "username": "NT AUTHORITY\\SYSTEM", "cpu_percent": 98.0},
        {"pid": 4, "name": "System", "ppid": 0, "exe": None,
         "username": "NT AUTHORITY\\SYSTEM", "cpu_percent": 0.1},
        {"pid": 500, "name": "csrss.exe", "ppid": 400, "exe": r"C:\Windows\System32\csrss.exe",
         "username": "NT AUTHORITY\\SYSTEM", "cpu_percent": 0.0},
        {"pid": 600, "name": "wininit.exe", "ppid": 400,
         "exe": r"C:\Windows\System32\wininit.exe",
         "username": "NT AUTHORITY\\SYSTEM", "cpu_percent": 0.0},
        {"pid": 700, "name": "services.exe", "ppid": 600,
         "exe": r"C:\Windows\System32\services.exe",
         "username": "NT AUTHORITY\\SYSTEM", "cpu_percent": 0.1},
        {"pid": 800, "name": "lsass.exe", "ppid": 600,
         "exe": r"C:\Windows\System32\lsass.exe",
         "username": "NT AUTHORITY\\SYSTEM", "cpu_percent": 0.2},
        {"pid": 1000, "name": "svchost.exe", "ppid": 700,
         "exe": r"C:\Windows\System32\svchost.exe",
         "username": "NT AUTHORITY\\SYSTEM", "cpu_percent": 0.5},
        {"pid": 2000, "name": "explorer.exe", "ppid": 1800,
         "exe": r"C:\Windows\explorer.exe",
         "username": "WORKSTATION\\user", "cpu_percent": 1.0},
        {"pid": 3000, "name": "dwm.exe", "ppid": 600,
         "exe": r"C:\Windows\System32\dwm.exe",
         "username": "Window Manager\\DWM-1", "cpu_percent": 2.0},
    ]


def make_suspicious_process_list() -> list[dict]:
    """Create a process list containing suspicious entries."""
    normal = make_normal_process_list()
    suspicious = [
        {"pid": 6666, "name": "mimikatz.exe", "ppid": 2000,
         "exe": r"C:\Users\user\Downloads\mimikatz.exe",
         "username": "WORKSTATION\\user", "cpu_percent": 15.0},
        {"pid": 7777, "name": "nc.exe", "ppid": 5000,
         "exe": r"C:\Temp\nc.exe",
         "username": "WORKSTATION\\user", "cpu_percent": 0.5},
    ]
    return normal + suspicious


def make_parent_child_suspicious_list() -> list[dict]:
    """Create a process list with suspicious parent-child relationship."""
    normal = make_normal_process_list()
    suspicious = [
        {"pid": 4000, "name": "WINWORD.EXE", "ppid": 2000,
         "exe": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
         "username": "WORKSTATION\\user", "cpu_percent": 5.0},
        {"pid": 4001, "name": "cmd.exe", "ppid": 4000,
         "exe": r"C:\Windows\System32\cmd.exe",
         "username": "WORKSTATION\\user", "cpu_percent": 0.1},
        {"pid": 4002, "name": "powershell.exe", "ppid": 4001,
         "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "username": "WORKSTATION\\user", "cpu_percent": 30.0},
    ]
    return normal + suspicious
