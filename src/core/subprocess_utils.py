"""Subprocess utilities for silent command execution on Windows.

All subprocess calls should use run_silent() instead of subprocess.run()
to prevent CMD windows from appearing in GUI mode.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Any

# On Windows, CREATE_NO_WINDOW prevents console windows from flashing
_CREATION_FLAGS = 0x08000000 if sys.platform == "win32" else 0


def run_silent(
    args: list[str],
    capture_output: bool = True,
    text: bool = True,
    timeout: int | None = 30,
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess without showing a console window.

    Args:
        args: Command and arguments list.
        capture_output: Capture stdout/stderr.
        text: Decode output as text.
        timeout: Timeout in seconds.
        **kwargs: Additional subprocess.run arguments.

    Returns:
        CompletedProcess result.

    Raises:
        FileNotFoundError: If the command is not found.
        subprocess.TimeoutExpired: If the command times out.
    """
    return subprocess.run(
        args,
        capture_output=capture_output,
        text=text,
        timeout=timeout,
        shell=False,
        creationflags=_CREATION_FLAGS,
        **kwargs,
    )
