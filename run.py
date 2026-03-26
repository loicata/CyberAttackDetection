"""Entry point for Cyber Attack Detection.

Launches the GUI on the main thread and the detection engine
in a background daemon thread.

Usage:
    python run.py           # GUI mode (default)
    python run.py --console # Console mode (Rich terminal)
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import threading

# Ensure project root is in path for imports
if getattr(sys, "frozen", False):
    _base_dir = sys._MEIPASS  # type: ignore[attr-defined]
else:
    _base_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _base_dir)

logger = logging.getLogger(__name__)


def _run_engine(bridge: object) -> None:
    """Run the async detection engine in a background thread.

    Args:
        bridge: ThreadBridge instance for GUI communication.
    """
    from src.main import Application

    app = Application(bridge=bridge)  # type: ignore[arg-type]
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(app.run())
    except Exception:
        logger.exception("Engine thread crashed")
    finally:
        loop.close()


def run_gui() -> None:
    """Launch the application in GUI mode."""
    from src.ui.bridge import ThreadBridge
    from src.core.config import load_config
    from src.core.logging_setup import setup_logging
    from dotenv import load_dotenv

    load_dotenv()
    config = load_config()
    setup_logging(level=config.log_level, log_dir=config.data_dir)

    bridge = ThreadBridge()

    # Start engine in daemon thread
    engine_thread = threading.Thread(
        target=_run_engine,
        args=(bridge,),
        daemon=True,
        name="DetectionEngine",
    )
    engine_thread.start()
    logger.info("Detection engine thread started")

    # Launch GUI on main thread (tkinter requirement)
    from src.ui.app import CyberAttackDetectionApp

    app = CyberAttackDetectionApp(
        bridge=bridge,
        config_data=config.raw,
        evidence_dir=config.forensics.evidence_dir,
        report_dir=config.forensics.report_dir,
    )

    logger.info("GUI launched")
    app.mainloop()

    logger.info("GUI closed, application exiting")


def run_console() -> None:
    """Launch the application in console mode."""
    from src.main import main
    main()


if __name__ == "__main__":
    if "--console" in sys.argv:
        run_console()
    else:
        run_gui()
