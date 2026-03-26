"""Theme constants for the CustomTkinter GUI."""

# Window
WINDOW_TITLE = "Cyber Attack Detection v1.0.1"
WINDOW_WIDTH = 1400
WINDOW_HEIGHT = 900
APPEARANCE_MODE = "dark"
COLOR_THEME = "blue"

# Colors — SOC dashboard palette
BG_DARK = "#0d1117"
BG_CARD = "#161b22"
BG_CARD_HOVER = "#1c2333"
BG_INPUT = "#0d1117"
BORDER_COLOR = "#30363d"

TEXT_PRIMARY = "#e6edf3"
TEXT_SECONDARY = "#8b949e"
TEXT_DIM = "#484f58"

ACCENT_BLUE = "#58a6ff"
ACCENT_GREEN = "#3fb950"
ACCENT_RED = "#f85149"
ACCENT_ORANGE = "#d29922"
ACCENT_PURPLE = "#bc8cff"
ACCENT_CYAN = "#39d2c0"

# Severity colors
SEVERITY_COLORS = {
    "CRITICAL": "#ff0040",
    "HIGH": "#ff6a00",
    "MEDIUM": "#ffc107",
    "LOW": "#58a6ff",
    "INFO": "#8b949e",
}

# Status colors
STATUS_COLORS = {
    "new": "#58a6ff",
    "investigating": "#d29922",
    "resolved": "#3fb950",
    "false_positive": "#484f58",
}

# Detector state colors
DETECTOR_COLORS = {
    "running": ACCENT_GREEN,
    "stopped": TEXT_DIM,
    "error": ACCENT_RED,
    "starting": ACCENT_ORANGE,
    "stopping": ACCENT_ORANGE,
}

# Fonts
FONT_FAMILY = "Segoe UI"
FONT_TITLE = (FONT_FAMILY, 20, "bold")
FONT_HEADING = (FONT_FAMILY, 14, "bold")
FONT_BODY = (FONT_FAMILY, 12)
FONT_SMALL = (FONT_FAMILY, 11)
FONT_MONO = ("Consolas", 11)
FONT_COUNTER = (FONT_FAMILY, 28, "bold")
FONT_COUNTER_LABEL = (FONT_FAMILY, 11)

# Padding
PAD_SECTION = 10
PAD_WIDGET = 5
PAD_INNER = 3

# Polling interval for queue consumption (ms)
POLL_INTERVAL_MS = 150
