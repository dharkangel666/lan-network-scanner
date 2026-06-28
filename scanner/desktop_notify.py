"""Desktop notifications via notify-send (libnotify)."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any

APP_NAME = "Network Scanner"


def notify_available() -> bool:
    return shutil.which("notify-send") is not None


def send_desktop_notification(
    title: str,
    body: str,
    *,
    urgency: str = "normal",
) -> dict[str, Any]:
    if not notify_available():
        return {"sent": False, "error": "notify-send not found. Install libnotify-bin."}

    args = ["notify-send", "-a", APP_NAME, "-u", urgency, title, body]
    try:
        subprocess.run(args, check=True, capture_output=True, text=True, timeout=5)
    except subprocess.CalledProcessError as exc:
        message = (exc.stderr or exc.stdout or str(exc)).strip()
        return {"sent": False, "error": message or "notify-send failed"}
    except OSError as exc:
        return {"sent": False, "error": str(exc)}
    return {"sent": True}
