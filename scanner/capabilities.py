import os
import socket
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VENV_DIR = PROJECT_ROOT / ".venv"
SETUP_SCRIPT = PROJECT_ROOT / "scripts" / "setup-capabilities.sh"


def can_use_raw_sockets() -> bool:
    if os.environ.get("NETWORK_SCANNER_FORCE_FALLBACK") == "1":
        return False

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.close()
        return True
    except PermissionError:
        return False
    except OSError:
        return False


def get_python_binary() -> Path:
    return Path(sys.executable).resolve()


def get_file_capabilities(path: Path) -> str | None:
    try:
        output = subprocess.check_output(
            ["getcap", str(path)],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return output or None


def venv_python_is_isolated() -> bool:
    exe = Path(sys.executable)
    if not exe.is_symlink():
        try:
            exe.resolve().relative_to(VENV_DIR.resolve())
            return True
        except ValueError:
            return False

    try:
        exe.resolve().relative_to(VENV_DIR.resolve())
        return True
    except ValueError:
        return False


def get_capabilities_info() -> dict:
    binary = get_python_binary()
    arp_available = can_use_raw_sockets()
    caps = get_file_capabilities(binary)
    isolated = venv_python_is_isolated()

    if arp_available:
        message = "Active ARP scanning is enabled."
    elif not isolated:
        message = (
            "This virtualenv uses a symlinked system Python. Run the one-time setup "
            "script to enable ARP scanning without sudo on every run."
        )
    else:
        message = (
            "Using ping + neighbor table discovery. Run the one-time setup script "
            "to enable faster active ARP scanning without sudo on every run."
        )

    return {
        "arp_available": arp_available,
        "discovery_mode": "arp" if arp_available else "fallback",
        "python_binary": str(binary),
        "capabilities": caps,
        "venv_python_isolated": isolated,
        "needs_setup": not arp_available,
        "setup_command": f"sudo {SETUP_SCRIPT}",
        "message": message,
    }
