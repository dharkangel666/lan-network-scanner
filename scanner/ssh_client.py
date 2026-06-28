import getpass
import ipaddress
import os
import shutil
import subprocess


def validate_ssh_host(host: str) -> str:
    host = host.strip()
    if not host:
        raise ValueError("Host is required")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        if not all(char in allowed for char in host):
            raise ValueError("Invalid host")
        return host

    if not (address.is_private or address.is_loopback or address.is_link_local):
        raise ValueError("Only local network addresses are allowed")
    return host


def launch_ssh(host: str, port: int = 22, username: str | None = None) -> dict:
    host = validate_ssh_host(host)
    user = (username or getpass.getuser()).strip()
    target = f"{user}@{host}"

    ssh_command = ["ssh"]
    if port != 22:
        ssh_command.extend(["-p", str(port)])
    ssh_command.append(target)

    env = os.environ.copy()
    env.setdefault("DISPLAY", ":0")

    if shutil.which("gnome-terminal"):
        subprocess.Popen(
            ["gnome-terminal", "--", *ssh_command],
            env=env,
            start_new_session=True,
        )
        return {"launched": True, "client": "gnome-terminal", "command": " ".join(ssh_command)}

    if shutil.which("konsole"):
        subprocess.Popen(
            ["konsole", "-e", *ssh_command],
            env=env,
            start_new_session=True,
        )
        return {"launched": True, "client": "konsole", "command": " ".join(ssh_command)}

    if shutil.which("xfce4-terminal"):
        subprocess.Popen(
            ["xfce4-terminal", "-e", " ".join(ssh_command)],
            env=env,
            start_new_session=True,
        )
        return {"launched": True, "client": "xfce4-terminal", "command": " ".join(ssh_command)}

    if shutil.which("x-terminal-emulator"):
        subprocess.Popen(
            ["x-terminal-emulator", "-e", *ssh_command],
            env=env,
            start_new_session=True,
        )
        return {"launched": True, "client": "x-terminal-emulator", "command": " ".join(ssh_command)}

    if shutil.which("xdg-open"):
        url = f"ssh://{target}" if port == 22 else f"ssh://{target}:{port}"
        subprocess.Popen(["xdg-open", url], env=env, start_new_session=True)
        return {"launched": True, "client": "xdg-open", "command": url}

    raise RuntimeError("No terminal or SSH client handler found on this system")
