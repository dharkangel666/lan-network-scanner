import re
import subprocess


def _normalize_mdns_name(name: str) -> str:
    if name.endswith(".local"):
        return name[: -len(".local")]
    return name


def resolve_mdns_hostname(ip: str, timeout: float = 2.0) -> str | None:
    try:
        completed = subprocess.run(
            [
                "dbus-send",
                "--system",
                "--print-reply",
                "--dest=org.freedesktop.Avahi",
                "/",
                "org.freedesktop.Avahi.Server.ResolveAddress",
                "int32:-1",
                "int32:0",
                f"string:{ip}",
                "uint32:0",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    if completed.returncode != 0:
        return None

    strings = re.findall(r'string "([^"]+)"', completed.stdout)
    if len(strings) < 2:
        return None

    address, name = strings[0], strings[1]
    if address != ip or not name:
        return None

    return _normalize_mdns_name(name)
