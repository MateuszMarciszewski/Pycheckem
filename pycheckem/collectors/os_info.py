from __future__ import annotations

import platform
from typing import Optional

from pycheckem.types import OSInfo


def _get_distro() -> Optional[str]:
    system = platform.system()

    if system == "Linux":
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except (FileNotFoundError, PermissionError):
            pass
        return None

    if system == "Darwin":
        ver = platform.mac_ver()[0]
        return f"macOS {ver}" if ver else None

    if system == "Windows":
        ver = platform.version()
        return f"Windows {ver}" if ver else None

    return None


def collect_os_info() -> OSInfo:
    return OSInfo(
        system=platform.system(),
        release=platform.release(),
        machine=platform.machine(),
        distro=_get_distro(),
    )
