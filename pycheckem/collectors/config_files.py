import hashlib
import os
import re
from typing import List, Optional

from pycheckem.types import ConfigFileInfo


def _extract_keys(path: str, text: str) -> Optional[List[str]]:
    basename = os.path.basename(path)

    if basename == ".env" or path.endswith(".env"):
        return sorted(
            m.group(1)
            for m in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*)=", text, re.MULTILINE)
        )

    if path.endswith(".ini") or path.endswith(".cfg"):
        return [m.group(1) for m in re.finditer(r"^\[([^\]]+)\]", text, re.MULTILINE)]

    return None


def collect_config_file(path: str) -> Optional[ConfigFileInfo]:
    try:
        with open(path, "rb") as f:
            content = f.read()
    except (FileNotFoundError, PermissionError):
        return None

    sha256 = hashlib.sha256(content).hexdigest()
    keys = _extract_keys(path, content.decode("utf-8", errors="replace"))
    return ConfigFileInfo(sha256=sha256, keys=keys)
