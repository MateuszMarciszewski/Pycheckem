from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SuppressionConfig:
    ignore_packages: List[str] = field(default_factory=list)
    ignore_env_vars: List[str] = field(default_factory=list)
    ignore_patterns: List[str] = field(default_factory=list)  # regex patterns


@dataclass
class PyCheckemConfig:
    suppression: SuppressionConfig = field(default_factory=SuppressionConfig)


def _load_toml(path):
    # type: (str) -> Dict[str, Any]
    """Load a TOML file. Uses tomllib (3.11+) or tomli. Returns {} if unavailable."""
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return {}

    with open(path, "rb") as f:
        return tomllib.load(f)


def load_config(search_dir=None):
    # type: (Optional[str]) -> PyCheckemConfig
    """Load pycheckem config from pyproject.toml [tool.pycheckem] section.

    Returns default config if file is missing, TOML parsing is unavailable,
    or the section doesn't exist.
    """
    if search_dir is None:
        search_dir = os.getcwd()

    toml_path = os.path.join(search_dir, "pyproject.toml")
    if not os.path.isfile(toml_path):
        return PyCheckemConfig()

    try:
        data = _load_toml(toml_path)
    except Exception:
        return PyCheckemConfig()

    if not data:
        return PyCheckemConfig()

    tool_section = data.get("tool", {}).get("pycheckem", {})
    if not tool_section:
        return PyCheckemConfig()

    suppression = SuppressionConfig(
        ignore_packages=tool_section.get("ignore_packages", []),
        ignore_env_vars=tool_section.get("ignore_env_vars", []),
        ignore_patterns=tool_section.get("ignore_patterns", []),
    )
    return PyCheckemConfig(suppression=suppression)
