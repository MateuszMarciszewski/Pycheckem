from __future__ import annotations

import configparser
import os

from pycheckem.types import ProjectInfo


def collect_project_info(search_dir=None):
    # type: (Optional[str]) -> Optional[ProjectInfo]
    """Detect and parse pyproject.toml or setup.cfg for project metadata.

    Returns None if no project file is found or parsing fails.
    """
    if search_dir is None:
        search_dir = os.getcwd()

    toml_path = os.path.join(search_dir, "pyproject.toml")
    if os.path.isfile(toml_path):
        result = _parse_pyproject_toml(toml_path)
        if result is not None:
            return result

    cfg_path = os.path.join(search_dir, "setup.cfg")
    if os.path.isfile(cfg_path):
        return _parse_setup_cfg(cfg_path)

    return None


def _parse_pyproject_toml(path):
    # type: (str) -> Optional[ProjectInfo]
    """Parse project metadata from pyproject.toml."""
    from pycheckem.config import _load_toml

    try:
        data = _load_toml(path)
    except Exception:
        return None

    if not data:
        return None

    project = data.get("project", {})
    if not project:
        return None

    return ProjectInfo(
        name=project.get("name"),
        version=project.get("version"),
        requires_python=project.get("requires-python"),
        dependencies=project.get("dependencies", []),
        source_file="pyproject.toml",
    )


def _parse_setup_cfg(path):
    # type: (str) -> Optional[ProjectInfo]
    """Parse project metadata from setup.cfg."""
    cfg = configparser.ConfigParser()
    try:
        cfg.read(path, encoding="utf-8")
    except Exception:
        return None

    name = cfg.get("metadata", "name", fallback=None)
    version = cfg.get("metadata", "version", fallback=None)
    requires_python = cfg.get("options", "python_requires", fallback=None)

    install_requires = cfg.get("options", "install_requires", fallback="")
    deps = [dep.strip() for dep in install_requires.strip().splitlines() if dep.strip()]

    if not name and not version:
        return None

    return ProjectInfo(
        name=name,
        version=version,
        requires_python=requires_python,
        dependencies=deps,
        source_file="setup.cfg",
    )
