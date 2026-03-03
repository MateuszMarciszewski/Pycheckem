from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

from pycheckem.types import (
    ConfigDiff,
    DiffResult,
    OSDiff,
    PackageDiff,
    PathDiff,
    ProjectDiff,
    PythonDiff,
    VarDiff,
)


def _get_terminal_width():
    # type: () -> int
    """Get the terminal width, defaulting to 80 if unavailable."""
    try:
        return os.get_terminal_size().columns
    except (AttributeError, ValueError, OSError):
        return 80


def _pad(text, width):
    # type: (str, int) -> str
    """Pad or truncate text to fit the given width."""
    if len(text) > width:
        return text[: width - 1] + "\u2026"
    return text.ljust(width)


def _section_python(python, label_a, label_b):
    # type: (Optional[PythonDiff], str, str) -> List[Tuple[str, str]]
    """Return (left, right) pairs for Python section."""
    if python is None:
        return []
    rows = []  # type: List[Tuple[str, str]]
    for field, (old, new) in python.changes.items():
        rows.append(("{}: {}".format(field.capitalize(), old),
                      "{}: {}".format(field.capitalize(), new)))
    return rows


def _section_packages(packages):
    # type: (PackageDiff) -> List[Tuple[str, str]]
    rows = []  # type: List[Tuple[str, str]]
    for name, ver in sorted(packages.added.items()):
        rows.append(("\u2014", "+ {} {}".format(name, ver)))
    for name, ver in sorted(packages.removed.items()):
        rows.append(("- {} {}".format(name, ver), "\u2014"))
    for name, vc in sorted(packages.changed.items()):
        rows.append(("! {} {}".format(name, vc.version_a),
                      "! {} {}".format(name, vc.version_b)))
    for name, sc in sorted(getattr(packages, "source_changed", {}).items()):
        rows.append(("! {} [{}]".format(name, sc.source_a),
                      "! {} [{}]".format(name, sc.source_b)))
    return rows


def _section_env_vars(env_vars):
    # type: (VarDiff) -> List[Tuple[str, str]]
    rows = []  # type: List[Tuple[str, str]]
    for name in sorted(env_vars.added):
        rows.append(("\u2014", "+ {}".format(name)))
    for name in sorted(env_vars.removed):
        rows.append(("- {}".format(name), "\u2014"))
    for name, (old, new) in sorted(env_vars.changed.items()):
        rows.append(("! {}={}".format(name, old),
                      "! {}={}".format(name, new)))
    return rows


def _section_os(os_info):
    # type: (Optional[OSDiff]) -> List[Tuple[str, str]]
    if os_info is None:
        return []
    rows = []  # type: List[Tuple[str, str]]
    for field, (old, new) in os_info.changes.items():
        rows.append(("{}: {}".format(field.capitalize(), old),
                      "{}: {}".format(field.capitalize(), new)))
    return rows


def _section_paths(paths):
    # type: (PathDiff) -> List[Tuple[str, str]]
    rows = []  # type: List[Tuple[str, str]]
    for p in paths.sys_path_added:
        rows.append(("\u2014", "+ sys.path: {}".format(p)))
    for p in paths.sys_path_removed:
        rows.append(("- sys.path: {}".format(p), "\u2014"))
    for p in paths.path_env_added:
        rows.append(("\u2014", "+ PATH: {}".format(p)))
    for p in paths.path_env_removed:
        rows.append(("- PATH: {}".format(p), "\u2014"))
    return rows


def _section_config_files(config_files):
    # type: (ConfigDiff) -> List[Tuple[str, str]]
    rows = []  # type: List[Tuple[str, str]]
    for name in config_files.added:
        rows.append(("\u2014", "+ {}".format(name)))
    for name in config_files.removed:
        rows.append(("- {}".format(name), "\u2014"))
    for name, fd in sorted(config_files.changed.items()):
        rows.append(("! {}".format(name), "! {} (HASH MISMATCH)".format(name)))
    return rows


def _section_project(project):
    # type: (Optional[ProjectDiff]) -> List[Tuple[str, str]]
    if project is None:
        return []
    rows = []  # type: List[Tuple[str, str]]
    if project.name_changed:
        old, new = project.name_changed
        rows.append(("Name: {}".format(old), "Name: {}".format(new)))
    if project.version_changed:
        old, new = project.version_changed
        rows.append(("Version: {}".format(old), "Version: {}".format(new)))
    if project.requires_python_changed:
        old, new = project.requires_python_changed
        rows.append(("Requires: {}".format(old), "Requires: {}".format(new)))
    for dep in project.deps_added:
        rows.append(("\u2014", "+ {}".format(dep)))
    for dep in project.deps_removed:
        rows.append(("- {}".format(dep), "\u2014"))
    return rows


def render_side_by_side(result, only=None, width=None):
    # type: (DiffResult, Optional[str], Optional[int]) -> str
    """Render a DiffResult as side-by-side comparison.

    Two columns showing the left (A) and right (B) environments,
    with a ``|`` separator.
    """
    if width is None:
        width = _get_terminal_width()

    # Ensure minimum usable width
    width = max(width, 40)

    # Column width: total minus separator " | "
    col_width = (width - 3) // 2

    lines = []  # type: List[str]

    # Header
    header_a = _pad(result.label_a, col_width)
    header_b = _pad(result.label_b, col_width)
    lines.append("{} | {}".format(header_a, header_b))
    lines.append("\u2550" * col_width + " | " + "\u2550" * col_width)

    if result.summary.severity == "identical" and only is None:
        msg = "No differences found."
        lines.append("{} | {}".format(_pad(msg, col_width), _pad(msg, col_width)))
        return "\n".join(lines)

    section_map = {
        "python": lambda: ("Python", _section_python(
            result.python, result.label_a, result.label_b)),
        "packages": lambda: ("Packages", _section_packages(result.packages)),
        "env": lambda: ("Environment Variables", _section_env_vars(result.env_vars)),
        "os": lambda: ("OS", _section_os(result.os_info)),
        "paths": lambda: ("Paths", _section_paths(result.paths)),
        "config": lambda: ("Config Files", _section_config_files(result.config_files)),
        "project": lambda: ("Project", _section_project(
            getattr(result, "project", None))),
    }

    def _render_section(key):
        # type: (str) -> None
        title, rows = section_map[key]()
        if not rows:
            return
        # Section title line
        title_line = "--- {} ---".format(title)
        lines.append("{} | {}".format(
            _pad(title_line, col_width), _pad(title_line, col_width)))
        for left, right in rows:
            lines.append("{} | {}".format(
                _pad(left, col_width), _pad(right, col_width)))

    if only is not None:
        if only in section_map:
            _render_section(only)
    else:
        for key in ("python", "packages", "env", "os", "paths", "config", "project"):
            _render_section(key)

    # Footer
    lines.append("\u2500" * col_width + " | " + "\u2500" * col_width)
    severity_display = result.summary.severity.upper()
    n = result.summary.total_differences
    summary_msg = "Summary: {} {} | Severity: {}".format(
        n, "difference" if n == 1 else "differences", severity_display
    )
    lines.append(summary_msg)

    if result.summary.breaking_changes:
        lines.append("Breaking: {}".format(", ".join(result.summary.breaking_changes)))

    return "\n".join(lines)
