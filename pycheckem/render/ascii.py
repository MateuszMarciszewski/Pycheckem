from __future__ import annotations

from typing import List, Optional

from pycheckem.diff import is_major_change
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

_SEVERITY_ORDER = {"identical": 0, "minor": 1, "major": 2, "critical": 3}

_HEADER_LINE = "\u2550" * 47  # ═
_FOOTER_LINE = "\u2500" * 47  # ─


def _section_python(python):
    # type: (Optional[PythonDiff]) -> List[str]
    if python is None:
        return []
    lines = ["Python"]
    for field, (old, new) in python.changes.items():
        label = field.capitalize() + ":"
        line = "  {:<12s} {}  \u2192  {}".format(label, old, new)
        if field == "version":
            if is_major_change(old, new):
                line += "  \u26a0 MAJOR VERSION MISMATCH"
            else:
                line += "  \u26a0 MINOR VERSION MISMATCH"
        lines.append(line)
    return lines


def _section_packages(packages):
    # type: (PackageDiff) -> List[str]
    source_changed = getattr(packages, "source_changed", {})
    total = (len(packages.added) + len(packages.removed)
             + len(packages.changed) + len(source_changed))
    if total == 0:
        return []
    lines = ["Packages ({} {})".format(total, "difference" if total == 1 else "differences")]
    for name, ver in sorted(packages.added.items()):
        lines.append("  + {} {}".format(name, ver))
    for name, ver in sorted(packages.removed.items()):
        lines.append("  - {} {}".format(name, ver))
    for name, vc in sorted(packages.changed.items()):
        line = "  ~ {} {} \u2192 {}".format(name, vc.version_a, vc.version_b)
        if vc.is_major:
            line += "  \u26a0 MAJOR VERSION CHANGE"
        elif vc.is_downgrade:
            line += "  \u26a0 DOWNGRADE"
        if getattr(vc, "source_a", "pypi") != getattr(vc, "source_b", "pypi"):
            line += "  [{}]\u2192[{}]".format(vc.source_a, vc.source_b)
        lines.append(line)
    for name, sc in sorted(source_changed.items()):
        line = "  ~ {} [{}] \u2192 [{}]".format(name, sc.source_a, sc.source_b)
        detail = sc.detail_a or sc.detail_b
        if detail:
            line += "  ({})".format(detail)
        lines.append(line)
    return lines


def _section_env_vars(env_vars):
    # type: (VarDiff) -> List[str]
    total = len(env_vars.added) + len(env_vars.removed) + len(env_vars.changed)
    if total == 0:
        return []
    lines = ["Environment Variables ({} {})".format(
        total, "difference" if total == 1 else "differences"
    )]
    for name in sorted(env_vars.added):
        lines.append("  + {}".format(name))
    for name in sorted(env_vars.removed):
        lines.append("  - {}".format(name))
    for name, (old, new) in sorted(env_vars.changed.items()):
        lines.append("  ~ {}: {} \u2192 {}".format(name, old, new))
    return lines


def _section_os(os_info):
    # type: (Optional[OSDiff]) -> List[str]
    if os_info is None:
        return []
    lines = ["OS"]
    for field, (old, new) in os_info.changes.items():
        label = field.capitalize() + ":"
        line = "  {:<12s} {}  \u2192  {}".format(label, old, new)
        if field == "system":
            line += "  \u26a0 DIFFERENT OS"
        elif field == "machine":
            line += "  \u26a0 DIFFERENT ARCHITECTURE"
        elif field == "distro":
            line += "  \u26a0 DIFFERENT DISTRO"
        lines.append(line)
    return lines


def _section_paths(paths):
    # type: (PathDiff) -> List[str]
    total = (len(paths.sys_path_added) + len(paths.sys_path_removed)
             + len(paths.path_env_added) + len(paths.path_env_removed))
    if total == 0:
        return []
    lines = ["Paths ({} {})".format(total, "difference" if total == 1 else "differences")]
    if paths.sys_path_added or paths.sys_path_removed:
        lines.append("  sys.path:")
        for p in paths.sys_path_added:
            lines.append("    + {}".format(p))
        for p in paths.sys_path_removed:
            lines.append("    - {}".format(p))
    if paths.path_env_added or paths.path_env_removed:
        lines.append("  PATH:")
        for p in paths.path_env_added:
            lines.append("    + {}".format(p))
        for p in paths.path_env_removed:
            lines.append("    - {}".format(p))
    return lines


def _section_config_files(config_files):
    # type: (ConfigDiff) -> List[str]
    total = len(config_files.added) + len(config_files.removed) + len(config_files.changed)
    if total == 0:
        return []
    lines = ["Config Files ({} {})".format(
        total, "difference" if total == 1 else "differences"
    )]
    for name in config_files.added:
        lines.append("  + {}".format(name))
    for name in config_files.removed:
        lines.append("  - {}".format(name))
    for name, fd in sorted(config_files.changed.items()):
        lines.append("  ~ {}  HASH MISMATCH".format(name))
        for k in fd.keys_added:
            lines.append("    + {}".format(k))
        for k in fd.keys_removed:
            lines.append("    - {}".format(k))
    return lines


def _section_project(project):
    # type: (Optional[ProjectDiff]) -> List[str]
    if project is None:
        return []
    lines = ["Project"]
    if project.name_changed:
        old, new = project.name_changed
        lines.append("  Name:     {}  \u2192  {}".format(old, new))
    if project.version_changed:
        old, new = project.version_changed
        lines.append("  Version:  {}  \u2192  {}".format(old, new))
    if project.requires_python_changed:
        old, new = project.requires_python_changed
        lines.append("  Requires: {}  \u2192  {}  \u26a0 PYTHON REQUIREMENT CHANGED".format(old, new))
    for dep in project.deps_added:
        lines.append("  + {}".format(dep))
    for dep in project.deps_removed:
        lines.append("  - {}".format(dep))
    return lines


def render_ascii(result, only=None):
    # type: (DiffResult, Optional[str]) -> str
    """Render a DiffResult as terminal-friendly plain text for the console.

    This is the default output format. It uses unicode box-drawing characters
    and symbols (+, -, ~) to show differences clearly in any terminal.

    Args:
        result: The DiffResult to render.
        only: If set, render just one section ("packages", "env", "python",
            "os", "paths", "config", "project").

    Returns:
        A multi-line string ready to print.

    Example:
        >>> from pycheckem.render import ascii
        >>> print(ascii(result))
    """
    if result.summary.severity == "identical" and only is None:
        return "pycheckem: {} vs {}\nNo differences found.".format(
            result.label_a, result.label_b
        )

    parts = []  # type: List[str]
    parts.append("pycheckem: {} vs {}".format(result.label_a, result.label_b))
    parts.append(_HEADER_LINE)

    section_map = {
        "python": lambda: _section_python(result.python),
        "packages": lambda: _section_packages(result.packages),
        "env": lambda: _section_env_vars(result.env_vars),
        "os": lambda: _section_os(result.os_info),
        "paths": lambda: _section_paths(result.paths),
        "config": lambda: _section_config_files(result.config_files),
        "project": lambda: _section_project(getattr(result, "project", None)),
    }

    if only is not None:
        fn = section_map.get(only)
        if fn is not None:
            lines = fn()
            if lines:
                parts.append("")
                parts.extend(lines)
    else:
        for key in ("python", "packages", "env", "os", "paths", "config", "project"):
            lines = section_map[key]()
            if lines:
                parts.append("")
                parts.extend(lines)

    parts.append("")
    parts.append(_FOOTER_LINE)

    severity_display = result.summary.severity.upper()
    parts.append("Summary: {} {} | Severity: {}".format(
        result.summary.total_differences,
        "difference" if result.summary.total_differences == 1 else "differences",
        severity_display,
    ))
    if result.summary.breaking_changes:
        parts.append("Breaking: {}".format(", ".join(result.summary.breaking_changes)))

    return "\n".join(parts)
