"""Parse dependency files (requirements.txt, pyproject.toml) into package dicts.

These parsers extract declared dependencies so they can be compared against
the actually installed packages in the current environment.
"""

from __future__ import annotations

import json as _json
import os
import re
from typing import Dict, Optional, Tuple


def parse_requirements(path):
    # type: (str) -> Dict[str, Optional[str]]
    """Parse a requirements.txt or pip freeze file into {name: version_spec}.

    Handles:
    - Pinned versions: ``requests==2.31.0``
    - Version ranges: ``flask>=2.0,<3.0``
    - Bare names: ``pytest``
    - Comments and blank lines (skipped)
    - ``-r`` / ``--requirement`` includes (skipped, not followed)
    - ``-e`` / ``--editable`` lines (skipped)
    - Environment markers: ``pywin32; sys_platform == 'win32'`` (markers stripped)
    - Extras: ``requests[security]`` (extras stripped, name kept)

    Args:
        path: Path to the requirements file.

    Returns:
        Dict mapping package names (lowercased, normalized) to version
        specifiers. The specifier is the full version string (e.g.
        ``"==2.31.0"`` or ``">=2.0,<3.0"``), or None if no version
        is pinned.

    Raises:
        FileNotFoundError: If the file does not exist.

    Example:
        >>> deps = parse_requirements("requirements.txt")
        >>> deps["requests"]
        '==2.31.0'
        >>> deps["pytest"]  # bare name, no version pin
        None
    """
    result = {}  # type: Dict[str, Optional[str]]

    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()

            # Skip blanks, comments, options, editables
            if not line or line.startswith("#"):
                continue
            if line.startswith("-r") or line.startswith("--requirement"):
                continue
            if line.startswith("-e") or line.startswith("--editable"):
                continue
            if line.startswith("-") or line.startswith("--"):
                continue

            # Strip inline comments
            if " #" in line:
                line = line[: line.index(" #")].strip()

            # Strip environment markers (everything after ";")
            if ";" in line:
                line = line[: line.index(";")].strip()

            if not line:
                continue

            # Split name from version specifier
            # Match on first version operator: ==, !=, >=, <=, ~=, >, <
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?)\s*(.*)", line)
            if not match:
                continue

            raw_name = match.group(1)
            version_spec = match.group(2).strip() or None

            # Strip extras from name: "requests[security]" -> "requests"
            name = re.sub(r"\[.*\]", "", raw_name)
            name = _normalize_name(name)

            result[name] = version_spec

    return result


def parse_pyproject_deps(path):
    # type: (str) -> Dict[str, Optional[str]]
    """Parse dependencies from a pyproject.toml file.

    Reads ``[project.dependencies]`` (PEP 621) and returns a dict mapping
    package names to version specifiers.

    Args:
        path: Path to pyproject.toml.

    Returns:
        Dict mapping package names (lowercased, normalized) to version
        specifiers, or None if no version constraint is declared.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file cannot be parsed or has no [project] table.

    Example:
        >>> deps = parse_pyproject_deps("pyproject.toml")
        >>> deps["flask"]
        '>=2.0'
    """
    data = _load_toml(path)

    project = data.get("project")
    if project is None:
        raise ValueError("No [project] table found in {}".format(path))

    raw_deps = project.get("dependencies", [])
    result = {}  # type: Dict[str, Optional[str]]

    for dep_str in raw_deps:
        name, spec = _parse_dep_string(dep_str)
        result[name] = spec

    return result


def _load_toml(path):
    # type: (str) -> dict
    """Load a TOML file using tomllib (3.11+) or tomli fallback."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            raise ImportError(
                "TOML parsing requires Python 3.11+ or the 'tomli' package. "
                "Install with: pip install pycheckem[toml]"
            )

    with open(path, "rb") as f:
        return tomllib.load(f)


def _parse_dep_string(dep):
    # type: (str) -> Tuple[str, Optional[str]]
    """Parse a PEP 508 dependency string into (name, version_spec).

    Examples:
        "flask>=2.0" -> ("flask", ">=2.0")
        "requests[security]>=2.28,<3" -> ("requests", ">=2.28,<3")
        "pytest" -> ("pytest", None)
        "pywin32; sys_platform == 'win32'" -> ("pywin32", None)
    """
    # Strip environment markers
    if ";" in dep:
        dep = dep[: dep.index(";")].strip()

    # Match name (possibly with extras) and version spec
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?)\s*(.*)", dep)
    if not match:
        return (_normalize_name(dep.strip()), None)

    raw_name = match.group(1)
    version_spec = match.group(2).strip() or None

    name = re.sub(r"\[.*\]", "", raw_name)
    return (_normalize_name(name), version_spec)


def _normalize_name(name):
    # type: (str) -> str
    """Normalize a package name: lowercase, replace [-_.] with hyphens."""
    return re.sub(r"[-_.]+", "-", name).lower()
