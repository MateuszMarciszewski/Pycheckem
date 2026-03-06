"""Verify installed packages against declared dependencies.

Compares what a project *declares* it needs (in requirements.txt or
pyproject.toml) against what is *actually installed* in the current
environment. Reports missing, extra, and version-mismatched packages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List

from pycheckem.collectors.packages import collect_packages
from pycheckem.parsers import _normalize_name


@dataclass
class VerifyResult:
    """Result of verifying installed packages against declared dependencies."""

    missing: List[str]
    extra: List[str]
    version_mismatches: Dict[str, "VersionMismatch"]
    satisfied: List[str]
    total_declared: int
    total_installed: int

    @property
    def is_satisfied(self):
        # type: () -> bool
        """True if all declared deps are installed and version-compatible."""
        return not self.missing and not self.version_mismatches


@dataclass
class VersionMismatch:
    """A package is installed but doesn't match the declared version spec."""

    installed: str
    declared: str


def verify(declared, include_extras=False):
    # type: (Dict[str, Optional[str]], bool) -> VerifyResult
    """Compare declared dependencies against installed packages.

    Args:
        declared: Dict from parse_requirements() or parse_pyproject_deps().
            Maps normalized package names to version specifiers (or None).
        include_extras: If True, report installed packages not in the
            declared list as "extra". If False, only report missing and
            mismatched.

    Returns:
        A VerifyResult with lists of missing, extra, and mismatched packages.

    Example:
        >>> from pycheckem.parsers import parse_requirements
        >>> from pycheckem.verify import verify
        >>> deps = parse_requirements("requirements.txt")
        >>> result = verify(deps)
        >>> result.is_satisfied
        False
        >>> result.missing
        ['pandas']
    """
    installed = collect_packages()

    # Normalize installed package names for lookup
    installed_norm = {}  # type: Dict[str, str]
    for name, info in installed.items():
        norm = _normalize_name(name)
        installed_norm[norm] = info.version

    missing = []  # type: List[str]
    mismatches = {}  # type: Dict[str, VersionMismatch]
    satisfied = []  # type: List[str]

    for name, spec in declared.items():
        if name not in installed_norm:
            missing.append(name)
            continue

        if spec is not None and not _version_satisfies(installed_norm[name], spec):
            mismatches[name] = VersionMismatch(
                installed=installed_norm[name],
                declared=spec,
            )
        else:
            satisfied.append(name)

    extra = []  # type: List[str]
    if include_extras:
        declared_set = set(declared.keys())
        extra = sorted(n for n in installed_norm if n not in declared_set)

    return VerifyResult(
        missing=sorted(missing),
        extra=extra,
        version_mismatches=mismatches,
        satisfied=sorted(satisfied),
        total_declared=len(declared),
        total_installed=len(installed),
    )


def _version_satisfies(installed_version, spec):
    # type: (str, str) -> bool
    """Check if an installed version satisfies a version specifier.

    Handles common operators: ==, !=, >=, <=, >, <, ~=.
    Multiple constraints can be comma-separated.
    Returns True if all constraints are satisfied.
    """
    constraints = [c.strip() for c in spec.split(",") if c.strip()]

    for constraint in constraints:
        match = re.match(r"^(~=|==|!=|>=|<=|>|<)\s*(.+)$", constraint)
        if not match:
            # Can't parse, assume satisfied (e.g. arbitrary equality ===)
            continue

        op = match.group(1)
        req_version = match.group(2).strip()

        if not _check_op(op, installed_version, req_version):
            return False

    return True


def _parse_version_tuple(v):
    # type: (str) -> tuple
    """Parse version string into a comparable tuple of ints."""
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (v,)


def _check_op(op, installed, required):
    # type: (str, str, str) -> bool
    """Check a single version comparison operation."""
    iv = _parse_version_tuple(installed)
    rv = _parse_version_tuple(required)

    if op == "==":
        # Handle wildcards like ==1.0.*
        if required.endswith(".*"):
            prefix = _parse_version_tuple(required[:-2])
            return iv[: len(prefix)] == prefix
        return iv == rv
    elif op == "!=":
        return iv != rv
    elif op == ">=":
        return iv >= rv
    elif op == "<=":
        return iv <= rv
    elif op == ">":
        return iv > rv
    elif op == "<":
        return iv < rv
    elif op == "~=":
        # Compatible release: ~=1.4.2 means >=1.4.2, <1.5.0
        if iv < rv:
            return False
        # Must match up to N-1 components
        if len(rv) >= 2:
            upper = rv[:-1]
            return iv[: len(upper)] == upper or (
                len(iv) >= len(upper)
                and iv[: len(upper) - 1] == upper[:-1]
                and iv[len(upper) - 1] <= upper[-1]
            )
        return iv >= rv

    return True


def render_verify(result):
    # type: (VerifyResult) -> str
    """Render a VerifyResult as human-readable text.

    Args:
        result: The VerifyResult to render.

    Returns:
        A multi-line string summarizing the verification.
    """
    lines = []  # type: List[str]

    if result.is_satisfied and not result.extra:
        lines.append(
            "All {} declared dependencies are satisfied.".format(result.total_declared)
        )
        return "\n".join(lines)

    lines.append("pycheckem verify")
    lines.append("=" * 47)

    if result.missing:
        lines.append("")
        lines.append("Missing ({})".format(len(result.missing)))
        for name in result.missing:
            lines.append("  - {}".format(name))

    if result.version_mismatches:
        lines.append("")
        lines.append("Version Mismatches ({})".format(len(result.version_mismatches)))
        for name, mm in sorted(result.version_mismatches.items()):
            lines.append(
                "  ~ {} installed={} declared={}".format(
                    name, mm.installed, mm.declared
                )
            )

    if result.extra:
        lines.append("")
        lines.append("Extra ({})".format(len(result.extra)))
        for name in result.extra:
            lines.append("  + {}".format(name))

    lines.append("")
    lines.append("-" * 47)
    satisfied_count = len(result.satisfied)
    total = result.total_declared
    status = "PASS" if result.is_satisfied else "FAIL"
    lines.append(
        "{}: {}/{} declared dependencies satisfied".format(
            status, satisfied_count, total
        )
    )

    return "\n".join(lines)
