from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from pycheckem.types import (
    ConfigDiff,
    ConfigFileDiff,
    ConfigFileInfo,
    DiffResult,
    DiffSummary,
    OSDiff,
    OSInfo,
    PackageDiff,
    PackageInfo,
    PathDiff,
    PathInfo,
    ProjectDiff,
    ProjectInfo,
    PythonDiff,
    PythonInfo,
    Snapshot,
    SourceChange,
    VarDiff,
    VersionChange,
)


# ---------------------------------------------------------------------------
# Version comparison utilities
# ---------------------------------------------------------------------------


def parse_version(v):
    # type: (str) -> tuple
    """Parse a PEP 440-ish version into a comparable tuple.

    Falls back to (original_string,) for non-standard versions.
    """
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (v,)


def is_major_change(a, b):
    # type: (str, str) -> bool
    """True if the first version component differs."""
    va, vb = parse_version(a), parse_version(b)
    if len(va) > 0 and len(vb) > 0 and isinstance(va[0], int) and isinstance(vb[0], int):
        return va[0] != vb[0]
    return a != b


def is_downgrade(a, b):
    # type: (str, str) -> bool
    """True if version b < version a."""
    return parse_version(b) < parse_version(a)


# ---------------------------------------------------------------------------
# Section diff functions
# ---------------------------------------------------------------------------


def diff_python(a, b):
    # type: (PythonInfo, PythonInfo) -> Optional[PythonDiff]
    """Compare two PythonInfo objects. Returns None if identical."""
    changes = {}  # type: Dict[str, Tuple[str, str]]
    for field in ("version", "implementation", "executable", "prefix", "platform"):
        val_a = getattr(a, field)
        val_b = getattr(b, field)
        if val_a != val_b:
            changes[field] = (val_a, val_b)
    if not changes:
        return None
    return PythonDiff(changes=changes)


def diff_packages(a, b):
    # type: (Dict[str, PackageInfo], Dict[str, PackageInfo]) -> PackageDiff
    """Compare two package dictionaries."""
    keys_a = set(a.keys())
    keys_b = set(b.keys())

    added = {name: b[name].version for name in sorted(keys_b - keys_a)}
    removed = {name: a[name].version for name in sorted(keys_a - keys_b)}

    changed = {}  # type: Dict[str, VersionChange]
    source_changed = {}  # type: Dict[str, SourceChange]
    unchanged_count = 0
    for name in sorted(keys_a & keys_b):
        pkg_a = a[name]
        pkg_b = b[name]

        src_a = getattr(pkg_a, "install_source", "pypi")
        src_b = getattr(pkg_b, "install_source", "pypi")

        if pkg_a.version != pkg_b.version:
            changed[name] = VersionChange(
                version_a=pkg_a.version,
                version_b=pkg_b.version,
                is_major=is_major_change(pkg_a.version, pkg_b.version),
                is_downgrade=is_downgrade(pkg_a.version, pkg_b.version),
                source_a=src_a,
                source_b=src_b,
            )
        elif src_a != src_b:
            source_changed[name] = SourceChange(
                source_a=src_a,
                source_b=src_b,
                url_a=getattr(pkg_a, "source_url", None),
                url_b=getattr(pkg_b, "source_url", None),
                detail_a=getattr(pkg_a, "source_detail", None),
                detail_b=getattr(pkg_b, "source_detail", None),
            )
        else:
            unchanged_count += 1

    return PackageDiff(
        added=added,
        removed=removed,
        changed=changed,
        unchanged_count=unchanged_count,
        source_changed=source_changed,
    )


def diff_env_vars(a, b):
    # type: (Dict[str, str], Dict[str, str]) -> VarDiff
    """Compare two env var dictionaries."""
    keys_a = set(a.keys())
    keys_b = set(b.keys())

    added = {k: b[k] for k in sorted(keys_b - keys_a)}
    removed = {k: a[k] for k in sorted(keys_a - keys_b)}

    changed = {}  # type: Dict[str, Tuple[str, str]]
    unchanged_count = 0
    for k in sorted(keys_a & keys_b):
        if a[k] != b[k]:
            changed[k] = (a[k], b[k])
        else:
            unchanged_count += 1

    return VarDiff(
        added=added,
        removed=removed,
        changed=changed,
        unchanged_count=unchanged_count,
    )


def diff_os(a, b):
    # type: (OSInfo, OSInfo) -> Optional[OSDiff]
    """Compare two OSInfo objects. Returns None if identical."""
    changes = {}  # type: Dict[str, Tuple[str, str]]
    for field in ("system", "release", "machine"):
        val_a = getattr(a, field)
        val_b = getattr(b, field)
        if val_a != val_b:
            changes[field] = (val_a, val_b)

    # distro can be None
    distro_a = a.distro or ""
    distro_b = b.distro or ""
    if distro_a != distro_b:
        changes["distro"] = (a.distro or "", b.distro or "")

    if not changes:
        return None
    return OSDiff(changes=changes)


def diff_paths(a, b):
    # type: (PathInfo, PathInfo) -> PathDiff
    """Compare two PathInfo objects."""
    set_sys_a = set(a.sys_path)
    set_sys_b = set(b.sys_path)
    set_env_a = set(a.path_env)
    set_env_b = set(b.path_env)

    return PathDiff(
        sys_path_added=sorted(set_sys_b - set_sys_a),
        sys_path_removed=sorted(set_sys_a - set_sys_b),
        path_env_added=sorted(set_env_b - set_env_a),
        path_env_removed=sorted(set_env_a - set_env_b),
    )


def diff_config_files(a, b):
    # type: (Dict[str, ConfigFileInfo], Dict[str, ConfigFileInfo]) -> ConfigDiff
    """Compare two config file dictionaries."""
    keys_a = set(a.keys())
    keys_b = set(b.keys())

    added = sorted(keys_b - keys_a)
    removed = sorted(keys_a - keys_b)

    changed = {}  # type: Dict[str, ConfigFileDiff]
    unchanged_count = 0
    for path in sorted(keys_a & keys_b):
        info_a = a[path]
        info_b = b[path]
        if info_a.sha256 == info_b.sha256:
            unchanged_count += 1
            continue

        keys_added = []  # type: List[str]
        keys_removed = []  # type: List[str]
        if info_a.keys is not None and info_b.keys is not None:
            set_ka = set(info_a.keys)
            set_kb = set(info_b.keys)
            keys_added = sorted(set_kb - set_ka)
            keys_removed = sorted(set_ka - set_kb)

        changed[path] = ConfigFileDiff(
            sha256_a=info_a.sha256,
            sha256_b=info_b.sha256,
            keys_added=keys_added,
            keys_removed=keys_removed,
        )

    return ConfigDiff(
        added=added,
        removed=removed,
        changed=changed,
        unchanged_count=unchanged_count,
    )


def diff_project(a, b):
    # type: (Optional[ProjectInfo], Optional[ProjectInfo]) -> Optional[ProjectDiff]
    """Compare two ProjectInfo objects. Returns None if both are None or identical."""
    if a is None and b is None:
        return None

    name_a = a.name if a else None
    name_b = b.name if b else None
    ver_a = a.version if a else None
    ver_b = b.version if b else None
    req_a = a.requires_python if a else None
    req_b = b.requires_python if b else None
    deps_a = set(a.dependencies) if a else set()
    deps_b = set(b.dependencies) if b else set()

    name_changed = None  # type: Optional[Tuple[str, str]]
    if name_a != name_b:
        name_changed = (name_a or "", name_b or "")

    version_changed = None  # type: Optional[Tuple[str, str]]
    if ver_a != ver_b:
        version_changed = (ver_a or "", ver_b or "")

    requires_python_changed = None  # type: Optional[Tuple[str, str]]
    if req_a != req_b:
        requires_python_changed = (req_a or "", req_b or "")

    deps_added = sorted(deps_b - deps_a)
    deps_removed = sorted(deps_a - deps_b)

    if (name_changed is None and version_changed is None
            and requires_python_changed is None
            and not deps_added and not deps_removed):
        return None

    return ProjectDiff(
        name_changed=name_changed,
        version_changed=version_changed,
        requires_python_changed=requires_python_changed,
        deps_added=deps_added,
        deps_removed=deps_removed,
    )


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"identical": 0, "minor": 1, "major": 2, "critical": 3}


def compute_severity(
    python_diff,   # type: Optional[PythonDiff]
    pkg_diff,      # type: PackageDiff
    env_diff,      # type: VarDiff
    os_diff,       # type: Optional[OSDiff]
    path_diff,     # type: PathDiff
    config_diff,   # type: ConfigDiff
    project_diff=None,  # type: Optional[ProjectDiff]
):
    # type: (...) -> Tuple[str, List[str]]
    """Compute overall severity and generate breaking_changes list."""
    severity = "identical"
    breaking = []  # type: List[str]

    def raise_to(level):
        # type: (str) -> None
        nonlocal severity
        if _SEVERITY_ORDER[level] > _SEVERITY_ORDER[severity]:
            severity = level

    # --- Python ---
    if python_diff is not None:
        if "version" in python_diff.changes:
            old, new = python_diff.changes["version"]
            if is_major_change(old, new):
                raise_to("critical")
                breaking.append(
                    "Python major version mismatch: {} vs {}".format(old, new)
                )
            else:
                raise_to("major")
                breaking.append(
                    "Python minor version mismatch: {} vs {}".format(old, new)
                )
        for field in ("implementation", "executable", "prefix", "platform"):
            if field in python_diff.changes:
                old, new = python_diff.changes[field]
                raise_to("minor")

    # --- OS ---
    if os_diff is not None:
        if "system" in os_diff.changes or "machine" in os_diff.changes:
            raise_to("critical")
            for field in ("system", "machine"):
                if field in os_diff.changes:
                    old, new = os_diff.changes[field]
                    breaking.append(
                        "OS {} mismatch: {} vs {}".format(field, old, new)
                    )
        else:
            raise_to("minor")

    # --- Packages ---
    if pkg_diff.removed:
        raise_to("major")
        for name, ver in pkg_diff.removed.items():
            breaking.append("Package removed: {} {}".format(name, ver))

    for name, vc in pkg_diff.changed.items():
        if vc.is_major:
            raise_to("critical")
            breaking.append(
                "Package major version change: {} {} -> {}".format(
                    name, vc.version_a, vc.version_b
                )
            )
        elif vc.is_downgrade:
            raise_to("major")
            breaking.append(
                "Package downgrade: {} {} -> {}".format(
                    name, vc.version_a, vc.version_b
                )
            )
        else:
            raise_to("minor")

    if pkg_diff.added:
        raise_to("minor")

    if pkg_diff.source_changed:
        raise_to("minor")

    # --- Env vars ---
    if env_diff.removed or env_diff.changed:
        raise_to("minor")
    if env_diff.added:
        raise_to("minor")

    # --- Paths ---
    if (path_diff.sys_path_added or path_diff.sys_path_removed
            or path_diff.path_env_added or path_diff.path_env_removed):
        raise_to("minor")

    # --- Config files ---
    if config_diff.added or config_diff.removed or config_diff.changed:
        raise_to("minor")

    # --- Project ---
    if project_diff is not None:
        if project_diff.requires_python_changed is not None:
            raise_to("major")
            old, new = project_diff.requires_python_changed
            breaking.append(
                "Project requires-python changed: {} -> {}".format(old, new)
            )
        if (project_diff.name_changed or project_diff.version_changed
                or project_diff.deps_added or project_diff.deps_removed):
            raise_to("minor")

    return severity, breaking


def count_differences(
    python_diff,   # type: Optional[PythonDiff]
    pkg_diff,      # type: PackageDiff
    env_diff,      # type: VarDiff
    os_diff,       # type: Optional[OSDiff]
    path_diff,     # type: PathDiff
    config_diff,   # type: ConfigDiff
    project_diff=None,  # type: Optional[ProjectDiff]
):
    # type: (...) -> int
    """Count total number of individual differences."""
    count = 0

    if python_diff is not None:
        count += len(python_diff.changes)

    count += (len(pkg_diff.added) + len(pkg_diff.removed)
              + len(pkg_diff.changed) + len(pkg_diff.source_changed))
    count += len(env_diff.added) + len(env_diff.removed) + len(env_diff.changed)

    if os_diff is not None:
        count += len(os_diff.changes)

    count += (len(path_diff.sys_path_added) + len(path_diff.sys_path_removed)
              + len(path_diff.path_env_added) + len(path_diff.path_env_removed))
    count += len(config_diff.added) + len(config_diff.removed) + len(config_diff.changed)

    if project_diff is not None:
        if project_diff.name_changed:
            count += 1
        if project_diff.version_changed:
            count += 1
        if project_diff.requires_python_changed:
            count += 1
        count += len(project_diff.deps_added) + len(project_diff.deps_removed)

    return count


# ---------------------------------------------------------------------------
# Top-level diff function
# ---------------------------------------------------------------------------


def diff(a, b):
    # type: (Snapshot, Snapshot) -> DiffResult
    """Compare two Snapshots and produce a structured DiffResult."""
    python = diff_python(a.python, b.python)
    packages = diff_packages(a.packages, b.packages)
    env_vars = diff_env_vars(a.env_vars, b.env_vars)
    os_info = diff_os(a.os_info, b.os_info)
    paths = diff_paths(a.paths, b.paths)
    config_files = diff_config_files(a.config_files, b.config_files)
    project = diff_project(
        getattr(a, "project", None),
        getattr(b, "project", None),
    )

    total = count_differences(
        python, packages, env_vars, os_info, paths, config_files, project
    )
    severity, breaking = compute_severity(
        python, packages, env_vars, os_info, paths, config_files, project
    )

    label_a = a.metadata.label or a.metadata.hostname
    label_b = b.metadata.label or b.metadata.hostname

    return DiffResult(
        label_a=label_a,
        label_b=label_b,
        python=python,
        packages=packages,
        env_vars=env_vars,
        os_info=os_info,
        paths=paths,
        config_files=config_files,
        project=project,
        summary=DiffSummary(
            total_differences=total,
            severity=severity,
            breaking_changes=breaking,
        ),
    )
