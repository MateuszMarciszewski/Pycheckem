from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from pycheckem.config import SuppressionConfig
from pycheckem.diff import compute_severity, count_differences
from pycheckem.types import (
    ConfigDiff,
    DiffResult,
    DiffSummary,
    PackageDiff,
    PathDiff,
    VarDiff,
    VersionChange,
)


def _matches_any(name, patterns):
    # type: (str, List[str]) -> bool
    """Check if a name matches any of the given regex patterns."""
    for pattern in patterns:
        try:
            if re.fullmatch(pattern, name, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def _should_suppress_package(name, config):
    # type: (str, SuppressionConfig) -> bool
    """Check if a package should be suppressed."""
    if name in config.ignore_packages or name.lower() in [
        p.lower() for p in config.ignore_packages
    ]:
        return True
    return _matches_any(name, config.ignore_patterns)


def _should_suppress_env_var(name, config):
    # type: (str, SuppressionConfig) -> bool
    """Check if an env var should be suppressed."""
    if name in config.ignore_env_vars:
        return True
    return _matches_any(name, config.ignore_patterns)


def _filter_packages(pkg_diff, config):
    # type: (PackageDiff, SuppressionConfig) -> PackageDiff
    """Return a new PackageDiff with suppressed packages removed."""
    added = {
        k: v for k, v in pkg_diff.added.items()
        if not _should_suppress_package(k, config)
    }
    removed = {
        k: v for k, v in pkg_diff.removed.items()
        if not _should_suppress_package(k, config)
    }
    changed = {
        k: v for k, v in pkg_diff.changed.items()
        if not _should_suppress_package(k, config)
    }
    suppressed_count = (
        (len(pkg_diff.added) - len(added))
        + (len(pkg_diff.removed) - len(removed))
        + (len(pkg_diff.changed) - len(changed))
    )
    return PackageDiff(
        added=added,
        removed=removed,
        changed=changed,
        unchanged_count=pkg_diff.unchanged_count + suppressed_count,
    )


def _filter_env_vars(env_diff, config):
    # type: (VarDiff, SuppressionConfig) -> VarDiff
    """Return a new VarDiff with suppressed env vars removed."""
    added = {
        k: v for k, v in env_diff.added.items()
        if not _should_suppress_env_var(k, config)
    }
    removed = {
        k: v for k, v in env_diff.removed.items()
        if not _should_suppress_env_var(k, config)
    }
    changed = {
        k: v for k, v in env_diff.changed.items()
        if not _should_suppress_env_var(k, config)
    }
    suppressed_count = (
        (len(env_diff.added) - len(added))
        + (len(env_diff.removed) - len(removed))
        + (len(env_diff.changed) - len(changed))
    )
    return VarDiff(
        added=added,
        removed=removed,
        changed=changed,
        unchanged_count=env_diff.unchanged_count + suppressed_count,
    )


def apply_suppression(result, config):
    # type: (DiffResult, SuppressionConfig) -> DiffResult
    """Return a new DiffResult with suppressed items filtered out.

    Severity and counts are recomputed from scratch after filtering.
    """
    if (not config.ignore_packages
            and not config.ignore_env_vars
            and not config.ignore_patterns):
        return result

    packages = _filter_packages(result.packages, config)
    env_vars = _filter_env_vars(result.env_vars, config)

    # Recompute severity and counts with filtered data
    total = count_differences(
        result.python, packages, env_vars,
        result.os_info, result.paths, result.config_files,
    )
    severity, breaking = compute_severity(
        result.python, packages, env_vars,
        result.os_info, result.paths, result.config_files,
    )

    return DiffResult(
        label_a=result.label_a,
        label_b=result.label_b,
        python=result.python,
        packages=packages,
        env_vars=env_vars,
        os_info=result.os_info,
        paths=result.paths,
        config_files=result.config_files,
        summary=DiffSummary(
            total_differences=total,
            severity=severity,
            breaking_changes=breaking,
        ),
    )
