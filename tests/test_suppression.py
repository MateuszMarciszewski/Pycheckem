from __future__ import annotations

from pycheckem.config import SuppressionConfig
from pycheckem.diff import diff
from pycheckem.suppression import apply_suppression
from pycheckem.types import (
    ConfigFileInfo,
    OSInfo,
    PackageInfo,
    PathInfo,
    PythonInfo,
    Snapshot,
    SnapshotMetadata,
)


def _make_snapshot(**overrides):
    defaults = dict(
        metadata=SnapshotMetadata(
            timestamp="2026-03-02T12:00:00Z",
            hostname="host-a",
            label="env-a",
            pycheckem_version="0.1.0",
        ),
        python=PythonInfo(
            version="3.11.4",
            implementation="CPython",
            executable="/usr/bin/python3",
            prefix="/usr",
            platform="linux",
        ),
        packages={
            "requests": PackageInfo(version="2.31.0", location="/sp", requires=[]),
            "flask": PackageInfo(version="3.0.0", location="/sp", requires=[]),
            "pip": PackageInfo(version="23.0", location="/sp", requires=[]),
            "setuptools": PackageInfo(version="68.0", location="/sp", requires=[]),
        },
        env_vars={
            "PATH": "/usr/bin",
            "HOME": "/home/dev",
            "HOSTNAME": "abc123",
            "LOG_LEVEL": "DEBUG",
        },
        os_info=OSInfo(system="Linux", release="6.1.0", machine="x86_64", distro="Ubuntu 22.04"),
        paths=PathInfo(sys_path=["/usr/lib/python3"], path_env=["/usr/bin"]),
        config_files={},
    )
    defaults.update(overrides)
    return Snapshot(**defaults)


class TestSuppressionPackages:
    def test_ignore_package_by_name(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
            packages={
                "requests": PackageInfo(version="2.31.0", location="/sp", requires=[]),
                "flask": PackageInfo(version="3.0.0", location="/sp", requires=[]),
                "pip": PackageInfo(version="24.0", location="/sp", requires=[]),
                "setuptools": PackageInfo(version="69.0", location="/sp", requires=[]),
                "gunicorn": PackageInfo(version="21.0", location="/sp", requires=[]),
            },
        )
        result = diff(snap_a, snap_b)
        config = SuppressionConfig(ignore_packages=["pip", "setuptools"])
        filtered = apply_suppression(result, config)

        # pip and setuptools changes should be suppressed
        assert "pip" not in filtered.packages.changed
        assert "setuptools" not in filtered.packages.changed
        # gunicorn should still show as added
        assert "gunicorn" in filtered.packages.added

    def test_ignore_package_added(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
            packages={
                "requests": PackageInfo(version="2.31.0", location="/sp", requires=[]),
                "flask": PackageInfo(version="3.0.0", location="/sp", requires=[]),
                "pip": PackageInfo(version="23.0", location="/sp", requires=[]),
                "setuptools": PackageInfo(version="68.0", location="/sp", requires=[]),
                "wheel": PackageInfo(version="0.41.0", location="/sp", requires=[]),
            },
        )
        result = diff(snap_a, snap_b)
        config = SuppressionConfig(ignore_packages=["wheel"])
        filtered = apply_suppression(result, config)

        assert "wheel" not in filtered.packages.added
        assert filtered.summary.total_differences == 0

    def test_ignore_package_removed(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
            packages={
                "requests": PackageInfo(version="2.31.0", location="/sp", requires=[]),
                "flask": PackageInfo(version="3.0.0", location="/sp", requires=[]),
                "setuptools": PackageInfo(version="68.0", location="/sp", requires=[]),
                # pip removed
            },
        )
        result = diff(snap_a, snap_b)
        config = SuppressionConfig(ignore_packages=["pip"])
        filtered = apply_suppression(result, config)

        assert "pip" not in filtered.packages.removed

    def test_case_insensitive_package_ignore(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
            packages={
                "requests": PackageInfo(version="2.31.0", location="/sp", requires=[]),
                "flask": PackageInfo(version="3.0.0", location="/sp", requires=[]),
                "pip": PackageInfo(version="24.0", location="/sp", requires=[]),
                "setuptools": PackageInfo(version="68.0", location="/sp", requires=[]),
            },
        )
        result = diff(snap_a, snap_b)
        config = SuppressionConfig(ignore_packages=["PIP"])
        filtered = apply_suppression(result, config)

        assert "pip" not in filtered.packages.changed


class TestSuppressionEnvVars:
    def test_ignore_env_var_by_name(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
            env_vars={
                "PATH": "/usr/bin",
                "HOME": "/home/dev",
                "HOSTNAME": "xyz789",
                "LOG_LEVEL": "WARNING",
            },
        )
        result = diff(snap_a, snap_b)
        config = SuppressionConfig(ignore_env_vars=["HOSTNAME"])
        filtered = apply_suppression(result, config)

        assert "HOSTNAME" not in filtered.env_vars.changed
        assert "LOG_LEVEL" in filtered.env_vars.changed

    def test_ignore_env_var_added(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
            env_vars={
                "PATH": "/usr/bin",
                "HOME": "/home/dev",
                "HOSTNAME": "abc123",
                "LOG_LEVEL": "DEBUG",
                "NEW_VAR": "value",
            },
        )
        result = diff(snap_a, snap_b)
        config = SuppressionConfig(ignore_env_vars=["NEW_VAR"])
        filtered = apply_suppression(result, config)

        assert "NEW_VAR" not in filtered.env_vars.added


class TestSuppressionPatterns:
    def test_pattern_matches_package(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
            packages={
                "requests": PackageInfo(version="2.31.0", location="/sp", requires=[]),
                "flask": PackageInfo(version="3.0.0", location="/sp", requires=[]),
                "pip": PackageInfo(version="24.0", location="/sp", requires=[]),
                "setuptools": PackageInfo(version="69.0", location="/sp", requires=[]),
            },
        )
        result = diff(snap_a, snap_b)
        # Pattern that matches pip and setuptools
        config = SuppressionConfig(ignore_patterns=["pip", "setuptools"])
        filtered = apply_suppression(result, config)

        assert "pip" not in filtered.packages.changed
        assert "setuptools" not in filtered.packages.changed

    def test_pattern_matches_env_var(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
            env_vars={
                "PATH": "/usr/bin",
                "HOME": "/home/dev",
                "HOSTNAME": "abc123",
                "LOG_LEVEL": "DEBUG",
                "MY_CACHE_DIR": "/tmp/cache",
            },
        )
        result = diff(snap_a, snap_b)
        config = SuppressionConfig(ignore_patterns=[".*_CACHE.*"])
        filtered = apply_suppression(result, config)

        assert "MY_CACHE_DIR" not in filtered.env_vars.added

    def test_invalid_pattern_is_skipped(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
            packages={
                "requests": PackageInfo(version="2.31.0", location="/sp", requires=[]),
                "flask": PackageInfo(version="3.0.0", location="/sp", requires=[]),
                "pip": PackageInfo(version="24.0", location="/sp", requires=[]),
                "setuptools": PackageInfo(version="68.0", location="/sp", requires=[]),
            },
        )
        result = diff(snap_a, snap_b)
        # Invalid regex should not crash
        config = SuppressionConfig(ignore_patterns=["[invalid regex"])
        filtered = apply_suppression(result, config)
        # pip change should still be there
        assert "pip" in filtered.packages.changed


class TestSuppressionSeverityRecomputation:
    def test_severity_reduced_after_suppression(self):
        """Suppressing a downgraded package should reduce severity from major."""
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
            packages={
                "requests": PackageInfo(version="2.28.0", location="/sp", requires=[]),
                "flask": PackageInfo(version="3.0.0", location="/sp", requires=[]),
                "pip": PackageInfo(version="23.0", location="/sp", requires=[]),
                "setuptools": PackageInfo(version="68.0", location="/sp", requires=[]),
            },
        )
        result = diff(snap_a, snap_b)
        assert result.summary.severity == "major"  # downgrade

        config = SuppressionConfig(ignore_packages=["requests"])
        filtered = apply_suppression(result, config)
        assert filtered.summary.severity == "identical"

    def test_no_suppression_returns_same_result(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
        )
        result = diff(snap_a, snap_b)
        config = SuppressionConfig()
        filtered = apply_suppression(result, config)
        assert filtered.summary.severity == result.summary.severity
        assert filtered.summary.total_differences == result.summary.total_differences

    def test_total_differences_updated(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
            packages={
                "requests": PackageInfo(version="2.31.0", location="/sp", requires=[]),
                "flask": PackageInfo(version="3.0.0", location="/sp", requires=[]),
                "pip": PackageInfo(version="24.0", location="/sp", requires=[]),
                "setuptools": PackageInfo(version="69.0", location="/sp", requires=[]),
            },
        )
        result = diff(snap_a, snap_b)
        assert result.summary.total_differences == 2  # pip + setuptools changed

        config = SuppressionConfig(ignore_packages=["pip"])
        filtered = apply_suppression(result, config)
        assert filtered.summary.total_differences == 1

    def test_breaking_changes_updated(self):
        """Suppressing a downgraded package should remove it from breaking_changes."""
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "env-b", "0.1.0"),
            packages={
                "requests": PackageInfo(version="2.28.0", location="/sp", requires=[]),
                "flask": PackageInfo(version="3.0.0", location="/sp", requires=[]),
                "pip": PackageInfo(version="23.0", location="/sp", requires=[]),
                "setuptools": PackageInfo(version="68.0", location="/sp", requires=[]),
            },
        )
        result = diff(snap_a, snap_b)
        assert any("requests" in b for b in result.summary.breaking_changes)

        config = SuppressionConfig(ignore_packages=["requests"])
        filtered = apply_suppression(result, config)
        assert not any("requests" in b for b in filtered.summary.breaking_changes)
