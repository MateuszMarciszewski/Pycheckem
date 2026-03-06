from __future__ import annotations

import json
import os
import subprocess
import sys

from pycheckem.snapshot import save
from pycheckem.types import (
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
            label="staging",
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
            "requests": PackageInfo(
                version="2.31.0", location="/sp", requires=["urllib3"]
            ),
            "flask": PackageInfo(
                version="3.0.0", location="/sp", requires=["werkzeug"]
            ),
        },
        env_vars={"PATH": "/usr/bin", "HOME": "/home/dev"},
        os_info=OSInfo(
            system="Linux", release="6.1.0", machine="x86_64", distro="Ubuntu 22.04"
        ),
        paths=PathInfo(sys_path=["/usr/lib/python3"], path_env=["/usr/bin"]),
        config_files={},
    )
    defaults.update(overrides)
    return Snapshot(**defaults)


def _save_pair(tmp_path, snap_a=None, snap_b=None):
    """Save two snapshots and return their paths as strings."""
    if snap_a is None:
        snap_a = _make_snapshot()
    if snap_b is None:
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            packages={
                "requests": PackageInfo("2.28.0", "/sp", ["urllib3"]),
                "flask": PackageInfo("3.0.0", "/sp", ["werkzeug"]),
                "gunicorn": PackageInfo("21.2.0", "/sp", []),
            },
            env_vars={
                "PATH": "/usr/bin",
                "HOME": "/home/dev",
                "DATABASE_URL": "postgres://...",
            },
        )
    file_a = str(tmp_path / "a.json")
    file_b = str(tmp_path / "b.json")
    save(snap_a, file_a)
    save(snap_b, file_b)
    return file_a, file_b


def _run_cli(*args):
    """Run pycheckem via subprocess and return the CompletedProcess."""
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "pycheckem"] + list(args),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )


class TestCLIDiffBasic:
    def test_diff_exits_zero(self, tmp_path):
        file_a, file_b = _save_pair(tmp_path)
        result = _run_cli("diff", file_a, file_b)
        assert result.returncode == 0

    def test_diff_prints_ascii_output(self, tmp_path):
        file_a, file_b = _save_pair(tmp_path)
        result = _run_cli("diff", file_a, file_b)
        assert "pycheckem:" in result.stdout
        assert "staging" in result.stdout
        assert "prod" in result.stdout

    def test_diff_identical_no_differences(self, tmp_path):
        snap = _make_snapshot()
        file_a, file_b = _save_pair(tmp_path, snap, snap)
        result = _run_cli("diff", file_a, file_b)
        assert "No differences" in result.stdout


class TestCLIDiffFormatJson:
    def test_json_format_is_valid(self, tmp_path):
        file_a, file_b = _save_pair(tmp_path)
        result = _run_cli("diff", file_a, file_b, "--format", "json")
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert "summary" in parsed

    def test_json_format_has_all_fields(self, tmp_path):
        file_a, file_b = _save_pair(tmp_path)
        result = _run_cli("diff", file_a, file_b, "--format", "json")
        parsed = json.loads(result.stdout)
        for key in ("label_a", "label_b", "packages", "env_vars", "summary"):
            assert key in parsed


class TestCLIDiffOnly:
    def test_only_packages(self, tmp_path):
        file_a, file_b = _save_pair(tmp_path)
        result = _run_cli("diff", file_a, file_b, "--only", "packages")
        assert result.returncode == 0
        assert "Packages" in result.stdout
        assert "Environment Variables" not in result.stdout

    def test_only_env(self, tmp_path):
        file_a, file_b = _save_pair(tmp_path)
        result = _run_cli("diff", file_a, file_b, "--only", "env")
        assert result.returncode == 0
        assert "Environment Variables" in result.stdout
        assert "Packages" not in result.stdout


class TestCLIDiffExitCode:
    def test_exit_code_with_differences(self, tmp_path):
        file_a, file_b = _save_pair(tmp_path)
        result = _run_cli("diff", file_a, file_b, "--exit-code")
        assert result.returncode == 1

    def test_exit_code_identical(self, tmp_path):
        snap = _make_snapshot()
        file_a, file_b = _save_pair(tmp_path, snap, snap)
        result = _run_cli("diff", file_a, file_b, "--exit-code")
        assert result.returncode == 0

    def test_fail_severity_critical_ignores_minor(self, tmp_path):
        # Default pair has minor/major diffs but not critical
        a = _make_snapshot()
        b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            env_vars={"PATH": "/usr/bin", "HOME": "/home/dev", "NEW_VAR": "val"},
        )
        file_a, file_b = _save_pair(tmp_path, a, b)
        result = _run_cli(
            "diff", file_a, file_b, "--exit-code", "--fail-severity", "critical"
        )
        assert result.returncode == 0

    def test_fail_severity_major_triggers_on_major(self, tmp_path):
        a = _make_snapshot()
        b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            packages={
                "requests": PackageInfo(
                    "2.28.0", "/sp", ["urllib3"]
                ),  # downgrade = major
                "flask": PackageInfo("3.0.0", "/sp", ["werkzeug"]),
            },
        )
        file_a, file_b = _save_pair(tmp_path, a, b)
        result = _run_cli(
            "diff", file_a, file_b, "--exit-code", "--fail-severity", "major"
        )
        assert result.returncode == 1


class TestCLIDiffFormatSbs:
    def test_sbs_format_produces_output(self, tmp_path):
        file_a, file_b = _save_pair(tmp_path)
        result = _run_cli("diff", file_a, file_b, "--format", "sbs")
        assert result.returncode == 0
        assert "|" in result.stdout  # side-by-side separator

    def test_side_by_side_alias(self, tmp_path):
        file_a, file_b = _save_pair(tmp_path)
        result = _run_cli("diff", file_a, file_b, "--format", "side-by-side")
        assert result.returncode == 0
        assert "|" in result.stdout


class TestCLIDiffOnlyProject:
    def test_only_project(self, tmp_path):
        from pycheckem.types import ProjectInfo

        a = _make_snapshot(
            project=ProjectInfo(
                "myapp", "1.0.0", ">=3.8", ["requests"], "pyproject.toml"
            ),
        )
        b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            project=ProjectInfo(
                "myapp", "2.0.0", ">=3.9", ["requests", "flask"], "pyproject.toml"
            ),
        )
        file_a, file_b = _save_pair(tmp_path, a, b)
        result = _run_cli("diff", file_a, file_b, "--only", "project")
        assert result.returncode == 0
        assert "Project" in result.stdout
        assert "Packages" not in result.stdout


class TestCLIDiffSuppression:
    def test_ignore_packages(self, tmp_path):
        a = _make_snapshot()
        b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            packages={
                "requests": PackageInfo("2.28.0", "/sp", ["urllib3"]),
                "flask": PackageInfo("3.0.0", "/sp", ["werkzeug"]),
            },
        )
        file_a, file_b = _save_pair(tmp_path, a, b)

        # Without suppression — requests downgrade should appear
        result = _run_cli("diff", file_a, file_b, "--format", "json")
        parsed = json.loads(result.stdout)
        assert len(parsed["packages"]["changed"]) > 0

        # With suppression — ignore requests
        result = _run_cli(
            "diff",
            file_a,
            file_b,
            "--format",
            "json",
            "--ignore-packages",
            "requests",
        )
        parsed = json.loads(result.stdout)
        assert "requests" not in parsed["packages"].get("changed", {})

    def test_ignore_env_vars(self, tmp_path):
        a = _make_snapshot()
        b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            env_vars={
                "PATH": "/usr/bin",
                "HOME": "/home/dev",
                "DATABASE_URL": "postgres://...",
            },
        )
        file_a, file_b = _save_pair(tmp_path, a, b)

        # With suppression — ignore DATABASE_URL
        result = _run_cli(
            "diff",
            file_a,
            file_b,
            "--format",
            "json",
            "--ignore-env-vars",
            "DATABASE_URL",
        )
        parsed = json.loads(result.stdout)
        assert "DATABASE_URL" not in parsed["env_vars"].get("added", {})

    def test_ignore_patterns(self, tmp_path):
        a = _make_snapshot(env_vars={"PATH": "/usr/bin", "MY_CACHE_DIR": "/tmp"})
        b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            env_vars={"PATH": "/usr/bin"},
        )
        file_a, file_b = _save_pair(tmp_path, a, b)

        # With pattern suppression — ignore anything with CACHE
        result = _run_cli(
            "diff",
            file_a,
            file_b,
            "--format",
            "json",
            "--ignore-patterns",
            ".*CACHE.*",
        )
        parsed = json.loads(result.stdout)
        assert "MY_CACHE_DIR" not in parsed["env_vars"].get("removed", {})
