from __future__ import annotations

import json
import os
import subprocess
import sys

from pycheckem.snapshot import save, snapshot as take_snapshot
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
            label="baseline",
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
            "requests": PackageInfo(version="2.31.0", location="/sp", requires=["urllib3"]),
        },
        env_vars={"PATH": "/usr/bin", "HOME": "/home/dev"},
        os_info=OSInfo(system="Linux", release="6.1.0", machine="x86_64", distro="Ubuntu 22.04"),
        paths=PathInfo(sys_path=["/usr/lib/python3"], path_env=["/usr/bin"]),
        config_files={},
    )
    defaults.update(overrides)
    return Snapshot(**defaults)


def _run_cli(*args):
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "pycheckem"] + list(args),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )


class TestGuardBasic:
    def test_guard_produces_output(self, tmp_path):
        """guard should produce diff output."""
        snap = take_snapshot(label="baseline")
        saved = str(tmp_path / "baseline.json")
        save(snap, saved)
        result = _run_cli("guard", saved)
        assert "pycheckem:" in result.stdout

    def test_guard_identical_exits_zero(self, tmp_path):
        """guard against a freshly taken snapshot should exit 0 (no drift)."""
        snap = take_snapshot(label="baseline")
        saved = str(tmp_path / "baseline.json")
        save(snap, saved)
        result = _run_cli("guard", saved, "--fail-severity", "critical")
        assert result.returncode == 0

    def test_guard_always_exits_on_drift(self, tmp_path):
        """guard always enables exit-code — no --exit-code flag needed."""
        # Create a snapshot with a different Python version to force a diff
        snap = _make_snapshot()
        saved = str(tmp_path / "baseline.json")
        save(snap, saved)
        result = _run_cli("guard", saved)
        # Should exit 1 because the live env will differ from the fake snapshot
        assert result.returncode == 1


class TestGuardFlags:
    def test_fail_severity_critical(self, tmp_path):
        """guard with --fail-severity critical should pass if no critical diffs."""
        snap = take_snapshot(label="baseline")
        saved = str(tmp_path / "baseline.json")
        save(snap, saved)
        result = _run_cli("guard", saved, "--fail-severity", "critical")
        assert result.returncode == 0

    def test_json_format(self, tmp_path):
        snap = take_snapshot(label="baseline")
        saved = str(tmp_path / "baseline.json")
        save(snap, saved)
        result = _run_cli("guard", saved, "--format", "json")
        parsed = json.loads(result.stdout)
        assert "summary" in parsed

    def test_only_flag(self, tmp_path):
        snap = take_snapshot(label="baseline")
        saved = str(tmp_path / "baseline.json")
        save(snap, saved)
        result = _run_cli("guard", saved, "--only", "packages")
        # Should not crash
        assert result.returncode in (0, 1)

    def test_label_flag(self, tmp_path):
        snap = take_snapshot(label="baseline")
        saved = str(tmp_path / "baseline.json")
        save(snap, saved)
        result = _run_cli("guard", saved, "--label", "ci-check")
        # Should not crash
        assert result.returncode in (0, 1)

    def test_ignore_packages(self, tmp_path):
        snap = take_snapshot(label="baseline")
        saved = str(tmp_path / "baseline.json")
        save(snap, saved)
        result = _run_cli(
            "guard", saved, "--format", "json",
            "--ignore-packages", "pip,setuptools,wheel",
        )
        parsed = json.loads(result.stdout)
        assert "summary" in parsed

    def test_sbs_format(self, tmp_path):
        snap = take_snapshot(label="baseline")
        saved = str(tmp_path / "baseline.json")
        save(snap, saved)
        result = _run_cli("guard", saved, "--format", "sbs")
        assert "|" in result.stdout


class TestGuardErrors:
    def test_missing_file(self, tmp_path):
        result = _run_cli("guard", str(tmp_path / "nonexistent.json"))
        assert result.returncode == 1
        assert "file not found" in result.stderr.lower()

    def test_invalid_json(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json at all")
        result = _run_cli("guard", str(bad_file))
        assert result.returncode == 1
        assert "invalid json" in result.stderr.lower()

    def test_invalid_snapshot(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text('{"foo": "bar"}')
        result = _run_cli("guard", str(bad_file))
        assert result.returncode == 1
        assert "invalid snapshot" in result.stderr.lower()
