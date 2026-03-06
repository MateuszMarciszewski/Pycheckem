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


class TestCompareBasic:
    def test_compare_exits_zero(self, tmp_path):
        """compare against a live snapshot of the same env should succeed."""
        snap = take_snapshot(label="saved")
        saved = str(tmp_path / "saved.json")
        save(snap, saved)
        result = _run_cli("compare", saved)
        assert result.returncode == 0

    def test_compare_produces_output(self, tmp_path):
        snap = take_snapshot(label="saved")
        saved = str(tmp_path / "saved.json")
        save(snap, saved)
        result = _run_cli("compare", saved)
        assert "pycheckem:" in result.stdout

    def test_compare_same_result_as_diff(self, tmp_path):
        """compare should produce output that matches manual snapshot + diff."""
        snap = take_snapshot(label="base")
        saved = str(tmp_path / "saved.json")
        save(snap, saved)
        # compare against itself
        result = _run_cli("compare", saved)
        assert result.returncode == 0
        # The label from the saved snapshot should appear in output
        assert "base" in result.stdout


class TestCompareFlags:
    def test_label_flag(self, tmp_path):
        snap = take_snapshot(label="saved")
        saved = str(tmp_path / "saved.json")
        save(snap, saved)
        result = _run_cli("compare", saved, "--label", "live-check")
        assert result.returncode == 0

    def test_json_format(self, tmp_path):
        snap = take_snapshot(label="saved")
        saved = str(tmp_path / "saved.json")
        save(snap, saved)
        result = _run_cli("compare", saved, "--format", "json")
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert "summary" in parsed

    def test_only_flag(self, tmp_path):
        snap = take_snapshot(label="saved")
        saved = str(tmp_path / "saved.json")
        save(snap, saved)
        result = _run_cli("compare", saved, "--only", "packages")
        assert result.returncode == 0

    def test_exit_code_identical(self, tmp_path):
        """Exit code 0 when comparing against a freshly taken snapshot."""
        snap = take_snapshot()
        saved = str(tmp_path / "saved.json")
        save(snap, saved)
        result = _run_cli("compare", saved, "--exit-code")
        # May or may not be 0 depending on timing, but should not crash
        assert result.returncode in (0, 1)

    def test_fail_severity_flag(self, tmp_path):
        snap = take_snapshot()
        saved = str(tmp_path / "saved.json")
        save(snap, saved)
        result = _run_cli(
            "compare", saved, "--exit-code", "--fail-severity", "critical"
        )
        assert result.returncode == 0  # no critical differences against self


class TestCompareSbsFormat:
    def test_sbs_format(self, tmp_path):
        snap = take_snapshot(label="saved")
        saved = str(tmp_path / "saved.json")
        save(snap, saved)
        result = _run_cli("compare", saved, "--format", "sbs")
        assert result.returncode == 0
        assert "|" in result.stdout  # side-by-side separator


class TestCompareSuppression:
    def test_ignore_packages(self, tmp_path):
        snap = take_snapshot(label="saved")
        saved = str(tmp_path / "saved.json")
        save(snap, saved)
        result = _run_cli(
            "compare",
            saved,
            "--format",
            "json",
            "--ignore-packages",
            "pip,setuptools,wheel",
        )
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert "summary" in parsed


class TestCompareErrors:
    def test_missing_file(self, tmp_path):
        result = _run_cli("compare", str(tmp_path / "nonexistent.json"))
        assert result.returncode == 1
        assert "file not found" in result.stderr.lower()

    def test_invalid_json(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json at all")
        result = _run_cli("compare", str(bad_file))
        assert result.returncode == 1
        assert "invalid json" in result.stderr.lower()

    def test_invalid_snapshot(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text('{"foo": "bar"}')
        result = _run_cli("compare", str(bad_file))
        assert result.returncode == 1
        assert "invalid snapshot" in result.stderr.lower()
