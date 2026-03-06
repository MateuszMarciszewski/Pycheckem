from __future__ import annotations

import os
import subprocess
import sys


from pycheckem.history import add as hist_add
from pycheckem.snapshot import save
from pycheckem.types import (
    OSInfo,
    PackageInfo,
    PathInfo,
    PythonInfo,
    Snapshot,
    SnapshotMetadata,
)


def _make_snapshot(label=None, timestamp="2026-03-02T12:00:00Z", version="3.11.4"):
    return Snapshot(
        metadata=SnapshotMetadata(
            timestamp=timestamp,
            hostname="test-host",
            label=label,
            pycheckem_version="0.2.0",
        ),
        python=PythonInfo(version, "CPython", "/usr/bin/python3", "/usr", "linux"),
        packages={"requests": PackageInfo("2.31.0", "/sp", [])},
        env_vars={"PATH": "/usr/bin"},
        os_info=OSInfo("Linux", "6.1.0", "x86_64", "Ubuntu 22.04"),
        paths=PathInfo(["/usr/lib"], ["/usr/bin"]),
        config_files={},
    )


def _run_cli(*args, cwd=None):
    """Run pycheckem CLI and return (returncode, stdout, stderr)."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(
        [sys.executable, "-m", "pycheckem"] + list(args),
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
        encoding="utf-8",
    )
    return result.returncode, result.stdout, result.stderr


class TestCliHistoryAdd:
    def test_add_snapshot(self, tmp_path):
        snap = _make_snapshot(label="dev")
        snap_path = str(tmp_path / "snap.json")
        save(snap, snap_path)

        rc, out, err = _run_cli("history", "add", snap_path, cwd=str(tmp_path))
        assert rc == 0
        assert "Added to history" in out

    def test_add_nonexistent_file(self, tmp_path):
        rc, out, err = _run_cli(
            "history", "add", str(tmp_path / "missing.json"), cwd=str(tmp_path)
        )
        assert rc == 1
        assert "not found" in err.lower() or "Error" in err


class TestCliHistoryShow:
    def test_empty_history(self, tmp_path):
        rc, out, err = _run_cli("history", "show", cwd=str(tmp_path))
        assert rc == 0
        assert "No snapshots" in out

    def test_show_with_entries(self, tmp_path):
        snap = _make_snapshot(label="staging", timestamp="2026-01-15T08:30:00Z")
        snap_path = str(tmp_path / "snap.json")
        save(snap, snap_path)
        hist_add(snap_path, base_dir=str(tmp_path))

        rc, out, err = _run_cli("history", "show", cwd=str(tmp_path))
        assert rc == 0
        assert "staging" in out


class TestCliHistoryDiff:
    def test_diff_last_2(self, tmp_path):
        for label, ts, ver in [
            ("first", "2026-01-01T10:00:00Z", "3.11.4"),
            ("second", "2026-02-01T10:00:00Z", "3.12.0"),
        ]:
            snap = _make_snapshot(label=label, timestamp=ts, version=ver)
            snap_path = str(tmp_path / f"{label}.json")
            save(snap, snap_path)
            hist_add(snap_path, base_dir=str(tmp_path))

        rc, out, err = _run_cli("history", "diff", "--last", "2", cwd=str(tmp_path))
        assert rc == 0
        assert "first" in out or "second" in out

    def test_diff_insufficient_history(self, tmp_path):
        snap = _make_snapshot(label="only")
        snap_path = str(tmp_path / "snap.json")
        save(snap, snap_path)
        hist_add(snap_path, base_dir=str(tmp_path))

        rc, out, err = _run_cli("history", "diff", "--last", "2", cwd=str(tmp_path))
        assert rc == 1
        assert "need at least 2" in err.lower()

    def test_diff_empty_history(self, tmp_path):
        rc, out, err = _run_cli("history", "diff", cwd=str(tmp_path))
        assert rc == 1
        assert "need at least 2" in err.lower()
