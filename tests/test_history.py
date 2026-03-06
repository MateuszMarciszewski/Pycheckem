from __future__ import annotations

import os

from pycheckem.history import (
    _history_dir,
    _snapshot_filename,
    add,
    get_last_n,
    list_snapshots,
)
from pycheckem.snapshot import save, load
from pycheckem.types import (
    OSInfo,
    PackageInfo,
    PathInfo,
    PythonInfo,
    Snapshot,
    SnapshotMetadata,
)


def _make_snapshot(label=None, timestamp="2026-03-02T12:00:00Z"):
    return Snapshot(
        metadata=SnapshotMetadata(
            timestamp=timestamp,
            hostname="test-host",
            label=label,
            pycheckem_version="0.2.0",
        ),
        python=PythonInfo("3.11.4", "CPython", "/usr/bin/python3", "/usr", "linux"),
        packages={"requests": PackageInfo("2.31.0", "/sp", [])},
        env_vars={"PATH": "/usr/bin"},
        os_info=OSInfo("Linux", "6.1.0", "x86_64", "Ubuntu 22.04"),
        paths=PathInfo(["/usr/lib"], ["/usr/bin"]),
        config_files={},
    )


class TestHistoryDir:
    def test_creates_directory(self, tmp_path):
        hdir = _history_dir(str(tmp_path))
        assert os.path.isdir(hdir)
        assert os.path.normpath(hdir).endswith(os.path.join(".pycheckem", "history"))

    def test_idempotent(self, tmp_path):
        hdir1 = _history_dir(str(tmp_path))
        hdir2 = _history_dir(str(tmp_path))
        assert hdir1 == hdir2


class TestSnapshotFilename:
    def test_basic_filename(self):
        snap = _make_snapshot(label="prod", timestamp="2026-03-02T12:00:00Z")
        name = _snapshot_filename(snap)
        assert name == "20260302T120000Z_prod.json"

    def test_unlabeled(self):
        snap = _make_snapshot(label=None, timestamp="2026-03-02T12:00:00Z")
        name = _snapshot_filename(snap)
        assert "unlabeled" in name

    def test_label_sanitization(self):
        snap = _make_snapshot(label="my app/v2.0", timestamp="2026-03-02T12:00:00Z")
        name = _snapshot_filename(snap)
        # Special characters replaced with underscore
        assert "/" not in name
        assert " " not in name
        assert name.endswith(".json")

    def test_timestamp_with_offset(self):
        snap = _make_snapshot(label="test", timestamp="2026-03-02T12:00:00+00:00")
        name = _snapshot_filename(snap)
        assert name == "20260302T120000Z_test.json"


class TestAdd:
    def test_add_snapshot(self, tmp_path):
        snap = _make_snapshot(label="dev")
        snap_path = str(tmp_path / "snap.json")
        save(snap, snap_path)

        dest = add(snap_path, base_dir=str(tmp_path))
        assert os.path.isfile(dest)
        assert ".pycheckem" in dest

        # Verify the copied file is valid
        loaded = load(dest)
        assert loaded.metadata.label == "dev"

    def test_add_nonexistent_file(self, tmp_path):
        import pytest

        with pytest.raises(FileNotFoundError):
            add(str(tmp_path / "missing.json"), base_dir=str(tmp_path))


class TestListSnapshots:
    def test_empty_history(self, tmp_path):
        entries = list_snapshots(base_dir=str(tmp_path))
        assert entries == []

    def test_lists_added_snapshots(self, tmp_path):
        for label, ts in [
            ("first", "2026-01-01T10:00:00Z"),
            ("second", "2026-02-01T10:00:00Z"),
        ]:
            snap = _make_snapshot(label=label, timestamp=ts)
            snap_path = str(tmp_path / f"{label}.json")
            save(snap, snap_path)
            add(snap_path, base_dir=str(tmp_path))

        entries = list_snapshots(base_dir=str(tmp_path))
        assert len(entries) == 2
        # Sorted chronologically
        assert entries[0][2] == "first"
        assert entries[1][2] == "second"

    def test_skips_non_json_files(self, tmp_path):
        # Create history dir with a non-JSON file
        hist_dir = _history_dir(str(tmp_path))
        with open(os.path.join(hist_dir, "README.txt"), "w") as f:
            f.write("not a snapshot")

        entries = list_snapshots(base_dir=str(tmp_path))
        assert entries == []

    def test_skips_invalid_json(self, tmp_path):
        hist_dir = _history_dir(str(tmp_path))
        with open(os.path.join(hist_dir, "bad.json"), "w") as f:
            f.write("{invalid json")

        entries = list_snapshots(base_dir=str(tmp_path))
        assert entries == []


class TestGetLastN:
    def test_get_last_2(self, tmp_path):
        for i, ts in enumerate(
            [
                "2026-01-01T10:00:00Z",
                "2026-02-01T10:00:00Z",
                "2026-03-01T10:00:00Z",
            ]
        ):
            snap = _make_snapshot(label=f"snap{i}", timestamp=ts)
            snap_path = str(tmp_path / f"snap{i}.json")
            save(snap, snap_path)
            add(snap_path, base_dir=str(tmp_path))

        snaps = get_last_n(2, base_dir=str(tmp_path))
        assert len(snaps) == 2
        # Should be the last two (most recent)
        assert snaps[0].metadata.label == "snap1"
        assert snaps[1].metadata.label == "snap2"

    def test_get_more_than_available(self, tmp_path):
        snap = _make_snapshot(label="only")
        snap_path = str(tmp_path / "snap.json")
        save(snap, snap_path)
        add(snap_path, base_dir=str(tmp_path))

        snaps = get_last_n(5, base_dir=str(tmp_path))
        assert len(snaps) == 1

    def test_empty_history(self, tmp_path):
        snaps = get_last_n(2, base_dir=str(tmp_path))
        assert snaps == []

    def test_get_zero(self, tmp_path):
        snap = _make_snapshot(label="test")
        snap_path = str(tmp_path / "snap.json")
        save(snap, snap_path)
        add(snap_path, base_dir=str(tmp_path))

        snaps = get_last_n(0, base_dir=str(tmp_path))
        assert snaps == []
