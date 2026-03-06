from __future__ import annotations

import dataclasses
import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from pycheckem.remote import snapshot_remote
from pycheckem.snapshot import load_from_string, to_json, _from_dict
from pycheckem.types import (
    OSInfo,
    PackageInfo,
    PathInfo,
    PythonInfo,
    Snapshot,
    SnapshotMetadata,
)


def _make_snapshot(label=None):
    return Snapshot(
        metadata=SnapshotMetadata(
            timestamp="2026-03-02T12:00:00Z",
            hostname="remote-host",
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


class TestFromDict:
    def test_roundtrip(self):
        snap = _make_snapshot(label="test")
        data = dataclasses.asdict(snap)
        loaded = _from_dict(data)
        assert loaded.metadata.label == "test"
        assert loaded.python.version == "3.11.4"

    def test_missing_keys_raises(self):
        with pytest.raises(ValueError, match="missing required keys"):
            _from_dict({"metadata": {}})


class TestLoadFromString:
    def test_valid_json(self):
        snap = _make_snapshot(label="from-string")
        json_str = to_json(snap)
        loaded = load_from_string(json_str)
        assert loaded.metadata.label == "from-string"

    def test_invalid_json(self):
        with pytest.raises(json.JSONDecodeError):
            load_from_string("not valid json {{{")

    def test_missing_keys(self):
        with pytest.raises(ValueError, match="missing required keys"):
            load_from_string('{"metadata": {}}')


class TestToJson:
    def test_produces_valid_json(self):
        snap = _make_snapshot(label="json-test")
        result = to_json(snap)
        data = json.loads(result)
        assert data["metadata"]["label"] == "json-test"


class TestSnapshotRemote:
    def test_success(self):
        snap = _make_snapshot(label="remote-test")
        json_output = to_json(snap)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json_output
        mock_result.stderr = ""

        with patch(
            "pycheckem.remote.subprocess.run", return_value=mock_result
        ) as mock_run:
            result = snapshot_remote("user@host1", label="test")

        assert result.metadata.hostname == "remote-host"
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "ssh" in cmd
        assert "user@host1" in cmd

    def test_with_label(self):
        snap = _make_snapshot(label="labeled")
        json_output = to_json(snap)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json_output
        mock_result.stderr = ""

        with patch(
            "pycheckem.remote.subprocess.run", return_value=mock_result
        ) as mock_run:
            snapshot_remote("host", label="prod")

        cmd = mock_run.call_args[0][0]
        assert "--label" in cmd
        assert "prod" in cmd

    def test_nonzero_exit(self):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Connection refused"

        with patch("pycheckem.remote.subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="Connection refused"):
                snapshot_remote("badhost")

    def test_timeout(self):
        with patch(
            "pycheckem.remote.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=30),
        ):
            with pytest.raises(RuntimeError, match="timed out"):
                snapshot_remote("slowhost", timeout=30)

    def test_ssh_not_found(self):
        with patch(
            "pycheckem.remote.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            with pytest.raises(RuntimeError, match="ssh command not found"):
                snapshot_remote("host")

    def test_empty_output(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("pycheckem.remote.subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="empty output"):
                snapshot_remote("host")

    def test_custom_timeout(self):
        snap = _make_snapshot()
        json_output = to_json(snap)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json_output
        mock_result.stderr = ""

        with patch(
            "pycheckem.remote.subprocess.run", return_value=mock_result
        ) as mock_run:
            snapshot_remote("host", timeout=60)

        assert mock_run.call_args[1]["timeout"] == 60
