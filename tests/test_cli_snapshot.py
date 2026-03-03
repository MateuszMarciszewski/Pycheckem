from __future__ import annotations

import json
import os
import subprocess
import sys

from pycheckem.snapshot import load
from pycheckem.types import Snapshot


class TestCLISnapshot:
    def test_snapshot_exits_zero(self, tmp_path):
        outfile = str(tmp_path / "snap.json")
        result = subprocess.run(
            [sys.executable, "-m", "pycheckem", "snapshot", "-o", outfile],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

    def test_snapshot_creates_valid_json(self, tmp_path):
        outfile = str(tmp_path / "snap.json")
        subprocess.run(
            [sys.executable, "-m", "pycheckem", "snapshot", "-o", outfile],
            capture_output=True,
            text=True,
        )
        with open(outfile, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "metadata" in data
        assert "python" in data
        assert "packages" in data

    def test_snapshot_deserializes_to_snapshot(self, tmp_path):
        outfile = str(tmp_path / "snap.json")
        subprocess.run(
            [sys.executable, "-m", "pycheckem", "snapshot", "-o", outfile],
            capture_output=True,
            text=True,
        )
        snap = load(outfile)
        assert isinstance(snap, Snapshot)

    def test_label_flag(self, tmp_path):
        outfile = str(tmp_path / "snap.json")
        result = subprocess.run(
            [
                sys.executable, "-m", "pycheckem", "snapshot",
                "-o", outfile,
                "--label", "staging",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        snap = load(outfile)
        assert snap.metadata.label == "staging"
        assert "staging" in result.stdout

    def test_config_files_flag(self, tmp_path):
        cfg = tmp_path / ".env"
        cfg.write_text("SECRET=hunter2\n")
        outfile = str(tmp_path / "snap.json")
        subprocess.run(
            [
                sys.executable, "-m", "pycheckem", "snapshot",
                "-o", outfile,
                "--config-files", str(cfg),
            ],
            capture_output=True,
            text=True,
        )
        snap = load(outfile)
        assert str(cfg) in snap.config_files
        assert snap.config_files[str(cfg)].sha256 is not None

    def test_output_message(self, tmp_path):
        outfile = str(tmp_path / "snap.json")
        result = subprocess.run(
            [sys.executable, "-m", "pycheckem", "snapshot", "-o", outfile],
            capture_output=True,
            text=True,
        )
        assert "Snapshot saved to" in result.stdout
