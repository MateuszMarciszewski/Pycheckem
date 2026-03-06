from __future__ import annotations

import json
import os
import subprocess
import sys


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


class TestVerifyCli:
    def test_verify_requirements_txt(self, tmp_path):
        """Verify against a requirements.txt with a known-installed package."""
        f = tmp_path / "req.txt"
        # pip is always installed in a dev environment
        f.write_text("pip\n")
        result = _run_cli("verify", str(f))
        assert result.returncode == 0
        assert "satisfied" in result.stdout.lower()

    def test_verify_missing_package(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("this-package-definitely-does-not-exist-xyz==1.0.0\n")
        result = _run_cli("verify", str(f), "--exit-code")
        assert result.returncode == 1
        assert "missing" in result.stdout.lower()

    def test_verify_json_format(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("pip\n")
        result = _run_cli("verify", str(f), "--format", "json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "is_satisfied" in data
        assert data["is_satisfied"] is True

    def test_verify_include_extras(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("pip\n")
        result = _run_cli("verify", str(f), "--include-extras")
        assert result.returncode == 0

    def test_verify_file_not_found(self, tmp_path):
        result = _run_cli("verify", str(tmp_path / "nope.txt"))
        assert result.returncode == 1
        assert "file not found" in result.stderr.lower()

    def test_verify_pyproject_toml(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\nname = "test"\ndependencies = ["pip"]\n')
        result = _run_cli("verify", str(f))
        assert result.returncode == 0

    def test_verify_exit_code_when_satisfied(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("pip\n")
        result = _run_cli("verify", str(f), "--exit-code")
        assert result.returncode == 0
