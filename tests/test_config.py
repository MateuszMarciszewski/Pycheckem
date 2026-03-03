from __future__ import annotations

import os
import sys

from pycheckem.config import PyCheckemConfig, SuppressionConfig, load_config


class TestLoadConfigMissing:
    def test_no_pyproject_returns_defaults(self, tmp_path):
        config = load_config(str(tmp_path))
        assert config.suppression.ignore_packages == []
        assert config.suppression.ignore_env_vars == []
        assert config.suppression.ignore_patterns == []

    def test_returns_pycheckem_config_type(self, tmp_path):
        config = load_config(str(tmp_path))
        assert isinstance(config, PyCheckemConfig)
        assert isinstance(config.suppression, SuppressionConfig)


class TestLoadConfigNoSection:
    def test_pyproject_without_tool_section(self, tmp_path):
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text(
            '[project]\nname = "myproject"\nversion = "1.0"\n'
        )
        config = load_config(str(tmp_path))
        assert config.suppression.ignore_packages == []

    def test_pyproject_without_pycheckem_section(self, tmp_path):
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text(
            '[tool.other]\nfoo = "bar"\n'
        )
        config = load_config(str(tmp_path))
        assert config.suppression.ignore_packages == []


class TestLoadConfigWithSuppression:
    def _skip_if_no_toml(self):
        if sys.version_info < (3, 11):
            try:
                import tomli  # noqa: F401
            except ImportError:
                import pytest
                pytest.skip("tomli not available on Python < 3.11")

    def test_ignore_packages(self, tmp_path):
        self._skip_if_no_toml()
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text(
            '[tool.pycheckem]\n'
            'ignore_packages = ["pip", "setuptools", "wheel"]\n'
        )
        config = load_config(str(tmp_path))
        assert config.suppression.ignore_packages == ["pip", "setuptools", "wheel"]

    def test_ignore_env_vars(self, tmp_path):
        self._skip_if_no_toml()
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text(
            '[tool.pycheckem]\n'
            'ignore_env_vars = ["HOSTNAME", "PWD"]\n'
        )
        config = load_config(str(tmp_path))
        assert config.suppression.ignore_env_vars == ["HOSTNAME", "PWD"]

    def test_ignore_patterns(self, tmp_path):
        self._skip_if_no_toml()
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text(
            '[tool.pycheckem]\n'
            'ignore_patterns = [".*_CACHE.*", "TEMP_.*"]\n'
        )
        config = load_config(str(tmp_path))
        assert config.suppression.ignore_patterns == [".*_CACHE.*", "TEMP_.*"]

    def test_all_suppression_keys(self, tmp_path):
        self._skip_if_no_toml()
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text(
            '[tool.pycheckem]\n'
            'ignore_packages = ["pip"]\n'
            'ignore_env_vars = ["HOSTNAME"]\n'
            'ignore_patterns = [".*_CACHE.*"]\n'
        )
        config = load_config(str(tmp_path))
        assert config.suppression.ignore_packages == ["pip"]
        assert config.suppression.ignore_env_vars == ["HOSTNAME"]
        assert config.suppression.ignore_patterns == [".*_CACHE.*"]

    def test_partial_suppression_keys(self, tmp_path):
        self._skip_if_no_toml()
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text(
            '[tool.pycheckem]\n'
            'ignore_packages = ["pip"]\n'
        )
        config = load_config(str(tmp_path))
        assert config.suppression.ignore_packages == ["pip"]
        assert config.suppression.ignore_env_vars == []
        assert config.suppression.ignore_patterns == []

    def test_default_search_dir_is_cwd(self, tmp_path, monkeypatch):
        self._skip_if_no_toml()
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text(
            '[tool.pycheckem]\n'
            'ignore_packages = ["pip"]\n'
        )
        monkeypatch.chdir(tmp_path)
        config = load_config()
        assert config.suppression.ignore_packages == ["pip"]


class TestLoadConfigInvalidToml:
    def test_malformed_toml_returns_defaults(self, tmp_path):
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text("this is not valid toml [[[[")
        config = load_config(str(tmp_path))
        assert config.suppression.ignore_packages == []
