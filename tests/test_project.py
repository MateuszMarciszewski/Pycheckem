from __future__ import annotations

import sys


from pycheckem.collectors.project import (
    collect_project_info,
    _parse_setup_cfg,
)


class TestCollectProjectInfoPyprojectToml:
    def _skip_if_no_toml(self):
        if sys.version_info < (3, 11):
            try:
                import tomli  # noqa: F401
            except ImportError:
                import pytest

                pytest.skip("tomli not available on Python < 3.11")

    def test_reads_pyproject_toml(self, tmp_path):
        self._skip_if_no_toml()
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            "[project]\n"
            'name = "myapp"\n'
            'version = "1.2.0"\n'
            'requires-python = ">=3.10"\n'
            'dependencies = ["requests>=2.28", "flask"]\n'
        )
        result = collect_project_info(str(tmp_path))
        assert result is not None
        assert result.name == "myapp"
        assert result.version == "1.2.0"
        assert result.requires_python == ">=3.10"
        assert result.dependencies == ["requests>=2.28", "flask"]
        assert result.source_file == "pyproject.toml"

    def test_pyproject_no_project_section(self, tmp_path):
        self._skip_if_no_toml()
        toml = tmp_path / "pyproject.toml"
        toml.write_text("[tool.ruff]\nline-length = 88\n")
        result = collect_project_info(str(tmp_path))
        assert result is None

    def test_pyproject_partial_fields(self, tmp_path):
        self._skip_if_no_toml()
        toml = tmp_path / "pyproject.toml"
        toml.write_text('[project]\nname = "myapp"\n')
        result = collect_project_info(str(tmp_path))
        assert result is not None
        assert result.name == "myapp"
        assert result.version is None
        assert result.requires_python is None
        assert result.dependencies == []

    def test_pyproject_malformed_returns_none(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text("this is not valid [[[[")
        result = collect_project_info(str(tmp_path))
        assert result is None


class TestCollectProjectInfoSetupCfg:
    def test_reads_setup_cfg(self, tmp_path):
        cfg = tmp_path / "setup.cfg"
        cfg.write_text(
            "[metadata]\n"
            "name = myapp\n"
            "version = 2.0.0\n"
            "\n"
            "[options]\n"
            "python_requires = >=3.8\n"
            "install_requires =\n"
            "    requests>=2.28\n"
            "    flask\n"
        )
        result = collect_project_info(str(tmp_path))
        assert result is not None
        assert result.name == "myapp"
        assert result.version == "2.0.0"
        assert result.requires_python == ">=3.8"
        assert result.dependencies == ["requests>=2.28", "flask"]
        assert result.source_file == "setup.cfg"

    def test_setup_cfg_no_metadata(self, tmp_path):
        cfg = tmp_path / "setup.cfg"
        cfg.write_text("[options]\npython_requires = >=3.8\n")
        result = collect_project_info(str(tmp_path))
        # No name or version => returns None
        assert result is None

    def test_setup_cfg_partial_fields(self, tmp_path):
        cfg = tmp_path / "setup.cfg"
        cfg.write_text("[metadata]\nname = myapp\n")
        result = collect_project_info(str(tmp_path))
        assert result is not None
        assert result.name == "myapp"
        assert result.version is None


class TestCollectProjectInfoFallback:
    def test_pyproject_preferred_over_setup_cfg(self, tmp_path):
        """If both exist, pyproject.toml is used."""
        if sys.version_info < (3, 11):
            try:
                import tomli  # noqa: F401
            except ImportError:
                import pytest

                pytest.skip("tomli not available on Python < 3.11")

        toml = tmp_path / "pyproject.toml"
        toml.write_text('[project]\nname = "from-toml"\nversion = "1.0.0"\n')
        cfg = tmp_path / "setup.cfg"
        cfg.write_text("[metadata]\nname = from-cfg\nversion = 2.0.0\n")

        result = collect_project_info(str(tmp_path))
        assert result is not None
        assert result.source_file == "pyproject.toml"
        assert result.name == "from-toml"

    def test_falls_back_to_setup_cfg(self, tmp_path):
        """If pyproject.toml doesn't exist, use setup.cfg."""
        cfg = tmp_path / "setup.cfg"
        cfg.write_text("[metadata]\nname = from-cfg\nversion = 2.0.0\n")

        result = collect_project_info(str(tmp_path))
        assert result is not None
        assert result.source_file == "setup.cfg"

    def test_no_project_files_returns_none(self, tmp_path):
        result = collect_project_info(str(tmp_path))
        assert result is None

    def test_default_search_dir_is_cwd(self, tmp_path, monkeypatch):
        cfg = tmp_path / "setup.cfg"
        cfg.write_text("[metadata]\nname = cwd-test\nversion = 1.0\n")
        monkeypatch.chdir(tmp_path)
        result = collect_project_info()
        assert result is not None
        assert result.name == "cwd-test"


class TestParseSetupCfg:
    def test_empty_install_requires(self, tmp_path):
        cfg = tmp_path / "setup.cfg"
        cfg.write_text("[metadata]\nname = myapp\nversion = 1.0\n[options]\n")
        result = _parse_setup_cfg(str(cfg))
        assert result is not None
        assert result.dependencies == []

    def test_nonexistent_file_returns_none(self, tmp_path):
        result = _parse_setup_cfg(str(tmp_path / "missing.cfg"))
        # configparser.read() silently ignores missing files; no name/version => None
        assert result is None
