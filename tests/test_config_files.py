import hashlib
import os
import tempfile

from pycheckem.collectors.config_files import collect_config_file
from pycheckem.types import ConfigFileInfo


class TestCollectConfigFile:
    def test_nonexistent_file_returns_none(self):
        result = collect_config_file("/nonexistent/path/.env")
        assert result is None

    def test_returns_config_file_info(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        result = collect_config_file(str(f))
        assert isinstance(result, ConfigFileInfo)

    def test_correct_sha256(self, tmp_path):
        content = b"test content for hashing"
        f = tmp_path / "data.txt"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        result = collect_config_file(str(f))
        assert result.sha256 == expected

    def test_unknown_format_keys_none(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("key: value\n")
        result = collect_config_file(str(f))
        assert result.keys is None

    def test_env_file_key_extraction(self, tmp_path):
        f = tmp_path / ".env"
        f.write_text("DATABASE_URL=postgres://localhost\nLOG_LEVEL=DEBUG\n# comment\nAPI_HOST=0.0.0.0\n")
        result = collect_config_file(str(f))
        assert result.keys is not None
        assert "API_HOST" in result.keys
        assert "DATABASE_URL" in result.keys
        assert "LOG_LEVEL" in result.keys

    def test_env_file_ignores_comments(self, tmp_path):
        f = tmp_path / ".env"
        f.write_text("# COMMENT_VAR=nope\nREAL_VAR=yes\n")
        result = collect_config_file(str(f))
        assert "REAL_VAR" in result.keys
        assert "COMMENT_VAR" not in result.keys

    def test_env_file_keys_sorted(self, tmp_path):
        f = tmp_path / ".env"
        f.write_text("ZEBRA=1\nAPPLE=2\nMIDDLE=3\n")
        result = collect_config_file(str(f))
        assert result.keys == ["APPLE", "MIDDLE", "ZEBRA"]

    def test_ini_file_section_extraction(self, tmp_path):
        f = tmp_path / "config.ini"
        f.write_text("[database]\nhost=localhost\n\n[logging]\nlevel=debug\n")
        result = collect_config_file(str(f))
        assert result.keys == ["database", "logging"]

    def test_cfg_file_section_extraction(self, tmp_path):
        f = tmp_path / "setup.cfg"
        f.write_text("[metadata]\nname=mypackage\n\n[options]\npackages=find:\n")
        result = collect_config_file(str(f))
        assert result.keys == ["metadata", "options"]

    def test_empty_file(self, tmp_path):
        f = tmp_path / ".env"
        f.write_text("")
        result = collect_config_file(str(f))
        assert result.sha256 == hashlib.sha256(b"").hexdigest()
        assert result.keys == []

    def test_env_suffix_detection(self, tmp_path):
        f = tmp_path / "production.env"
        f.write_text("HOST=prod\n")
        result = collect_config_file(str(f))
        assert result.keys == ["HOST"]
