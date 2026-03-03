from unittest.mock import patch

from pycheckem.collectors.env_vars import (
    DEFAULT_EXCLUDE_PATTERNS,
    _is_sensitive,
    collect_env_vars,
)

MOCK_ENV = {
    "PATH": "/usr/bin",
    "HOME": "/home/user",
    "LOG_LEVEL": "DEBUG",
    "DATABASE_URL": "postgres://localhost/db",
    "MY_SECRET_KEY": "supersecret",
    "AWS_ACCESS_KEY_ID": "AKIA...",
    "API_TOKEN": "tok_123",
    "GITHUB_PASSWORD": "hunter2",
    "CACHE_KEY_PREFIX": "myapp",
    "KEYBOARD_LAYOUT": "us",
    "SSH_PRIVATE_KEY": "-----BEGIN",
    "DB_PASS": "secret",
    "MY_CREDENTIAL_STORE": "/path",
}


class TestIsSensitive:
    def test_secret_pattern(self):
        assert _is_sensitive("MY_SECRET_KEY", DEFAULT_EXCLUDE_PATTERNS)

    def test_password_pattern(self):
        assert _is_sensitive("GITHUB_PASSWORD", DEFAULT_EXCLUDE_PATTERNS)

    def test_token_pattern(self):
        assert _is_sensitive("API_TOKEN", DEFAULT_EXCLUDE_PATTERNS)

    def test_key_suffix_pattern(self):
        assert _is_sensitive("MY_SECRET_KEY", DEFAULT_EXCLUDE_PATTERNS)

    def test_key_id_suffix_pattern(self):
        assert _is_sensitive("AWS_ACCESS_KEY_ID", DEFAULT_EXCLUDE_PATTERNS)

    def test_credential_pattern(self):
        assert _is_sensitive("MY_CREDENTIAL_STORE", DEFAULT_EXCLUDE_PATTERNS)

    def test_pass_suffix_pattern(self):
        assert _is_sensitive("DB_PASS", DEFAULT_EXCLUDE_PATTERNS)

    def test_private_pattern(self):
        assert _is_sensitive("SSH_PRIVATE_KEY", DEFAULT_EXCLUDE_PATTERNS)

    def test_safe_path(self):
        assert not _is_sensitive("PATH", DEFAULT_EXCLUDE_PATTERNS)

    def test_safe_home(self):
        assert not _is_sensitive("HOME", DEFAULT_EXCLUDE_PATTERNS)

    def test_safe_cache_key_prefix(self):
        assert not _is_sensitive("CACHE_KEY_PREFIX", DEFAULT_EXCLUDE_PATTERNS)

    def test_safe_keyboard_layout(self):
        assert not _is_sensitive("KEYBOARD_LAYOUT", DEFAULT_EXCLUDE_PATTERNS)

    def test_case_insensitive(self):
        assert _is_sensitive("my_secret_key", DEFAULT_EXCLUDE_PATTERNS)


class TestCollectEnvVars:
    @patch.dict("os.environ", MOCK_ENV, clear=True)
    def test_excludes_sensitive_by_default(self):
        result = collect_env_vars()
        assert "MY_SECRET_KEY" not in result
        assert "API_TOKEN" not in result
        assert "GITHUB_PASSWORD" not in result
        assert "AWS_ACCESS_KEY_ID" not in result
        assert "DB_PASS" not in result

    @patch.dict("os.environ", MOCK_ENV, clear=True)
    def test_includes_safe_vars(self):
        result = collect_env_vars()
        assert result["PATH"] == "/usr/bin"
        assert result["HOME"] == "/home/user"
        assert result["LOG_LEVEL"] == "DEBUG"
        assert result["DATABASE_URL"] == "postgres://localhost/db"

    @patch.dict("os.environ", MOCK_ENV, clear=True)
    def test_cache_key_prefix_not_excluded(self):
        result = collect_env_vars()
        assert "CACHE_KEY_PREFIX" in result

    @patch.dict("os.environ", MOCK_ENV, clear=True)
    def test_keyboard_layout_not_excluded(self):
        result = collect_env_vars()
        assert "KEYBOARD_LAYOUT" in result

    @patch.dict("os.environ", MOCK_ENV, clear=True)
    def test_include_sensitive_bypasses_filter(self):
        result = collect_env_vars(include_sensitive=True)
        assert "MY_SECRET_KEY" in result
        assert "API_TOKEN" in result

    @patch.dict("os.environ", MOCK_ENV, clear=True)
    def test_custom_exclude_patterns(self):
        result = collect_env_vars(exclude_patterns=[r".*DATABASE.*"])
        assert "DATABASE_URL" not in result
        assert "PATH" in result

    @patch.dict("os.environ", MOCK_ENV, clear=True)
    def test_include_patterns_whitelist(self):
        result = collect_env_vars(include_patterns=[r"PATH", r"HOME"])
        assert "PATH" in result
        assert "HOME" in result
        assert "LOG_LEVEL" not in result
