from unittest.mock import patch

from pycheckem.collectors.python_info import collect_python_info
from pycheckem.types import PythonInfo


class TestCollectPythonInfo:
    def test_returns_python_info(self):
        result = collect_python_info()
        assert isinstance(result, PythonInfo)

    def test_version_format(self):
        result = collect_python_info()
        parts = result.version.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_implementation_is_string(self):
        result = collect_python_info()
        assert result.implementation in ("CPython", "PyPy", "Jython", "IronPython")

    def test_executable_is_nonempty(self):
        result = collect_python_info()
        assert len(result.executable) > 0

    def test_platform_is_nonempty(self):
        result = collect_python_info()
        assert len(result.platform) > 0

    @patch("pycheckem.collectors.python_info.platform")
    @patch("pycheckem.collectors.python_info.sys")
    def test_with_mocked_values(self, mock_sys, mock_platform):
        mock_platform.python_version.return_value = "3.12.0"
        mock_platform.python_implementation.return_value = "CPython"
        mock_sys.executable = "/usr/local/bin/python3"
        mock_sys.prefix = "/usr/local"
        mock_sys.platform = "linux"

        result = collect_python_info()
        assert result.version == "3.12.0"
        assert result.implementation == "CPython"
        assert result.executable == "/usr/local/bin/python3"
        assert result.prefix == "/usr/local"
        assert result.platform == "linux"
