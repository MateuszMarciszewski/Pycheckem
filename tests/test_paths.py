import os
from unittest.mock import patch

from pycheckem.collectors.paths import collect_paths
from pycheckem.types import PathInfo

# Build a PATH string using the platform's actual separator
_MOCK_PATH = os.pathsep.join(["/usr/local/bin", "/usr/bin", "/bin"])


class TestCollectPaths:
    def test_returns_path_info(self):
        result = collect_paths()
        assert isinstance(result, PathInfo)

    def test_sys_path_is_list(self):
        result = collect_paths()
        assert isinstance(result.sys_path, list)
        assert len(result.sys_path) > 0

    def test_path_env_is_list(self):
        result = collect_paths()
        assert isinstance(result.path_env, list)

    @patch("pycheckem.collectors.paths.sys")
    @patch.dict("os.environ", {"PATH": _MOCK_PATH})
    def test_mocked_values(self, mock_sys):
        mock_sys.path = ["/app/src", "/usr/lib/python3"]

        result = collect_paths()
        assert result.sys_path == ["/app/src", "/usr/lib/python3"]
        assert "/usr/local/bin" in result.path_env
        assert "/usr/bin" in result.path_env

    @patch.dict("os.environ", {}, clear=True)
    def test_missing_path_env(self):
        result = collect_paths()
        assert result.path_env == [""]
