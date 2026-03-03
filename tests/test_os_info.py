from unittest.mock import mock_open, patch

from pycheckem.collectors.os_info import _get_distro, collect_os_info
from pycheckem.types import OSInfo


class TestCollectOsInfo:
    def test_returns_os_info(self):
        result = collect_os_info()
        assert isinstance(result, OSInfo)

    def test_system_is_known(self):
        result = collect_os_info()
        assert result.system in ("Linux", "Darwin", "Windows", "Java")

    def test_machine_is_nonempty(self):
        result = collect_os_info()
        assert len(result.machine) > 0

    @patch("pycheckem.collectors.os_info.platform")
    def test_mocked_linux(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "6.1.0-generic"
        mock_platform.machine.return_value = "x86_64"

        with patch(
            "builtins.open",
            mock_open(read_data='PRETTY_NAME="Ubuntu 22.04.3 LTS"\nID=ubuntu\n'),
        ):
            result = collect_os_info()

        assert result.system == "Linux"
        assert result.release == "6.1.0-generic"
        assert result.machine == "x86_64"
        assert result.distro == "Ubuntu 22.04.3 LTS"

    @patch("pycheckem.collectors.os_info.platform")
    def test_mocked_darwin(self, mock_platform):
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "23.1.0"
        mock_platform.machine.return_value = "arm64"
        mock_platform.mac_ver.return_value = ("14.1.1", ("", "", ""), "")

        result = collect_os_info()
        assert result.distro == "macOS 14.1.1"

    @patch("pycheckem.collectors.os_info.platform")
    def test_mocked_windows(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        mock_platform.release.return_value = "11"
        mock_platform.machine.return_value = "AMD64"
        mock_platform.version.return_value = "10.0.22631"

        result = collect_os_info()
        assert result.distro == "Windows 10.0.22631"


class TestGetDistro:
    @patch("pycheckem.collectors.os_info.platform")
    def test_linux_no_os_release(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = _get_distro()
        assert result is None

    @patch("pycheckem.collectors.os_info.platform")
    def test_unknown_system(self, mock_platform):
        mock_platform.system.return_value = "FreeBSD"
        result = _get_distro()
        assert result is None
