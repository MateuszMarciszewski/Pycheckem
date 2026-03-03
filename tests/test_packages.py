from unittest.mock import MagicMock, patch

from pycheckem.collectors.packages import collect_packages
from pycheckem.types import PackageInfo


def _make_mock_dist(name, version, requires=None, has_files=True):
    dist = MagicMock()

    metadata = MagicMock()
    metadata.__getitem__ = lambda self, key: {"Name": name, "Version": version}[key]
    metadata.get_all = lambda key: requires if key == "Requires-Dist" else None
    dist.metadata = metadata

    if has_files:
        mock_file = MagicMock()
        mock_file.locate.return_value = MagicMock()
        mock_file.locate.return_value.parent = "/site-packages/fakepkg"
        dist.files = [mock_file]
    else:
        dist.files = None

    return dist


class TestCollectPackages:
    @patch("pycheckem.collectors.packages.distributions")
    def test_basic_package(self, mock_dists):
        mock_dists.return_value = [
            _make_mock_dist("Requests", "2.31.0", ["urllib3", "certifi"]),
        ]
        result = collect_packages()
        assert "requests" in result
        assert isinstance(result["requests"], PackageInfo)
        assert result["requests"].version == "2.31.0"

    @patch("pycheckem.collectors.packages.distributions")
    def test_name_lowercased(self, mock_dists):
        mock_dists.return_value = [
            _make_mock_dist("Flask-SQLAlchemy", "3.1.0"),
        ]
        result = collect_packages()
        assert "flask-sqlalchemy" in result
        assert "Flask-SQLAlchemy" not in result

    @patch("pycheckem.collectors.packages.distributions")
    def test_requires_strips_markers(self, mock_dists):
        mock_dists.return_value = [
            _make_mock_dist(
                "mylib",
                "1.0.0",
                ['extra-pkg ; python_version >= "3.8"', "simple-dep"],
            ),
        ]
        result = collect_packages()
        assert result["mylib"].requires == ["extra-pkg", "simple-dep"]

    @patch("pycheckem.collectors.packages.distributions")
    def test_no_requires(self, mock_dists):
        mock_dists.return_value = [
            _make_mock_dist("simple", "0.1.0", None),
        ]
        result = collect_packages()
        assert result["simple"].requires == []

    @patch("pycheckem.collectors.packages.distributions")
    def test_no_files_gives_none_location(self, mock_dists):
        mock_dists.return_value = [
            _make_mock_dist("nofiles", "1.0.0", has_files=False),
        ]
        result = collect_packages()
        assert result["nofiles"].location is None

    @patch("pycheckem.collectors.packages.distributions")
    def test_locate_exception_gives_none_location(self, mock_dists):
        dist = _make_mock_dist("broken", "1.0.0")
        dist.files[0].locate.side_effect = Exception("broken")
        mock_dists.return_value = [dist]
        result = collect_packages()
        assert result["broken"].location is None

    def test_real_packages_includes_pip(self):
        result = collect_packages()
        assert "pip" in result or "setuptools" in result
