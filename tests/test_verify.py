from __future__ import annotations

from unittest.mock import patch, MagicMock

from pycheckem.verify import (
    verify,
    render_verify,
    _version_satisfies,
    VerifyResult,
    VersionMismatch,
)
from pycheckem.types import PackageInfo


class TestVersionSatisfies:
    def test_exact_match(self):
        assert _version_satisfies("2.31.0", "==2.31.0")

    def test_exact_no_match(self):
        assert not _version_satisfies("2.30.0", "==2.31.0")

    def test_gte(self):
        assert _version_satisfies("2.31.0", ">=2.28.0")

    def test_gte_fail(self):
        assert not _version_satisfies("2.27.0", ">=2.28.0")

    def test_lt(self):
        assert _version_satisfies("2.9.0", "<3.0.0")

    def test_lt_fail(self):
        assert not _version_satisfies("3.0.0", "<3.0.0")

    def test_lte(self):
        assert _version_satisfies("3.0.0", "<=3.0.0")

    def test_gt(self):
        assert _version_satisfies("3.1.0", ">3.0.0")

    def test_ne(self):
        assert _version_satisfies("2.0.0", "!=1.0.0")

    def test_ne_fail(self):
        assert not _version_satisfies("1.0.0", "!=1.0.0")

    def test_multiple_constraints(self):
        assert _version_satisfies("2.5.0", ">=2.0,<3.0")

    def test_multiple_constraints_fail(self):
        assert not _version_satisfies("3.1.0", ">=2.0,<3.0")

    def test_compatible_release(self):
        assert _version_satisfies("2.0.3", "~=2.0.1")

    def test_compatible_release_fail(self):
        assert not _version_satisfies("1.9.0", "~=2.0.1")

    def test_wildcard_match(self):
        assert _version_satisfies("1.0.5", "==1.0.*")

    def test_wildcard_no_match(self):
        assert not _version_satisfies("2.0.0", "==1.0.*")


def _mock_packages(pkg_dict):
    """Create a mock collect_packages that returns the given dict."""
    packages = {}
    for name, version in pkg_dict.items():
        packages[name] = PackageInfo(version=version, location="/sp", requires=[])
    return packages


class TestVerify:
    @patch("pycheckem.verify.collect_packages")
    def test_all_satisfied(self, mock_collect):
        mock_collect.return_value = _mock_packages({
            "requests": "2.31.0",
            "flask": "2.3.0",
        })
        declared = {"requests": "==2.31.0", "flask": ">=2.0"}
        result = verify(declared)
        assert result.is_satisfied
        assert len(result.satisfied) == 2
        assert not result.missing
        assert not result.version_mismatches

    @patch("pycheckem.verify.collect_packages")
    def test_missing_package(self, mock_collect):
        mock_collect.return_value = _mock_packages({"requests": "2.31.0"})
        declared = {"requests": "==2.31.0", "pandas": ">=1.0"}
        result = verify(declared)
        assert not result.is_satisfied
        assert "pandas" in result.missing

    @patch("pycheckem.verify.collect_packages")
    def test_version_mismatch(self, mock_collect):
        mock_collect.return_value = _mock_packages({"requests": "2.28.0"})
        declared = {"requests": "==2.31.0"}
        result = verify(declared)
        assert not result.is_satisfied
        assert "requests" in result.version_mismatches
        assert result.version_mismatches["requests"].installed == "2.28.0"
        assert result.version_mismatches["requests"].declared == "==2.31.0"

    @patch("pycheckem.verify.collect_packages")
    def test_bare_name_always_satisfied(self, mock_collect):
        mock_collect.return_value = _mock_packages({"pytest": "7.4.0"})
        declared = {"pytest": None}
        result = verify(declared)
        assert result.is_satisfied

    @patch("pycheckem.verify.collect_packages")
    def test_include_extras(self, mock_collect):
        mock_collect.return_value = _mock_packages({
            "requests": "2.31.0",
            "debugpy": "1.8.0",
        })
        declared = {"requests": "==2.31.0"}
        result = verify(declared, include_extras=True)
        assert "debugpy" in result.extra

    @patch("pycheckem.verify.collect_packages")
    def test_no_extras_by_default(self, mock_collect):
        mock_collect.return_value = _mock_packages({
            "requests": "2.31.0",
            "debugpy": "1.8.0",
        })
        declared = {"requests": "==2.31.0"}
        result = verify(declared, include_extras=False)
        assert result.extra == []

    @patch("pycheckem.verify.collect_packages")
    def test_name_normalization(self, mock_collect):
        # Installed as "My_Package" but declared as "my-package"
        mock_collect.return_value = _mock_packages({"My_Package": "1.0.0"})
        declared = {"my-package": "==1.0.0"}
        result = verify(declared)
        assert result.is_satisfied


class TestRenderVerify:
    def test_all_satisfied(self):
        result = VerifyResult(
            missing=[], extra=[], version_mismatches={},
            satisfied=["flask", "requests"], total_declared=2, total_installed=10,
        )
        output = render_verify(result)
        assert "All 2 declared dependencies are satisfied" in output

    def test_missing_shown(self):
        result = VerifyResult(
            missing=["pandas"], extra=[], version_mismatches={},
            satisfied=["flask"], total_declared=2, total_installed=10,
        )
        output = render_verify(result)
        assert "Missing (1)" in output
        assert "pandas" in output
        assert "FAIL" in output

    def test_mismatch_shown(self):
        result = VerifyResult(
            missing=[], extra=[],
            version_mismatches={"requests": VersionMismatch("2.28.0", "==2.31.0")},
            satisfied=["flask"], total_declared=2, total_installed=10,
        )
        output = render_verify(result)
        assert "Version Mismatches (1)" in output
        assert "requests" in output
        assert "2.28.0" in output
        assert "FAIL" in output

    def test_extras_shown(self):
        result = VerifyResult(
            missing=[], extra=["debugpy"], version_mismatches={},
            satisfied=["flask"], total_declared=1, total_installed=10,
        )
        output = render_verify(result)
        assert "Extra (1)" in output
        assert "debugpy" in output
