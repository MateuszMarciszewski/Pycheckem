"""Tests for native library diff logic and rendering."""

from __future__ import annotations

from pycheckem.diff import diff_native_libs, compute_severity, count_differences
from pycheckem.types import (
    NativeLibDiff,
    NativeLibInfo,
    PackageDiff,
    PathDiff,
    VarDiff,
    ConfigDiff,
)
from pycheckem.render.ascii import _section_native_libs


def _empty_pkg_diff():
    return PackageDiff(added={}, removed={}, changed={}, unchanged_count=0)


def _empty_var_diff():
    return VarDiff(added={}, removed={}, changed={}, unchanged_count=0)


def _empty_path_diff():
    return PathDiff(
        sys_path_added=[], sys_path_removed=[], path_env_added=[], path_env_removed=[]
    )


def _empty_config_diff():
    return ConfigDiff(added=[], removed=[], changed={}, unchanged_count=0)


class TestDiffNativeLibs:
    """Tests for diff_native_libs."""

    def test_identical_returns_none(self):
        libs = {
            "numpy": [
                NativeLibInfo(
                    extension="core.so", linked_libs=["libm.so.6"], missing=[]
                )
            ]
        }
        result = diff_native_libs(libs, libs)
        assert result is None

    def test_package_added(self):
        a = {}
        b = {
            "numpy": [
                NativeLibInfo(
                    extension="core.so", linked_libs=["libm.so.6"], missing=[]
                )
            ]
        }
        result = diff_native_libs(a, b)
        assert result is not None
        assert "numpy" in result.packages_added

    def test_package_removed(self):
        a = {
            "numpy": [
                NativeLibInfo(
                    extension="core.so", linked_libs=["libm.so.6"], missing=[]
                )
            ]
        }
        b = {}
        result = diff_native_libs(a, b)
        assert result is not None
        assert "numpy" in result.packages_removed

    def test_lib_added(self):
        a = {
            "numpy": [
                NativeLibInfo(
                    extension="core.so", linked_libs=["libm.so.6"], missing=[]
                )
            ]
        }
        b = {
            "numpy": [
                NativeLibInfo(
                    extension="core.so",
                    linked_libs=["libm.so.6", "libopenblas.so.0"],
                    missing=[],
                )
            ]
        }
        result = diff_native_libs(a, b)
        assert result is not None
        assert "numpy" in result.libs_added
        assert "libopenblas.so.0" in result.libs_added["numpy"]

    def test_lib_removed(self):
        a = {
            "numpy": [
                NativeLibInfo(
                    extension="core.so",
                    linked_libs=["libm.so.6", "libopenblas.so.0"],
                    missing=[],
                )
            ]
        }
        b = {
            "numpy": [
                NativeLibInfo(
                    extension="core.so", linked_libs=["libm.so.6"], missing=[]
                )
            ]
        }
        result = diff_native_libs(a, b)
        assert result is not None
        assert "numpy" in result.libs_removed
        assert "libopenblas.so.0" in result.libs_removed["numpy"]

    def test_missing_in_b(self):
        a = {
            "numpy": [
                NativeLibInfo(
                    extension="core.so", linked_libs=["libm.so.6"], missing=[]
                )
            ]
        }
        b = {
            "numpy": [
                NativeLibInfo(
                    extension="core.so",
                    linked_libs=["libm.so.6"],
                    missing=["libopenblas.so.0"],
                )
            ]
        }
        result = diff_native_libs(a, b)
        assert result is not None
        assert "numpy" in result.missing_in_b

    def test_missing_in_added_package(self):
        a = {}
        b = {
            "numpy": [
                NativeLibInfo(
                    extension="core.so",
                    linked_libs=[],
                    missing=["libopenblas.so.0"],
                )
            ]
        }
        result = diff_native_libs(a, b)
        assert result is not None
        assert "numpy" in result.missing_in_b

    def test_empty_both(self):
        result = diff_native_libs({}, {})
        assert result is None


class TestNativeLibSeverity:
    """Tests for native lib severity scoring."""

    def test_missing_in_b_is_critical(self):
        native_diff = NativeLibDiff(
            packages_added=[],
            packages_removed=[],
            libs_added={},
            libs_removed={},
            missing_in_a={},
            missing_in_b={"numpy": ["libopenblas.so.0"]},
        )
        severity, breaking = compute_severity(
            None,
            _empty_pkg_diff(),
            _empty_var_diff(),
            None,
            _empty_path_diff(),
            _empty_config_diff(),
            None,
            native_diff,
        )
        assert severity == "critical"
        assert any("libopenblas.so.0" in b for b in breaking)

    def test_libs_removed_is_major(self):
        native_diff = NativeLibDiff(
            packages_added=[],
            packages_removed=[],
            libs_added={},
            libs_removed={"numpy": ["libopenblas.so.0"]},
            missing_in_a={},
            missing_in_b={},
        )
        severity, breaking = compute_severity(
            None,
            _empty_pkg_diff(),
            _empty_var_diff(),
            None,
            _empty_path_diff(),
            _empty_config_diff(),
            None,
            native_diff,
        )
        assert severity == "major"

    def test_libs_added_is_minor(self):
        native_diff = NativeLibDiff(
            packages_added=[],
            packages_removed=[],
            libs_added={"numpy": ["libopenblas.so.0"]},
            libs_removed={},
            missing_in_a={},
            missing_in_b={},
        )
        severity, breaking = compute_severity(
            None,
            _empty_pkg_diff(),
            _empty_var_diff(),
            None,
            _empty_path_diff(),
            _empty_config_diff(),
            None,
            native_diff,
        )
        assert severity == "minor"

    def test_no_native_diff_is_identical(self):
        severity, breaking = compute_severity(
            None,
            _empty_pkg_diff(),
            _empty_var_diff(),
            None,
            _empty_path_diff(),
            _empty_config_diff(),
            None,
            None,
        )
        assert severity == "identical"


class TestNativeLibCount:
    """Tests for native lib difference counting."""

    def test_counts_all_diffs(self):
        native_diff = NativeLibDiff(
            packages_added=["scipy"],
            packages_removed=["pillow"],
            libs_added={"numpy": ["libopenblas.so.0"]},
            libs_removed={"numpy": ["libatlas.so.3"]},
            missing_in_a={},
            missing_in_b={"numpy": ["libfoo.so.1"]},
        )
        count = count_differences(
            None,
            _empty_pkg_diff(),
            _empty_var_diff(),
            None,
            _empty_path_diff(),
            _empty_config_diff(),
            None,
            native_diff,
        )
        # 1 pkg added + 1 pkg removed + 1 lib added + 1 lib removed + 1 missing
        assert count == 5


class TestNativeLibAsciiRender:
    """Tests for native lib ASCII rendering."""

    def test_none_returns_empty(self):
        assert _section_native_libs(None) == []

    def test_renders_missing_libs(self):
        native_diff = NativeLibDiff(
            packages_added=[],
            packages_removed=[],
            libs_added={},
            libs_removed={},
            missing_in_a={},
            missing_in_b={"numpy": ["libopenblas.so.0"]},
        )
        lines = _section_native_libs(native_diff)
        assert len(lines) > 0
        assert any("NOT FOUND" in line for line in lines)
        assert any("numpy" in line for line in lines)

    def test_renders_added_packages(self):
        native_diff = NativeLibDiff(
            packages_added=["scipy"],
            packages_removed=[],
            libs_added={},
            libs_removed={},
            missing_in_a={},
            missing_in_b={},
        )
        lines = _section_native_libs(native_diff)
        assert any("scipy" in line and "+" in line for line in lines)

    def test_renders_removed_libs(self):
        native_diff = NativeLibDiff(
            packages_added=[],
            packages_removed=[],
            libs_added={},
            libs_removed={"numpy": ["libopenblas.so.0"]},
            missing_in_a={},
            missing_in_b={},
        )
        lines = _section_native_libs(native_diff)
        assert any("libopenblas.so.0" in line and "-" in line for line in lines)

    def test_empty_diff_returns_empty(self):
        native_diff = NativeLibDiff(
            packages_added=[],
            packages_removed=[],
            libs_added={},
            libs_removed={},
            missing_in_a={},
            missing_in_b={},
        )
        assert _section_native_libs(native_diff) == []
