"""Tests for the native library collector."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from pycheckem.collectors.native_libs import (
    _find_extension_files,
    _get_linked_libs,
    _parse_ldd_output,
    _parse_otool_output,
    collect_native_libs,
)


class TestParseLddOutput:
    """Tests for _parse_ldd_output."""

    def test_basic_linked_libs(self):
        output = (
            "\tlinux-vdso.so.1 (0x00007fff)\n"
            "\tlibm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f)\n"
            "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f)\n"
        )
        linked, missing = _parse_ldd_output(output)
        assert "libm.so.6" in linked
        assert "libc.so.6" in linked
        assert missing == []

    def test_not_found(self):
        output = (
            "\tlibfoo.so.1 => not found\n"
            "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f)\n"
        )
        linked, missing = _parse_ldd_output(output)
        assert "libfoo.so.1" in missing
        assert "libc.so.6" in linked

    def test_empty_output(self):
        linked, missing = _parse_ldd_output("")
        assert linked == []
        assert missing == []

    def test_vdso_and_ld_linux_skipped(self):
        output = (
            "\tlinux-vdso.so.1 (0x00007fff)\n"
            "\t/lib64/ld-linux-x86-64.so.2 (0x00007f)\n"
            "\tlibm.so.6 => /lib/libm.so.6 (0x00007f)\n"
        )
        linked, missing = _parse_ldd_output(output)
        # vdso and ld-linux should be skipped
        assert "linux-vdso.so.1" not in linked
        assert "libm.so.6" in linked

    def test_multiple_not_found(self):
        output = "\tlibfoo.so.1 => not found\n\tlibbar.so.2 => not found\n"
        linked, missing = _parse_ldd_output(output)
        assert linked == []
        assert "libfoo.so.1" in missing
        assert "libbar.so.2" in missing


class TestParseOtoolOutput:
    """Tests for _parse_otool_output."""

    def test_basic_output(self):
        output = (
            "/path/to/lib.dylib:\n"
            "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
            "\t@rpath/libopenblas.dylib (compatibility version 0.0.0)\n"
        )
        linked, missing = _parse_otool_output(output)
        assert "libSystem.B.dylib" in linked
        assert "libopenblas.dylib" in linked
        assert missing == []

    def test_empty_output(self):
        linked, missing = _parse_otool_output("")
        assert linked == []
        assert missing == []

    def test_header_line_skipped(self):
        output = (
            "/some/extension.so:\n"
            "\t/usr/lib/libfoo.dylib (compatibility version 1.0.0)\n"
        )
        linked, missing = _parse_otool_output(output)
        assert len(linked) == 1
        assert "libfoo.dylib" in linked


class TestFindExtensionFiles:
    """Tests for _find_extension_files."""

    def test_finds_so_files(self, tmp_path):
        # Create a fake .so file
        so_file = tmp_path / "ext.cpython-311-x86_64-linux-gnu.so"
        so_file.write_text("")

        dist = MagicMock()
        mock_file = MagicMock()
        mock_file.__str__ = lambda self: "ext.cpython-311-x86_64-linux-gnu.so"
        mock_file.locate.return_value = so_file
        dist.files = [mock_file]

        paths = _find_extension_files(dist)
        assert len(paths) == 1
        assert str(so_file) in paths[0]

    def test_finds_pyd_files(self, tmp_path):
        pyd_file = tmp_path / "ext.pyd"
        pyd_file.write_text("")

        dist = MagicMock()
        mock_file = MagicMock()
        mock_file.__str__ = lambda self: "ext.pyd"
        mock_file.locate.return_value = pyd_file
        dist.files = [mock_file]

        paths = _find_extension_files(dist)
        assert len(paths) == 1

    def test_skips_non_native_files(self):
        dist = MagicMock()
        mock_file = MagicMock()
        mock_file.__str__ = lambda self: "module.py"
        dist.files = [mock_file]

        paths = _find_extension_files(dist)
        assert paths == []

    def test_handles_no_files(self):
        dist = MagicMock()
        dist.files = None

        paths = _find_extension_files(dist)
        assert paths == []

    def test_handles_exception(self):
        dist = MagicMock()
        dist.files = property(lambda self: (_ for _ in ()).throw(Exception))
        type(dist).files = property(lambda self: (_ for _ in ()).throw(Exception))

        # Should not raise
        paths = _find_extension_files(dist)
        assert paths == []


class TestGetLinkedLibs:
    """Tests for _get_linked_libs."""

    @patch("pycheckem.collectors.native_libs.platform")
    def test_unsupported_platform_returns_empty(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        linked, missing = _get_linked_libs("/fake/path.pyd")
        assert linked == []
        assert missing == []

    @patch("pycheckem.collectors.native_libs.platform")
    @patch("pycheckem.collectors.native_libs.subprocess")
    def test_linux_calls_ldd(self, mock_subprocess, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "\tlibm.so.6 => /lib/libm.so.6 (0x00007f)\n"
        mock_subprocess.run.return_value = mock_result
        mock_subprocess.TimeoutExpired = TimeoutError

        linked, missing = _get_linked_libs("/fake/path.so")
        assert "libm.so.6" in linked
        mock_subprocess.run.assert_called_once()

    @patch("pycheckem.collectors.native_libs.platform")
    @patch("pycheckem.collectors.native_libs.subprocess")
    def test_darwin_calls_otool(self, mock_subprocess, mock_platform):
        mock_platform.system.return_value = "Darwin"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "/path.so:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
        )
        mock_subprocess.run.return_value = mock_result
        mock_subprocess.TimeoutExpired = TimeoutError

        linked, missing = _get_linked_libs("/fake/path.so")
        assert "libSystem.B.dylib" in linked

    @patch("pycheckem.collectors.native_libs.platform")
    @patch("pycheckem.collectors.native_libs.subprocess")
    def test_ldd_not_found_falls_back(self, mock_subprocess, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_subprocess.run.side_effect = FileNotFoundError
        mock_subprocess.TimeoutExpired = TimeoutError

        linked, missing = _get_linked_libs("/fake/path.so")
        assert linked == []
        assert missing == []


class TestCollectNativeLibs:
    """Tests for the main collect_native_libs function."""

    @patch("pycheckem.collectors.native_libs.distributions")
    @patch("pycheckem.collectors.native_libs._get_linked_libs")
    def test_collects_from_packages(self, mock_get_libs, mock_dists, tmp_path):
        so_file = tmp_path / "ext.so"
        so_file.write_text("")

        mock_file = MagicMock()
        mock_file.__str__ = lambda self: "ext.so"
        mock_file.locate.return_value = so_file

        dist = MagicMock()
        dist.metadata = {"Name": "numpy"}
        dist.files = [mock_file]

        mock_dists.return_value = [dist]
        mock_get_libs.return_value = (["libm.so.6", "libc.so.6"], [])

        result = collect_native_libs()
        assert "numpy" in result
        assert len(result["numpy"]) == 1
        assert "libm.so.6" in result["numpy"][0].linked_libs

    @patch("pycheckem.collectors.native_libs.distributions")
    def test_skips_packages_without_native_extensions(self, mock_dists):
        dist = MagicMock()
        dist.metadata = {"Name": "requests"}
        mock_file = MagicMock()
        mock_file.__str__ = lambda self: "requests/__init__.py"
        dist.files = [mock_file]

        mock_dists.return_value = [dist]
        result = collect_native_libs()
        assert "requests" not in result

    @patch("pycheckem.collectors.native_libs.distributions")
    @patch("pycheckem.collectors.native_libs._get_linked_libs")
    def test_captures_missing_libs(self, mock_get_libs, mock_dists, tmp_path):
        so_file = tmp_path / "ext.so"
        so_file.write_text("")

        mock_file = MagicMock()
        mock_file.__str__ = lambda self: "ext.so"
        mock_file.locate.return_value = so_file

        dist = MagicMock()
        dist.metadata = {"Name": "cryptography"}
        dist.files = [mock_file]

        mock_dists.return_value = [dist]
        mock_get_libs.return_value = (["libssl.so.3"], ["libfoo.so.1"])

        result = collect_native_libs()
        assert "cryptography" in result
        assert "libfoo.so.1" in result["cryptography"][0].missing
