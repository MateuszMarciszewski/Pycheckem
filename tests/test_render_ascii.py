from __future__ import annotations

from pycheckem.diff import diff
from pycheckem.render.ascii import render_ascii
from pycheckem.types import (
    ConfigFileInfo,
    DiffResult,
    DiffSummary,
    OSInfo,
    PackageInfo,
    PathInfo,
    PythonInfo,
    Snapshot,
    SnapshotMetadata,
)


def _make_snapshot(**overrides):
    defaults = dict(
        metadata=SnapshotMetadata(
            timestamp="2026-03-02T12:00:00Z",
            hostname="host-a",
            label="staging",
            pycheckem_version="0.1.0",
        ),
        python=PythonInfo(
            version="3.11.4",
            implementation="CPython",
            executable="/usr/bin/python3",
            prefix="/usr",
            platform="linux",
        ),
        packages={
            "requests": PackageInfo(version="2.31.0", location="/sp", requires=["urllib3"]),
            "flask": PackageInfo(version="3.0.0", location="/sp", requires=["werkzeug"]),
        },
        env_vars={"PATH": "/usr/bin", "HOME": "/home/dev"},
        os_info=OSInfo(system="Linux", release="6.1.0", machine="x86_64", distro="Ubuntu 22.04"),
        paths=PathInfo(sys_path=["/usr/lib/python3"], path_env=["/usr/bin"]),
        config_files={},
    )
    defaults.update(overrides)
    return Snapshot(**defaults)


class TestRenderAsciiIdentical:
    def test_identical_shows_no_differences(self):
        snap = _make_snapshot()
        result = diff(snap, snap)
        output = render_ascii(result)
        assert "No differences" in output

    def test_identical_shows_labels(self):
        snap = _make_snapshot()
        result = diff(snap, snap)
        output = render_ascii(result)
        assert "staging" in output


class TestRenderAsciiPackages:
    def test_added_package_plus_prefix(self):
        a = _make_snapshot()
        b_pkgs = dict(a.packages)
        b_pkgs["gunicorn"] = PackageInfo("21.2.0", "/sp", [])
        b = _make_snapshot(packages=b_pkgs)
        result = diff(a, b)
        output = render_ascii(result)
        assert "+ gunicorn" in output

    def test_removed_package_minus_prefix(self):
        a = _make_snapshot()
        b_pkgs = {"requests": a.packages["requests"]}
        b = _make_snapshot(packages=b_pkgs)
        result = diff(a, b)
        output = render_ascii(result)
        assert "- flask" in output

    def test_changed_version_tilde_and_arrow(self):
        a = _make_snapshot()
        b_pkgs = dict(a.packages)
        b_pkgs["requests"] = PackageInfo("2.28.0", "/sp", ["urllib3"])
        b = _make_snapshot(packages=b_pkgs)
        result = diff(a, b)
        output = render_ascii(result)
        assert "~ requests" in output
        assert "\u2192" in output  # arrow

    def test_downgrade_marker(self):
        a = _make_snapshot()
        b_pkgs = dict(a.packages)
        b_pkgs["requests"] = PackageInfo("2.28.0", "/sp", ["urllib3"])
        b = _make_snapshot(packages=b_pkgs)
        result = diff(a, b)
        output = render_ascii(result)
        assert "DOWNGRADE" in output

    def test_major_version_change_marker(self):
        a = _make_snapshot()
        b_pkgs = dict(a.packages)
        b_pkgs["requests"] = PackageInfo("3.0.0", "/sp", ["urllib3"])
        b = _make_snapshot(packages=b_pkgs)
        result = diff(a, b)
        output = render_ascii(result)
        assert "MAJOR VERSION CHANGE" in output


class TestRenderAsciiSections:
    def test_empty_section_omitted(self):
        a = _make_snapshot()
        b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"),
            env_vars={"PATH": "/usr/bin", "HOME": "/home/dev", "NEW": "val"},
        )
        result = diff(a, b)
        output = render_ascii(result)
        # Packages section should be absent since no package changes
        assert "Packages" not in output
        # Env var section should be present
        assert "Environment Variables" in output

    def test_python_minor_version_section(self):
        a = _make_snapshot()
        b = _make_snapshot(
            python=PythonInfo("3.12.0", "CPython", "/usr/bin/python3", "/usr", "linux")
        )
        result = diff(a, b)
        output = render_ascii(result)
        assert "Python" in output
        assert "3.11.4" in output
        assert "3.12.0" in output
        assert "MINOR VERSION MISMATCH" in output

    def test_python_major_version_section(self):
        a = _make_snapshot()
        b = _make_snapshot(
            python=PythonInfo("4.0.0", "CPython", "/usr/bin/python3", "/usr", "linux")
        )
        result = diff(a, b)
        output = render_ascii(result)
        assert "MAJOR VERSION MISMATCH" in output
        assert "MINOR VERSION MISMATCH" not in output

    def test_os_section(self):
        a = _make_snapshot()
        b = _make_snapshot(os_info=OSInfo("Darwin", "23.1.0", "arm64", "macOS 14.1.1"))
        result = diff(a, b)
        output = render_ascii(result)
        assert "OS" in output
        assert "DIFFERENT OS" in output

    def test_paths_section(self):
        a = _make_snapshot()
        b = _make_snapshot(paths=PathInfo(["/usr/lib/python3", "/new"], ["/usr/bin"]))
        result = diff(a, b)
        output = render_ascii(result)
        assert "Paths" in output
        assert "+ /new" in output

    def test_config_files_section(self):
        a = _make_snapshot(config_files={".env": ConfigFileInfo("aaa", ["DB"])})
        b = _make_snapshot(config_files={".env": ConfigFileInfo("bbb", ["DB", "CACHE"])})
        result = diff(a, b)
        output = render_ascii(result)
        assert "Config Files" in output
        assert "HASH MISMATCH" in output
        assert "+ CACHE" in output

    def test_env_vars_section(self):
        a = _make_snapshot()
        b = _make_snapshot(env_vars={"PATH": "/changed", "HOME": "/home/dev"})
        result = diff(a, b)
        output = render_ascii(result)
        assert "Environment Variables" in output
        assert "~ PATH" in output


class TestRenderAsciiSummary:
    def test_summary_line(self):
        a = _make_snapshot()
        b_pkgs = dict(a.packages)
        b_pkgs["gunicorn"] = PackageInfo("21.2.0", "/sp", [])
        b = _make_snapshot(packages=b_pkgs)
        result = diff(a, b)
        output = render_ascii(result)
        assert "Summary:" in output
        assert "MINOR" in output

    def test_breaking_line(self):
        a = _make_snapshot()
        b_pkgs = {"requests": a.packages["requests"]}  # remove flask
        b = _make_snapshot(packages=b_pkgs)
        result = diff(a, b)
        output = render_ascii(result)
        assert "Breaking:" in output
        assert "flask" in output

    def test_no_breaking_line_for_minor(self):
        a = _make_snapshot()
        b = _make_snapshot(env_vars={"PATH": "/usr/bin", "HOME": "/home/dev", "NEW": "val"})
        result = diff(a, b)
        output = render_ascii(result)
        assert "Breaking:" not in output


class TestRenderAsciiOnly:
    def test_only_packages(self):
        a = _make_snapshot()
        b_pkgs = dict(a.packages)
        b_pkgs["gunicorn"] = PackageInfo("21.2.0", "/sp", [])
        b = _make_snapshot(
            packages=b_pkgs,
            env_vars={"PATH": "/changed", "HOME": "/home/dev"},
        )
        result = diff(a, b)
        output = render_ascii(result, only="packages")
        assert "Packages" in output
        assert "Environment Variables" not in output

    def test_only_env(self):
        a = _make_snapshot()
        b = _make_snapshot(
            env_vars={"PATH": "/changed", "HOME": "/home/dev"},
            packages={
                "requests": PackageInfo("2.31.0", "/sp", ["urllib3"]),
                "flask": PackageInfo("3.0.0", "/sp", ["werkzeug"]),
                "new": PackageInfo("1.0.0", "/sp", []),
            },
        )
        result = diff(a, b)
        output = render_ascii(result, only="env")
        assert "Environment Variables" in output
        assert "Packages" not in output


class TestAsciiSourceChanges:
    def test_source_change_rendered(self):
        a = _make_snapshot(packages={
            "mylib": PackageInfo("1.0.0", "/sp", [], install_source="editable",
                                  source_url="file:///dev/mylib",
                                  source_detail="file:///dev/mylib"),
        })
        b = _make_snapshot(packages={
            "mylib": PackageInfo("1.0.0", "/sp", [], install_source="pypi"),
        })
        result = diff(a, b)
        output = render_ascii(result)
        assert "[editable]" in output
        assert "[pypi]" in output
        assert "mylib" in output

    def test_version_change_with_source_shows_source(self):
        a = _make_snapshot(packages={
            "mylib": PackageInfo("1.0.0", "/sp", [], install_source="editable"),
        })
        b = _make_snapshot(packages={
            "mylib": PackageInfo("2.0.0", "/sp", [], install_source="pypi"),
        })
        result = diff(a, b)
        output = render_ascii(result)
        assert "[editable]" in output
        assert "[pypi]" in output
        assert "\u2192" in output
