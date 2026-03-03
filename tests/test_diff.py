from __future__ import annotations

from pycheckem.diff import (
    diff,
    diff_config_files,
    diff_env_vars,
    diff_os,
    diff_packages,
    diff_paths,
    diff_project,
    diff_python,
)
from pycheckem.types import (
    ConfigFileInfo,
    DiffResult,
    OSInfo,
    PackageInfo,
    PathInfo,
    ProjectInfo,
    PythonInfo,
    Snapshot,
    SnapshotMetadata,
)


def _make_snapshot(**overrides):
    defaults = dict(
        metadata=SnapshotMetadata(
            timestamp="2026-03-02T12:00:00Z",
            hostname="host-a",
            label="a",
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


class TestDiffPython:
    def test_identical_returns_none(self):
        py = PythonInfo("3.11.4", "CPython", "/usr/bin/python3", "/usr", "linux")
        assert diff_python(py, py) is None

    def test_version_change(self):
        a = PythonInfo("3.11.4", "CPython", "/usr/bin/python3", "/usr", "linux")
        b = PythonInfo("3.12.0", "CPython", "/usr/bin/python3", "/usr", "linux")
        result = diff_python(a, b)
        assert result is not None
        assert "version" in result.changes
        assert result.changes["version"] == ("3.11.4", "3.12.0")

    def test_multiple_changes(self):
        a = PythonInfo("3.11.4", "CPython", "/usr/bin/python3", "/usr", "linux")
        b = PythonInfo("3.11.4", "PyPy", "/usr/bin/pypy3", "/usr", "linux")
        result = diff_python(a, b)
        assert "implementation" in result.changes
        assert "executable" in result.changes


class TestDiffPackages:
    def test_identical(self):
        pkgs = {"requests": PackageInfo("2.31.0", "/sp", ["urllib3"])}
        result = diff_packages(pkgs, pkgs)
        assert result.added == {}
        assert result.removed == {}
        assert result.changed == {}
        assert result.unchanged_count == 1

    def test_added_package(self):
        a = {"requests": PackageInfo("2.31.0", "/sp", [])}
        b = {
            "requests": PackageInfo("2.31.0", "/sp", []),
            "flask": PackageInfo("3.0.0", "/sp", []),
        }
        result = diff_packages(a, b)
        assert "flask" in result.added
        assert result.added["flask"] == "3.0.0"

    def test_removed_package(self):
        a = {
            "requests": PackageInfo("2.31.0", "/sp", []),
            "flask": PackageInfo("3.0.0", "/sp", []),
        }
        b = {"requests": PackageInfo("2.31.0", "/sp", [])}
        result = diff_packages(a, b)
        assert "flask" in result.removed
        assert result.removed["flask"] == "3.0.0"

    def test_version_changed(self):
        a = {"requests": PackageInfo("2.28.0", "/sp", [])}
        b = {"requests": PackageInfo("2.31.0", "/sp", [])}
        result = diff_packages(a, b)
        assert "requests" in result.changed
        vc = result.changed["requests"]
        assert vc.version_a == "2.28.0"
        assert vc.version_b == "2.31.0"
        assert vc.is_major is False
        assert vc.is_downgrade is False

    def test_version_downgrade(self):
        a = {"requests": PackageInfo("2.31.0", "/sp", [])}
        b = {"requests": PackageInfo("2.28.0", "/sp", [])}
        result = diff_packages(a, b)
        assert result.changed["requests"].is_downgrade is True

    def test_major_version_change(self):
        a = {"requests": PackageInfo("2.31.0", "/sp", [])}
        b = {"requests": PackageInfo("3.0.0", "/sp", [])}
        result = diff_packages(a, b)
        assert result.changed["requests"].is_major is True


class TestDiffEnvVars:
    def test_identical(self):
        env = {"PATH": "/usr/bin", "HOME": "/home"}
        result = diff_env_vars(env, env)
        assert result.added == {}
        assert result.removed == {}
        assert result.changed == {}
        assert result.unchanged_count == 2

    def test_added_var(self):
        a = {"PATH": "/usr/bin"}
        b = {"PATH": "/usr/bin", "NEW_VAR": "value"}
        result = diff_env_vars(a, b)
        assert "NEW_VAR" in result.added

    def test_removed_var(self):
        a = {"PATH": "/usr/bin", "OLD_VAR": "value"}
        b = {"PATH": "/usr/bin"}
        result = diff_env_vars(a, b)
        assert "OLD_VAR" in result.removed

    def test_changed_var(self):
        a = {"LOG_LEVEL": "DEBUG"}
        b = {"LOG_LEVEL": "INFO"}
        result = diff_env_vars(a, b)
        assert "LOG_LEVEL" in result.changed
        assert result.changed["LOG_LEVEL"] == ("DEBUG", "INFO")


class TestDiffOS:
    def test_identical_returns_none(self):
        os_info = OSInfo("Linux", "6.1.0", "x86_64", "Ubuntu 22.04")
        assert diff_os(os_info, os_info) is None

    def test_system_mismatch(self):
        a = OSInfo("Linux", "6.1.0", "x86_64", "Ubuntu 22.04")
        b = OSInfo("Darwin", "23.1.0", "arm64", "macOS 14.1.1")
        result = diff_os(a, b)
        assert result is not None
        assert "system" in result.changes
        assert "machine" in result.changes

    def test_distro_change(self):
        a = OSInfo("Linux", "6.1.0", "x86_64", "Ubuntu 22.04")
        b = OSInfo("Linux", "6.1.0", "x86_64", "Ubuntu 24.04")
        result = diff_os(a, b)
        assert "distro" in result.changes

    def test_distro_none_to_value(self):
        a = OSInfo("Linux", "6.1.0", "x86_64", None)
        b = OSInfo("Linux", "6.1.0", "x86_64", "Ubuntu 22.04")
        result = diff_os(a, b)
        assert "distro" in result.changes


class TestDiffPaths:
    def test_identical(self):
        p = PathInfo(["/usr/lib"], ["/usr/bin"])
        result = diff_paths(p, p)
        assert result.sys_path_added == []
        assert result.sys_path_removed == []
        assert result.path_env_added == []
        assert result.path_env_removed == []

    def test_sys_path_added(self):
        a = PathInfo(["/usr/lib"], ["/usr/bin"])
        b = PathInfo(["/usr/lib", "/app/src"], ["/usr/bin"])
        result = diff_paths(a, b)
        assert "/app/src" in result.sys_path_added

    def test_path_env_removed(self):
        a = PathInfo(["/usr/lib"], ["/usr/bin", "/opt/bin"])
        b = PathInfo(["/usr/lib"], ["/usr/bin"])
        result = diff_paths(a, b)
        assert "/opt/bin" in result.path_env_removed


class TestDiffConfigFiles:
    def test_identical(self):
        cfg = {".env": ConfigFileInfo(sha256="abc123", keys=["DB"])}
        result = diff_config_files(cfg, cfg)
        assert result.added == []
        assert result.removed == []
        assert result.changed == {}
        assert result.unchanged_count == 1

    def test_added_file(self):
        a = {}
        b = {".env": ConfigFileInfo(sha256="abc", keys=["DB"])}
        result = diff_config_files(a, b)
        assert ".env" in result.added

    def test_removed_file(self):
        a = {".env": ConfigFileInfo(sha256="abc", keys=["DB"])}
        b = {}
        result = diff_config_files(a, b)
        assert ".env" in result.removed

    def test_hash_changed_with_key_diff(self):
        a = {".env": ConfigFileInfo(sha256="aaa", keys=["DB", "LOG"])}
        b = {".env": ConfigFileInfo(sha256="bbb", keys=["DB", "CACHE"])}
        result = diff_config_files(a, b)
        assert ".env" in result.changed
        fd = result.changed[".env"]
        assert fd.sha256_a == "aaa"
        assert fd.sha256_b == "bbb"
        assert "CACHE" in fd.keys_added
        assert "LOG" in fd.keys_removed

    def test_hash_changed_keys_none(self):
        a = {"config.yaml": ConfigFileInfo(sha256="aaa", keys=None)}
        b = {"config.yaml": ConfigFileInfo(sha256="bbb", keys=None)}
        result = diff_config_files(a, b)
        fd = result.changed["config.yaml"]
        assert fd.keys_added == []
        assert fd.keys_removed == []


class TestDiffTopLevel:
    def test_identical_snapshots(self):
        snap = _make_snapshot()
        result = diff(snap, snap)
        assert isinstance(result, DiffResult)
        assert result.summary.severity == "identical"
        assert result.summary.total_differences == 0
        assert result.summary.breaking_changes == []

    def test_labels_from_metadata(self):
        a = _make_snapshot()
        b = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-b", "b", "0.1.0")
        )
        result = diff(a, b)
        assert result.label_a == "a"
        assert result.label_b == "b"

    def test_labels_fallback_to_hostname(self):
        a = _make_snapshot(
            metadata=SnapshotMetadata("2026-03-02T12:00:00Z", "host-a", None, "0.1.0")
        )
        result = diff(a, a)
        assert result.label_a == "host-a"

    def test_added_package_minor_severity(self):
        a = _make_snapshot()
        b_pkgs = dict(a.packages)
        b_pkgs["newpkg"] = PackageInfo("1.0.0", "/sp", [])
        b = _make_snapshot(packages=b_pkgs)
        result = diff(a, b)
        assert "newpkg" in result.packages.added
        assert result.summary.severity == "minor"
        assert result.summary.total_differences >= 1

    def test_removed_package_major_severity(self):
        a = _make_snapshot()
        b_pkgs = {"requests": a.packages["requests"]}  # remove flask
        b = _make_snapshot(packages=b_pkgs)
        result = diff(a, b)
        assert "flask" in result.packages.removed
        assert result.summary.severity == "major"
        assert any("flask" in bc for bc in result.summary.breaking_changes)

    def test_package_downgrade_major_severity(self):
        a = _make_snapshot()
        b_pkgs = dict(a.packages)
        b_pkgs["requests"] = PackageInfo("2.28.0", "/sp", ["urllib3"])
        b = _make_snapshot(packages=b_pkgs)
        result = diff(a, b)
        assert result.summary.severity == "major"
        assert any("downgrade" in bc.lower() for bc in result.summary.breaking_changes)

    def test_package_major_version_critical(self):
        a = _make_snapshot()
        b_pkgs = dict(a.packages)
        b_pkgs["requests"] = PackageInfo("3.0.0", "/sp", ["urllib3"])
        b = _make_snapshot(packages=b_pkgs)
        result = diff(a, b)
        assert result.summary.severity == "critical"

    def test_python_version_mismatch_breaking(self):
        a = _make_snapshot()
        b = _make_snapshot(
            python=PythonInfo("3.12.0", "CPython", "/usr/bin/python3", "/usr", "linux")
        )
        result = diff(a, b)
        assert result.summary.severity == "major"
        assert any("Python" in bc for bc in result.summary.breaking_changes)

    def test_python_major_version_critical(self):
        a = _make_snapshot()
        b = _make_snapshot(
            python=PythonInfo("4.0.0", "CPython", "/usr/bin/python3", "/usr", "linux")
        )
        result = diff(a, b)
        assert result.summary.severity == "critical"
        assert any("major" in bc.lower() for bc in result.summary.breaking_changes)

    def test_os_mismatch_critical(self):
        a = _make_snapshot()
        b = _make_snapshot(
            os_info=OSInfo("Darwin", "23.1.0", "arm64", "macOS 14.1.1")
        )
        result = diff(a, b)
        assert result.summary.severity == "critical"
        assert any("OS" in bc for bc in result.summary.breaking_changes)

    def test_env_var_added_minor(self):
        a = _make_snapshot()
        b = _make_snapshot(env_vars={"PATH": "/usr/bin", "HOME": "/home/dev", "NEW": "val"})
        result = diff(a, b)
        assert result.summary.severity == "minor"

    def test_config_hash_mismatch_in_diff(self):
        a = _make_snapshot(
            config_files={".env": ConfigFileInfo("aaa", ["DB", "LOG"])}
        )
        b = _make_snapshot(
            config_files={".env": ConfigFileInfo("bbb", ["DB", "CACHE"])}
        )
        result = diff(a, b)
        assert ".env" in result.config_files.changed
        fd = result.config_files.changed[".env"]
        assert "CACHE" in fd.keys_added
        assert "LOG" in fd.keys_removed

    def test_total_differences_count(self):
        a = _make_snapshot()
        b = _make_snapshot(
            env_vars={"PATH": "/changed", "HOME": "/changed", "NEW": "val"}
        )
        result = diff(a, b)
        # 2 changed + 1 added = 3 env var diffs
        assert result.summary.total_differences == 3


class TestDiffProject:
    def test_both_none_returns_none(self):
        assert diff_project(None, None) is None

    def test_identical_returns_none(self):
        p = ProjectInfo("myapp", "1.0.0", ">=3.10", ["requests"], "pyproject.toml")
        assert diff_project(p, p) is None

    def test_name_changed(self):
        a = ProjectInfo("app-a", "1.0.0", ">=3.10", [], "pyproject.toml")
        b = ProjectInfo("app-b", "1.0.0", ">=3.10", [], "pyproject.toml")
        result = diff_project(a, b)
        assert result is not None
        assert result.name_changed == ("app-a", "app-b")
        assert result.version_changed is None

    def test_version_changed(self):
        a = ProjectInfo("myapp", "1.0.0", ">=3.10", [], "pyproject.toml")
        b = ProjectInfo("myapp", "2.0.0", ">=3.10", [], "pyproject.toml")
        result = diff_project(a, b)
        assert result.version_changed == ("1.0.0", "2.0.0")

    def test_requires_python_changed(self):
        a = ProjectInfo("myapp", "1.0.0", ">=3.8", [], "pyproject.toml")
        b = ProjectInfo("myapp", "1.0.0", ">=3.10", [], "pyproject.toml")
        result = diff_project(a, b)
        assert result.requires_python_changed == (">=3.8", ">=3.10")

    def test_deps_added_and_removed(self):
        a = ProjectInfo("myapp", "1.0.0", None, ["requests", "flask"], "pyproject.toml")
        b = ProjectInfo("myapp", "1.0.0", None, ["requests", "django"], "pyproject.toml")
        result = diff_project(a, b)
        assert "django" in result.deps_added
        assert "flask" in result.deps_removed

    def test_one_none_other_exists(self):
        b = ProjectInfo("myapp", "1.0.0", None, ["requests"], "pyproject.toml")
        result = diff_project(None, b)
        assert result is not None
        assert result.name_changed == ("", "myapp")
        assert result.version_changed == ("", "1.0.0")
        assert "requests" in result.deps_added

    def test_project_diff_in_top_level(self):
        a = _make_snapshot(
            project=ProjectInfo("myapp", "1.0.0", ">=3.10", ["requests"], "pyproject.toml")
        )
        b = _make_snapshot(
            project=ProjectInfo("myapp", "2.0.0", ">=3.11", ["requests", "flask"], "pyproject.toml")
        )
        result = diff(a, b)
        assert result.project is not None
        assert result.project.version_changed == ("1.0.0", "2.0.0")
        assert result.project.requires_python_changed == (">=3.10", ">=3.11")
        assert "flask" in result.project.deps_added

    def test_requires_python_change_major_severity(self):
        a = _make_snapshot(
            project=ProjectInfo("myapp", "1.0.0", ">=3.8", [], "pyproject.toml")
        )
        b = _make_snapshot(
            project=ProjectInfo("myapp", "1.0.0", ">=3.11", [], "pyproject.toml")
        )
        result = diff(a, b)
        assert result.summary.severity == "major"
        assert any("requires-python" in bc.lower() for bc in result.summary.breaking_changes)

    def test_project_version_change_minor_severity(self):
        a = _make_snapshot(
            project=ProjectInfo("myapp", "1.0.0", None, [], "pyproject.toml")
        )
        b = _make_snapshot(
            project=ProjectInfo("myapp", "2.0.0", None, [], "pyproject.toml")
        )
        result = diff(a, b)
        assert result.summary.severity == "minor"

    def test_project_deps_counted(self):
        a = _make_snapshot(
            project=ProjectInfo("myapp", "1.0.0", None, ["requests"], "pyproject.toml")
        )
        b = _make_snapshot(
            project=ProjectInfo("myapp", "1.0.0", None, ["requests", "flask", "django"], "pyproject.toml")
        )
        result = diff(a, b)
        # 2 deps added
        assert result.summary.total_differences == 2


class TestDiffPackageSources:
    def test_same_version_different_source(self):
        a = {"mylib": PackageInfo("1.0.0", "/sp", [], install_source="editable",
                                   source_url="file:///dev/mylib")}
        b = {"mylib": PackageInfo("1.0.0", "/sp", [], install_source="pypi")}
        result = diff_packages(a, b)
        assert result.changed == {}
        assert "mylib" in result.source_changed
        assert result.source_changed["mylib"].source_a == "editable"
        assert result.source_changed["mylib"].source_b == "pypi"

    def test_same_version_same_source_unchanged(self):
        a = {"mylib": PackageInfo("1.0.0", "/sp", [], install_source="pypi")}
        b = {"mylib": PackageInfo("1.0.0", "/sp", [], install_source="pypi")}
        result = diff_packages(a, b)
        assert result.source_changed == {}
        assert result.unchanged_count == 1

    def test_version_change_carries_source(self):
        a = {"mylib": PackageInfo("1.0.0", "/sp", [], install_source="editable")}
        b = {"mylib": PackageInfo("2.0.0", "/sp", [], install_source="pypi")}
        result = diff_packages(a, b)
        assert "mylib" in result.changed
        assert result.changed["mylib"].source_a == "editable"
        assert result.changed["mylib"].source_b == "pypi"
        assert result.source_changed == {}

    def test_source_change_minor_severity(self):
        a = _make_snapshot(packages={
            "mylib": PackageInfo("1.0.0", "/sp", [], install_source="editable"),
        })
        b = _make_snapshot(packages={
            "mylib": PackageInfo("1.0.0", "/sp", [], install_source="pypi"),
        })
        result = diff(a, b)
        assert result.summary.severity == "minor"

    def test_source_change_counted(self):
        a = _make_snapshot(packages={
            "mylib": PackageInfo("1.0.0", "/sp", [], install_source="editable"),
        })
        b = _make_snapshot(packages={
            "mylib": PackageInfo("1.0.0", "/sp", [], install_source="pypi"),
        })
        result = diff(a, b)
        assert result.summary.total_differences == 1

    def test_old_packageinfo_defaults(self):
        old = PackageInfo("1.0.0", "/sp", [])
        assert old.install_source == "pypi"
        assert old.source_url is None
        assert old.source_detail is None
