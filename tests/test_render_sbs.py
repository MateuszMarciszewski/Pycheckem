from __future__ import annotations

from pycheckem.render.side_by_side import render_side_by_side
from pycheckem.types import (
    ConfigDiff,
    ConfigFileDiff,
    DiffResult,
    DiffSummary,
    OSDiff,
    PackageDiff,
    PathDiff,
    ProjectDiff,
    PythonDiff,
    VarDiff,
    VersionChange,
)


def _make_result(**overrides):
    defaults = dict(
        label_a="dev",
        label_b="prod",
        python=None,
        packages=PackageDiff({}, {}, {}, 10),
        env_vars=VarDiff({}, {}, {}, 5),
        os_info=None,
        paths=PathDiff([], [], [], []),
        config_files=ConfigDiff([], [], {}, 0),
        summary=DiffSummary(0, "identical", []),
    )
    defaults.update(overrides)
    return DiffResult(**defaults)


class TestSideBySideBasic:
    def test_identical_output(self):
        result = _make_result()
        output = render_side_by_side(result, width=80)
        assert "dev" in output
        assert "prod" in output
        assert "No differences found" in output

    def test_header_contains_labels(self):
        result = _make_result()
        output = render_side_by_side(result, width=80)
        lines = output.split("\n")
        assert "dev" in lines[0]
        assert "prod" in lines[0]

    def test_separator_line(self):
        result = _make_result()
        output = render_side_by_side(result, width=80)
        lines = output.split("\n")
        assert "\u2550" in lines[1]  # ═
        assert " | " in lines[1]

    def test_custom_width(self):
        result = _make_result()
        output = render_side_by_side(result, width=60)
        lines = output.split("\n")
        # Each line should respect the width
        for line in lines:
            assert len(line) <= 60 or line.startswith("Summary")

    def test_minimum_width(self):
        result = _make_result()
        output = render_side_by_side(result, width=10)
        # Should not crash, width clamped to 40
        assert "dev" in output


class TestSideBySidePackages:
    def test_added_package(self):
        result = _make_result(
            packages=PackageDiff({"flask": "3.0.0"}, {}, {}, 10),
            summary=DiffSummary(1, "minor", []),
        )
        output = render_side_by_side(result, width=80)
        assert "+ flask" in output
        assert "\u2014" in output  # em dash for missing side

    def test_removed_package(self):
        result = _make_result(
            packages=PackageDiff({}, {"debugpy": "1.8.0"}, {}, 10),
            summary=DiffSummary(1, "major", ["Package removed: debugpy 1.8.0"]),
        )
        output = render_side_by_side(result, width=80)
        assert "- debugpy" in output

    def test_changed_package(self):
        result = _make_result(
            packages=PackageDiff({}, {}, {
                "requests": VersionChange("2.28.0", "2.31.0", False, False),
            }, 10),
            summary=DiffSummary(1, "minor", []),
        )
        output = render_side_by_side(result, width=80)
        assert "! requests 2.28.0" in output
        assert "! requests 2.31.0" in output


class TestSideBySideEnvVars:
    def test_added_env_var(self):
        result = _make_result(
            env_vars=VarDiff({"DATABASE_URL": "postgres://..."}, {}, {}, 5),
            summary=DiffSummary(1, "minor", []),
        )
        output = render_side_by_side(result, width=80)
        assert "+ DATABASE_URL" in output

    def test_changed_env_var(self):
        result = _make_result(
            env_vars=VarDiff({}, {}, {"LOG_LEVEL": ("DEBUG", "WARNING")}, 5),
            summary=DiffSummary(1, "minor", []),
        )
        output = render_side_by_side(result, width=80)
        assert "LOG_LEVEL=DEBUG" in output
        assert "LOG_LEVEL=WARNING" in output


class TestSideBySidePython:
    def test_python_version_diff(self):
        result = _make_result(
            python=PythonDiff({"version": ("3.11.4", "3.10.8")}),
            summary=DiffSummary(1, "major", []),
        )
        output = render_side_by_side(result, width=80)
        assert "Version: 3.11.4" in output
        assert "Version: 3.10.8" in output
        assert "Python" in output


class TestSideBySideOS:
    def test_os_diff(self):
        result = _make_result(
            os_info=OSDiff({"system": ("Linux", "Darwin")}),
            summary=DiffSummary(1, "critical", []),
        )
        output = render_side_by_side(result, width=80)
        assert "System: Linux" in output
        assert "System: Darwin" in output


class TestSideBySidePaths:
    def test_sys_path_added(self):
        result = _make_result(
            paths=PathDiff(["/app/src"], [], [], []),
            summary=DiffSummary(1, "minor", []),
        )
        output = render_side_by_side(result, width=80)
        assert "+ sys.path: /app/src" in output

    def test_path_env_removed(self):
        result = _make_result(
            paths=PathDiff([], [], [], ["/opt/bin"]),
            summary=DiffSummary(1, "minor", []),
        )
        output = render_side_by_side(result, width=80)
        assert "- PATH: /opt/bin" in output


class TestSideBySideConfigFiles:
    def test_config_changed(self):
        result = _make_result(
            config_files=ConfigDiff([], [], {
                ".env": ConfigFileDiff("aaa", "bbb", ["NEW_KEY"], ["OLD_KEY"]),
            }, 0),
            summary=DiffSummary(1, "minor", []),
        )
        output = render_side_by_side(result, width=80)
        assert ".env" in output
        assert "HASH MISMATCH" in output


class TestSideBySideProject:
    def test_project_version_changed(self):
        result = _make_result(
            project=ProjectDiff(None, ("1.0.0", "2.0.0"), None, [], []),
            summary=DiffSummary(1, "minor", []),
        )
        output = render_side_by_side(result, width=80)
        assert "Version: 1.0.0" in output
        assert "Version: 2.0.0" in output

    def test_project_deps_added(self):
        result = _make_result(
            project=ProjectDiff(None, None, None, ["flask"], []),
            summary=DiffSummary(1, "minor", []),
        )
        output = render_side_by_side(result, width=80)
        assert "+ flask" in output


class TestSideBySideOnly:
    def test_only_packages(self):
        result = _make_result(
            python=PythonDiff({"version": ("3.11.4", "3.10.8")}),
            packages=PackageDiff({"flask": "3.0.0"}, {}, {}, 10),
            summary=DiffSummary(2, "major", []),
        )
        output = render_side_by_side(result, only="packages", width=80)
        assert "Packages" in output
        assert "Python" not in output

    def test_only_python(self):
        result = _make_result(
            python=PythonDiff({"version": ("3.11.4", "3.10.8")}),
            packages=PackageDiff({"flask": "3.0.0"}, {}, {}, 10),
            summary=DiffSummary(2, "major", []),
        )
        output = render_side_by_side(result, only="python", width=80)
        assert "Python" in output
        assert "Packages" not in output


class TestSideBySideSummary:
    def test_summary_footer(self):
        result = _make_result(
            packages=PackageDiff({"flask": "3.0.0"}, {}, {}, 10),
            summary=DiffSummary(1, "minor", []),
        )
        output = render_side_by_side(result, width=80)
        assert "Summary: 1 difference" in output
        assert "MINOR" in output

    def test_breaking_changes_shown(self):
        result = _make_result(
            summary=DiffSummary(1, "critical", ["OS system mismatch"]),
            os_info=OSDiff({"system": ("Linux", "Darwin")}),
        )
        output = render_side_by_side(result, width=80)
        assert "Breaking:" in output
        assert "OS system mismatch" in output

    def test_plural_differences(self):
        result = _make_result(
            packages=PackageDiff({"flask": "3.0", "django": "4.0"}, {}, {}, 10),
            summary=DiffSummary(2, "minor", []),
        )
        output = render_side_by_side(result, width=80)
        assert "2 differences" in output
