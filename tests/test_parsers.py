from __future__ import annotations

import pytest

from pycheckem.parsers import parse_requirements, parse_pyproject_deps, _normalize_name


class TestNormalizeName:
    def test_lowercase(self):
        assert _normalize_name("Flask") == "flask"

    def test_underscores(self):
        assert _normalize_name("my_package") == "my-package"

    def test_dots(self):
        assert _normalize_name("zope.interface") == "zope-interface"

    def test_mixed(self):
        assert _normalize_name("My_Cool.Package") == "my-cool-package"

    def test_consecutive_separators(self):
        assert _normalize_name("a--b__c..d") == "a-b-c-d"


class TestParseRequirements:
    def test_pinned_version(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("requests==2.31.0\n")
        result = parse_requirements(str(f))
        assert result["requests"] == "==2.31.0"

    def test_version_range(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("flask>=2.0,<3.0\n")
        result = parse_requirements(str(f))
        assert result["flask"] == ">=2.0,<3.0"

    def test_bare_name(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("pytest\n")
        result = parse_requirements(str(f))
        assert result["pytest"] is None

    def test_comments_skipped(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("# this is a comment\nrequests==1.0\n")
        result = parse_requirements(str(f))
        assert len(result) == 1

    def test_blank_lines_skipped(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("requests==1.0\n\nflask==2.0\n")
        result = parse_requirements(str(f))
        assert len(result) == 2

    def test_inline_comment(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("requests==1.0  # for HTTP\n")
        result = parse_requirements(str(f))
        assert result["requests"] == "==1.0"

    def test_editable_skipped(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("-e git+https://github.com/foo/bar.git\nrequests==1.0\n")
        result = parse_requirements(str(f))
        assert len(result) == 1

    def test_requirement_flag_skipped(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("-r other.txt\nrequests==1.0\n")
        result = parse_requirements(str(f))
        assert len(result) == 1

    def test_environment_marker_stripped(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("pywin32; sys_platform == 'win32'\n")
        result = parse_requirements(str(f))
        assert "pywin32" in result
        assert result["pywin32"] is None

    def test_extras_stripped(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("requests[security]>=2.28\n")
        result = parse_requirements(str(f))
        assert result["requests"] == ">=2.28"

    def test_names_normalized(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("My_Package==1.0\n")
        result = parse_requirements(str(f))
        assert "my-package" in result

    def test_pip_freeze_output(self, tmp_path):
        f = tmp_path / "freeze.txt"
        f.write_text("certifi==2023.7.22\ncharset-normalizer==3.2.0\n")
        result = parse_requirements(str(f))
        assert result["certifi"] == "==2023.7.22"
        assert result["charset-normalizer"] == "==3.2.0"

    def test_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            parse_requirements(str(tmp_path / "nope.txt"))

    def test_option_flags_skipped(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("--index-url https://pypi.org/simple\nrequests==1.0\n")
        result = parse_requirements(str(f))
        assert len(result) == 1

    def test_compatible_release(self, tmp_path):
        f = tmp_path / "req.txt"
        f.write_text("flask~=2.0.1\n")
        result = parse_requirements(str(f))
        assert result["flask"] == "~=2.0.1"


class TestParsePyprojectDeps:
    def test_basic_deps(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text(
            '[project]\nname = "myapp"\ndependencies = [\n'
            '  "flask>=2.0",\n  "requests",\n]\n'
        )
        result = parse_pyproject_deps(str(f))
        assert result["flask"] == ">=2.0"
        assert result["requests"] is None

    def test_no_project_table(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[build-system]\nrequires = ["setuptools"]\n')
        with pytest.raises(ValueError, match="No \\[project\\] table"):
            parse_pyproject_deps(str(f))

    def test_empty_deps(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\nname = "myapp"\ndependencies = []\n')
        result = parse_pyproject_deps(str(f))
        assert result == {}

    def test_no_deps_key(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\nname = "myapp"\n')
        result = parse_pyproject_deps(str(f))
        assert result == {}

    def test_extras_stripped(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text(
            '[project]\nname = "myapp"\ndependencies = [\n'
            '  "requests[security]>=2.28",\n]\n'
        )
        result = parse_pyproject_deps(str(f))
        assert result["requests"] == ">=2.28"

    def test_markers_stripped(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text(
            '[project]\nname = "myapp"\ndependencies = [\n'
            '  "pywin32; sys_platform == \'win32\'",\n]\n'
        )
        result = parse_pyproject_deps(str(f))
        assert "pywin32" in result

    def test_names_normalized(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text(
            '[project]\nname = "myapp"\ndependencies = [\n'
            '  "My_Package>=1.0",\n]\n'
        )
        result = parse_pyproject_deps(str(f))
        assert "my-package" in result

    def test_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            parse_pyproject_deps(str(tmp_path / "nope.toml"))
