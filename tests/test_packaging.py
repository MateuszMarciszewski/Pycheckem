from __future__ import annotations

import os

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


PYPROJECT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "pyproject.toml"
)


class TestPyprojectToml:
    def test_pyproject_exists(self):
        assert os.path.isfile(PYPROJECT_PATH)

    def test_pyproject_is_valid_toml(self):
        if tomllib is None:
            # On Python 3.8-3.10 without tomli, skip gracefully
            # At minimum, verify the file is non-empty and starts with [
            with open(PYPROJECT_PATH, "r", encoding="utf-8") as f:
                content = f.read()
            assert content.startswith("[")
            return

        with open(PYPROJECT_PATH, "rb") as f:
            data = tomllib.load(f)
        assert "project" in data
        assert "build-system" in data

    def test_project_name(self):
        if tomllib is None:
            return
        with open(PYPROJECT_PATH, "rb") as f:
            data = tomllib.load(f)
        assert data["project"]["name"] == "pycheckem"

    def test_project_version(self):
        if tomllib is None:
            return
        from pycheckem.version import __version__

        with open(PYPROJECT_PATH, "rb") as f:
            data = tomllib.load(f)
        assert data["project"]["version"] == __version__

    def test_requires_python(self):
        if tomllib is None:
            return
        with open(PYPROJECT_PATH, "rb") as f:
            data = tomllib.load(f)
        assert data["project"]["requires-python"] == ">=3.8"

    def test_has_classifiers(self):
        if tomllib is None:
            return
        with open(PYPROJECT_PATH, "rb") as f:
            data = tomllib.load(f)
        classifiers = data["project"].get("classifiers", [])
        assert len(classifiers) >= 3

    def test_has_urls(self):
        if tomllib is None:
            return
        with open(PYPROJECT_PATH, "rb") as f:
            data = tomllib.load(f)
        urls = data["project"].get("urls", {})
        assert "Homepage" in urls
        assert "Repository" in urls

    def test_has_pretty_extra(self):
        if tomllib is None:
            return
        with open(PYPROJECT_PATH, "rb") as f:
            data = tomllib.load(f)
        extras = data["project"].get("optional-dependencies", {})
        assert "pretty" in extras
        assert any("rich" in dep for dep in extras["pretty"])

    def test_has_dev_extra(self):
        if tomllib is None:
            return
        with open(PYPROJECT_PATH, "rb") as f:
            data = tomllib.load(f)
        extras = data["project"].get("optional-dependencies", {})
        assert "dev" in extras
        assert any("pytest" in dep for dep in extras["dev"])

    def test_has_toml_extra(self):
        if tomllib is None:
            return
        with open(PYPROJECT_PATH, "rb") as f:
            data = tomllib.load(f)
        extras = data["project"].get("optional-dependencies", {})
        assert "toml" in extras
        assert any("tomli" in dep for dep in extras["toml"])

    def test_has_entry_point(self):
        if tomllib is None:
            return
        with open(PYPROJECT_PATH, "rb") as f:
            data = tomllib.load(f)
        scripts = data["project"].get("scripts", {})
        assert "pycheckem" in scripts
        assert scripts["pycheckem"] == "pycheckem.cli:main"

    def test_build_backend(self):
        if tomllib is None:
            return
        with open(PYPROJECT_PATH, "rb") as f:
            data = tomllib.load(f)
        assert data["build-system"]["build-backend"] == "setuptools.build_meta"


class TestPackageMetadata:
    def test_version_matches_pyproject(self):
        from pycheckem.version import __version__

        if tomllib is None:
            return
        with open(PYPROJECT_PATH, "rb") as f:
            data = tomllib.load(f)
        assert __version__ == data["project"]["version"]

    def test_importable_package(self):
        import pycheckem

        assert hasattr(pycheckem, "__version__")
        assert hasattr(pycheckem, "snapshot")
        assert hasattr(pycheckem, "diff")
        assert hasattr(pycheckem, "render")

    def test_readme_exists(self):
        readme_path = os.path.join(os.path.dirname(PYPROJECT_PATH), "README.md")
        assert os.path.isfile(readme_path)
