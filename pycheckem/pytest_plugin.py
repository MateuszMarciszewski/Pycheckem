"""pytest plugin for pycheckem — verify environment parity as part of your test suite.

Usage:
    pytest --check-env requirements.txt
    pytest --check-env pyproject.toml

Or in pyproject.toml:
    [tool.pytest.ini_options]
    addopts = "--check-env=requirements.txt"

The environment check runs before all other tests. If the current environment
doesn't match the declared dependencies, a clear failure is reported.
"""

from __future__ import annotations


def pytest_addoption(parser):
    """Register the --check-env CLI option."""
    parser.addoption(
        "--check-env",
        action="store",
        default=None,
        help="Path to requirements.txt or pyproject.toml for environment parity check",
    )


def pytest_configure(config):
    """Register the env_parity marker."""
    config.addinivalue_line(
        "markers",
        "env_parity: mark test as an environment parity check",
    )


def pytest_collection_modifyitems(config, items):
    """If --check-env is set, prepend an environment verification test."""
    deps_file = config.getoption("--check-env")
    if deps_file is None:
        return

    import pytest

    class EnvParityItem(pytest.Item):
        """A synthetic test item that verifies environment parity."""

        def __init__(self, name, parent, deps_file):
            super().__init__(name, parent)
            self._deps_file = deps_file

        def runtest(self):
            from pycheckem.parsers import parse_requirements, parse_pyproject_deps
            from pycheckem.verify import verify, render_verify

            if self._deps_file.endswith(".toml"):
                declared = parse_pyproject_deps(self._deps_file)
            else:
                declared = parse_requirements(self._deps_file)

            result = verify(declared)
            if not result.is_satisfied:
                pytest.fail(render_verify(result))

        def repr_failure(self, excinfo):
            return str(excinfo.value)

        def reportinfo(self):
            return (self._deps_file, None, "pycheckem environment parity check")

    # Create the item and insert at the beginning
    if items:
        parent = items[0].parent
    else:
        parent = config.rootpath

    env_item = EnvParityItem.from_parent(
        parent,
        name="pycheckem_env_check",
        deps_file=deps_file,
    )
    items.insert(0, env_item)
