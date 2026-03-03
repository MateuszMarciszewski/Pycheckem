import pytest

from pycheckem.types import (
    ConfigFileInfo,
    OSInfo,
    PackageInfo,
    PathInfo,
    ProjectInfo,
    PythonInfo,
    Snapshot,
    SnapshotMetadata,
)


@pytest.fixture
def sample_metadata():
    return SnapshotMetadata(
        timestamp="2026-03-02T12:00:00Z",
        hostname="dev-machine",
        label="dev",
        pycheckem_version="0.1.0",
    )


@pytest.fixture
def sample_python_info():
    return PythonInfo(
        version="3.11.4",
        implementation="CPython",
        executable="/usr/bin/python3",
        prefix="/usr",
        platform="linux",
    )


@pytest.fixture
def sample_packages():
    return {
        "requests": PackageInfo(
            version="2.31.0",
            location="/usr/lib/python3/site-packages",
            requires=["urllib3", "charset-normalizer", "idna", "certifi"],
        ),
        "flask": PackageInfo(
            version="3.0.0",
            location="/usr/lib/python3/site-packages",
            requires=["werkzeug", "jinja2", "click", "blinker"],
        ),
    }


@pytest.fixture
def sample_env_vars():
    return {
        "PATH": "/usr/local/bin:/usr/bin",
        "HOME": "/home/dev",
        "LOG_LEVEL": "DEBUG",
    }


@pytest.fixture
def sample_os_info():
    return OSInfo(
        system="Linux",
        release="6.1.0",
        machine="x86_64",
        distro="Ubuntu 22.04",
    )


@pytest.fixture
def sample_paths():
    return PathInfo(
        sys_path=["/usr/lib/python3", "/app/src"],
        path_env=["/usr/local/bin", "/usr/bin"],
    )


@pytest.fixture
def sample_config_files():
    return {
        ".env": ConfigFileInfo(
            sha256="abc123",
            keys=["DATABASE_URL", "LOG_LEVEL"],
        ),
    }


@pytest.fixture
def sample_project_info():
    return ProjectInfo(
        name="myproject",
        version="1.0.0",
        requires_python=">=3.8",
        dependencies=["requests", "flask"],
        source_file="pyproject.toml",
    )


@pytest.fixture
def sample_snapshot(
    sample_metadata,
    sample_python_info,
    sample_packages,
    sample_env_vars,
    sample_os_info,
    sample_paths,
    sample_config_files,
    sample_project_info,
):
    return Snapshot(
        metadata=sample_metadata,
        python=sample_python_info,
        packages=sample_packages,
        env_vars=sample_env_vars,
        os_info=sample_os_info,
        paths=sample_paths,
        config_files=sample_config_files,
        project=sample_project_info,
        plugins={"example_plugin": {"key": "value"}},
    )
