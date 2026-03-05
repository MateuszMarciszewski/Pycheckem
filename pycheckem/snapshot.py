from __future__ import annotations

import dataclasses
import json
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pycheckem.collectors import (
    collect_config_file,
    collect_env_vars,
    collect_os_info,
    collect_packages,
    collect_paths,
    collect_project_info,
    collect_python_info,
)
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
from pycheckem.plugins import run_plugins
from pycheckem.version import __version__


def snapshot(
    label: Optional[str] = None,
    config_files: Optional[List[str]] = None,
    include_sensitive: bool = False,
    exclude_patterns: Optional[List[str]] = None,
) -> Snapshot:
    """Capture a complete snapshot of the current Python runtime environment.

    Collects everything needed to compare environments: Python version,
    installed packages (with install sources via PEP 610), environment
    variables, OS details, sys.path, PATH, config file hashes, project
    metadata, and any registered plugin data.

    Args:
        label: Human-readable label for this snapshot (e.g. "staging", "prod").
        config_files: Paths to config files to hash (e.g. [".env", "setup.cfg"]).
        include_sensitive: If True, include env vars that match sensitive
            patterns (passwords, tokens, keys). Filtered by default.
        exclude_patterns: Additional regex patterns for env vars to exclude.

    Returns:
        A Snapshot dataclass containing all collected environment data.

    Example:
        >>> import pycheckem
        >>> snap = pycheckem.snapshot(label="dev")
        >>> snap.python.version
        '3.12.0'
        >>> len(snap.packages)
        42
    """
    metadata = SnapshotMetadata(
        timestamp=datetime.now(timezone.utc).isoformat(),
        hostname=socket.gethostname(),
        label=label,
        pycheckem_version=__version__,
    )

    python = collect_python_info()
    packages = collect_packages()
    env_vars = collect_env_vars(
        include_sensitive=include_sensitive,
        exclude_patterns=exclude_patterns,
    )
    os_info = collect_os_info()
    paths = collect_paths()

    cfg = {}  # type: Dict[str, ConfigFileInfo]
    if config_files:
        for path in config_files:
            info = collect_config_file(path)
            if info is not None:
                cfg[path] = info

    project = collect_project_info()
    plugin_data = run_plugins()

    return Snapshot(
        metadata=metadata,
        python=python,
        packages=packages,
        env_vars=env_vars,
        os_info=os_info,
        paths=paths,
        config_files=cfg,
        project=project,
        plugins=plugin_data,
    )


def to_json(snap):
    # type: (Snapshot) -> str
    """Serialize a Snapshot to a JSON string."""
    data = dataclasses.asdict(snap)
    return json.dumps(data, indent=2, ensure_ascii=False)


def save(snap: Snapshot, path: str) -> None:
    """Save a snapshot to a JSON file for later comparison.

    The JSON file can be loaded back with ``load()`` or shared between
    machines to compare environments.

    Args:
        snap: The Snapshot to serialize.
        path: Output file path (e.g. "staging.json").

    Example:
        >>> import pycheckem
        >>> snap = pycheckem.snapshot(label="prod")
        >>> pycheckem.save(snap, "prod.json")
    """
    data = dataclasses.asdict(snap)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _from_dict(data):
    # type: (dict) -> Snapshot
    """Reconstruct a Snapshot from a plain dict.

    Raises ValueError if required keys are missing.
    """
    required_keys = ["metadata", "python", "packages", "env_vars", "os_info", "paths"]
    missing = [k for k in required_keys if k not in data]
    if missing:
        raise ValueError(
            f"Invalid snapshot data: missing required keys: {', '.join(missing)}"
        )

    metadata = SnapshotMetadata(**data["metadata"])
    python = PythonInfo(**data["python"])

    packages = {
        name: PackageInfo(**info) for name, info in data["packages"].items()
    }

    env_vars = data["env_vars"]

    os_info = OSInfo(**data["os_info"])
    paths_info = PathInfo(**data["paths"])

    config_files = {}  # type: Dict[str, ConfigFileInfo]
    for cfg_path, cfg_data in data.get("config_files", {}).items():
        config_files[cfg_path] = ConfigFileInfo(**cfg_data)

    project = None
    project_data = data.get("project")
    if project_data is not None:
        project = ProjectInfo(**project_data)

    plugins = data.get("plugins", {})

    return Snapshot(
        metadata=metadata,
        python=python,
        packages=packages,
        env_vars=env_vars,
        os_info=os_info,
        paths=paths_info,
        config_files=config_files,
        project=project,
        plugins=plugins,
    )


def load(path: str) -> Snapshot:
    """Load a previously saved snapshot from a JSON file.

    Use this to load snapshots captured on other machines or at earlier
    points in time, then pass two loaded snapshots to ``diff()`` to
    compare them.

    Args:
        path: Path to the snapshot JSON file.

    Returns:
        A Snapshot dataclass with all environment data.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
        ValueError: If required snapshot keys are missing.

    Example:
        >>> import pycheckem
        >>> snap = pycheckem.load("prod.json")
        >>> snap.metadata.label
        'prod'
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return _from_dict(data)


def load_from_string(s):
    # type: (str) -> Snapshot
    """Deserialize a Snapshot from a JSON string.

    Raises:
        json.JSONDecodeError: if the string is not valid JSON
        ValueError: if required keys are missing
    """
    data = json.loads(s)
    return _from_dict(data)
