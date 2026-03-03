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
    """Collect a full snapshot of the current runtime environment."""
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
    """Serialize a Snapshot to a JSON file."""
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
    """Deserialize a Snapshot from a JSON file.

    Raises:
        FileNotFoundError: if the file does not exist
        json.JSONDecodeError: if the file is not valid JSON
        ValueError: if required keys are missing
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
