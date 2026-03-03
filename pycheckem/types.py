from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Snapshot types
# ---------------------------------------------------------------------------


@dataclass
class SnapshotMetadata:
    timestamp: str  # ISO 8601
    hostname: str
    label: Optional[str]
    pycheckem_version: str


@dataclass
class PythonInfo:
    version: str  # e.g. "3.11.4"
    implementation: str  # CPython, PyPy, etc.
    executable: str  # sys.executable
    prefix: str  # sys.prefix (venv detection)
    platform: str  # sys.platform


@dataclass
class PackageInfo:
    version: str
    location: Optional[str]  # install path
    requires: List[str]  # direct dependencies
    install_source: str = "pypi"  # "pypi", "editable", "local", "vcs", "archive"
    source_url: Optional[str] = None  # URL from direct_url.json
    source_detail: Optional[str] = None  # VCS commit hash, editable path, etc.


@dataclass
class OSInfo:
    system: str  # Linux, Darwin, Windows
    release: str  # kernel version
    machine: str  # x86_64, arm64
    distro: Optional[str]  # Ubuntu 22.04, Alpine 3.18, etc.


@dataclass
class ConfigFileInfo:
    sha256: str
    keys: Optional[List[str]]  # top-level keys/var names if parseable


@dataclass
class PathInfo:
    sys_path: List[str]
    path_env: List[str]  # $PATH split


@dataclass
class ProjectInfo:
    name: Optional[str]
    version: Optional[str]
    requires_python: Optional[str]  # e.g. ">=3.10"
    dependencies: List[str]  # e.g. ["requests>=2.28", "flask"]
    source_file: str  # "pyproject.toml" or "setup.cfg"


@dataclass
class Snapshot:
    metadata: SnapshotMetadata
    python: PythonInfo
    packages: Dict[str, PackageInfo]
    env_vars: Dict[str, str]
    os_info: OSInfo
    paths: PathInfo
    config_files: Dict[str, ConfigFileInfo] = field(default_factory=dict)
    project: Optional[ProjectInfo] = None
    plugins: Dict[str, Dict] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Diff types
# ---------------------------------------------------------------------------


@dataclass
class VersionChange:
    version_a: str
    version_b: str
    is_major: bool
    is_downgrade: bool
    source_a: str = "pypi"
    source_b: str = "pypi"


@dataclass
class SourceChange:
    source_a: str
    source_b: str
    url_a: Optional[str]
    url_b: Optional[str]
    detail_a: Optional[str]
    detail_b: Optional[str]


@dataclass
class PackageDiff:
    added: Dict[str, str]  # pkg -> version (in B, not A)
    removed: Dict[str, str]  # pkg -> version (in A, not B)
    changed: Dict[str, VersionChange]  # pkg -> change details
    unchanged_count: int
    source_changed: Dict[str, SourceChange] = field(default_factory=dict)


@dataclass
class VarDiff:
    added: Dict[str, str]
    removed: Dict[str, str]
    changed: Dict[str, Tuple[str, str]]
    unchanged_count: int


@dataclass
class PythonDiff:
    changes: Dict[str, Tuple[str, str]]  # field -> (old, new)


@dataclass
class OSDiff:
    changes: Dict[str, Tuple[str, str]]  # field -> (old, new)


@dataclass
class PathDiff:
    sys_path_added: List[str]
    sys_path_removed: List[str]
    path_env_added: List[str]
    path_env_removed: List[str]


@dataclass
class ConfigFileDiff:
    sha256_a: Optional[str]
    sha256_b: Optional[str]
    keys_added: List[str]
    keys_removed: List[str]


@dataclass
class ConfigDiff:
    added: List[str]  # files only in B
    removed: List[str]  # files only in A
    changed: Dict[str, ConfigFileDiff]  # files in both with differences
    unchanged_count: int


@dataclass
class ProjectDiff:
    name_changed: Optional[Tuple[str, str]]  # (old, new) or None
    version_changed: Optional[Tuple[str, str]]
    requires_python_changed: Optional[Tuple[str, str]]
    deps_added: List[str]
    deps_removed: List[str]


@dataclass
class DiffSummary:
    total_differences: int
    severity: str  # "identical", "minor", "major", "critical"
    breaking_changes: List[str]  # human-readable descriptions


@dataclass
class DiffResult:
    label_a: str
    label_b: str
    python: Optional[PythonDiff]
    packages: PackageDiff
    env_vars: VarDiff
    os_info: Optional[OSDiff]
    paths: PathDiff
    config_files: ConfigDiff
    project: Optional[ProjectDiff] = None
    summary: DiffSummary = field(default_factory=lambda: DiffSummary(0, "identical", []))
