import dataclasses

from pycheckem.types import (
    ConfigDiff,
    ConfigFileDiff,
    ConfigFileInfo,
    DiffResult,
    DiffSummary,
    OSDiff,
    OSInfo,
    PackageDiff,
    PackageInfo,
    PathDiff,
    PathInfo,
    PythonDiff,
    PythonInfo,
    Snapshot,
    SnapshotMetadata,
    VarDiff,
    VersionChange,
)


class TestSnapshotTypes:
    def test_snapshot_metadata_fields(self):
        meta = SnapshotMetadata(
            timestamp="2026-01-01T00:00:00Z",
            hostname="test-host",
            label="prod",
            pycheckem_version="0.1.0",
        )
        assert meta.timestamp == "2026-01-01T00:00:00Z"
        assert meta.hostname == "test-host"
        assert meta.label == "prod"

    def test_snapshot_metadata_optional_label(self):
        meta = SnapshotMetadata(
            timestamp="2026-01-01T00:00:00Z",
            hostname="test-host",
            label=None,
            pycheckem_version="0.1.0",
        )
        assert meta.label is None

    def test_python_info_fields(self):
        info = PythonInfo(
            version="3.11.4",
            implementation="CPython",
            executable="/usr/bin/python3",
            prefix="/usr",
            platform="linux",
        )
        assert info.version == "3.11.4"
        assert info.implementation == "CPython"

    def test_package_info_fields(self):
        pkg = PackageInfo(
            version="2.31.0", location="/site-packages", requires=["urllib3"]
        )
        assert pkg.version == "2.31.0"
        assert pkg.requires == ["urllib3"]

    def test_package_info_no_location(self):
        pkg = PackageInfo(version="1.0.0", location=None, requires=[])
        assert pkg.location is None

    def test_os_info_fields(self):
        info = OSInfo(
            system="Linux", release="6.1.0", machine="x86_64", distro="Ubuntu 22.04"
        )
        assert info.distro == "Ubuntu 22.04"

    def test_config_file_info(self):
        cfg = ConfigFileInfo(sha256="abc123", keys=["DB_HOST", "DB_PORT"])
        assert cfg.sha256 == "abc123"
        assert cfg.keys == ["DB_HOST", "DB_PORT"]

    def test_config_file_info_no_keys(self):
        cfg = ConfigFileInfo(sha256="abc123", keys=None)
        assert cfg.keys is None

    def test_path_info_fields(self):
        paths = PathInfo(sys_path=["/lib"], path_env=["/usr/bin"])
        assert paths.sys_path == ["/lib"]

    def test_snapshot_construction(self, sample_snapshot):
        assert sample_snapshot.metadata.label == "dev"
        assert "requests" in sample_snapshot.packages
        assert sample_snapshot.python.version == "3.11.4"

    def test_snapshot_default_config_files(
        self, sample_metadata, sample_python_info, sample_os_info, sample_paths
    ):
        snap = Snapshot(
            metadata=sample_metadata,
            python=sample_python_info,
            packages={},
            env_vars={},
            os_info=sample_os_info,
            paths=sample_paths,
        )
        assert snap.config_files == {}

    def test_snapshot_asdict_roundtrip(self, sample_snapshot):
        d = dataclasses.asdict(sample_snapshot)
        assert isinstance(d, dict)
        assert d["metadata"]["hostname"] == "dev-machine"
        assert d["packages"]["requests"]["version"] == "2.31.0"
        assert d["config_files"][".env"]["sha256"] == "abc123"


class TestDiffTypes:
    def test_version_change(self):
        vc = VersionChange(
            version_a="2.31.0", version_b="2.28.0", is_major=False, is_downgrade=True
        )
        assert vc.is_downgrade is True
        assert vc.is_major is False

    def test_package_diff(self):
        pd = PackageDiff(
            added={"gunicorn": "21.2.0"},
            removed={"debugpy": "1.8.0"},
            changed={},
            unchanged_count=50,
        )
        assert "gunicorn" in pd.added
        assert pd.unchanged_count == 50

    def test_var_diff(self):
        vd = VarDiff(
            added={"NEW_VAR": "value"},
            removed={},
            changed={"LOG_LEVEL": ("DEBUG", "WARNING")},
            unchanged_count=10,
        )
        assert vd.changed["LOG_LEVEL"] == ("DEBUG", "WARNING")

    def test_python_diff(self):
        pd = PythonDiff(changes={"version": ("3.11.4", "3.10.8")})
        assert pd.changes["version"] == ("3.11.4", "3.10.8")

    def test_os_diff(self):
        od = OSDiff(changes={"distro": ("Ubuntu 22.04", "Alpine 3.18")})
        assert "distro" in od.changes

    def test_path_diff(self):
        pd = PathDiff(
            sys_path_added=["/new/path"],
            sys_path_removed=[],
            path_env_added=[],
            path_env_removed=["/old/bin"],
        )
        assert pd.sys_path_added == ["/new/path"]

    def test_config_file_diff(self):
        cfd = ConfigFileDiff(
            sha256_a="aaa",
            sha256_b="bbb",
            keys_added=["NEW_KEY"],
            keys_removed=[],
        )
        assert cfd.keys_added == ["NEW_KEY"]

    def test_config_diff(self):
        cd = ConfigDiff(added=[], removed=[], changed={}, unchanged_count=3)
        assert cd.unchanged_count == 3

    def test_diff_summary(self):
        ds = DiffSummary(
            total_differences=7,
            severity="major",
            breaking_changes=["Python minor version mismatch"],
        )
        assert ds.severity == "major"
        assert len(ds.breaking_changes) == 1

    def test_diff_result_construction(self):
        result = DiffResult(
            label_a="staging",
            label_b="prod",
            python=None,
            packages=PackageDiff(added={}, removed={}, changed={}, unchanged_count=0),
            env_vars=VarDiff(added={}, removed={}, changed={}, unchanged_count=0),
            os_info=None,
            paths=PathDiff(
                sys_path_added=[],
                sys_path_removed=[],
                path_env_added=[],
                path_env_removed=[],
            ),
            config_files=ConfigDiff(
                added=[], removed=[], changed={}, unchanged_count=0
            ),
            summary=DiffSummary(
                total_differences=0, severity="identical", breaking_changes=[]
            ),
        )
        assert result.label_a == "staging"
        assert result.summary.severity == "identical"

    def test_diff_result_asdict(self):
        result = DiffResult(
            label_a="a",
            label_b="b",
            python=PythonDiff(changes={"version": ("3.11", "3.10")}),
            packages=PackageDiff(added={}, removed={}, changed={}, unchanged_count=0),
            env_vars=VarDiff(added={}, removed={}, changed={}, unchanged_count=0),
            os_info=None,
            paths=PathDiff(
                sys_path_added=[],
                sys_path_removed=[],
                path_env_added=[],
                path_env_removed=[],
            ),
            config_files=ConfigDiff(
                added=[], removed=[], changed={}, unchanged_count=0
            ),
            summary=DiffSummary(
                total_differences=1, severity="major", breaking_changes=[]
            ),
        )
        d = dataclasses.asdict(result)
        assert isinstance(d, dict)
        assert d["python"]["changes"]["version"] == ("3.11", "3.10")
        assert d["os_info"] is None
