from __future__ import annotations

import json
import os
import dataclasses

import pytest

from pycheckem.snapshot import snapshot, save, load
from pycheckem.version import __version__
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


class TestSnapshot:
    def test_returns_snapshot(self):
        result = snapshot()
        assert isinstance(result, Snapshot)

    def test_metadata_populated(self):
        result = snapshot()
        assert isinstance(result.metadata, SnapshotMetadata)
        assert len(result.metadata.timestamp) > 0
        assert len(result.metadata.hostname) > 0
        assert result.metadata.pycheckem_version == __version__

    def test_label_propagates(self):
        result = snapshot(label="prod")
        assert result.metadata.label == "prod"

    def test_label_default_none(self):
        result = snapshot()
        assert result.metadata.label is None

    def test_python_populated(self):
        result = snapshot()
        assert isinstance(result.python, PythonInfo)
        assert len(result.python.version) > 0

    def test_packages_populated(self):
        result = snapshot()
        assert isinstance(result.packages, dict)
        assert len(result.packages) > 0

    def test_env_vars_populated(self):
        result = snapshot()
        assert isinstance(result.env_vars, dict)

    def test_os_info_populated(self):
        result = snapshot()
        assert isinstance(result.os_info, OSInfo)

    def test_paths_populated(self):
        result = snapshot()
        assert isinstance(result.paths, PathInfo)

    def test_config_files_default_empty(self):
        result = snapshot()
        assert result.config_files == {}

    def test_config_files_with_real_file(self, tmp_path):
        f = tmp_path / ".env"
        f.write_text("DB_HOST=localhost\n")
        result = snapshot(config_files=[str(f)])
        assert str(f) in result.config_files
        assert isinstance(result.config_files[str(f)], ConfigFileInfo)

    def test_config_files_nonexistent_skipped(self):
        result = snapshot(config_files=["/nonexistent/file.env"])
        assert result.config_files == {}


class TestSaveLoad:
    def test_roundtrip(self, tmp_path):
        snap = snapshot(label="roundtrip-test")
        path = str(tmp_path / "snap.json")
        save(snap, path)
        loaded = load(path)

        assert loaded.metadata.label == "roundtrip-test"
        assert loaded.metadata.timestamp == snap.metadata.timestamp
        assert loaded.metadata.hostname == snap.metadata.hostname
        assert loaded.python.version == snap.python.version
        assert loaded.python.implementation == snap.python.implementation
        assert loaded.os_info.system == snap.os_info.system
        assert loaded.paths.sys_path == snap.paths.sys_path

    def test_roundtrip_with_config_files(self, tmp_path):
        cfg = tmp_path / "test.env"
        cfg.write_text("KEY=value\n")
        snap = snapshot(config_files=[str(cfg)])
        path = str(tmp_path / "snap.json")
        save(snap, path)
        loaded = load(path)

        assert str(cfg) in loaded.config_files
        info = loaded.config_files[str(cfg)]
        assert isinstance(info, ConfigFileInfo)
        assert info.keys == ["KEY"]

    def test_roundtrip_packages_preserved(self, tmp_path):
        snap = snapshot()
        path = str(tmp_path / "snap.json")
        save(snap, path)
        loaded = load(path)

        for name, pkg in snap.packages.items():
            assert name in loaded.packages
            assert loaded.packages[name].version == pkg.version

    def test_save_creates_valid_json(self, tmp_path):
        snap = snapshot()
        path = str(tmp_path / "snap.json")
        save(snap, path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "metadata" in data
        assert "python" in data
        assert "packages" in data

    def test_save_uses_indent(self, tmp_path):
        snap = snapshot()
        path = str(tmp_path / "snap.json")
        save(snap, path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        # indent=2 means lines should start with spaces
        assert "\n  " in content

    def test_load_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load("/nonexistent/snap.json")

    def test_load_invalid_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not json at all")
        with pytest.raises(json.JSONDecodeError):
            load(str(path))

    def test_load_missing_required_keys(self, tmp_path):
        path = tmp_path / "partial.json"
        path.write_text(json.dumps({"metadata": {}}))
        with pytest.raises(ValueError, match="missing required keys"):
            load(str(path))

    def test_load_missing_multiple_keys(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text("{}")
        with pytest.raises(ValueError, match="metadata"):
            load(str(path))

    def test_asdict_roundtrip_equivalence(self, tmp_path):
        snap = snapshot()
        path = str(tmp_path / "snap.json")
        save(snap, path)
        loaded = load(path)
        assert dataclasses.asdict(snap) == dataclasses.asdict(loaded)

    def test_roundtrip_project_preserved(self, tmp_path):
        snap = snapshot()
        path = str(tmp_path / "snap.json")
        save(snap, path)
        loaded = load(path)
        # Both should have project (may be None if no pyproject.toml in cwd)
        if snap.project is not None:
            assert isinstance(loaded.project, ProjectInfo)
            assert loaded.project.name == snap.project.name
            assert loaded.project.version == snap.project.version
            assert loaded.project.dependencies == snap.project.dependencies
        else:
            assert loaded.project is None

    def test_roundtrip_project_explicit(self, tmp_path):
        """Roundtrip a snapshot with an explicit ProjectInfo."""
        from pycheckem.snapshot import _from_dict

        snap = snapshot(label="project-test")
        # Inject a known project
        snap_dict = dataclasses.asdict(snap)
        snap_dict["project"] = {
            "name": "testpkg",
            "version": "2.0.0",
            "requires_python": ">=3.9",
            "dependencies": ["click", "flask"],
            "source_file": "pyproject.toml",
        }
        path = str(tmp_path / "snap.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snap_dict, f, indent=2)
        loaded = load(path)
        assert loaded.project is not None
        assert loaded.project.name == "testpkg"
        assert loaded.project.version == "2.0.0"
        assert loaded.project.dependencies == ["click", "flask"]

    def test_roundtrip_plugins_preserved(self, tmp_path):
        snap = snapshot()
        path = str(tmp_path / "snap.json")
        save(snap, path)
        loaded = load(path)
        assert isinstance(loaded.plugins, dict)
        assert loaded.plugins == snap.plugins

    def test_roundtrip_plugins_explicit(self, tmp_path):
        """Roundtrip a snapshot with explicit plugin data."""
        snap = snapshot(label="plugin-test")
        snap_dict = dataclasses.asdict(snap)
        snap_dict["plugins"] = {
            "my_collector": {"status": "ok", "items": [1, 2, 3]},
        }
        path = str(tmp_path / "snap.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snap_dict, f, indent=2)
        loaded = load(path)
        assert "my_collector" in loaded.plugins
        assert loaded.plugins["my_collector"]["status"] == "ok"
        assert loaded.plugins["my_collector"]["items"] == [1, 2, 3]

    def test_load_missing_project_defaults_none(self, tmp_path):
        """Old snapshots without project/plugins fields still load."""
        snap = snapshot()
        snap_dict = dataclasses.asdict(snap)
        snap_dict.pop("project", None)
        snap_dict.pop("plugins", None)
        path = str(tmp_path / "snap.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snap_dict, f, indent=2)
        loaded = load(path)
        assert loaded.project is None
        assert loaded.plugins == {}

    def test_load_old_snapshot_without_source_fields(self, tmp_path):
        """Old snapshots lacking install_source fields load with defaults."""
        snap = snapshot()
        snap_dict = dataclasses.asdict(snap)
        for pkg_data in snap_dict["packages"].values():
            pkg_data.pop("install_source", None)
            pkg_data.pop("source_url", None)
            pkg_data.pop("source_detail", None)
        path = str(tmp_path / "old_snap.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snap_dict, f, indent=2)
        loaded = load(path)
        for pkg in loaded.packages.values():
            assert pkg.install_source == "pypi"
            assert pkg.source_url is None
            assert pkg.source_detail is None

    def test_roundtrip_preserves_source_fields(self, tmp_path):
        """Source fields survive save/load roundtrip."""
        snap = snapshot(label="source-test")
        path = str(tmp_path / "snap.json")
        save(snap, path)
        loaded = load(path)
        for name, pkg in snap.packages.items():
            assert loaded.packages[name].install_source == pkg.install_source
