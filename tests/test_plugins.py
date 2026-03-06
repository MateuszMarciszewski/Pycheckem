from __future__ import annotations

from unittest.mock import MagicMock, patch

from pycheckem.plugins import discover_plugins, run_plugins


class TestDiscoverPlugins:
    def test_no_plugins_returns_empty(self):
        with patch("pycheckem.plugins.entry_points") as mock_eps:
            mock_eps.return_value = {}
            result = discover_plugins()
            assert result == {}

    def test_discovers_entry_points_dict_form(self):
        """Python 3.8-3.9 returns a dict from entry_points()."""
        ep = MagicMock()
        ep.name = "my_collector"
        ep.load.return_value = lambda: {"key": "value"}

        with patch("pycheckem.plugins.entry_points") as mock_eps:
            mock_eps.return_value = {"pycheckem.collectors": [ep]}
            result = discover_plugins()

            assert "my_collector" in result
            assert callable(result["my_collector"])

    def test_discovers_entry_points_select_form(self):
        """Python 3.10+ returns SelectableGroups with .select()."""
        ep = MagicMock()
        ep.name = "my_collector"
        ep.load.return_value = lambda: {"key": "value"}

        mock_eps_result = MagicMock()
        mock_eps_result.select.return_value = [ep]
        # Not a dict
        mock_eps_result.__class__ = type("SelectableGroups", (), {})

        with patch("pycheckem.plugins.entry_points") as mock_eps:
            mock_eps.return_value = mock_eps_result
            result = discover_plugins()

            assert "my_collector" in result

    def test_load_error_skipped(self):
        """Plugin entry points that fail to load are skipped."""
        ep = MagicMock()
        ep.name = "bad_plugin"
        ep.load.side_effect = ImportError("missing module")

        with patch("pycheckem.plugins.entry_points") as mock_eps:
            mock_eps.return_value = {"pycheckem.collectors": [ep]}
            result = discover_plugins()
            assert result == {}


class TestRunPlugins:
    def test_runs_discovered_plugins(self):
        plugin_func = MagicMock(return_value={"db_version": "14.2"})

        with patch("pycheckem.plugins.discover_plugins") as mock_discover:
            mock_discover.return_value = {"db_checker": plugin_func}
            result = run_plugins()

            assert "db_checker" in result
            assert result["db_checker"] == {"db_version": "14.2"}
            plugin_func.assert_called_once()

    def test_plugin_exception_recorded(self):
        plugin_func = MagicMock(side_effect=RuntimeError("boom"))

        with patch("pycheckem.plugins.discover_plugins") as mock_discover:
            mock_discover.return_value = {"bad_plugin": plugin_func}
            result = run_plugins()

            assert "bad_plugin" in result
            assert "_error" in result["bad_plugin"]
            assert "boom" in result["bad_plugin"]["_error"]

    def test_non_dict_return_ignored(self):
        plugin_func = MagicMock(return_value="not a dict")

        with patch("pycheckem.plugins.discover_plugins") as mock_discover:
            mock_discover.return_value = {"string_plugin": plugin_func}
            result = run_plugins()

            assert "string_plugin" not in result

    def test_empty_plugins(self):
        with patch("pycheckem.plugins.discover_plugins") as mock_discover:
            mock_discover.return_value = {}
            result = run_plugins()
            assert result == {}

    def test_multiple_plugins(self):
        func_a = MagicMock(return_value={"a": 1})
        func_b = MagicMock(return_value={"b": 2})

        with patch("pycheckem.plugins.discover_plugins") as mock_discover:
            mock_discover.return_value = {"plugin_a": func_a, "plugin_b": func_b}
            result = run_plugins()

            assert result["plugin_a"] == {"a": 1}
            assert result["plugin_b"] == {"b": 2}


class TestPluginSnapshotIntegration:
    def test_snapshot_roundtrip_with_plugins(self, tmp_path):
        """Plugin data survives save/load roundtrip."""
        from pycheckem.snapshot import load, save, snapshot as take_snapshot

        with patch("pycheckem.snapshot.run_plugins") as mock_run:
            mock_run.return_value = {"my_plugin": {"version": "1.0"}}
            snap = take_snapshot(label="test")

        assert snap.plugins == {"my_plugin": {"version": "1.0"}}

        path = str(tmp_path / "snap.json")
        save(snap, path)
        loaded = load(path)

        assert loaded.plugins == {"my_plugin": {"version": "1.0"}}

    def test_load_old_snapshot_without_plugins(self, tmp_path):
        """Snapshots saved before plugin support should load with plugins={}."""
        import json

        # Simulate an old snapshot without "plugins" key
        data = {
            "metadata": {
                "timestamp": "2026-03-02T12:00:00Z",
                "hostname": "test",
                "label": "old",
                "pycheckem_version": "0.1.0",
            },
            "python": {
                "version": "3.11.4",
                "implementation": "CPython",
                "executable": "/usr/bin/python3",
                "prefix": "/usr",
                "platform": "linux",
            },
            "packages": {},
            "env_vars": {},
            "os_info": {
                "system": "Linux",
                "release": "6.1.0",
                "machine": "x86_64",
                "distro": "Ubuntu 22.04",
            },
            "paths": {"sys_path": [], "path_env": []},
        }
        path = str(tmp_path / "old.json")
        with open(path, "w") as f:
            json.dump(data, f)

        from pycheckem.snapshot import load

        snap = load(path)
        assert snap.plugins == {}
