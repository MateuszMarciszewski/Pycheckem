from __future__ import annotations

from unittest.mock import patch

from pycheckem.diff import diff
from pycheckem.render.rich import render_rich
from pycheckem.types import (
    OSInfo,
    PackageInfo,
    PathInfo,
    PythonInfo,
    Snapshot,
    SnapshotMetadata,
)


def _make_snapshot(**overrides):
    defaults = dict(
        metadata=SnapshotMetadata(
            timestamp="2026-03-02T12:00:00Z",
            hostname="host-a",
            label="staging",
            pycheckem_version="0.1.0",
        ),
        python=PythonInfo(
            version="3.11.4",
            implementation="CPython",
            executable="/usr/bin/python3",
            prefix="/usr",
            platform="linux",
        ),
        packages={
            "requests": PackageInfo(
                version="2.31.0", location="/sp", requires=["urllib3"]
            ),
            "flask": PackageInfo(
                version="3.0.0", location="/sp", requires=["werkzeug"]
            ),
        },
        env_vars={"PATH": "/usr/bin", "HOME": "/home/dev", "LOG_LEVEL": "DEBUG"},
        os_info=OSInfo(
            system="Linux", release="6.1.0", machine="x86_64", distro="Ubuntu 22.04"
        ),
        paths=PathInfo(sys_path=["/usr/lib/python3"], path_env=["/usr/bin"]),
        config_files={},
    )
    defaults.update(overrides)
    return Snapshot(**defaults)


class TestRichRendererAvailable:
    """Tests for when rich is available."""

    def test_render_returns_string(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot()
        result = diff(snap_a, snap_b)
        output = render_rich(result)
        assert isinstance(output, str)

    def test_identical_shows_no_differences(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot()
        result = diff(snap_a, snap_b)
        output = render_rich(result)
        assert "No differences" in output

    def test_shows_labels(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
        )
        result = diff(snap_a, snap_b)
        output = render_rich(result)
        assert "staging" in output
        assert "prod" in output

    def test_shows_package_differences(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            packages={
                "requests": PackageInfo("2.28.0", "/sp", ["urllib3"]),
                "flask": PackageInfo("3.0.0", "/sp", ["werkzeug"]),
                "gunicorn": PackageInfo("21.2.0", "/sp", []),
            },
        )
        result = diff(snap_a, snap_b)
        output = render_rich(result)
        assert "gunicorn" in output
        assert "requests" in output

    def test_shows_env_var_differences(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            env_vars={"PATH": "/usr/bin", "HOME": "/home/dev", "LOG_LEVEL": "WARNING"},
        )
        result = diff(snap_a, snap_b)
        output = render_rich(result)
        assert "LOG_LEVEL" in output

    def test_shows_summary(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            packages={
                "requests": PackageInfo("2.28.0", "/sp", ["urllib3"]),
                "flask": PackageInfo("3.0.0", "/sp", ["werkzeug"]),
            },
        )
        result = diff(snap_a, snap_b)
        output = render_rich(result)
        assert "Summary" in output

    def test_only_filter(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            packages={
                "requests": PackageInfo("2.28.0", "/sp", ["urllib3"]),
                "flask": PackageInfo("3.0.0", "/sp", ["werkzeug"]),
            },
            env_vars={"PATH": "/usr/bin", "HOME": "/home/dev", "NEW_VAR": "val"},
        )
        result = diff(snap_a, snap_b)
        output = render_rich(result, only="packages")
        assert "requests" in output

    def test_breaking_changes_shown(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            packages={
                "requests": PackageInfo("2.28.0", "/sp", ["urllib3"]),
                "flask": PackageInfo("3.0.0", "/sp", ["werkzeug"]),
            },
        )
        result = diff(snap_a, snap_b)
        output = render_rich(result)
        assert "Breaking" in output


class TestRichFallback:
    """Tests for graceful fallback when rich is not available."""

    def test_fallback_to_ascii(self):
        """When _RICH_AVAILABLE is False, render_rich should delegate to render_ascii."""
        snap_a = _make_snapshot()
        snap_b = _make_snapshot()
        result = diff(snap_a, snap_b)

        with patch("pycheckem.render.rich._RICH_AVAILABLE", False):
            output = render_rich(result)

        from pycheckem.render.ascii import render_ascii

        expected = render_ascii(result)
        assert output == expected

    def test_fallback_with_differences(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            packages={
                "requests": PackageInfo("2.28.0", "/sp", ["urllib3"]),
                "flask": PackageInfo("3.0.0", "/sp", ["werkzeug"]),
            },
        )
        result = diff(snap_a, snap_b)

        with patch("pycheckem.render.rich._RICH_AVAILABLE", False):
            output = render_rich(result)

        from pycheckem.render.ascii import render_ascii

        expected = render_ascii(result)
        assert output == expected

    def test_fallback_with_only_filter(self):
        snap_a = _make_snapshot()
        snap_b = _make_snapshot(
            metadata=SnapshotMetadata(
                "2026-03-02T12:00:00Z", "host-b", "prod", "0.1.0"
            ),
            packages={
                "requests": PackageInfo("2.28.0", "/sp", ["urllib3"]),
                "flask": PackageInfo("3.0.0", "/sp", ["werkzeug"]),
            },
        )
        result = diff(snap_a, snap_b)

        with patch("pycheckem.render.rich._RICH_AVAILABLE", False):
            output = render_rich(result, only="packages")

        from pycheckem.render.ascii import render_ascii

        expected = render_ascii(result, only="packages")
        assert output == expected
