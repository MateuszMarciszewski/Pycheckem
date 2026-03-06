from __future__ import annotations

import dataclasses
import json

from pycheckem.diff import diff
from pycheckem.render.json import render_json
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
        },
        env_vars={"PATH": "/usr/bin"},
        os_info=OSInfo(
            system="Linux", release="6.1.0", machine="x86_64", distro="Ubuntu 22.04"
        ),
        paths=PathInfo(sys_path=["/usr/lib/python3"], path_env=["/usr/bin"]),
        config_files={},
    )
    defaults.update(overrides)
    return Snapshot(**defaults)


class TestRenderJson:
    def test_output_is_valid_json(self):
        snap = _make_snapshot()
        result = diff(snap, snap)
        output = render_json(result)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_roundtrip_matches_asdict(self):
        snap = _make_snapshot()
        result = diff(snap, snap)
        output = render_json(result)
        parsed = json.loads(output)
        expected = dataclasses.asdict(result)
        assert parsed == expected

    def test_all_top_level_fields_present(self):
        snap = _make_snapshot()
        result = diff(snap, snap)
        output = render_json(result)
        parsed = json.loads(output)
        for key in (
            "label_a",
            "label_b",
            "python",
            "packages",
            "env_vars",
            "os_info",
            "paths",
            "config_files",
            "summary",
        ):
            assert key in parsed

    def test_summary_fields(self):
        snap = _make_snapshot()
        result = diff(snap, snap)
        output = render_json(result)
        parsed = json.loads(output)
        summary = parsed["summary"]
        assert "total_differences" in summary
        assert "severity" in summary
        assert "breaking_changes" in summary

    def test_diff_with_changes(self):
        a = _make_snapshot()
        b = _make_snapshot(
            packages={
                "requests": PackageInfo("3.0.0", "/sp", ["urllib3"]),
            }
        )
        result = diff(a, b)
        output = render_json(result)
        parsed = json.loads(output)
        assert parsed["packages"]["changed"]["requests"]["is_major"] is True

    def test_output_is_pretty_printed(self):
        snap = _make_snapshot()
        result = diff(snap, snap)
        output = render_json(result)
        # Pretty-printed JSON has newlines
        assert "\n" in output
