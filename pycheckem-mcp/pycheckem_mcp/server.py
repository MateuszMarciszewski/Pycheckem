"""pycheckem MCP server — exposes environment snapshot, diff, and verify as tools.

Run with:
    pycheckem-mcp          # after pip install pycheckem-mcp
    python -m pycheckem_mcp.server   # from source
"""

from __future__ import annotations

from fastmcp import FastMCP

mcp = FastMCP(
    "pycheckem",
    description=(
        "Python environment parity checker. Snapshot installed packages, "
        "Python version, OS details, and environment variables, then diff "
        "two environments to find mismatches."
    ),
)


@mcp.tool
def snapshot_environment(
    output_path: str = "environment-snapshot.json",
    label: str | None = None,
) -> str:
    """Capture the current Python environment as a JSON snapshot file.

    Use this when a user wants to record what packages are installed,
    their Python version, OS details, and environment variables — for
    later comparison or as a baseline for drift detection.

    Args:
        output_path: Where to save the snapshot file.
        label: Human-readable label (e.g. "dev", "staging", "prod").

    Returns:
        Confirmation with file path and summary of what was captured.
    """
    import pycheckem

    snap = pycheckem.snapshot(label=label)
    pycheckem.save(snap, output_path)

    pkg_count = len(snap.packages)
    py_version = snap.python.version
    return (
        f"Snapshot saved to {output_path}\n"
        f"  Python: {py_version}\n"
        f"  Packages: {pkg_count}\n"
        f"  OS: {snap.os_info.system} {snap.os_info.machine}\n"
        f"  Label: {label or '(none)'}"
    )


@mcp.tool
def diff_environments(
    snapshot_a: str,
    snapshot_b: str,
) -> str:
    """Compare two saved environment snapshots and report all differences.

    Use this when a user asks about environment mismatches, dependency
    drift, or why something works locally but fails in CI/production.

    Args:
        snapshot_a: Path to the first snapshot file (baseline).
        snapshot_b: Path to the second snapshot file (target).

    Returns:
        A structured report of all differences between the two environments.
    """
    import pycheckem
    from pycheckem.render.ascii import render_ascii

    snap_a = pycheckem.load(snapshot_a)
    snap_b = pycheckem.load(snapshot_b)
    result = pycheckem.diff(snap_a, snap_b)

    return render_ascii(result)


@mcp.tool
def compare_environment(
    baseline_snapshot: str,
) -> str:
    """Compare the current live environment against a saved baseline snapshot.

    Use this to check if the current environment has drifted from a
    known-good state — for CI validation, deployment checks, or
    debugging "works on my machine" issues.

    Args:
        baseline_snapshot: Path to the baseline snapshot file.

    Returns:
        A report showing differences between the baseline and current environment.
    """
    import pycheckem
    from pycheckem.render.ascii import render_ascii

    baseline = pycheckem.load(baseline_snapshot)
    live = pycheckem.snapshot(label="live")
    result = pycheckem.diff(baseline, live)

    return render_ascii(result)


@mcp.tool
def verify_dependencies(
    deps_file: str,
    include_extras: bool = False,
) -> str:
    """Check if installed packages satisfy declared dependencies.

    Compares a requirements.txt or pyproject.toml against the actually
    installed packages. Reports missing packages, version mismatches,
    and optionally extra packages not in the declared list.

    Args:
        deps_file: Path to requirements.txt or pyproject.toml.
        include_extras: If True, also report installed packages not
            in the declared list.

    Returns:
        A report showing missing, mismatched, and extra packages.
    """
    from pycheckem.parsers import parse_requirements, parse_pyproject_deps
    from pycheckem.verify import verify, render_verify

    if deps_file.endswith(".toml"):
        declared = parse_pyproject_deps(deps_file)
    else:
        declared = parse_requirements(deps_file)

    result = verify(declared, include_extras=include_extras)
    return render_verify(result)


def main():
    """Entry point for the pycheckem-mcp CLI."""
    mcp.run()


if __name__ == "__main__":
    main()
