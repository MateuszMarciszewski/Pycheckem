import argparse
import sys

from pycheckem.version import __version__


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="pycheckem",
        description=(
            "Snapshot and diff Python runtime environments to debug "
            "\"works on my machine\" parity issues across dev, staging, "
            "prod, and containers."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"pycheckem {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # snapshot subcommand
    snap_parser = subparsers.add_parser(
        "snapshot", help="Capture a snapshot of the current environment"
    )
    snap_parser.add_argument("-o", "--output", required=True, help="Output file path")
    snap_parser.add_argument("--label", default=None, help="Label for this snapshot")
    snap_parser.add_argument(
        "--config-files", nargs="*", default=[], help="Config files to hash"
    )
    snap_parser.add_argument(
        "--include-sensitive",
        action="store_true",
        help="Include sensitive environment variables",
    )

    # diff subcommand
    diff_parser = subparsers.add_parser("diff", help="Diff two snapshots")
    diff_parser.add_argument("snapshot_a", help="First snapshot file")
    diff_parser.add_argument("snapshot_b", help="Second snapshot file")
    diff_parser.add_argument(
        "--format",
        choices=["ascii", "json", "rich", "side-by-side", "sbs"],
        default="ascii",
        help="Output format (default: ascii)",
    )
    diff_parser.add_argument(
        "--only",
        choices=["packages", "env", "python", "os", "paths", "config", "project"],
        default=None,
        help="Only show a specific section",
    )
    diff_parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with non-zero status if differences found",
    )
    diff_parser.add_argument(
        "--fail-severity",
        choices=["minor", "major", "critical"],
        default="minor",
        help="Minimum severity to trigger non-zero exit (default: minor)",
    )
    diff_parser.add_argument(
        "--ignore-packages",
        default=None,
        help="Comma-separated packages to ignore in diff",
    )
    diff_parser.add_argument(
        "--ignore-env-vars",
        default=None,
        help="Comma-separated env vars to ignore in diff",
    )
    diff_parser.add_argument(
        "--ignore-patterns",
        default=None,
        help="Comma-separated regex patterns to ignore in diff",
    )

    # compare subcommand
    compare_parser = subparsers.add_parser(
        "compare",
        help="Snapshot current env and diff against a saved snapshot",
    )
    compare_parser.add_argument("snapshot", help="Saved snapshot file to compare against")
    compare_parser.add_argument(
        "--format",
        choices=["ascii", "json", "rich", "side-by-side", "sbs"],
        default="ascii",
        help="Output format (default: ascii)",
    )
    compare_parser.add_argument(
        "--only",
        choices=["packages", "env", "python", "os", "paths", "config", "project"],
        default=None,
        help="Only show a specific section",
    )
    compare_parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with non-zero status if differences found",
    )
    compare_parser.add_argument(
        "--fail-severity",
        choices=["minor", "major", "critical"],
        default="minor",
        help="Minimum severity to trigger non-zero exit (default: minor)",
    )
    compare_parser.add_argument(
        "--label", default=None, help="Label for the live snapshot",
    )
    compare_parser.add_argument(
        "--config-files", nargs="*", default=[], help="Config files to hash",
    )
    compare_parser.add_argument(
        "--include-sensitive",
        action="store_true",
        help="Include sensitive environment variables",
    )
    compare_parser.add_argument(
        "--ignore-packages",
        default=None,
        help="Comma-separated packages to ignore in diff",
    )
    compare_parser.add_argument(
        "--ignore-env-vars",
        default=None,
        help="Comma-separated env vars to ignore in diff",
    )
    compare_parser.add_argument(
        "--ignore-patterns",
        default=None,
        help="Comma-separated regex patterns to ignore in diff",
    )

    # history subcommand
    history_parser = subparsers.add_parser(
        "history", help="Manage snapshot history"
    )
    history_sub = history_parser.add_subparsers(
        dest="history_action", metavar="ACTION"
    )

    # history add
    hist_add = history_sub.add_parser("add", help="Add a snapshot to history")
    hist_add.add_argument("snapshot_file", help="Snapshot file to add")
    hist_add.add_argument(
        "--dir", default=None,
        help="Base directory for history store (default: cwd)",
    )

    # history show
    hist_show = history_sub.add_parser("show", help="List snapshots in history")
    hist_show.add_argument(
        "--dir", default=None,
        help="Base directory for history store (default: cwd)",
    )

    # history diff
    hist_diff = history_sub.add_parser(
        "diff", help="Diff the last N snapshots from history"
    )
    hist_diff.add_argument(
        "--last", type=int, default=2,
        help="Number of recent snapshots to diff (default: 2)",
    )
    hist_diff.add_argument(
        "--format",
        choices=["ascii", "json", "rich", "side-by-side", "sbs"],
        default="ascii",
        help="Output format (default: ascii)",
    )
    hist_diff.add_argument(
        "--only",
        choices=["packages", "env", "python", "os", "paths", "config", "project"],
        default=None,
        help="Only show a specific section",
    )
    hist_diff.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with non-zero status if differences found",
    )
    hist_diff.add_argument(
        "--fail-severity",
        choices=["minor", "major", "critical"],
        default="minor",
        help="Minimum severity to trigger non-zero exit (default: minor)",
    )
    hist_diff.add_argument(
        "--ignore-packages", default=None,
        help="Comma-separated packages to ignore in diff",
    )
    hist_diff.add_argument(
        "--ignore-env-vars", default=None,
        help="Comma-separated env vars to ignore in diff",
    )
    hist_diff.add_argument(
        "--ignore-patterns", default=None,
        help="Comma-separated regex patterns to ignore in diff",
    )
    hist_diff.add_argument(
        "--dir", default=None,
        help="Base directory for history store (default: cwd)",
    )

    # remote subcommand
    remote_parser = subparsers.add_parser(
        "remote",
        help="Snapshot remote host(s) via SSH and diff",
    )
    remote_parser.add_argument(
        "hosts", nargs="+", metavar="HOST",
        help="SSH host(s) to snapshot (1 = diff vs local, 2 = diff both)",
    )
    remote_parser.add_argument(
        "--format",
        choices=["ascii", "json", "rich", "side-by-side", "sbs"],
        default="ascii",
        help="Output format (default: ascii)",
    )
    remote_parser.add_argument(
        "--only",
        choices=["packages", "env", "python", "os", "paths", "config", "project"],
        default=None,
        help="Only show a specific section",
    )
    remote_parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with non-zero status if differences found",
    )
    remote_parser.add_argument(
        "--fail-severity",
        choices=["minor", "major", "critical"],
        default="minor",
        help="Minimum severity to trigger non-zero exit (default: minor)",
    )
    remote_parser.add_argument(
        "--label", default=None,
        help="Label for the local snapshot (when using 1 host)",
    )
    remote_parser.add_argument(
        "--timeout", type=int, default=30,
        help="SSH timeout in seconds (default: 30)",
    )
    remote_parser.add_argument(
        "--ignore-packages", default=None,
        help="Comma-separated packages to ignore in diff",
    )
    remote_parser.add_argument(
        "--ignore-env-vars", default=None,
        help="Comma-separated env vars to ignore in diff",
    )
    remote_parser.add_argument(
        "--ignore-patterns", default=None,
        help="Comma-separated regex patterns to ignore in diff",
    )

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return

    if args.command == "snapshot":
        from pycheckem.snapshot import snapshot as take_snapshot, save, to_json

        try:
            snap = take_snapshot(
                label=args.label,
                config_files=args.config_files if args.config_files else None,
                include_sensitive=args.include_sensitive,
            )
        except Exception as exc:
            print(f"Error creating snapshot: {exc}", file=sys.stderr)
            sys.exit(1)

        if args.output == "-":
            print(to_json(snap))
        else:
            try:
                save(snap, args.output)
            except OSError as exc:
                print(f"Error writing file: {exc}", file=sys.stderr)
                sys.exit(1)

            label_msg = f" (label: {args.label})" if args.label else ""
            print(f"Snapshot saved to {args.output}{label_msg}")

    elif args.command == "diff":
        from pycheckem.snapshot import load

        snap_a = _load_snapshot(args.snapshot_a)
        snap_b = _load_snapshot(args.snapshot_b)
        result = _diff_and_render(snap_a, snap_b, args)

    elif args.command == "compare":
        from pycheckem.snapshot import snapshot as take_snapshot, load

        saved = _load_snapshot(args.snapshot)

        try:
            live = take_snapshot(
                label=args.label,
                config_files=args.config_files if args.config_files else None,
                include_sensitive=args.include_sensitive,
            )
        except Exception as exc:
            print(f"Error creating snapshot: {exc}", file=sys.stderr)
            sys.exit(1)

        result = _diff_and_render(saved, live, args)

    elif args.command == "history":
        from pycheckem.history import add as hist_add, list_snapshots, get_last_n

        if args.history_action is None:
            history_parser.print_help()
            return

        if args.history_action == "add":
            try:
                dest = hist_add(args.snapshot_file, base_dir=args.dir)
            except FileNotFoundError:
                print(
                    f"Error: file not found: {args.snapshot_file}",
                    file=sys.stderr,
                )
                sys.exit(1)
            except Exception as exc:
                print(f"Error adding to history: {exc}", file=sys.stderr)
                sys.exit(1)
            print(f"Added to history: {dest}")

        elif args.history_action == "show":
            entries = list_snapshots(base_dir=args.dir)
            if not entries:
                print("No snapshots in history.")
            else:
                for fname, ts, label in entries:
                    label_str = label or "(no label)"
                    print(f"  {ts}  {label_str}  [{fname}]")

        elif args.history_action == "diff":
            snapshots = get_last_n(args.last, base_dir=args.dir)
            if len(snapshots) < 2:
                print(
                    "Error: need at least 2 snapshots in history to diff "
                    f"(found {len(snapshots)})",
                    file=sys.stderr,
                )
                sys.exit(1)
            # Diff the oldest vs newest of the selected snapshots
            result = _diff_and_render(snapshots[0], snapshots[-1], args)

    elif args.command == "remote":
        from pycheckem.remote import snapshot_remote

        hosts = args.hosts
        if len(hosts) > 2:
            print("Error: at most 2 hosts supported", file=sys.stderr)
            sys.exit(1)

        try:
            if len(hosts) == 1:
                # Diff remote vs local
                from pycheckem.snapshot import snapshot as take_snapshot

                remote_snap = snapshot_remote(
                    hosts[0], label=hosts[0], timeout=args.timeout
                )
                local_snap = take_snapshot(label=args.label)
                result = _diff_and_render(remote_snap, local_snap, args)
            else:
                # Diff two remote hosts
                snap_a = snapshot_remote(
                    hosts[0], label=hosts[0], timeout=args.timeout
                )
                snap_b = snapshot_remote(
                    hosts[1], label=hosts[1], timeout=args.timeout
                )
                result = _diff_and_render(snap_a, snap_b, args)
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)


def _load_snapshot(path):
    """Load a snapshot file with friendly error messages."""
    import json as _json

    from pycheckem.snapshot import load

    try:
        return load(path)
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except _json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in {path}: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: invalid snapshot file {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def _build_suppression_config(args):
    """Build a SuppressionConfig from CLI flags, merged with pyproject.toml config."""
    from pycheckem.config import SuppressionConfig, load_config

    config = load_config()
    suppression = config.suppression

    # Merge CLI flags (extend, not replace)
    ignore_packages = list(suppression.ignore_packages)
    ignore_env_vars = list(suppression.ignore_env_vars)
    ignore_patterns = list(suppression.ignore_patterns)

    cli_pkgs = getattr(args, "ignore_packages", None)
    if cli_pkgs:
        ignore_packages.extend(p.strip() for p in cli_pkgs.split(",") if p.strip())

    cli_vars = getattr(args, "ignore_env_vars", None)
    if cli_vars:
        ignore_env_vars.extend(v.strip() for v in cli_vars.split(",") if v.strip())

    cli_pats = getattr(args, "ignore_patterns", None)
    if cli_pats:
        ignore_patterns.extend(p.strip() for p in cli_pats.split(",") if p.strip())

    return SuppressionConfig(
        ignore_packages=ignore_packages,
        ignore_env_vars=ignore_env_vars,
        ignore_patterns=ignore_patterns,
    )


def _diff_and_render(snap_a, snap_b, args):
    """Diff two snapshots, render output, and handle exit code logic.

    Returns the DiffResult for further inspection if needed.
    """
    from pycheckem.diff import diff as do_diff
    from pycheckem.suppression import apply_suppression

    result = do_diff(snap_a, snap_b)

    # Apply suppression rules from config + CLI flags
    suppression = _build_suppression_config(args)
    result = apply_suppression(result, suppression)

    fmt = args.format
    if fmt == "json":
        from pycheckem.render.json import render_json
        print(render_json(result))
    elif fmt == "rich":
        from pycheckem.render.rich import render_rich
        print(render_rich(result, only=getattr(args, "only", None)))
    elif fmt in ("side-by-side", "sbs"):
        from pycheckem.render.side_by_side import render_side_by_side
        print(render_side_by_side(result, only=getattr(args, "only", None)))
    else:
        from pycheckem.render.ascii import render_ascii
        print(render_ascii(result, only=getattr(args, "only", None)))

    if args.exit_code:
        severity_order = {"identical": 0, "minor": 1, "major": 2, "critical": 3}
        threshold = severity_order[args.fail_severity]
        actual = severity_order[result.summary.severity]
        if actual >= threshold:
            sys.exit(1)

    return result
