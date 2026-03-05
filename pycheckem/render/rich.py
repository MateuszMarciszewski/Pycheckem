from __future__ import annotations

from typing import List, Optional

from pycheckem.diff import is_major_change
from pycheckem.types import (
    ConfigDiff,
    DiffResult,
    OSDiff,
    PackageDiff,
    PathDiff,
    ProjectDiff,
    PythonDiff,
    VarDiff,
)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False


def _section_python(python):
    # type: (Optional[PythonDiff]) -> Optional[Table]
    if python is None:
        return None
    table = Table(title="Python", show_header=True, title_style="bold cyan")
    table.add_column("Field", style="bold")
    table.add_column("Old")
    table.add_column("New")
    table.add_column("Note", style="yellow")
    for field, (old, new) in python.changes.items():
        note = ""
        if field == "version":
            if is_major_change(old, new):
                note = "MAJOR VERSION MISMATCH"
            else:
                note = "MINOR VERSION MISMATCH"
        table.add_row(field.capitalize(), old, new, note)
    return table


def _section_packages(packages):
    # type: (PackageDiff) -> Optional[Table]
    source_changed = getattr(packages, "source_changed", {})
    total = (len(packages.added) + len(packages.removed)
             + len(packages.changed) + len(source_changed))
    if total == 0:
        return None
    n = "difference" if total == 1 else "differences"
    table = Table(
        title="Packages ({} {})".format(total, n),
        show_header=True,
        title_style="bold cyan",
    )
    table.add_column("Change", style="bold")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Note", style="yellow")
    for name, ver in sorted(packages.added.items()):
        table.add_row("[green]+[/green]", name, ver, "")
    for name, ver in sorted(packages.removed.items()):
        table.add_row("[red]-[/red]", name, ver, "")
    for name, vc in sorted(packages.changed.items()):
        ver_str = "{} \u2192 {}".format(vc.version_a, vc.version_b)
        note = ""
        if vc.is_major:
            note = "MAJOR VERSION CHANGE"
        elif vc.is_downgrade:
            note = "DOWNGRADE"
        if getattr(vc, "source_a", "pypi") != getattr(vc, "source_b", "pypi"):
            note += " [{}]\u2192[{}]".format(vc.source_a, vc.source_b)
        table.add_row("[yellow]~[/yellow]", name, ver_str, note.strip())
    for name, sc in sorted(source_changed.items()):
        src_str = "[{}] \u2192 [{}]".format(sc.source_a, sc.source_b)
        table.add_row("[yellow]~[/yellow]", name, src_str, "SOURCE CHANGED")
    return table


def _section_env_vars(env_vars):
    # type: (VarDiff) -> Optional[Table]
    total = len(env_vars.added) + len(env_vars.removed) + len(env_vars.changed)
    if total == 0:
        return None
    n = "difference" if total == 1 else "differences"
    table = Table(
        title="Environment Variables ({} {})".format(total, n),
        show_header=True,
        title_style="bold cyan",
    )
    table.add_column("Change", style="bold")
    table.add_column("Variable")
    table.add_column("Value")
    for name in sorted(env_vars.added):
        table.add_row("[green]+[/green]", name, "")
    for name in sorted(env_vars.removed):
        table.add_row("[red]-[/red]", name, "")
    for name, (old, new) in sorted(env_vars.changed.items()):
        table.add_row("[yellow]~[/yellow]", name, "{} \u2192 {}".format(old, new))
    return table


def _section_os(os_info):
    # type: (Optional[OSDiff]) -> Optional[Table]
    if os_info is None:
        return None
    table = Table(title="OS", show_header=True, title_style="bold cyan")
    table.add_column("Field", style="bold")
    table.add_column("Old")
    table.add_column("New")
    table.add_column("Note", style="yellow")
    for field, (old, new) in os_info.changes.items():
        note = ""
        if field == "system":
            note = "DIFFERENT OS"
        elif field == "machine":
            note = "DIFFERENT ARCHITECTURE"
        elif field == "distro":
            note = "DIFFERENT DISTRO"
        table.add_row(field.capitalize(), old, new, note)
    return table


def _section_paths(paths):
    # type: (PathDiff) -> Optional[Table]
    total = (len(paths.sys_path_added) + len(paths.sys_path_removed)
             + len(paths.path_env_added) + len(paths.path_env_removed))
    if total == 0:
        return None
    n = "difference" if total == 1 else "differences"
    table = Table(
        title="Paths ({} {})".format(total, n),
        show_header=True,
        title_style="bold cyan",
    )
    table.add_column("Change", style="bold")
    table.add_column("Source")
    table.add_column("Path")
    for p in paths.sys_path_added:
        table.add_row("[green]+[/green]", "sys.path", p)
    for p in paths.sys_path_removed:
        table.add_row("[red]-[/red]", "sys.path", p)
    for p in paths.path_env_added:
        table.add_row("[green]+[/green]", "PATH", p)
    for p in paths.path_env_removed:
        table.add_row("[red]-[/red]", "PATH", p)
    return table


def _section_config_files(config_files):
    # type: (ConfigDiff) -> Optional[Table]
    total = len(config_files.added) + len(config_files.removed) + len(config_files.changed)
    if total == 0:
        return None
    n = "difference" if total == 1 else "differences"
    table = Table(
        title="Config Files ({} {})".format(total, n),
        show_header=True,
        title_style="bold cyan",
    )
    table.add_column("Change", style="bold")
    table.add_column("File")
    table.add_column("Details")
    for name in config_files.added:
        table.add_row("[green]+[/green]", name, "")
    for name in config_files.removed:
        table.add_row("[red]-[/red]", name, "")
    for name, fd in sorted(config_files.changed.items()):
        details_parts = ["HASH MISMATCH"]
        for k in fd.keys_added:
            details_parts.append("  + {}".format(k))
        for k in fd.keys_removed:
            details_parts.append("  - {}".format(k))
        table.add_row("[yellow]~[/yellow]", name, "\n".join(details_parts))
    return table


def _section_project(project):
    # type: (Optional[ProjectDiff]) -> Optional[Table]
    if project is None:
        return None
    table = Table(title="Project", show_header=True, title_style="bold cyan")
    table.add_column("Field", style="bold")
    table.add_column("Old")
    table.add_column("New")
    table.add_column("Note", style="yellow")
    if project.name_changed:
        old, new = project.name_changed
        table.add_row("Name", old, new, "")
    if project.version_changed:
        old, new = project.version_changed
        table.add_row("Version", old, new, "")
    if project.requires_python_changed:
        old, new = project.requires_python_changed
        table.add_row("Requires", old, new, "PYTHON REQUIREMENT CHANGED")
    for dep in project.deps_added:
        table.add_row("[green]+[/green]", dep, "", "")
    for dep in project.deps_removed:
        table.add_row("[red]-[/red]", dep, "", "")
    return table


def render_rich(result, only=None):
    # type: (DiffResult, Optional[str]) -> str
    """Render a DiffResult with color-coded tables using the rich library.

    Produces visually rich output with colored severity indicators,
    styled tables, and panels. Requires ``pip install pycheckem[pretty]``.
    Falls back to plain ASCII rendering if rich is not installed.

    Args:
        result: The DiffResult to render.
        only: If set, render just one section ("packages", "env", "python",
            "os", "paths", "config", "project").

    Returns:
        A string with ANSI color codes (or plain ASCII if rich is missing).

    Example:
        >>> from pycheckem.render import rich
        >>> print(rich(result))
    """
    if not _RICH_AVAILABLE:
        from pycheckem.render.ascii import render_ascii
        return render_ascii(result, only=only)

    console = Console(record=True, force_terminal=True)

    header = Text("pycheckem: {} vs {}".format(result.label_a, result.label_b))
    header.stylize("bold")
    console.print(header)

    if result.summary.severity == "identical" and only is None:
        console.print("[green]No differences found.[/green]")
        return console.export_text()

    section_map = {
        "python": lambda: _section_python(result.python),
        "packages": lambda: _section_packages(result.packages),
        "env": lambda: _section_env_vars(result.env_vars),
        "os": lambda: _section_os(result.os_info),
        "paths": lambda: _section_paths(result.paths),
        "config": lambda: _section_config_files(result.config_files),
        "project": lambda: _section_project(getattr(result, "project", None)),
    }

    if only is not None:
        fn = section_map.get(only)
        if fn is not None:
            table = fn()
            if table is not None:
                console.print(table)
    else:
        for key in ("python", "packages", "env", "os", "paths", "config", "project"):
            table = section_map[key]()
            if table is not None:
                console.print(table)

    severity = result.summary.severity.upper()
    severity_color = {
        "IDENTICAL": "green",
        "MINOR": "yellow",
        "MAJOR": "red",
        "CRITICAL": "bold red",
    }.get(severity, "white")

    n = result.summary.total_differences
    summary_text = "Summary: {} {} | Severity: [{}]{}[/{}]".format(
        n,
        "difference" if n == 1 else "differences",
        severity_color,
        severity,
        severity_color,
    )
    console.print(Panel(summary_text, title="Result", border_style="dim"))

    if result.summary.breaking_changes:
        breaking = ", ".join(result.summary.breaking_changes)
        console.print("[bold red]Breaking:[/bold red] {}".format(breaking))

    return console.export_text()
