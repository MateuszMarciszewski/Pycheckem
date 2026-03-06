from __future__ import annotations

from importlib.metadata import entry_points


def discover_plugins():
    # type: () -> Dict[str, Callable]
    """Discover all registered pycheckem.collectors entry points.

    Returns a dict mapping plugin name to its callable.
    Compatible with Python 3.8 through 3.13+.
    """
    eps = entry_points()

    # Python 3.10+: SelectableGroups has .select()
    if hasattr(eps, "select"):
        group_eps = eps.select(group="pycheckem.collectors")
    elif isinstance(eps, dict):
        # Python 3.8-3.9: entry_points() returns a plain dict of lists
        group_eps = eps.get("pycheckem.collectors", [])
    else:
        group_eps = [
            ep for ep in eps if getattr(ep, "group", None) == "pycheckem.collectors"
        ]

    plugins = {}  # type: Dict[str, Callable]
    for ep in group_eps:
        try:
            plugins[ep.name] = ep.load()
        except Exception:
            continue
    return plugins


def run_plugins():
    # type: () -> Dict[str, Any]
    """Run all discovered plugins and collect their data.

    Each plugin is expected to be a callable that returns a dict.
    Plugin errors are caught and recorded as {"_error": "..."}.
    Non-dict returns are ignored.
    """
    results = {}  # type: Dict[str, Any]
    for name, func in discover_plugins().items():
        try:
            data = func()
            if isinstance(data, dict):
                results[name] = data
        except Exception as exc:
            results[name] = {"_error": str(exc)}
    return results
