from __future__ import annotations

import json as _json
from importlib.metadata import distributions

from pycheckem.types import PackageInfo


def _parse_install_source(dist):
    # type: (object) -> Tuple[str, Optional[str], Optional[str]]
    """Parse PEP 610 direct_url.json and return (install_source, source_url, source_detail)."""
    try:
        raw = dist.read_text("direct_url.json")
    except Exception:
        return ("pypi", None, None)

    if raw is None:
        return ("pypi", None, None)

    try:
        data = _json.loads(raw)
    except (ValueError, TypeError):
        return ("pypi", None, None)

    url = data.get("url")

    # Editable or local directory install
    dir_info = data.get("dir_info")
    if dir_info is not None:
        if dir_info.get("editable", False):
            return ("editable", url, url)
        return ("local", url, None)

    # VCS install (git, hg, etc.)
    vcs_info = data.get("vcs_info")
    if vcs_info is not None:
        vcs = vcs_info.get("vcs", "")
        commit = vcs_info.get("commit_id", "")
        detail = "{}@{}".format(vcs, commit) if commit else vcs
        return ("vcs", url, detail)

    # Archive install (.whl, .tar.gz from URL or local)
    archive_info = data.get("archive_info")
    if archive_info is not None:
        return ("archive", url, None)

    return ("pypi", None, None)


def collect_packages() -> dict:
    pkgs = {}
    for dist in distributions():
        name = dist.metadata["Name"]
        version = dist.metadata["Version"]
        requires = dist.metadata.get_all("Requires-Dist") or []

        location = None
        try:
            files = dist.files
            if files:
                location = str(files[0].locate().parent)
        except Exception:
            pass

        install_source, source_url, source_detail = _parse_install_source(dist)

        pkgs[name.lower()] = PackageInfo(
            version=version,
            location=location,
            requires=[r.split(";")[0].strip() for r in requires],
            install_source=install_source,
            source_url=source_url,
            source_detail=source_detail,
        )
    return pkgs
