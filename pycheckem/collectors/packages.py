from importlib.metadata import distributions

from pycheckem.types import PackageInfo


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

        pkgs[name.lower()] = PackageInfo(
            version=version,
            location=location,
            requires=[r.split(";")[0].strip() for r in requires],
        )
    return pkgs
