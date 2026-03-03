import os
import sys

from pycheckem.types import PathInfo


def collect_paths() -> PathInfo:
    return PathInfo(
        sys_path=list(sys.path),
        path_env=os.environ.get("PATH", "").split(os.pathsep),
    )
