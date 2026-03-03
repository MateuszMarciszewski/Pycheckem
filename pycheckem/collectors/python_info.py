import platform
import sys

from pycheckem.types import PythonInfo


def collect_python_info() -> PythonInfo:
    return PythonInfo(
        version=platform.python_version(),
        implementation=platform.python_implementation(),
        executable=sys.executable,
        prefix=sys.prefix,
        platform=sys.platform,
    )
