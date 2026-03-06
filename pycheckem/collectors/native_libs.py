"""Collector for native shared library dependencies of compiled Python extensions.

Finds .so (Linux), .dylib (macOS), and .pyd (Windows) files in installed
packages, then uses platform-specific tools (ldd, otool) to resolve which
system libraries they link against. This is useful for debugging multi-stage
Docker builds where native libraries can go missing between build and
runtime stages.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
from importlib.metadata import distributions

from pycheckem.types import NativeLibInfo

# File extensions that indicate compiled native extensions
_NATIVE_EXTENSIONS = (".so", ".pyd", ".dylib")


def _find_extension_files(dist):
    # type: (object) -> List[str]
    """Find native extension file paths for an installed distribution."""
    paths = []
    try:
        files = dist.files
        if not files:
            return paths
    except Exception:
        return paths

    for f in files:
        name = str(f)
        # Check if this is a native extension (not a plain .so symlink like libfoo.so)
        if any(name.endswith(ext) for ext in _NATIVE_EXTENSIONS):
            try:
                full_path = str(f.locate())
                if os.path.isfile(full_path):
                    paths.append(full_path)
            except Exception:
                continue
    return paths


def _parse_ldd_output(output):
    # type: (str) -> Tuple[List[str], List[str]]
    """Parse ldd output into (linked_libs, missing_libs).

    ldd output looks like:
        linux-vdso.so.1 (0x00007fff...)
        libopenblas.so.0 => /usr/lib/libopenblas.so.0 (0x00007f...)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f...)
        libfoo.so.1 => not found
    """
    linked = []
    missing = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        # "not found" entries
        if "not found" in line:
            match = re.match(r"^\s*(\S+)\s+=>\s+not found", line)
            if match:
                missing.append(match.group(1))
            continue
        # "libfoo.so => /path/to/libfoo.so (addr)" entries
        match = re.match(r"^\s*(\S+)\s+=>\s+(\S+)", line)
        if match:
            linked.append(match.group(1))
            continue
        # "linux-vdso.so.1 (addr)" — virtual, skip
        if "vdso" in line or "ld-linux" in line:
            continue
        # Bare library name (e.g. "/lib64/ld-linux-x86-64.so.2 (addr)")
        match = re.match(r"^\s*(\/\S+)", line)
        if match:
            lib_name = os.path.basename(match.group(1))
            linked.append(lib_name)
    return linked, missing


def _parse_otool_output(output):
    # type: (str) -> Tuple[List[str], List[str]]
    """Parse otool -L output into (linked_libs, missing_libs).

    otool output looks like:
        /path/to/lib.dylib:
            /usr/lib/libSystem.B.dylib (compatibility version ...)
            @rpath/libopenblas.dylib (compatibility version ...)
    """
    linked = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line or line.endswith(":"):
            continue
        # Extract the library path before the " (compatibility" part
        match = re.match(r"^(\S+)\s+\(", line)
        if match:
            lib_path = match.group(1)
            linked.append(os.path.basename(lib_path))
    return linked, []  # otool doesn't report "not found" directly


def _get_linked_libs(filepath):
    # type: (str) -> Tuple[List[str], List[str]]
    """Get linked shared libraries for a native extension file.

    Returns (linked_libs, missing_libs). Falls back gracefully if the
    platform tool is unavailable.
    """
    system = platform.system()

    if system == "Linux":
        try:
            result = subprocess.run(
                ["ldd", filepath],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return _parse_ldd_output(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    elif system == "Darwin":
        try:
            result = subprocess.run(
                ["otool", "-L", filepath],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return _parse_otool_output(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    # Windows or tool not available — return empty
    return [], []


def collect_native_libs():
    # type: () -> Dict[str, List[NativeLibInfo]]
    """Collect native library dependency info for all installed packages.

    Scans each installed distribution for compiled extension files (.so,
    .pyd, .dylib), then resolves their shared library dependencies using
    platform-specific tools (ldd on Linux, otool on macOS).

    Returns:
        A dict mapping package names to lists of NativeLibInfo, one per
        extension file. Packages with no native extensions are omitted.
    """
    result = {}  # type: Dict[str, List[NativeLibInfo]]

    for dist in distributions():
        name = dist.metadata["Name"].lower()
        ext_files = _find_extension_files(dist)
        if not ext_files:
            continue

        infos = []
        for filepath in ext_files:
            linked, missing = _get_linked_libs(filepath)
            # Make the extension path relative to the package location
            # for cleaner display
            try:
                pkg_files = dist.files
                if pkg_files:
                    base = str(pkg_files[0].locate().parent)
                    rel_path = os.path.relpath(filepath, base)
                else:
                    rel_path = os.path.basename(filepath)
            except Exception:
                rel_path = os.path.basename(filepath)

            infos.append(
                NativeLibInfo(
                    extension=rel_path,
                    linked_libs=sorted(set(linked)),
                    missing=sorted(set(missing)),
                )
            )

        if infos:
            result[name] = infos

    return result
