from __future__ import annotations

import subprocess

from pycheckem.snapshot import load_from_string


_DEFAULT_TIMEOUT = 30


def snapshot_remote(host, label=None, timeout=None):
    # type: (str, Optional[str], Optional[int]) -> Snapshot
    """Capture a snapshot on a remote host via SSH.

    Runs ``python -m pycheckem snapshot -o -`` on the remote host and
    parses the JSON output.

    Args:
        host: SSH host (e.g. ``user@hostname`` or just ``hostname``).
        label: Optional label for the remote snapshot.
        timeout: SSH command timeout in seconds (default: 30).

    Raises:
        RuntimeError: if the SSH command fails.
        ValueError: if the remote output is not valid snapshot JSON.
    """
    if timeout is None:
        timeout = _DEFAULT_TIMEOUT

    cmd = ["ssh", host, "python", "-m", "pycheckem", "snapshot", "-o", "-"]
    if label:
        cmd.extend(["--label", label])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"SSH command timed out after {timeout} seconds connecting to {host}"
        )
    except FileNotFoundError:
        raise RuntimeError(
            "ssh command not found. Ensure OpenSSH is installed and on PATH."
        )

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(
            f"Remote snapshot failed on {host} (exit {result.returncode}): {stderr}"
        )

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError(f"Remote host {host} returned empty output")

    return load_from_string(stdout)
