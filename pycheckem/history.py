from __future__ import annotations

import os
import shutil

from pycheckem.snapshot import load


# Default storage directory
def _history_dir(base_dir=None):
    # type: (Optional[str]) -> str
    """Return the history directory path, creating it if necessary."""
    if base_dir is None:
        base_dir = os.getcwd()
    path = os.path.join(base_dir, ".pycheckem", "history")
    os.makedirs(path, exist_ok=True)
    return path


def _snapshot_filename(snap):
    # type: (Snapshot) -> str
    """Generate a filename from snapshot metadata.

    Format: YYYYMMDDTHHMMSSZ_label.json (label sanitized).
    """
    ts = snap.metadata.timestamp
    # Strip timezone offset before compacting
    for tz_suffix in ("+00:00", "-00:00", "+0000", "-0000"):
        if ts.endswith(tz_suffix):
            ts = ts[: -len(tz_suffix)]
            break
    if ts.endswith("Z"):
        ts = ts[:-1]
    # Remove sub-second precision
    if "." in ts:
        ts = ts[: ts.index(".")]
    # Convert to compact form
    compact_ts = ts.replace("-", "").replace(":", "") + "Z"

    label = snap.metadata.label or "unlabeled"
    # Sanitize label for use in filename
    safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)

    return "{}_{}.json".format(compact_ts, safe_label)


def add(snapshot_path, base_dir=None):
    # type: (str, Optional[str]) -> str
    """Copy a snapshot file into the history store.

    Returns the destination path.
    """
    snap = load(snapshot_path)
    hist_dir = _history_dir(base_dir)
    filename = _snapshot_filename(snap)
    dest = os.path.join(hist_dir, filename)
    shutil.copy2(snapshot_path, dest)
    return dest


def list_snapshots(base_dir=None):
    # type: (Optional[str]) -> List[Tuple[str, str, Optional[str]]]
    """List all snapshots in the history store.

    Returns a list of (filename, timestamp, label) tuples, sorted by filename
    (which sorts chronologically since filenames start with timestamps).
    """
    hist_dir = _history_dir(base_dir)
    entries = []  # type: List[Tuple[str, str, Optional[str]]]

    for fname in sorted(os.listdir(hist_dir)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(hist_dir, fname)
        try:
            snap = load(fpath)
            entries.append(
                (
                    fname,
                    snap.metadata.timestamp,
                    snap.metadata.label,
                )
            )
        except Exception:
            # Skip files that can't be loaded
            continue

    return entries


def get_last_n(n, base_dir=None):
    # type: (int, Optional[str]) -> List[Snapshot]
    """Load the last N snapshots from history (most recent last).

    Returns fewer than N if history has fewer entries.
    """
    hist_dir = _history_dir(base_dir)
    json_files = sorted(f for f in os.listdir(hist_dir) if f.endswith(".json"))
    # Take the last N files
    selected = json_files[-n:] if n > 0 else []
    snapshots = []  # type: List[Snapshot]
    for fname in selected:
        fpath = os.path.join(hist_dir, fname)
        try:
            snapshots.append(load(fpath))
        except Exception:
            continue
    return snapshots
