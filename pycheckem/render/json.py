from __future__ import annotations

import dataclasses
import json as _json

from pycheckem.types import DiffResult


def render_json(result):
    # type: (DiffResult) -> str
    """Serialize a DiffResult to pretty-printed JSON."""
    data = dataclasses.asdict(result)
    return _json.dumps(data, indent=2, ensure_ascii=False)
