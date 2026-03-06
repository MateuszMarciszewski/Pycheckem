from __future__ import annotations

import dataclasses
import json as _json


def render_json(result):
    # type: (DiffResult) -> str
    """Render a DiffResult as pretty-printed JSON for scripts and CI pipelines.

    Args:
        result: The DiffResult to serialize.

    Returns:
        A JSON string with 2-space indentation.

    Example:
        >>> from pycheckem.render import json
        >>> output = json(result)
        >>> import json as _json
        >>> data = _json.loads(output)
        >>> data["summary"]["severity"]
        'major'
    """
    data = dataclasses.asdict(result)
    return _json.dumps(data, indent=2, ensure_ascii=False)
