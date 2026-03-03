import os
import re
from typing import List, Optional

DEFAULT_EXCLUDE_PATTERNS = [
    r".*SECRET.*",
    r".*PASSWORD.*",
    r".*TOKEN.*",
    r".*_KEY$",
    r".*_KEY_ID$",
    r".*CREDENTIAL.*",
    r".*_PASS$",
    r".*PRIVATE.*",
]


def _is_sensitive(name: str, patterns: List[str]) -> bool:
    return any(re.fullmatch(p, name, re.IGNORECASE) for p in patterns)


def collect_env_vars(
    include_sensitive: bool = False,
    exclude_patterns: Optional[List[str]] = None,
    include_patterns: Optional[List[str]] = None,
) -> dict:
    if exclude_patterns is None:
        exclude_patterns = DEFAULT_EXCLUDE_PATTERNS

    result = {}
    for name, value in os.environ.items():
        if not include_sensitive and _is_sensitive(name, exclude_patterns):
            continue
        if include_patterns and not any(
            re.fullmatch(p, name, re.IGNORECASE) for p in include_patterns
        ):
            continue
        result[name] = value
    return result
