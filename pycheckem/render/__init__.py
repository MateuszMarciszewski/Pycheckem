from .ascii import render_ascii as ascii
from .json import render_json as json
from .rich import render_rich as rich
from .side_by_side import render_side_by_side as side_by_side

__all__ = ["ascii", "json", "rich", "side_by_side"]
