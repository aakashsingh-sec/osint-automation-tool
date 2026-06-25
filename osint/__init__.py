"""OSINT Automation Tool package.

Re-exports the most commonly used names so callers (e.g. the dashboard)
can do `from osint import validate_indicator` without reaching into
submodules directly.
"""

from osint.validation import validate_indicator, hash_subtype
from osint.scoring import calculate_verdict
from osint.io_utils import save_report
from osint.core import investigate, DISPLAY_ORDER, SOURCE_DISPLAY_NAMES

__all__ = [
    "validate_indicator",
    "hash_subtype",
    "calculate_verdict",
    "save_report",
    "investigate",
    "DISPLAY_ORDER",
    "SOURCE_DISPLAY_NAMES",
]
