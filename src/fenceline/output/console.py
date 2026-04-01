"""Console output formatting for fenceline check results.

Supports colored output (respects NO_COLOR env var) and both
compact and verbose modes.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fenceline.check.scoring import RiskReport


# ANSI color codes
_COLORS = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH": "\033[31m",      # red
    "MEDIUM": "\033[33m",    # yellow
    "LOW": "\033[32m",       # green
    "RESET": "\033[0m",
}

_ICONS = {"LOW": ".", "MEDIUM": "~", "HIGH": "!", "CRITICAL": "X"}


def _color(level: str, text: str) -> str:
    """Wrap text in ANSI color if colors are enabled."""
    if os.environ.get("NO_COLOR"):
        return text
    code = _COLORS.get(level, "")
    reset = _COLORS["RESET"]
    return f"{code}{text}{reset}" if code else text


def format_console(reports: list[RiskReport]) -> str:
    """Format risk reports for terminal output.

    Returns a string ready to print.
    """
    lines: list[str] = []
    for r in reports:
        marker = _ICONS.get(r.level, "?")
        ver = f"{r.old_version or '(new)'} -> {r.new_version or '(removed)'}"
        header = f"[{marker}] {r.level:8s} ({r.score:3d}) {r.name}  {ver}"
        lines.append(_color(r.level, header))
        for s in r.signals:
            lines.append(f"         +{s['points']:2d}  {s['signal']}: {s['detail']}")
        lines.append("")
    return "\n".join(lines)
