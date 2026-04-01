"""GitHub PR comment formatting for fenceline check results.

Produces markdown tables with collapsible signal details,
suitable for posting as GitHub PR comments.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fenceline.check.scoring import RiskReport


_LEVEL_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}


def format_markdown(reports: list[RiskReport]) -> str:
    """Format risk reports as a markdown table.

    Returns a string ready to print or post as a PR comment.
    """
    lines: list[str] = []
    lines.append("| Status | Package | Change | Score | Level | Signals |")
    lines.append("|--------|---------|--------|-------|-------|---------|")

    for r in reports:
        emoji = _LEVEL_EMOJI.get(r.level, "⚪")
        ver = f"{r.old_version or 'new'} -> {r.new_version or 'removed'}"
        sigs = ", ".join(s["signal"] for s in r.signals) or "none"
        lines.append(f"| {emoji} | {r.name} | {ver} | {r.score} | {r.level} | {sigs} |")

    # Summary line
    total = len(reports)
    high_count = sum(1 for r in reports if r.level in ("HIGH", "CRITICAL"))
    if high_count:
        lines.append(f"\n**{high_count} of {total}** package(s) flagged as HIGH or CRITICAL risk.")
    else:
        lines.append(f"\n{total} package(s) checked. All LOW/MEDIUM risk.")

    return "\n".join(lines)
