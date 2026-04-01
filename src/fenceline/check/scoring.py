"""Risk scoring model for package changes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta


@dataclass
class RiskReport:
    """Risk assessment for a single package change."""

    name: str
    old_version: str | None
    new_version: str | None
    change_type: str
    score: int
    level: str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    signals: list[dict] = field(default_factory=list)


def _level_for_score(score: int) -> str:
    if score <= 15:
        return "LOW"
    if score <= 35:
        return "MEDIUM"
    if score <= 60:
        return "HIGH"
    return "CRITICAL"


def compute_risk(
    change,
    age: timedelta | None,
    maintainer_change: dict,
    provenance: dict,
    capabilities: list[str],
    scorecard: dict | None = None,
) -> RiskReport:
    """Score a package change and return a :class:`RiskReport`.

    Parameters
    ----------
    change:
        A :class:`~fenceline.check.lockfile.PackageChange` instance.
    age:
        Time since the version was published, or ``None`` if unknown.
    maintainer_change:
        Dict with ``changed``, ``added``, ``removed`` keys.
    provenance:
        Dict with ``has_provenance``, ``has_signatures``,
        ``attestation_count`` keys.
    capabilities:
        List of capability signal strings.
    scorecard:
        Reserved for future OpenSSF Scorecard integration.
    """
    signals: list[dict] = []
    score = 0

    # --- Package age ---
    if age is not None:
        if age < timedelta(days=7):
            pts = 30
            score += pts
            signals.append({
                "signal": "very_new_version",
                "points": pts,
                "detail": f"Published {age.days}d ago (< 7 days)",
            })
        elif age < timedelta(days=30):
            pts = 15
            score += pts
            signals.append({
                "signal": "new_version",
                "points": pts,
                "detail": f"Published {age.days}d ago (< 30 days)",
            })

    # --- Maintainer changes ---
    if maintainer_change.get("removed"):
        pts = 25
        score += pts
        signals.append({
            "signal": "maintainer_changed",
            "points": pts,
            "detail": (
                f"Maintainers removed: {', '.join(maintainer_change['removed'])}"
            ),
        })
    elif maintainer_change.get("added") and not maintainer_change.get("removed"):
        pts = 10
        score += pts
        signals.append({
            "signal": "maintainer_added",
            "points": pts,
            "detail": (
                f"New maintainers: {', '.join(maintainer_change['added'])}"
            ),
        })

    # --- Install scripts ---
    if "has_postinstall" in capabilities:
        pts = 20
        score += pts
        signals.append({
            "signal": "has_postinstall",
            "points": pts,
            "detail": "Package declares a postinstall script",
        })
    if "has_preinstall" in capabilities:
        pts = 25
        score += pts
        signals.append({
            "signal": "has_preinstall",
            "points": pts,
            "detail": "Package declares a preinstall script",
        })

    # --- Provenance ---
    if not provenance.get("has_provenance"):
        pts = 10
        score += pts
        signals.append({
            "signal": "no_provenance",
            "points": pts,
            "detail": "No Sigstore provenance attestation",
        })

    # --- New package (not an update) ---
    if change.change_type == "added":
        pts = 5
        score += pts
        signals.append({
            "signal": "new_package",
            "points": pts,
            "detail": "Newly added dependency (not an update)",
        })

    # --- Capability escalation (postinstall/preinstall added between versions) ---
    for cap_signal in capabilities:
        if cap_signal.startswith("capability_escalation_"):
            script_type = cap_signal.replace("capability_escalation_", "")
            pts = 20
            score += pts
            signals.append({
                "signal": cap_signal,
                "points": pts,
                "detail": f"{script_type} script added between versions (was not present before)",
            })

    level = _level_for_score(score)

    return RiskReport(
        name=change.name,
        old_version=change.old_version,
        new_version=change.new_version,
        change_type=change.change_type,
        score=score,
        level=level,
        signals=signals,
    )
