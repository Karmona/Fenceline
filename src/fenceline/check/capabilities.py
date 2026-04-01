"""Detect dangerous capabilities declared in package metadata."""

from __future__ import annotations


def check_capabilities(info: dict, version: str) -> list[str]:
    """Return a list of capability signals for *version*.

    Inspects the ``scripts`` field in the version metadata for
    lifecycle hooks that run code at install time.
    """
    versions = info.get("versions", {})
    meta = versions.get(version, {})
    scripts = meta.get("scripts", {})

    capabilities: list[str] = []

    if "preinstall" in scripts:
        capabilities.append("has_preinstall")
    if "postinstall" in scripts:
        capabilities.append("has_postinstall")
    if "prepare" in scripts:
        capabilities.append("has_prepare")

    return capabilities


def diff_capabilities(
    info: dict, old_version: str | None, new_version: str
) -> list[str]:
    """Compare capabilities between two versions.

    Returns signals for capability escalation (e.g., postinstall
    script added between versions).
    """
    if old_version is None:
        return []  # New package, no diff to compare

    old_caps = set(check_capabilities(info, old_version))
    new_caps = set(check_capabilities(info, new_version))

    signals: list[str] = []
    added = new_caps - old_caps

    if "has_preinstall" in added:
        signals.append("capability_escalation_preinstall")
    if "has_postinstall" in added:
        signals.append("capability_escalation_postinstall")
    if "has_prepare" in added:
        signals.append("capability_escalation_prepare")

    return signals
