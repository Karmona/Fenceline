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
