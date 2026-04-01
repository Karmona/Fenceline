"""Detect dangerous capabilities declared in package metadata.

Supports both npm (scripts.preinstall/postinstall) and PyPI
(setup.py detection, native extensions).
"""

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


def check_pypi_capabilities(info: dict, version: str) -> list[str]:
    """Return capability signals for a PyPI package version.

    Checks for:
    - Native extensions (C/C++ code that compiles during install)
    - setup.py usage (arbitrary code execution during install)
    """
    capabilities: list[str] = []

    # Check file list for native extensions / setup.py indicators
    releases = info.get("releases", {})
    files = releases.get(version, [])
    if not isinstance(files, list):
        files = []

    has_sdist = False
    has_wheel = False
    for f in files:
        filename = f.get("filename", "")
        if filename.endswith(".tar.gz") or filename.endswith(".zip"):
            has_sdist = True
        if filename.endswith(".whl"):
            has_wheel = True

    # If there's only an sdist (no wheel), setup.py runs during install
    if has_sdist and not has_wheel:
        capabilities.append("has_setup_py_only")

    # Check package info for native extension indicators
    pkg_info = info.get("info", {})
    classifiers = pkg_info.get("classifiers", [])
    for c in classifiers:
        if "C Extension" in c or "Cython" in c:
            capabilities.append("has_native_extension")
            break

    return capabilities
