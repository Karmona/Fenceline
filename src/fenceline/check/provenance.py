"""Check package provenance and signature attestations (npm + PyPI)."""

from __future__ import annotations

import json
import urllib.request
import urllib.error
import urllib.parse

from fenceline import __version__ as _ver
_USER_AGENT = f"fenceline/{_ver} (https://github.com/Karmona/Fenceline)"
_NPM_REGISTRY = "https://registry.npmjs.org"
_PYPI_REGISTRY = "https://pypi.org"
_TIMEOUT = 15  # seconds


def check_provenance(name: str, version: str) -> dict:
    """Query npm registry for provenance info on a specific version.

    Returns a dict with:
        - ``has_provenance``: Sigstore attestations present
        - ``has_signatures``: legacy npm signatures present
        - ``attestation_count``: number of attestation entries
    """
    url = f"{_NPM_REGISTRY}/{name}/{version}"
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})

    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, json.JSONDecodeError):
        return {
            "has_provenance": False,
            "has_signatures": False,
            "attestation_count": 0,
        }

    dist = data.get("dist", {})

    attestations = dist.get("attestations", [])
    if isinstance(attestations, dict):
        # Some packages wrap attestations in an object with a list inside.
        attestations = attestations.get("predicates", attestations.get("attestations", []))
    if not isinstance(attestations, list):
        attestations = []

    signatures = dist.get("signatures", [])
    if not isinstance(signatures, list):
        signatures = []

    return {
        "has_provenance": len(attestations) > 0,
        "has_signatures": len(signatures) > 0,
        "attestation_count": len(attestations),
    }


def check_pypi_provenance(name: str, version: str) -> dict:
    """Query PyPI for provenance info on a specific version.

    PyPI supports Sigstore-based attestations via the JSON API.
    Returns a dict with the same shape as check_provenance().
    """
    safe_name = urllib.parse.quote(name, safe='')
    url = f"{_PYPI_REGISTRY}/pypi/{safe_name}/{version}/json"
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})

    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, json.JSONDecodeError):
        return {
            "has_provenance": False,
            "has_signatures": False,
            "attestation_count": 0,
        }

    # Check for PEP 740 provenance attestations in the "urls" array.
    # Note: has_sig is deprecated by PyPI and always returns false.
    # We rely solely on PEP 740 attestations (provenance/attestations fields).
    urls = data.get("urls", [])
    if not isinstance(urls, list):
        urls = []

    attestation_count = sum(
        1 for u in urls
        if u.get("provenance") or u.get("attestations")
    )

    return {
        "has_provenance": attestation_count > 0,
        "has_signatures": False,  # has_sig deprecated by PyPI, always false
        "attestation_count": attestation_count,
    }
