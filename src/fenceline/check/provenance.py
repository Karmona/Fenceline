"""Check npm package provenance and signature attestations."""

from __future__ import annotations

import json
import urllib.request
import urllib.error

_USER_AGENT = "fenceline/0.1 (https://github.com/karmona/fenceline)"
_REGISTRY = "https://registry.npmjs.org"
_TIMEOUT = 15  # seconds


def check_provenance(name: str, version: str) -> dict:
    """Query the registry for provenance info on a specific version.

    Returns a dict with:
        - ``has_provenance``: Sigstore attestations present
        - ``has_signatures``: legacy npm signatures present
        - ``attestation_count``: number of attestation entries
    """
    url = f"{_REGISTRY}/{name}/{version}"
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
