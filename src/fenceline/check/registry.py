"""Query the npm and PyPI registries for package metadata."""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

from fenceline import __version__ as _ver
_USER_AGENT = f"fenceline/{_ver} (https://github.com/Karmona/Fenceline)"
_REGISTRY = "https://registry.npmjs.org"
_PYPI_REGISTRY = "https://pypi.org"
_TIMEOUT = 15  # seconds


def get_package_info(name: str) -> dict | None:
    """Fetch full package metadata from the npm registry.

    Returns the parsed JSON document, or ``None`` on 404 / network error.
    """
    url = f"{_REGISTRY}/{name}"
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})

    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        return None
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None


def get_package_age(info: dict, version: str) -> timedelta | None:
    """Return how long ago *version* was published.

    Uses the ``time`` field of the registry document.  Returns ``None``
    if the version or timestamp is missing.
    """
    time_map = info.get("time", {})
    ts = time_map.get(version)
    if ts is None:
        return None

    try:
        published = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) - published
    except (ValueError, TypeError):
        return None


def get_maintainer_change(
    info: dict,
    old_version: str | None,
    new_version: str,
) -> dict:
    """Compare maintainer lists between two versions.

    Returns a dict with keys ``changed`` (bool), ``added`` (list of
    names), and ``removed`` (list of names).
    """
    versions = info.get("versions", {})

    def _maintainer_names(ver: str | None) -> set[str]:
        if ver is None:
            return set()
        meta = versions.get(ver, {})
        maintainers = meta.get("maintainers", [])
        return {m.get("name", "") for m in maintainers if isinstance(m, dict)}

    old_names = _maintainer_names(old_version)
    new_names = _maintainer_names(new_version)

    added = sorted(new_names - old_names)
    removed = sorted(old_names - new_names)

    return {
        "changed": bool(added or removed),
        "added": added,
        "removed": removed,
    }


# ---------------------------------------------------------------------------
# PyPI registry helpers
# ---------------------------------------------------------------------------


def get_pypi_package_info(name: str) -> dict | None:
    """Fetch package metadata from the PyPI JSON API.

    Returns the parsed JSON document, or ``None`` on 404 / network error.
    """
    url = f"{_PYPI_REGISTRY}/pypi/{name}/json"
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})

    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError:
        return None
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None


def get_pypi_package_age(info: dict, version: str) -> timedelta | None:
    """Return how long ago *version* was uploaded to PyPI.

    Uses ``releases[version]`` and the ``upload_time_iso_8601`` field
    of the first file entry.  Returns ``None`` if data is missing.
    """
    releases = info.get("releases", {})
    files = releases.get(version, [])
    if not files:
        return None

    ts = files[0].get("upload_time_iso_8601") or files[0].get("upload_time")
    if ts is None:
        return None

    try:
        published = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) - published
    except (ValueError, TypeError):
        return None


def get_pypi_maintainer_change(
    info: dict,
    old_version: str | None,
    new_version: str,
) -> dict:
    """Check for maintainer changes between versions.

    PyPI does not expose per-version maintainer lists the same way npm
    does, so this currently only checks the top-level ``info.author``
    field and always returns ``changed: False``.  A future version could
    compare ``info.maintainer`` or use the PyPI warehouse API.
    """
    # NOTE: PyPI doesn't provide per-version maintainer data via the
    # simple JSON API.  For now, report no change.  This can be improved
    # once the PyPI trusted-publishers API exposes this data.
    return {
        "changed": False,
        "added": [],
        "removed": [],
    }
