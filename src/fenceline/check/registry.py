"""Query the npm registry for package metadata."""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

_USER_AGENT = "fenceline/0.1 (https://github.com/karmona/fenceline)"
_REGISTRY = "https://registry.npmjs.org"
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
