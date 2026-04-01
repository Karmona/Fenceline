"""Simple file-based cache for registry lookups.

Stores JSON responses in ~/.cache/fenceline/ with a 1-hour TTL.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Optional


_CACHE_DIR = Path.home() / ".cache" / "fenceline" / "registry"
_DEFAULT_TTL = 3600  # 1 hour


def get_cached(key: str) -> Optional[dict]:
    """Return cached data if valid, or None."""
    cache_file = _cache_path(key)
    if not cache_file.exists():
        return None

    try:
        data = json.loads(cache_file.read_text())
        if time.time() - data.get("_cached_at", 0) > _DEFAULT_TTL:
            return None  # Expired
        return data.get("payload")
    except (json.JSONDecodeError, OSError):
        return None


def set_cached(key: str, payload: dict) -> None:
    """Store data in cache."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_file = _cache_path(key)
        data = {"_cached_at": time.time(), "payload": payload}
        cache_file.write_text(json.dumps(data))
    except OSError:
        pass  # Cache failures are silent


def _cache_path(key: str) -> Path:
    """Generate a safe filesystem path from a cache key."""
    safe = hashlib.sha256(key.encode()).hexdigest()[:16]
    return _CACHE_DIR / f"{safe}.json"
