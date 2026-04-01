"""Tests for fenceline.check.cache — file-based registry cache."""

import json
import time
from pathlib import Path
from unittest import mock

import pytest

from fenceline.check.cache import (
    _cache_path,
    _get_cache_dir,
    get_cached,
    set_cached,
)


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    """Redirect all cache operations to a temp directory."""
    monkeypatch.setenv("FENCELINE_CACHE_DIR", str(tmp_path / "cache"))


class TestGetCacheDir:
    def test_respects_env_override(self, tmp_path, monkeypatch):
        custom = tmp_path / "custom"
        monkeypatch.setenv("FENCELINE_CACHE_DIR", str(custom))
        assert _get_cache_dir() == custom

    def test_default_when_no_env(self, monkeypatch):
        monkeypatch.delenv("FENCELINE_CACHE_DIR", raising=False)
        result = _get_cache_dir()
        assert result == Path.home() / ".cache" / "fenceline" / "registry"


class TestSetCached:
    def test_creates_cache_directory(self, tmp_path):
        cache_dir = tmp_path / "cache"
        assert not cache_dir.exists()
        set_cached("test-key", {"name": "lodash"})
        assert cache_dir.exists()

    def test_writes_valid_json(self):
        payload = {"name": "express", "version": "4.18.2"}
        set_cached("express", payload)
        cache_file = _cache_path("express")
        data = json.loads(cache_file.read_text())
        assert data["payload"] == payload
        assert "_cached_at" in data

    def test_stores_timestamp(self):
        before = time.time()
        set_cached("ts-test", {"v": 1})
        after = time.time()
        data = json.loads(_cache_path("ts-test").read_text())
        assert before <= data["_cached_at"] <= after

    def test_silent_on_write_failure(self, monkeypatch):
        """Cache write failures must not raise."""
        monkeypatch.setenv("FENCELINE_CACHE_DIR", "/nonexistent/readonly/path")
        # Should not raise
        set_cached("fail-key", {"v": 1})


class TestGetCached:
    def test_returns_payload_when_valid(self):
        payload = {"name": "is-odd", "downloads": 1000}
        set_cached("is-odd", payload)
        result = get_cached("is-odd")
        assert result == payload

    def test_returns_none_when_missing(self):
        assert get_cached("nonexistent-key") is None

    def test_returns_none_when_expired(self):
        set_cached("old-pkg", {"v": 1})
        # Backdate the timestamp to 2 hours ago
        cache_file = _cache_path("old-pkg")
        data = json.loads(cache_file.read_text())
        data["_cached_at"] = time.time() - 7200
        cache_file.write_text(json.dumps(data))

        assert get_cached("old-pkg") is None

    def test_returns_payload_when_not_yet_expired(self):
        set_cached("fresh-pkg", {"v": 2})
        # Set timestamp to 30 minutes ago (within 1-hour TTL)
        cache_file = _cache_path("fresh-pkg")
        data = json.loads(cache_file.read_text())
        data["_cached_at"] = time.time() - 1800
        cache_file.write_text(json.dumps(data))

        assert get_cached("fresh-pkg") == {"v": 2}

    def test_returns_none_on_corrupt_json(self):
        cache_file = _cache_path("corrupt")
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text("{broken json!!!")
        assert get_cached("corrupt") is None

    def test_returns_none_when_cached_at_missing(self):
        """If _cached_at field is missing, treat as expired."""
        cache_file = _cache_path("no-ts")
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps({"payload": {"v": 1}}))
        # _cached_at defaults to 0, so time.time() - 0 > 3600 => expired
        assert get_cached("no-ts") is None


class TestCachePath:
    def test_different_keys_get_different_paths(self):
        p1 = _cache_path("lodash")
        p2 = _cache_path("express")
        assert p1 != p2

    def test_same_key_gets_same_path(self):
        assert _cache_path("lodash") == _cache_path("lodash")

    def test_path_is_safe_filename(self):
        """Even dangerous characters produce a safe hex filename."""
        p = _cache_path("../../etc/passwd")
        assert ".." not in p.name
        assert p.name.endswith(".json")
