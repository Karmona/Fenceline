"""Tests for npm and PyPI registry lookups."""

from __future__ import annotations

import json
import os
import tempfile
import urllib.error
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from fenceline.check.registry import (
    get_package_info,
    get_package_age,
    get_maintainer_change,
    get_pypi_package_info,
    get_pypi_package_age,
    get_pypi_maintainer_change,
)


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    """Redirect registry cache to a temp directory for test isolation."""
    monkeypatch.setenv("FENCELINE_CACHE_DIR", str(tmp_path / "cache"))


def _mock_urlopen(data: dict, status: int = 200):
    """Create a mock for urllib.request.urlopen."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(data).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


class TestGetPackageInfo:
    @patch("fenceline.check.registry.urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"name": "express", "versions": {}})
        result = get_package_info("express")
        assert result is not None
        assert result["name"] == "express"

    @patch("fenceline.check.registry.urllib.request.urlopen")
    def test_404_returns_none(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "url", 404, "Not Found", {}, None
        )
        assert get_package_info("nonexistent") is None

    @patch("fenceline.check.registry.urllib.request.urlopen")
    def test_timeout_returns_none(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("timeout")
        assert get_package_info("express") is None

    @patch("fenceline.check.registry.urllib.request.urlopen")
    def test_scoped_package_url_safe(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"name": "@types/node"})
        get_package_info("@types/node")
        call_args = mock_urlopen.call_args
        url = call_args[0][0].full_url
        assert "@types/node" in url  # @ and / preserved


class TestGetPackageAge:
    def test_new_package(self):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        info = {"time": {"1.0.0": now}}
        age = get_package_age(info, "1.0.0")
        assert age is not None
        assert age < timedelta(minutes=1)

    def test_missing_version(self):
        info = {"time": {"1.0.0": "2020-01-01T00:00:00Z"}}
        assert get_package_age(info, "2.0.0") is None

    def test_missing_time_field(self):
        assert get_package_age({}, "1.0.0") is None

    def test_invalid_timestamp(self):
        info = {"time": {"1.0.0": "not-a-date"}}
        assert get_package_age(info, "1.0.0") is None


class TestGetMaintainerChange:
    def test_no_change(self):
        info = {"versions": {
            "1.0.0": {"maintainers": [{"name": "alice"}]},
            "2.0.0": {"maintainers": [{"name": "alice"}]},
        }}
        result = get_maintainer_change(info, "1.0.0", "2.0.0")
        assert result["changed"] is False

    def test_maintainer_added(self):
        info = {"versions": {
            "1.0.0": {"maintainers": [{"name": "alice"}]},
            "2.0.0": {"maintainers": [{"name": "alice"}, {"name": "bob"}]},
        }}
        result = get_maintainer_change(info, "1.0.0", "2.0.0")
        assert result["changed"] is True
        assert "bob" in result["added"]

    def test_maintainer_removed(self):
        info = {"versions": {
            "1.0.0": {"maintainers": [{"name": "alice"}, {"name": "bob"}]},
            "2.0.0": {"maintainers": [{"name": "alice"}]},
        }}
        result = get_maintainer_change(info, "1.0.0", "2.0.0")
        assert result["changed"] is True
        assert "bob" in result["removed"]

    def test_new_package_no_old_version(self):
        info = {"versions": {
            "1.0.0": {"maintainers": [{"name": "alice"}]},
        }}
        result = get_maintainer_change(info, None, "1.0.0")
        assert result["changed"] is True
        assert "alice" in result["added"]


class TestPyPIFunctions:
    @patch("fenceline.check.registry.urllib.request.urlopen")
    def test_get_pypi_info_success(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen({"info": {"name": "requests"}})
        result = get_pypi_package_info("requests")
        assert result is not None

    @patch("fenceline.check.registry.urllib.request.urlopen")
    def test_get_pypi_info_404(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "url", 404, "Not Found", {}, None
        )
        assert get_pypi_package_info("nonexistent") is None

    def test_pypi_age_with_data(self):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        info = {"releases": {"2.31.0": [{"upload_time_iso_8601": now}]}}
        age = get_pypi_package_age(info, "2.31.0")
        assert age is not None
        assert age < timedelta(minutes=1)

    def test_pypi_age_missing_version(self):
        info = {"releases": {}}
        assert get_pypi_package_age(info, "1.0.0") is None

    def test_pypi_maintainer_change_stub(self):
        """PyPI maintainer check currently always returns no change."""
        result = get_pypi_maintainer_change({}, None, "1.0.0")
        assert result["changed"] is False
