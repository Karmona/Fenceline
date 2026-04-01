"""Tests for the check/scanner.py orchestrator."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from fenceline.check.scanner import run


def _make_args(**kwargs):
    """Create a mock args namespace."""
    defaults = {"lockfile": None, "base_ref": "HEAD", "format": "text", "verbose": False}
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class TestScannerNoLockfile:
    def test_no_lockfile_returns_2(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = run(_make_args())
        assert result == 2


class TestScannerNoChanges:
    @patch("fenceline.check.scanner.get_base_lockfile")
    @patch("fenceline.check.scanner.diff_lockfiles", return_value=[])
    def test_no_changes_returns_0(self, _mock_diff, mock_base, tmp_path):
        # Create a lockfile
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text('{"lockfileVersion": 2, "packages": {}}')
        result = run(_make_args(lockfile=str(lockfile)))
        assert result == 0


class TestScannerWithChanges:
    def _mock_registry(self):
        """Set up mocks for registry calls (short names for patch.multiple)."""
        return {
            "get_package_info": MagicMock(return_value={
                "name": "evil-pkg",
                "versions": {"1.0.0": {"scripts": {"postinstall": "node evil.js"}}},
                "time": {"1.0.0": "2026-03-30T00:00:00Z"},
            }),
            "get_package_age": MagicMock(return_value=timedelta(days=1)),
            "get_maintainer_change": MagicMock(return_value={
                "changed": True, "added": ["attacker"], "removed": ["original"],
            }),
            "check_provenance": MagicMock(return_value={
                "has_provenance": False, "has_signatures": False, "attestation_count": 0,
            }),
            "check_capabilities": MagicMock(return_value=["has_postinstall"]),
        }

    @patch("fenceline.check.scanner.get_base_lockfile", return_value={})
    def test_high_risk_returns_1(self, _mock_base, tmp_path, capsys):
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "node_modules/evil-pkg": {"version": "1.0.0", "resolved": "https://..."},
            },
        }))

        with patch.multiple("fenceline.check.scanner", **self._mock_registry()):
            result = run(_make_args(lockfile=str(lockfile)))

        assert result == 1  # HIGH/CRITICAL

    @patch("fenceline.check.scanner.get_base_lockfile", return_value={})
    def test_json_output_valid(self, _mock_base, tmp_path, capsys):
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "node_modules/evil-pkg": {"version": "1.0.0", "resolved": "https://..."},
            },
        }))

        with patch.multiple("fenceline.check.scanner", **self._mock_registry()):
            run(_make_args(lockfile=str(lockfile), format="json"))

        captured = capsys.readouterr()
        # Output contains progress text + JSON. Extract the JSON array.
        out = captured.out
        json_start = out.index("[")
        data = json.loads(out[json_start:])
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["name"] == "evil-pkg"
        assert "score" in data[0]
        assert "level" in data[0]

    @patch("fenceline.check.scanner.get_base_lockfile", return_value={})
    def test_markdown_output_has_table(self, _mock_base, tmp_path, capsys):
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "node_modules/evil-pkg": {"version": "1.0.0", "resolved": "https://..."},
            },
        }))

        with patch.multiple("fenceline.check.scanner", **self._mock_registry()):
            run(_make_args(lockfile=str(lockfile), format="markdown"))

        captured = capsys.readouterr()
        assert "| Package |" in captured.out
        assert "evil-pkg" in captured.out


class TestScannerLowRisk:
    @patch("fenceline.check.scanner.get_base_lockfile", return_value={})
    @patch("fenceline.check.scanner.get_package_info", return_value={
        "name": "lodash", "versions": {"4.17.21": {}},
        "time": {"4.17.21": "2020-01-01T00:00:00Z"},
    })
    @patch("fenceline.check.scanner.get_package_age",
           return_value=timedelta(days=365 * 5))
    @patch("fenceline.check.scanner.get_maintainer_change", return_value={
        "changed": False, "added": [], "removed": [],
    })
    @patch("fenceline.check.scanner.check_provenance", return_value={
        "has_provenance": True, "has_signatures": True, "attestation_count": 1,
    })
    @patch("fenceline.check.scanner.check_capabilities", return_value=[])
    def test_low_risk_returns_0(self, m1, m2, m3, m4, m5, m6, tmp_path):
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "node_modules/lodash": {"version": "4.17.21", "resolved": "https://..."},
            },
        }))

        result = run(_make_args(lockfile=str(lockfile)))
        assert result == 0
