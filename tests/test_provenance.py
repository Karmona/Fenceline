"""Tests for provenance and capabilities checking."""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import patch, MagicMock

from fenceline.check.provenance import check_provenance
from fenceline.check.capabilities import check_capabilities


class TestCheckProvenance:
    def _mock_urlopen(self, data):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    @patch("fenceline.check.provenance.urllib.request.urlopen")
    def test_has_provenance(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            "dist": {
                "attestations": [{"predicateType": "https://slsa.dev/provenance/v1"}],
                "signatures": [],
            }
        })
        result = check_provenance("express", "4.18.0")
        assert result["has_provenance"] is True
        assert result["attestation_count"] == 1

    @patch("fenceline.check.provenance.urllib.request.urlopen")
    def test_no_provenance(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            "dist": {"shasum": "abc123"}
        })
        result = check_provenance("lodash", "4.17.21")
        assert result["has_provenance"] is False
        assert result["attestation_count"] == 0

    @patch("fenceline.check.provenance.urllib.request.urlopen")
    def test_has_legacy_signatures(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_urlopen({
            "dist": {
                "attestations": [],
                "signatures": [{"keyid": "abc", "sig": "def"}],
            }
        })
        result = check_provenance("express", "4.18.0")
        assert result["has_signatures"] is True
        assert result["has_provenance"] is False

    @patch("fenceline.check.provenance.urllib.request.urlopen")
    def test_network_error_returns_empty(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("timeout")
        result = check_provenance("express", "4.18.0")
        assert result["has_provenance"] is False
        assert result["attestation_count"] == 0

    @patch("fenceline.check.provenance.urllib.request.urlopen")
    def test_attestations_as_dict(self, mock_urlopen):
        """Some packages wrap attestations in a dict with a list inside."""
        mock_urlopen.return_value = self._mock_urlopen({
            "dist": {
                "attestations": {"predicates": [{"type": "slsa"}]},
            }
        })
        result = check_provenance("pkg", "1.0.0")
        assert result["has_provenance"] is True


class TestCheckCapabilities:
    def test_postinstall_detected(self):
        info = {"versions": {"1.0.0": {"scripts": {"postinstall": "node setup.js"}}}}
        caps = check_capabilities(info, "1.0.0")
        assert "has_postinstall" in caps

    def test_preinstall_detected(self):
        info = {"versions": {"1.0.0": {"scripts": {"preinstall": "sh pre.sh"}}}}
        caps = check_capabilities(info, "1.0.0")
        assert "has_preinstall" in caps

    def test_prepare_detected(self):
        info = {"versions": {"1.0.0": {"scripts": {"prepare": "npm run build"}}}}
        caps = check_capabilities(info, "1.0.0")
        assert "has_prepare" in caps

    def test_no_scripts(self):
        info = {"versions": {"1.0.0": {}}}
        caps = check_capabilities(info, "1.0.0")
        assert caps == []

    def test_missing_version(self):
        info = {"versions": {}}
        caps = check_capabilities(info, "1.0.0")
        assert caps == []

    def test_only_safe_scripts(self):
        info = {"versions": {"1.0.0": {"scripts": {"test": "jest", "start": "node ."}}}}
        caps = check_capabilities(info, "1.0.0")
        assert caps == []
