"""Tests for HTTP logging proxy and behavior analysis."""

from __future__ import annotations

import ipaddress

from fenceline.install.http_logger import (
    parse_http_log,
    check_http_behavior,
    HttpLogEntry,
)
from fenceline.deepmap.models import AllowedDomain, CDNMap, DeepMap, ToolMap


def _make_deep_map():
    cdn = CDNMap(
        id="cloudflare", name="Cloudflare", asn="AS13335",
        ipv4_prefixes=[ipaddress.IPv4Network("104.16.0.0/16")],
        ipv6_prefixes=[],
    )
    tool = ToolMap(
        id="npm", description="npm",
        primary_domains=[
            AllowedDomain(domain="registry.npmjs.org", cdn_provider="cloudflare"),
        ],
        upload_domains=[],
        uploads_during_install=False,
        expected_processes=["node", "npm"],
    )
    return DeepMap(tools=[tool], cdns=[cdn])


class TestParseHttpLog:
    def test_connect_entry(self):
        output = "CONNECT registry.npmjs.org:443\n"
        entries = parse_http_log(output)
        assert len(entries) == 1
        assert entries[0].method == "CONNECT"
        assert entries[0].host == "registry.npmjs.org:443"

    def test_get_entry(self):
        output = "GET registry.npmjs.org /express\n"
        entries = parse_http_log(output)
        assert len(entries) == 1
        assert entries[0].method == "GET"
        assert entries[0].path == "/express"

    def test_multiple_entries(self):
        output = (
            "CONNECT registry.npmjs.org:443\n"
            "CONNECT registry.npmjs.org:443\n"
            "GET example.com /api\n"
        )
        entries = parse_http_log(output)
        assert len(entries) == 3

    def test_empty_output(self):
        assert parse_http_log("") == []

    def test_malformed_line_skipped(self):
        output = "BADLINE\nCONNECT registry.npmjs.org:443\n"
        entries = parse_http_log(output)
        assert len(entries) == 1


class TestCheckHttpBehavior:
    def test_expected_domain_no_warnings(self):
        entries = [HttpLogEntry("CONNECT", "registry.npmjs.org:443")]
        deep_map = _make_deep_map()
        warnings = check_http_behavior(entries, "npm", deep_map)
        assert len(warnings) == 0

    def test_unexpected_domain_warns(self):
        entries = [HttpLogEntry("CONNECT", "api.github.com:443")]
        deep_map = _make_deep_map()
        warnings = check_http_behavior(entries, "npm", deep_map)
        assert len(warnings) == 1
        assert "unexpected domain" in warnings[0].lower()

    def test_post_to_non_upload_domain_warns(self):
        entries = [HttpLogEntry("POST", "evil.com", "/exfil")]
        deep_map = _make_deep_map()
        warnings = check_http_behavior(entries, "npm", deep_map)
        assert len(warnings) >= 1
        assert "POST" in warnings[0]

    def test_post_allowed_when_uploads_during_install(self):
        deep_map = _make_deep_map()
        deep_map.tools[0].uploads_during_install = True
        entries = [HttpLogEntry("POST", "registry.npmjs.org", "/package")]
        warnings = check_http_behavior(entries, "npm", deep_map)
        # uploads_during_install=True means POST is OK
        assert len(warnings) == 0

    def test_subdomain_of_expected_is_ok(self):
        entries = [HttpLogEntry("CONNECT", "cdn.registry.npmjs.org:443")]
        deep_map = _make_deep_map()
        warnings = check_http_behavior(entries, "npm", deep_map)
        assert len(warnings) == 0

    def test_unknown_tool_returns_empty(self):
        entries = [HttpLogEntry("CONNECT", "evil.com:443")]
        deep_map = _make_deep_map()
        warnings = check_http_behavior(entries, "unknown-tool", deep_map)
        assert len(warnings) == 0

    def test_put_to_unexpected_warns(self):
        entries = [HttpLogEntry("PUT", "attacker.com", "/data")]
        deep_map = _make_deep_map()
        warnings = check_http_behavior(entries, "npm", deep_map)
        assert len(warnings) >= 1

    def test_get_to_unexpected_no_warn(self):
        """GET requests to unexpected domains are OK (CDN redirects etc)."""
        entries = [HttpLogEntry("GET", "cdn.example.com", "/file.tgz")]
        deep_map = _make_deep_map()
        warnings = check_http_behavior(entries, "npm", deep_map)
        # GET is not suspicious (only CONNECT triggers domain check)
        # POST/PUT/PATCH to unknown domains is suspicious
        assert all("GET" not in w for w in warnings)
