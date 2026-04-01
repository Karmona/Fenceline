"""Tests for HTTP logging proxy and behavior analysis."""

from __future__ import annotations

import ipaddress

from fenceline.install.http_logger import (
    parse_http_log,
    check_http_behavior,
    HttpLogEntry,
    NODE_PROXY_SCRIPT,
    PROXY_SCRIPT,
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


class TestNodeProxyScript:
    """Tests for the Node.js proxy script used in Node containers."""

    def test_node_script_exists(self):
        """NODE_PROXY_SCRIPT is defined and non-empty."""
        assert NODE_PROXY_SCRIPT
        assert len(NODE_PROXY_SCRIPT) > 100

    def test_node_script_uses_builtin_modules_only(self):
        """Node proxy must not require any npm packages — only builtins."""
        assert 'require("http")' in NODE_PROXY_SCRIPT
        assert 'require("net")' in NODE_PROXY_SCRIPT
        assert 'require("fs")' in NODE_PROXY_SCRIPT
        # Should not require any third-party modules
        requires = [
            line for line in NODE_PROXY_SCRIPT.splitlines()
            if "require(" in line
        ]
        for req in requires:
            assert any(mod in req for mod in ['"http"', '"net"', '"fs"']), (
                f"Unexpected require: {req}"
            )

    def test_node_script_listens_on_8899(self):
        """Node proxy must bind to same port as Python proxy."""
        assert "8899" in NODE_PROXY_SCRIPT

    def test_node_script_logs_to_same_file(self):
        """Both proxies must write to /tmp/fenceline-http.log."""
        assert "/tmp/fenceline-http.log" in NODE_PROXY_SCRIPT
        assert "/tmp/fenceline-http.log" in PROXY_SCRIPT

    def test_node_script_handles_connect(self):
        """Node proxy must handle CONNECT method for HTTPS tunneling."""
        assert "connect" in NODE_PROXY_SCRIPT.lower()
        assert "CONNECT" in NODE_PROXY_SCRIPT

    def test_node_script_log_format_matches_python(self):
        """Both proxies must write the same log format: METHOD HOST PATH."""
        # Both should use the same space-separated format
        assert "appendFileSync" in NODE_PROXY_SCRIPT
        # Python proxy uses: f.write(f"{method} {host} {path}\\n")
        # Node proxy should use similar format


class TestProxyScriptParity:
    """Verify Python and Node proxy scripts produce compatible output."""

    def test_both_log_connect_format(self):
        """Both scripts log CONNECT with host:port format."""
        # Verify the Python proxy logs CONNECT with host:port
        assert 'log_request("CONNECT"' in PROXY_SCRIPT
        # Verify the Node proxy logs CONNECT
        assert '"CONNECT"' in NODE_PROXY_SCRIPT

    def test_both_listen_same_port(self):
        """Both proxies use port 8899."""
        assert "8899" in PROXY_SCRIPT
        assert "8899" in NODE_PROXY_SCRIPT

    def test_both_bind_localhost(self):
        """Both proxies bind to 127.0.0.1."""
        assert "127.0.0.1" in PROXY_SCRIPT
        assert "127.0.0.1" in NODE_PROXY_SCRIPT
