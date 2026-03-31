"""Tests for the connection matcher."""

import ipaddress

from fenceline.deepmap.models import AllowedDomain, CDNMap, DeepMap, ToolMap
from fenceline.install.matcher import check_connection
from fenceline.install.monitor import Connection


def _make_connection(remote_ip: str, remote_port: int = 443) -> Connection:
    """Helper to create a Connection with defaults."""
    return Connection(
        pid=1000,
        process_name="npm",
        remote_ip=remote_ip,
        remote_port=remote_port,
        protocol="TCP",
        timestamp=0.0,
    )


def _make_deep_map() -> DeepMap:
    """Create a simple DeepMap with one CDN range (Cloudflare)."""
    cdn = CDNMap(
        id="cloudflare",
        name="Cloudflare",
        asn="AS13335",
        ipv4_prefixes=[ipaddress.IPv4Network("104.16.0.0/16")],
        ipv6_prefixes=[ipaddress.IPv6Network("2606:4700::/32")],
    )
    tool = ToolMap(
        id="npm",
        description="npm registry",
        primary_domains=[
            AllowedDomain(
                domain="registry.npmjs.org",
                cdn_provider="cloudflare",
            )
        ],
    )
    return DeepMap(tools=[tool], cdns=[cdn])


class TestNonStandardPort:
    """Non-443 ports should raise critical alerts."""

    def test_port_8080_is_critical(self):
        deep_map = _make_deep_map()
        conn = _make_connection("104.16.0.1", remote_port=8080)
        alert = check_connection(conn, deep_map, "npm")

        assert alert is not None
        assert alert.severity == "critical"
        assert "8080" in alert.reason

    def test_port_443_no_alert_for_known_cdn(self):
        deep_map = _make_deep_map()
        conn = _make_connection("104.16.0.1", remote_port=443)
        alert = check_connection(conn, deep_map, "npm")

        assert alert is None


class TestCDNMatching:
    """IP-to-CDN matching tests."""

    def test_ip_in_known_range_returns_none(self):
        deep_map = _make_deep_map()
        conn = _make_connection("104.16.50.1")
        alert = check_connection(conn, deep_map, "npm")

        assert alert is None

    def test_ip_outside_range_returns_warning(self):
        deep_map = _make_deep_map()
        conn = _make_connection("198.51.100.5")
        alert = check_connection(conn, deep_map, "npm")

        assert alert is not None
        assert alert.severity == "warning"
        assert "Unknown IP" in alert.reason
        assert "198.51.100.5" in alert.reason

    def test_ip_in_wrong_cdn_returns_warning(self):
        """IP is in a CDN range, but the tool doesn't use that CDN."""
        # Add a second CDN that npm does NOT use
        deep_map = _make_deep_map()
        deep_map.cdns.append(
            CDNMap(
                id="akamai",
                name="Akamai",
                asn="AS20940",
                ipv4_prefixes=[ipaddress.IPv4Network("23.0.0.0/16")],
            )
        )

        conn = _make_connection("23.0.0.1")
        alert = check_connection(conn, deep_map, "npm")

        assert alert is not None
        assert alert.severity == "warning"
        assert "Akamai" in alert.reason
        assert "npm" in alert.reason


class TestIPv6Matching:
    """IPv6 address matching tests."""

    def test_ipv6_in_known_range_returns_none(self):
        deep_map = _make_deep_map()
        conn = _make_connection("2606:4700::6810:722")
        alert = check_connection(conn, deep_map, "npm")

        assert alert is None

    def test_ipv6_outside_range_returns_warning(self):
        deep_map = _make_deep_map()
        conn = _make_connection("2001:db8::1")
        alert = check_connection(conn, deep_map, "npm")

        assert alert is not None
        assert alert.severity == "warning"

    def test_ipv6_non_standard_port_is_critical(self):
        deep_map = _make_deep_map()
        conn = _make_connection("2606:4700::6810:722", remote_port=8080)
        alert = check_connection(conn, deep_map, "npm")

        assert alert is not None
        assert alert.severity == "critical"
