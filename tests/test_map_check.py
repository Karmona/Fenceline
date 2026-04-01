"""Tests for map freshness checking."""

from __future__ import annotations

import ipaddress
from unittest.mock import patch, MagicMock

from fenceline.map_check import _resolve_dns, _ip_in_any_cdn, _check_domain
from fenceline.deepmap.models import AllowedDomain, CDNMap, DeepMap, ToolMap


def _make_deep_map():
    cdn = CDNMap(
        id="cloudflare", name="Cloudflare", asn="AS13335",
        ipv4_prefixes=[ipaddress.IPv4Network("104.16.0.0/16")],
        ipv6_prefixes=[],
    )
    tool = ToolMap(
        id="npm", description="npm",
        primary_domains=[AllowedDomain(domain="registry.npmjs.org",
                                       cdn_provider="cloudflare")],
    )
    return DeepMap(tools=[tool], cdns=[cdn])


class TestResolveDns:
    @patch("fenceline.map_check.socket.getaddrinfo")
    def test_returns_ips(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('104.16.1.34', 443)),
            (2, 1, 6, '', ('104.16.1.35', 443)),
        ]
        ips = _resolve_dns("registry.npmjs.org")
        assert "104.16.1.34" in ips
        assert "104.16.1.35" in ips

    @patch("fenceline.map_check.socket.getaddrinfo")
    def test_deduplicates_ips(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('104.16.1.34', 443)),
            (2, 1, 6, '', ('104.16.1.34', 443)),
        ]
        ips = _resolve_dns("registry.npmjs.org")
        assert len(ips) == 1

    @patch("fenceline.map_check.socket.getaddrinfo")
    def test_returns_empty_on_error(self, mock_getaddrinfo):
        import socket
        mock_getaddrinfo.side_effect = socket.gaierror("DNS failed")
        ips = _resolve_dns("nonexistent.example.com")
        assert ips == []


class TestIpInCdn:
    def test_ip_in_range(self):
        deep_map = _make_deep_map()
        assert _ip_in_any_cdn("104.16.1.34", deep_map) is True

    def test_ip_not_in_range(self):
        deep_map = _make_deep_map()
        assert _ip_in_any_cdn("8.8.8.8", deep_map) is False

    def test_invalid_ip(self):
        deep_map = _make_deep_map()
        assert _ip_in_any_cdn("not-an-ip", deep_map) is False


class TestCheckDomain:
    @patch("fenceline.map_check._resolve_dns")
    def test_domain_ok_when_ip_in_cdn(self, mock_dns):
        mock_dns.return_value = ["104.16.1.34"]
        deep_map = _make_deep_map()
        domain_info = deep_map.tools[0].primary_domains[0]
        result = _check_domain("registry.npmjs.org", domain_info, deep_map)
        assert result is None  # None = OK

    @patch("fenceline.map_check._resolve_dns")
    def test_domain_issue_when_ip_not_in_cdn(self, mock_dns):
        mock_dns.return_value = ["8.8.8.8"]
        deep_map = _make_deep_map()
        domain_info = deep_map.tools[0].primary_domains[0]
        result = _check_domain("registry.npmjs.org", domain_info, deep_map)
        assert result is not None
        assert "not in any known CDN" in result

    @patch("fenceline.map_check._resolve_dns")
    def test_domain_dns_failure(self, mock_dns):
        import socket
        mock_dns.side_effect = socket.gaierror("DNS failed")
        deep_map = _make_deep_map()
        domain_info = deep_map.tools[0].primary_domains[0]
        result = _check_domain("registry.npmjs.org", domain_info, deep_map)
        assert result is not None
        assert "DNS" in result
