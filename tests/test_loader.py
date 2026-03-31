"""Tests for the deep map loader."""

from fenceline.deepmap.loader import load_maps


def test_load_maps_returns_tools_and_cdns():
    dm = load_maps()
    assert len(dm.tools) >= 8
    assert len(dm.cdns) >= 4


def test_npm_tool_has_primary_domains():
    dm = load_maps()
    npm = None
    for t in dm.tools:
        if t.id == "npm":
            npm = t
            break
    assert npm is not None
    assert len(npm.primary_domains) > 0
    assert npm.port == 443
    assert npm.uploads_during_install is False


def test_cloudflare_cdn_has_ipv4_and_ipv6():
    dm = load_maps()
    cf = None
    for c in dm.cdns:
        if c.id == "cloudflare":
            cf = c
            break
    assert cf is not None
    assert len(cf.ipv4_prefixes) > 0
    assert len(cf.ipv6_prefixes) > 0


def test_is_known_ip_ipv4():
    dm = load_maps()
    # Cloudflare IPv4 range
    assert dm.is_known_ip("104.16.1.34") is True
    assert dm.is_known_ip("192.0.2.1") is False


def test_is_known_ip_ipv6():
    dm = load_maps()
    # Cloudflare IPv6 range (2606:4700::/32)
    assert dm.is_known_ip("2606:4700::6810:722") is True
    assert dm.is_known_ip("2001:db8::1") is False


def test_is_known_domain():
    dm = load_maps()
    assert dm.is_known_domain("registry.npmjs.org") is True
    assert dm.is_known_domain("evil-server.xyz") is False


def test_get_tool_for_command():
    dm = load_maps()
    npm_tool = dm.get_tool_for_command("npm")
    assert npm_tool is not None
    assert npm_tool.id == "npm"

    pip_tool = dm.get_tool_for_command("pip")
    assert pip_tool is not None

    assert dm.get_tool_for_command("unknown_tool") is None
