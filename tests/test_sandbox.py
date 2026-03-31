"""Tests for Docker-sandboxed install."""

from unittest.mock import patch, MagicMock
import subprocess

from fenceline.install.sandbox import (
    docker_available,
    detect_image,
    parse_ss_output,
    SandboxedInstall,
    ContainerMonitor,
)
from fenceline.install.monitor import Connection


# --- docker_available ---


class TestDockerAvailable:
    def test_docker_installed_and_running(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert docker_available() is True

    def test_docker_not_installed(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert docker_available() is False

    def test_docker_daemon_not_running(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert docker_available() is False

    def test_docker_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 10)):
            assert docker_available() is False


# --- detect_image ---


class TestDetectImage:
    def test_npm_maps_to_node_alpine(self):
        assert detect_image(["npm", "install", "express"]) == "node:alpine"

    def test_pip_maps_to_python_alpine(self):
        assert detect_image(["pip", "install", "requests"]) == "python:3.12-alpine"

    def test_yarn_maps_to_node_alpine(self):
        assert detect_image(["yarn", "add", "react"]) == "node:alpine"

    def test_cargo_maps_to_rust_alpine(self):
        assert detect_image(["cargo", "install", "ripgrep"]) == "rust:alpine"

    def test_unknown_defaults_to_node(self):
        assert detect_image(["unknown-tool", "install"]) == "node:alpine"

    def test_empty_defaults_to_node(self):
        assert detect_image([]) == "node:alpine"


# --- parse_ss_output ---


class TestParseSsOutput:
    MOCK_SS = (
        "State    Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "ESTAB    0       0       172.17.0.2:34567    104.16.1.34:443    users:((\"node\",pid=1,fd=3))\n"
        "ESTAB    0       0       172.17.0.2:34568    45.33.32.1:8080    users:((\"curl\",pid=2,fd=4))\n"
        "LISTEN   0       128     0.0.0.0:3000       0.0.0.0:*\n"
    )

    def test_parses_established_connections(self):
        conns = parse_ss_output(self.MOCK_SS)
        assert len(conns) == 2

    def test_extracts_remote_ip_and_port(self):
        conns = parse_ss_output(self.MOCK_SS)
        assert conns[0].remote_ip == "104.16.1.34"
        assert conns[0].remote_port == 443
        assert conns[1].remote_ip == "45.33.32.1"
        assert conns[1].remote_port == 8080

    def test_extracts_process_name(self):
        conns = parse_ss_output(self.MOCK_SS)
        assert conns[0].process_name == "node"
        assert conns[1].process_name == "curl"

    def test_ignores_listen_state(self):
        conns = parse_ss_output(self.MOCK_SS)
        # Only ESTAB, not LISTEN
        for c in conns:
            assert c.remote_port != 3000

    def test_empty_output(self):
        assert parse_ss_output("") == []

    def test_header_only(self):
        assert parse_ss_output("State Recv-Q Send-Q Local Peer Process\n") == []


# --- SandboxedInstall ---


class TestSandboxedInstall:
    def _make_deep_map(self):
        """Create a minimal DeepMap for testing."""
        import ipaddress
        from fenceline.deepmap.models import AllowedDomain, CDNMap, DeepMap, ToolMap
        cdn = CDNMap(
            id="cloudflare", name="Cloudflare", asn="AS13335",
            ipv4_prefixes=[ipaddress.IPv4Network("104.16.0.0/16")],
            ipv6_prefixes=[ipaddress.IPv6Network("2606:4700::/32")],
        )
        tool = ToolMap(
            id="npm", description="npm",
            primary_domains=[AllowedDomain(domain="registry.npmjs.org", cdn_provider="cloudflare")],
        )
        return DeepMap(tools=[tool], cdns=[cdn])

    @patch("fenceline.install.sandbox.subprocess.run")
    def test_docker_start_failure_returns_error(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="error", stdout="")
        sandbox = SandboxedInstall(self._make_deep_map())
        alerts, code = sandbox.run(["npm", "install", "express"])
        assert code == 1

    @patch("fenceline.install.sandbox.subprocess.run")
    def test_clean_install_returns_zero(self, mock_run):
        # Use a single mock that returns success for all docker commands
        mock_run.return_value = MagicMock(returncode=0, stdout="abc123container\n", stderr="")

        # Override specific calls by checking the command
        def side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            result = MagicMock(returncode=0, stderr="")
            if cmd[0:2] == ["docker", "run"]:
                result.stdout = "abc123container\n"
            elif cmd[0:2] == ["docker", "wait"]:
                result.stdout = "0\n"
            elif cmd[0:2] == ["docker", "exec"]:
                result.stdout = ""  # no connections = clean
            elif cmd[0:2] == ["docker", "cp"]:
                result.stdout = ""
            elif cmd[0:2] == ["docker", "rm"]:
                result.stdout = ""
            else:
                result.stdout = ""
            return result

        mock_run.side_effect = side_effect

        sandbox = SandboxedInstall(self._make_deep_map())
        alerts, code = sandbox.run(["npm", "install", "express"])
        assert code == 0
        assert len(alerts) == 0

    @patch("fenceline.install.sandbox.subprocess.run")
    def test_docker_not_found_raises_cleanly(self, mock_run):
        mock_run.side_effect = FileNotFoundError("docker not found")
        sandbox = SandboxedInstall(self._make_deep_map())
        alerts, code = sandbox.run(["npm", "install", "express"])
        assert code == 1


# --- ContainerMonitor ---


class TestContainerMonitor:
    def _make_deep_map(self):
        import ipaddress
        from fenceline.deepmap.models import AllowedDomain, CDNMap, DeepMap, ToolMap
        cdn = CDNMap(
            id="cloudflare", name="Cloudflare", asn="AS13335",
            ipv4_prefixes=[ipaddress.IPv4Network("104.16.0.0/16")],
            ipv6_prefixes=[],
        )
        tool = ToolMap(
            id="npm", description="npm",
            primary_domains=[AllowedDomain(domain="registry.npmjs.org", cdn_provider="cloudflare")],
        )
        return DeepMap(tools=[tool], cdns=[cdn])

    @patch("fenceline.install.sandbox.subprocess.run")
    def test_detects_suspicious_connection(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "State Recv-Q Send-Q Local Peer Process\n"
                'ESTAB 0 0 172.17.0.2:1234 45.33.32.1:8080 users:(("node",pid=1,fd=3))\n'
            ),
        )

        monitor = ContainerMonitor("abc123", self._make_deep_map(), "npm")
        conns = monitor._get_container_connections()
        assert len(conns) == 1
        assert conns[0].remote_port == 8080

    @patch("fenceline.install.sandbox.subprocess.run")
    def test_docker_exec_failure_returns_empty(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 5)
        monitor = ContainerMonitor("abc123", self._make_deep_map(), "npm")
        conns = monitor._get_container_connections()
        assert conns == []
