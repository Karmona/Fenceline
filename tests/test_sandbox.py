"""Tests for Docker-sandboxed install."""

from unittest.mock import patch, MagicMock
import subprocess

from fenceline.install.sandbox import (
    docker_available,
    detect_image,
    SandboxedInstall,
    ContainerMonitor,
    _safe_package_name,
)
from fenceline.install.monitor import Connection, parse_ss_output, parse_iptables_log


# --- _safe_package_name ---


class TestSafePackageName:
    def test_normal_package(self):
        assert _safe_package_name("express") is True

    def test_scoped_package(self):
        assert _safe_package_name("@types/node") is True

    def test_package_with_dots(self):
        assert _safe_package_name("co.js") is True

    def test_injection_attempt_semicolon(self):
        assert _safe_package_name("foo';process.exit()//") is False

    def test_injection_attempt_quotes(self):
        assert _safe_package_name("foo\"bar") is False

    def test_path_traversal(self):
        assert _safe_package_name("../../../etc/passwd") is False

    def test_empty_string(self):
        assert _safe_package_name("") is False

    def test_spaces(self):
        assert _safe_package_name("foo bar") is False


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


# --- parse_iptables_log ---


class TestParseIptablesLog:
    SAMPLE_DMESG = (
        "[  123.456] random kernel message\n"
        "[  124.789] FENCELINE:IN= OUT=eth0 SRC=172.17.0.2 DST=93.184.216.34 "
        "LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP "
        "SPT=45678 DPT=8080 WINDOW=29200 RES=0x00 SYN URGP=0\n"
        "[  125.012] FENCELINE:IN= OUT=eth0 SRC=172.17.0.2 DST=104.16.1.34 "
        "LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12346 DF PROTO=TCP "
        "SPT=45679 DPT=443 WINDOW=29200 RES=0x00 SYN URGP=0\n"
    )

    def test_parses_connections(self):
        conns = parse_iptables_log(self.SAMPLE_DMESG)
        assert len(conns) == 2

    def test_extracts_ip_and_port(self):
        conns = parse_iptables_log(self.SAMPLE_DMESG)
        assert conns[0].remote_ip == "93.184.216.34"
        assert conns[0].remote_port == 8080
        assert conns[1].remote_ip == "104.16.1.34"
        assert conns[1].remote_port == 443

    def test_empty_output(self):
        assert parse_iptables_log("") == []

    def test_no_fenceline_lines(self):
        output = "[  123.456] generic kernel message\n[  124.789] another message\n"
        assert parse_iptables_log(output) == []

    def test_mixed_output(self):
        output = (
            "lots of kernel noise\n"
            "FENCELINE:IN= OUT=eth0 SRC=10.0.0.1 DST=8.8.8.8 "
            "PROTO=TCP SPT=1234 DPT=53\n"
            "more noise\n"
        )
        conns = parse_iptables_log(output)
        assert len(conns) == 1
        assert conns[0].remote_ip == "8.8.8.8"
        assert conns[0].remote_port == 53

    def test_malformed_dpt_ignored(self):
        output = "FENCELINE:IN= OUT=eth0 DST=1.2.3.4 DPT=notanumber\n"
        conns = parse_iptables_log(output)
        assert len(conns) == 0  # DPT parse fails, no connection created


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

    @patch("fenceline.install.sandbox._docker", return_value="docker")
    @patch("fenceline.install.sandbox.subprocess.run")
    def test_failed_docker_cp_returns_error(self, mock_run, _mock_docker):
        """A failed docker cp must not report success (P2 fix)."""
        def side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            result = MagicMock(returncode=0, stderr=b"")
            if cmd[0:2] == ["docker", "run"]:
                result.stdout = "abc123container\n"
            elif cmd[0:2] == ["docker", "wait"]:
                result.stdout = "0\n"
            elif cmd[0:2] == ["docker", "exec"]:
                result.stdout = ""  # no connections = clean
            elif cmd[0:2] == ["docker", "cp"]:
                result.returncode = 1
                result.stderr = b"no such container"
            elif cmd[0:2] == ["docker", "rm"]:
                result.stdout = ""
            else:
                result.stdout = ""
            return result

        mock_run.side_effect = side_effect
        sandbox = SandboxedInstall(self._make_deep_map())
        alerts, code = sandbox.run(["npm", "install", "express"])
        assert code == 1  # must fail, not silently succeed

    @patch("fenceline.install.sandbox._docker", return_value="docker")
    @patch("fenceline.install.sandbox.snapshot_container", return_value={})
    @patch("fenceline.install.sandbox.subprocess.run")
    def test_pip_install_copies_new_packages(self, mock_run, _mock_snap, _mock_docker):
        """Pip installs should diff package lists and copy new packages."""
        import json

        pre_packages = json.dumps([{"name": "pip", "version": "24.0"},
                                   {"name": "setuptools", "version": "69.0"}])
        post_packages = json.dumps([{"name": "pip", "version": "24.0"},
                                    {"name": "setuptools", "version": "69.0"},
                                    {"name": "requests", "version": "2.31.0"}])

        call_count = {"exec": 0}

        def side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            result = MagicMock(returncode=0, stderr=b"")
            if cmd[0:2] == ["docker", "run"]:
                result.stdout = "pip123container\n"
            elif cmd[0:2] == ["docker", "wait"]:
                result.stdout = "0\n"
            elif cmd[0:2] == ["docker", "exec"]:
                call_count["exec"] += 1
                # Route different exec calls
                if "cat" in cmd:
                    result.stdout = pre_packages
                elif "pip" in cmd and "list" in cmd:
                    result.stdout = post_packages
                elif "python3" in cmd and "site" in str(cmd):
                    result.stdout = "/usr/local/lib/python3.12/site-packages\n"
                elif "test" in cmd and "-d" in cmd:
                    result.returncode = 0  # directory exists
                else:
                    result.stdout = ""
            elif cmd[0:2] == ["docker", "cp"]:
                result.returncode = 0
            elif cmd[0:2] == ["docker", "rm"]:
                result.stdout = ""
            else:
                result.stdout = ""
            return result

        mock_run.side_effect = side_effect

        # Need a deep map with pip tool
        import ipaddress
        from fenceline.deepmap.models import AllowedDomain, CDNMap, DeepMap, ToolMap
        cdn = CDNMap(
            id="fastly", name="Fastly", asn="AS54113",
            ipv4_prefixes=[ipaddress.IPv4Network("151.101.0.0/16")],
            ipv6_prefixes=[],
        )
        tool = ToolMap(
            id="pip", description="pip",
            primary_domains=[AllowedDomain(domain="pypi.org", cdn_provider="fastly")],
        )
        deep_map = DeepMap(tools=[tool], cdns=[cdn])

        sandbox = SandboxedInstall(deep_map)
        alerts, code = sandbox.run(["pip", "install", "requests"])
        assert code == 0


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
        # netstat -tnp format (not ss format)
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "Active Internet connections (w/o servers)\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
                "tcp        0      1 172.17.0.2:1234         45.33.32.1:8080         SYN_SENT    1/node\n"
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


# --- Node proxy setup in sandbox ---


class TestNodeProxySetup:
    """Verify that the sandbox sets up HTTP proxy for Node containers."""

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

    @patch("fenceline.install.sandbox._docker", return_value="docker")
    @patch("fenceline.install.sandbox.subprocess.run")
    def test_npm_container_gets_node_proxy(self, mock_run, _mock_docker):
        """npm install should set up the Node.js HTTP proxy."""
        docker_run_cmd = None

        def side_effect(*args, **kwargs):
            nonlocal docker_run_cmd
            cmd = args[0] if args else kwargs.get("args", [])
            result = MagicMock(returncode=0, stderr="")
            if cmd[0:2] == ["docker", "run"]:
                docker_run_cmd = cmd
                result.stdout = "node123container\n"
            elif cmd[0:2] == ["docker", "wait"]:
                result.stdout = "0\n"
            elif cmd[0:2] == ["docker", "exec"]:
                result.stdout = ""
            elif cmd[0:2] == ["docker", "cp"]:
                result.stdout = ""
            elif cmd[0:2] == ["docker", "rm"]:
                result.stdout = ""
            else:
                result.stdout = ""
            return result

        mock_run.side_effect = side_effect

        sandbox = SandboxedInstall(self._make_deep_map())
        sandbox.run(["npm", "install", "express"])

        # The docker run command should contain the shell command
        assert docker_run_cmd is not None
        shell_cmd = docker_run_cmd[-1]  # last arg is the shell command
        assert "fenceline-proxy.js" in shell_cmd, (
            f"Node proxy script not found in shell cmd: {shell_cmd}"
        )
        assert "node /tmp/fenceline-proxy.js" in shell_cmd
        assert "HTTP_PROXY=http://127.0.0.1:8899" in shell_cmd
        assert "HTTPS_PROXY=http://127.0.0.1:8899" in shell_cmd

    @patch("fenceline.install.sandbox._docker", return_value="docker")
    @patch("fenceline.install.sandbox.subprocess.run")
    def test_yarn_container_gets_node_proxy(self, mock_run, _mock_docker):
        """yarn add should also set up the Node.js HTTP proxy."""
        docker_run_cmd = None

        def side_effect(*args, **kwargs):
            nonlocal docker_run_cmd
            cmd = args[0] if args else kwargs.get("args", [])
            result = MagicMock(returncode=0, stderr="")
            if cmd[0:2] == ["docker", "run"]:
                docker_run_cmd = cmd
                result.stdout = "yarn123container\n"
            elif cmd[0:2] == ["docker", "wait"]:
                result.stdout = "0\n"
            elif cmd[0:2] == ["docker", "exec"]:
                result.stdout = ""
            elif cmd[0:2] == ["docker", "cp"]:
                result.stdout = ""
            elif cmd[0:2] == ["docker", "rm"]:
                result.stdout = ""
            else:
                result.stdout = ""
            return result

        mock_run.side_effect = side_effect

        sandbox = SandboxedInstall(self._make_deep_map())
        sandbox.run(["yarn", "add", "lodash"])

        assert docker_run_cmd is not None
        shell_cmd = docker_run_cmd[-1]
        assert "fenceline-proxy.js" in shell_cmd

    @patch("fenceline.install.sandbox._docker", return_value="docker")
    @patch("fenceline.install.sandbox.subprocess.run")
    def test_pip_still_uses_python_proxy(self, mock_run, _mock_docker):
        """pip install should still use the Python proxy, not Node."""
        docker_run_cmd = None

        def side_effect(*args, **kwargs):
            nonlocal docker_run_cmd
            cmd = args[0] if args else kwargs.get("args", [])
            result = MagicMock(returncode=0, stderr="")
            if cmd[0:2] == ["docker", "run"]:
                docker_run_cmd = cmd
                result.stdout = "pip123container\n"
            elif cmd[0:2] == ["docker", "wait"]:
                result.stdout = "0\n"
            elif cmd[0:2] == ["docker", "exec"]:
                if "cat" in cmd:
                    result.stdout = "[]"  # empty pre-packages
                elif "pip" in cmd and "list" in cmd:
                    result.stdout = "[]"
                elif "python3" in cmd:
                    result.stdout = "/usr/lib/python3/site-packages\n"
                else:
                    result.stdout = ""
            elif cmd[0:2] == ["docker", "cp"]:
                result.stdout = ""
            elif cmd[0:2] == ["docker", "rm"]:
                result.stdout = ""
            else:
                result.stdout = ""
            return result

        mock_run.side_effect = side_effect

        import ipaddress
        from fenceline.deepmap.models import AllowedDomain, CDNMap, DeepMap, ToolMap
        cdn = CDNMap(
            id="fastly", name="Fastly", asn="AS54113",
            ipv4_prefixes=[ipaddress.IPv4Network("151.101.0.0/16")],
            ipv6_prefixes=[],
        )
        tool = ToolMap(
            id="pip", description="pip",
            primary_domains=[AllowedDomain(domain="pypi.org", cdn_provider="fastly")],
        )
        deep_map = DeepMap(tools=[tool], cdns=[cdn])

        sandbox = SandboxedInstall(deep_map)
        sandbox.run(["pip", "install", "requests"])

        assert docker_run_cmd is not None
        shell_cmd = docker_run_cmd[-1]
        assert "fenceline-proxy.py" in shell_cmd, "pip should use Python proxy"
        assert "fenceline-proxy.js" not in shell_cmd, "pip should NOT use Node proxy"


# --- Dry-run mode ---


class TestDryRun:
    """Verify that --dry-run skips artifact copy."""

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

    @patch("fenceline.install.sandbox._docker", return_value="docker")
    @patch("fenceline.install.sandbox.subprocess.run")
    def test_dry_run_skips_artifact_copy(self, mock_run, _mock_docker, capsys):
        """dry_run=True should not call docker cp."""
        docker_cp_called = False

        def side_effect(*args, **kwargs):
            nonlocal docker_cp_called
            cmd = args[0] if args else kwargs.get("args", [])
            result = MagicMock(returncode=0, stderr="")
            if cmd[0:2] == ["docker", "run"]:
                result.stdout = "dryrun123\n"
            elif cmd[0:2] == ["docker", "exec"]:
                result.stdout = ""
            elif cmd[0:2] == ["docker", "cp"]:
                docker_cp_called = True
                result.stdout = ""
            elif cmd[0:2] == ["docker", "kill"]:
                result.stdout = ""
            elif cmd[0:2] == ["docker", "rm"]:
                result.stdout = ""
            else:
                result.stdout = ""
            return result

        mock_run.side_effect = side_effect

        sandbox = SandboxedInstall(self._make_deep_map(), dry_run=True)
        alerts, exit_code = sandbox.run(["npm", "install", "is-odd"])

        assert not docker_cp_called, "dry_run should skip docker cp"
        captured = capsys.readouterr()
        assert "dry-run" in captured.out.lower() or "dry-run" in captured.err.lower()

    @patch("fenceline.install.sandbox._docker", return_value="docker")
    @patch("fenceline.install.sandbox.subprocess.run")
    def test_non_dry_run_copies_artifacts(self, mock_run, _mock_docker):
        """Default (dry_run=False) should call docker cp for clean installs."""
        docker_cp_called = False

        def side_effect(*args, **kwargs):
            nonlocal docker_cp_called
            cmd = args[0] if args else kwargs.get("args", [])
            result = MagicMock(returncode=0, stderr="")
            if cmd[0:2] == ["docker", "run"]:
                result.stdout = "normal123\n"
            elif cmd[0:2] == ["docker", "exec"]:
                result.stdout = ""
            elif cmd[0:2] == ["docker", "cp"]:
                docker_cp_called = True
                result.stdout = ""
            elif cmd[0:2] == ["docker", "kill"]:
                result.stdout = ""
            elif cmd[0:2] == ["docker", "rm"]:
                result.stdout = ""
            else:
                result.stdout = ""
            return result

        mock_run.side_effect = side_effect

        sandbox = SandboxedInstall(self._make_deep_map(), dry_run=False)
        sandbox.run(["npm", "install", "is-odd"])

        assert docker_cp_called, "non-dry-run should call docker cp"


# --- Pip import name resolution ---


class TestPipImportNameResolution:
    """Verify distribution→import name mapping for Stage 2 pip imports."""

    def test_well_known_renames(self):
        """Well-known renames should be resolved without Docker."""
        renames = SandboxedInstall._PIP_IMPORT_RENAMES
        assert renames["pillow"] == "PIL"
        assert renames["pyyaml"] == "yaml"
        assert renames["python-dateutil"] == "dateutil"
        assert renames["scikit-learn"] == "sklearn"
        assert renames["beautifulsoup4"] == "bs4"
        assert renames["pyjwt"] == "jwt"
        assert renames["opencv-python"] == "cv2"

    def test_renames_are_case_insensitive(self):
        """Lookup should work regardless of case."""
        renames = SandboxedInstall._PIP_IMPORT_RENAMES
        # The lookup uses .lower() so Pillow → pillow → PIL
        assert "pillow" in renames
        assert "Pillow".lower() in renames

    @patch("fenceline.install.sandbox._docker", return_value="docker")
    @patch("fenceline.install.sandbox.subprocess.run")
    def test_resolve_falls_back_to_underscore(self, mock_run, _mock_docker):
        """Unknown packages should fall back to hyphen→underscore."""
        import ipaddress
        from fenceline.deepmap.models import AllowedDomain, CDNMap, DeepMap, ToolMap
        cdn = CDNMap(
            id="fastly", name="Fastly", asn="AS54113",
            ipv4_prefixes=[ipaddress.IPv4Network("151.101.0.0/16")],
            ipv6_prefixes=[],
        )
        tool = ToolMap(
            id="pip", description="pip",
            primary_domains=[AllowedDomain(domain="pypi.org", cdn_provider="fastly")],
        )
        deep_map = DeepMap(tools=[tool], cdns=[cdn])

        sandbox = SandboxedInstall(deep_map)
        sandbox._container_id = "fake123"

        # Mock docker exec to return empty (no top_level.txt found)
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

        result = sandbox._resolve_pip_import_name("my-cool-package")
        assert result == "my_cool_package"
