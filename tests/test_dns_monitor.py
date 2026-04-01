"""Tests for DNS query monitoring."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

from fenceline.install.dns_monitor import (
    parse_dns_iptables_log,
    get_dns_queries_from_container,
    check_dns_activity,
)


class TestParseDnsIptablesLog:
    SAMPLE_DMESG = (
        "[  100.123] random kernel message\n"
        "[  101.456] FENCELINE_DNS:IN= OUT=eth0 SRC=172.17.0.2 DST=8.8.8.8 "
        "LEN=60 PROTO=UDP SPT=12345 DPT=53\n"
        "[  102.789] FENCELINE:IN= OUT=eth0 SRC=172.17.0.2 DST=104.16.1.34 "
        "PROTO=TCP SPT=45678 DPT=443 SYN\n"
        "[  103.012] FENCELINE_DNS:IN= OUT=eth0 SRC=172.17.0.2 DST=8.8.4.4 "
        "LEN=60 PROTO=UDP SPT=12346 DPT=53\n"
    )

    def test_parses_dns_servers(self):
        servers = parse_dns_iptables_log(self.SAMPLE_DMESG)
        assert len(servers) == 2
        assert "8.8.8.8" in servers
        assert "8.8.4.4" in servers

    def test_ignores_tcp_lines(self):
        """Should only parse FENCELINE_DNS lines, not FENCELINE TCP lines."""
        servers = parse_dns_iptables_log(self.SAMPLE_DMESG)
        assert "104.16.1.34" not in servers

    def test_empty_output(self):
        assert parse_dns_iptables_log("") == []

    def test_no_dns_lines(self):
        output = "FENCELINE:IN= OUT=eth0 DST=1.2.3.4 PROTO=TCP DPT=443\n"
        assert parse_dns_iptables_log(output) == []

    def test_deduplicates_servers(self):
        output = (
            "FENCELINE_DNS:IN= OUT=eth0 DST=8.8.8.8 DPT=53\n"
            "FENCELINE_DNS:IN= OUT=eth0 DST=8.8.8.8 DPT=53\n"
        )
        servers = parse_dns_iptables_log(output)
        assert len(servers) == 1


class TestCheckDnsActivity:
    def test_normal_activity(self):
        """1-2 DNS servers is normal."""
        assert check_dns_activity(["8.8.8.8"]) is None
        assert check_dns_activity(["8.8.8.8", "8.8.4.4"]) is None

    def test_excessive_servers_warns(self):
        """Many DNS servers suggests tunneling or exfiltration."""
        servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]
        result = check_dns_activity(servers, expected_count=2)
        assert result is not None
        assert "Unusual DNS" in result

    def test_empty_is_fine(self):
        assert check_dns_activity([]) is None


class TestGetDnsFromContainer:
    @patch("fenceline.install.dns_monitor.subprocess.run")
    def test_returns_servers(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="FENCELINE_DNS:IN= OUT=eth0 DST=8.8.8.8 DPT=53\n",
        )
        servers = get_dns_queries_from_container("docker", "abc123")
        assert "8.8.8.8" in servers

    @patch("fenceline.install.dns_monitor.subprocess.run")
    def test_returns_empty_on_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        servers = get_dns_queries_from_container("docker", "abc123")
        assert servers == []

    @patch("fenceline.install.dns_monitor.subprocess.run")
    def test_returns_empty_on_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 5)
        servers = get_dns_queries_from_container("docker", "abc123")
        assert servers == []
