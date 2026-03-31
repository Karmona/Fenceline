"""Tests for the install network monitor."""

import time
from unittest.mock import patch

from fenceline.install.monitor import Alert, Connection, NetworkMonitor
from fenceline.deepmap.models import DeepMap


class TestDataclasses:
    """Verify Connection and Alert dataclasses."""

    def test_connection_fields(self):
        conn = Connection(
            pid=1234,
            process_name="node",
            remote_ip="104.16.0.1",
            remote_port=443,
            protocol="TCP",
            timestamp=1000.0,
        )
        assert conn.pid == 1234
        assert conn.process_name == "node"
        assert conn.remote_ip == "104.16.0.1"
        assert conn.remote_port == 443
        assert conn.protocol == "TCP"
        assert conn.timestamp == 1000.0

    def test_alert_fields(self):
        conn = Connection(
            pid=1,
            process_name="curl",
            remote_ip="1.2.3.4",
            remote_port=8080,
            protocol="TCP",
            timestamp=0.0,
        )
        alert = Alert(
            connection=conn,
            reason="Non-standard port 8080",
            severity="critical",
        )
        assert alert.severity == "critical"
        assert alert.reason == "Non-standard port 8080"
        assert alert.connection is conn


class TestLsofParsing:
    """Verify lsof output parsing."""

    MOCK_LSOF_OUTPUT = """\
COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node      12345   user   25u  IPv4 0x1234      0t0  TCP 192.168.1.10:54321->104.16.0.1:443 (ESTABLISHED)
node      12345   user   26u  IPv4 0x1235      0t0  TCP 192.168.1.10:54322->198.51.100.5:8080 (ESTABLISHED)
node      12345   user   27u  IPv4 0x1236      0t0  TCP 192.168.1.10:54323->203.0.113.10:443 (LISTEN)
python3    9999   user   10u  IPv4 0x1237      0t0  TCP 10.0.0.1:44444->93.184.216.34:443 (ESTABLISHED)
"""

    def test_parse_established_connections(self):
        deep_map = DeepMap()
        monitor = NetworkMonitor(deep_map)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = self.MOCK_LSOF_OUTPUT
            mock_run.return_value.returncode = 0

            connections = monitor._get_connections_macos()

        # Should pick up the ESTABLISHED lines only (not LISTEN)
        assert len(connections) == 3

        # First connection
        assert connections[0].process_name == "node"
        assert connections[0].pid == 12345
        assert connections[0].remote_ip == "104.16.0.1"
        assert connections[0].remote_port == 443

        # Second connection (non-standard port)
        assert connections[1].remote_ip == "198.51.100.5"
        assert connections[1].remote_port == 8080

        # Third connection (python3)
        assert connections[2].process_name == "python3"
        assert connections[2].remote_ip == "93.184.216.34"
        assert connections[2].remote_port == 443

    def test_empty_output(self):
        deep_map = DeepMap()
        monitor = NetworkMonitor(deep_map)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0

            connections = monitor._get_connections_macos()

        assert connections == []


class TestDeduplication:
    """Verify that the monitor deduplicates connections."""

    def test_same_ip_port_deduped(self):
        deep_map = DeepMap()
        monitor = NetworkMonitor(deep_map, poll_interval=0.1)

        # Simulate adding the same key twice
        monitor._seen.add(("104.16.0.1", 443))

        # The key should already be present
        assert ("104.16.0.1", 443) in monitor._seen

    def test_different_ports_not_deduped(self):
        deep_map = DeepMap()
        monitor = NetworkMonitor(deep_map)

        monitor._seen.add(("104.16.0.1", 443))
        assert ("104.16.0.1", 8080) not in monitor._seen
