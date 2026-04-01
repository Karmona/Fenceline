"""Tests for parse_netstat_output() in sandbox.py.

Alpine/BusyBox containers use netstat (not ss), so this parser
is critical for production network monitoring inside Docker.
"""

from fenceline.install.monitor import parse_netstat_output


class TestParseNetstatOutput:
    """Parse Alpine/BusyBox netstat -tnp output."""

    HEADER = (
        "Active Internet connections (w/o servers)\n"
        "Proto Recv-Q Send-Q Local Address           "
        "Foreign Address         State       PID/Program name\n"
    )

    def test_parses_established_connection(self):
        output = self.HEADER + (
            "tcp        0      0 172.17.0.2:45678        "
            "104.16.24.35:443        ESTABLISHED 1/node\n"
        )
        conns = parse_netstat_output(output)
        assert len(conns) == 1
        assert conns[0].remote_ip == "104.16.24.35"
        assert conns[0].remote_port == 443
        assert conns[0].process_name == "node"
        assert conns[0].pid == 1

    def test_parses_syn_sent(self):
        output = self.HEADER + (
            "tcp        0      1 172.17.0.2:34567        "
            "93.184.216.34:8080      SYN_SENT    42/curl\n"
        )
        conns = parse_netstat_output(output)
        assert len(conns) == 1
        assert conns[0].remote_ip == "93.184.216.34"
        assert conns[0].remote_port == 8080
        assert conns[0].process_name == "curl"

    def test_ignores_listen_and_time_wait(self):
        output = self.HEADER + (
            "tcp        0      0 0.0.0.0:8899            "
            "0.0.0.0:*               LISTEN      1/python3\n"
            "tcp        0      0 172.17.0.2:45678        "
            "104.16.24.35:443        TIME_WAIT   -\n"
        )
        conns = parse_netstat_output(output)
        assert len(conns) == 0

    def test_multiple_connections(self):
        output = self.HEADER + (
            "tcp        0      0 172.17.0.2:45678        "
            "104.16.24.35:443        ESTABLISHED 1/node\n"
            "tcp        0      0 172.17.0.2:45679        "
            "151.101.1.63:443        ESTABLISHED 1/node\n"
            "tcp        0      0 172.17.0.2:45680        "
            "93.184.216.34:8080      SYN_SENT    42/curl\n"
        )
        conns = parse_netstat_output(output)
        assert len(conns) == 3
        ips = {c.remote_ip for c in conns}
        assert ips == {"104.16.24.35", "151.101.1.63", "93.184.216.34"}

    def test_empty_output(self):
        assert parse_netstat_output("") == []

    def test_header_only(self):
        conns = parse_netstat_output(self.HEADER)
        assert conns == []

    def test_handles_missing_pid_program(self):
        """Some netstat lines show '-' instead of PID/Program."""
        output = self.HEADER + (
            "tcp        0      0 172.17.0.2:45678        "
            "104.16.24.35:443        ESTABLISHED -\n"
        )
        conns = parse_netstat_output(output)
        assert len(conns) == 1
        assert conns[0].process_name == ""
        assert conns[0].pid == 0

    def test_handles_malformed_port(self):
        output = self.HEADER + (
            "tcp        0      0 172.17.0.2:45678        "
            "104.16.24.35:badport   ESTABLISHED 1/node\n"
        )
        conns = parse_netstat_output(output)
        assert len(conns) == 0

    def test_handles_short_line(self):
        output = self.HEADER + "tcp   0   0\n"
        conns = parse_netstat_output(output)
        assert len(conns) == 0

    def test_extracts_process_with_path(self):
        """Process name might include path like /usr/bin/node."""
        output = self.HEADER + (
            "tcp        0      0 172.17.0.2:45678        "
            "104.16.24.35:443        ESTABLISHED 1/usr/bin/node\n"
        )
        conns = parse_netstat_output(output)
        assert len(conns) == 1
        # split("/", 1) means process_name is "usr/bin/node"
        assert conns[0].pid == 1
