"""Network monitor for install-time connection tracking."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

from fenceline.deepmap.models import DeepMap


@dataclass
class Connection:
    """A single observed network connection."""

    pid: int
    process_name: str
    remote_ip: str
    remote_port: int
    protocol: str
    timestamp: float


@dataclass
class Alert:
    """An alert raised by connection analysis."""

    connection: Connection
    reason: str
    severity: str  # "warning" | "critical"


def parse_netstat_output(output: str) -> List[Connection]:
    """Parse netstat -tnp output into Connection objects.

    Alpine/BusyBox netstat format:
    Proto Recv-Q Send-Q Local Address       Foreign Address     State       PID/Program name
    tcp        0      0 172.17.0.2:34567    93.184.216.34:8080  ESTABLISHED 1/node
    """
    connections: List[Connection] = []
    now = time.time()

    for line in output.splitlines():
        # Catch both ESTABLISHED and SYN_SENT (outbound attempt)
        if "ESTABLISHED" not in line and "SYN_SENT" not in line:
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        # Foreign address is column 4 (0-indexed)
        foreign = parts[4]
        colon_idx = foreign.rfind(":")
        if colon_idx == -1:
            continue

        remote_ip = foreign[:colon_idx]
        try:
            remote_port = int(foreign[colon_idx + 1:])
        except ValueError:
            continue

        # PID/Program is the last column: "1/node"
        pid = 0
        process_name = ""
        pid_prog = parts[-1] if "/" in parts[-1] else ""
        if pid_prog:
            try:
                pid_str, process_name = pid_prog.split("/", 1)
                pid = int(pid_str)
            except (ValueError, IndexError):
                pass

        connections.append(
            Connection(
                pid=pid,
                process_name=process_name,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol="TCP",
                timestamp=now,
            )
        )

    return connections


def parse_ss_output(output: str) -> List[Connection]:
    """Parse ss -tnp output into Connection objects.

    Works for both host-side and container-side ss output.
    """
    connections: List[Connection] = []
    now = time.time()

    for line in output.splitlines():
        if "ESTAB" not in line:
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        # Peer address is column 4 (0-indexed)
        peer = parts[4]
        colon_idx = peer.rfind(":")
        if colon_idx == -1:
            continue

        remote_ip = peer[:colon_idx].strip("[]")
        try:
            remote_port = int(peer[colon_idx + 1:])
        except ValueError:
            continue

        # Process info: users:(("name",pid=N,...))
        pid = 0
        process_name = ""
        for p in parts:
            if "pid=" in p:
                try:
                    pid = int(p.split("pid=")[1].split(",")[0].split(")")[0])
                except (ValueError, IndexError):
                    pass
            if p.startswith("users:"):
                try:
                    process_name = p.split('"')[1]
                except IndexError:
                    pass

        connections.append(
            Connection(
                pid=pid,
                process_name=process_name,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol="TCP",
                timestamp=now,
            )
        )

    return connections


def parse_iptables_log(output: str) -> List[Connection]:
    """Parse iptables LOG output from dmesg for outbound TCP SYN packets.

    Expected format (from --log-prefix 'FENCELINE:'):
      FENCELINE:IN= OUT=eth0 SRC=172.17.0.2 DST=93.184.216.34 ...
      PROTO=TCP SPT=45678 DPT=443 ...

    This captures EVERY outbound connection attempt with zero race condition,
    complementing the netstat polling which can miss short-lived connections.
    """
    connections: List[Connection] = []
    now = time.time()

    for line in output.splitlines():
        if "FENCELINE:" not in line:
            continue

        dst = ""
        dpt = 0
        for token in line.split():
            if token.startswith("DST="):
                dst = token[4:]
            elif token.startswith("DPT="):
                try:
                    dpt = int(token[4:])
                except ValueError:
                    pass

        if dst and dpt > 0:
            connections.append(
                Connection(
                    pid=0,
                    process_name="(iptables)",
                    remote_ip=dst,
                    remote_port=dpt,
                    protocol="TCP",
                    timestamp=now,
                )
            )

    return connections


class NetworkMonitor:
    """Monitor network connections during package installs.

    Polls active connections in a background thread and collects
    alerts for unexpected network activity.
    """

    def __init__(self, deep_map: DeepMap, poll_interval: float = 0.5, watch_pid: Optional[int] = None) -> None:
        self._deep_map = deep_map
        self._poll_interval = poll_interval
        self._watch_pid = watch_pid
        self._alerts: List[Alert] = []
        self._seen: Set[Tuple[str, int]] = set()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start polling connections in a background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()

    def stop(self) -> List[Alert]:
        """Stop polling and return all collected alerts."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        return list(self._alerts)

    def _poll(self) -> None:
        """Background loop: poll connections and check them."""
        while self._running:
            try:
                if sys.platform == "darwin":
                    connections = self._get_connections_macos()
                else:
                    connections = self._get_connections_linux()

                # Filter to watched PIDs if set
                if self._watch_pid is not None:
                    watched_pids = self._get_child_pids(self._watch_pid)
                    watched_pids.add(self._watch_pid)
                    connections = [c for c in connections if c.pid in watched_pids]

                for conn in connections:
                    key = (conn.remote_ip, conn.remote_port)
                    if key in self._seen:
                        continue
                    self._seen.add(key)

                    alert = self._check_connection(conn)
                    if alert is not None:
                        self._alerts.append(alert)

            except Exception as exc:
                print(f"[fenceline] Warning: monitor poll error: {exc}", file=sys.stderr)

            time.sleep(self._poll_interval)

    def set_watch_pid(self, pid: int) -> None:
        """Set the PID to watch (and its children)."""
        self._watch_pid = pid

    def _get_child_pids(self, parent_pid: int) -> Set[int]:
        """Get all child PIDs of a process (recursive)."""
        children: Set[int] = set()
        try:
            result = subprocess.run(
                ["pgrep", "-P", str(parent_pid)],
                capture_output=True, text=True, timeout=2,
            )
            for line in result.stdout.strip().splitlines():
                try:
                    child = int(line.strip())
                    children.add(child)
                    children.update(self._get_child_pids(child))
                except ValueError:
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return children

    def _check_connection(self, conn: Connection) -> Optional[Alert]:
        """Check a single connection against the deep map."""
        from fenceline.install.matcher import check_connection

        # Detect tool from process name
        tool_id = conn.process_name.lower()
        return check_connection(conn, self._deep_map, tool_id)

    def _get_connections_macos(self) -> List[Connection]:
        """Parse connections from macOS lsof output."""
        try:
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        connections: List[Connection] = []
        now = time.time()

        for line in result.stdout.splitlines():
            if "ESTABLISHED" not in line:
                continue

            parts = line.split()
            if len(parts) < 9:
                continue

            command = parts[0]
            try:
                pid = int(parts[1])
            except (ValueError, IndexError):
                continue

            # NAME column contains "local->remote" for ESTABLISHED connections
            name_col = parts[-1] if "->" in parts[-1] else ""
            if not name_col or "->" not in name_col:
                # Try to find the column with ->
                for p in parts:
                    if "->" in p:
                        name_col = p
                        break
                if not name_col:
                    continue

            remote_part = name_col.split("->")[-1]

            # Parse remote_ip:port — handle IPv6 brackets
            if remote_part.startswith("["):
                # IPv6: [addr]:port
                bracket_end = remote_part.find("]")
                if bracket_end == -1:
                    continue
                remote_ip = remote_part[1:bracket_end]
                port_str = remote_part[bracket_end + 2:]  # skip ]:
            else:
                # IPv4: addr:port — split on last colon
                colon_idx = remote_part.rfind(":")
                if colon_idx == -1:
                    continue
                remote_ip = remote_part[:colon_idx]
                port_str = remote_part[colon_idx + 1:]

            try:
                remote_port = int(port_str)
            except ValueError:
                continue

            # Determine protocol from lsof TYPE column
            protocol = "TCP"
            if len(parts) > 4 and parts[4].upper() in ("UDP", "TCP"):
                protocol = parts[4].upper()

            connections.append(
                Connection(
                    pid=pid,
                    process_name=command,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    protocol=protocol,
                    timestamp=now,
                )
            )

        return connections

    def _get_connections_linux(self) -> List[Connection]:
        """Parse connections from Linux ss output."""
        try:
            result = subprocess.run(
                ["ss", "-tnp"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        return parse_ss_output(result.stdout)
