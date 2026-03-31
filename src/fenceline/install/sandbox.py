"""Docker-sandboxed package install.

Runs package installs inside a Docker container so untrusted code never
executes on the host machine. Monitors the container's network activity
from outside and only copies install artifacts to the host if no
suspicious connections are detected.

Requires Docker to be installed and running.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple

from fenceline.deepmap.models import DeepMap
from fenceline.install.matcher import check_connection
from fenceline.install.monitor import Alert, Connection


# Map package manager commands to Docker base images
_IMAGES = {
    "npm": "node:alpine",
    "npx": "node:alpine",
    "yarn": "node:alpine",
    "pnpm": "node:alpine",
    "pip": "python:3.12-alpine",
    "pip3": "python:3.12-alpine",
    "cargo": "rust:alpine",
    "gem": "ruby:alpine",
}

# Map package manager to the install directory inside the container
_ARTIFACT_PATHS = {
    "npm": "/app/node_modules",
    "yarn": "/app/node_modules",
    "pnpm": "/app/node_modules",
}


def _find_docker() -> str:
    """Find the docker executable, checking common paths."""
    import shutil
    docker = shutil.which("docker")
    if docker:
        return docker
    # Check common locations
    for path in ["/usr/local/bin/docker", "/opt/homebrew/bin/docker", "/usr/bin/docker"]:
        if os.path.isfile(path):
            return path
    return "docker"  # fallback, will fail with FileNotFoundError


_DOCKER_BIN: Optional[str] = None


def _docker() -> str:
    """Get the docker binary path (cached)."""
    global _DOCKER_BIN
    if _DOCKER_BIN is None:
        _DOCKER_BIN = _find_docker()
    return _DOCKER_BIN


def _extract_package_name(cmd: list[str]) -> Optional[str]:
    """Extract the main package name from an install command.

    Examples:
        ["npm", "install", "express"] → "express"
        ["pip", "install", "requests"] → "requests"
        ["npm", "install", "express@4.18"] → "express"
        ["npm", "install", "--save", "express"] → "express"
    """
    # Skip the tool name and the "install"/"add" verb
    args = cmd[1:] if cmd else []

    # Skip known verbs
    verbs = {"install", "add", "i"}
    args = [a for a in args if a.lower() not in verbs]

    # Skip flags (start with -)
    args = [a for a in args if not a.startswith("-")]

    if not args:
        return None

    pkg = args[0]
    # Strip version specifier: express@4.18 → express
    if "@" in pkg and not pkg.startswith("@"):
        pkg = pkg.split("@")[0]
    # Handle scoped packages: @scope/name@version → @scope/name
    elif pkg.startswith("@") and "@" in pkg[1:]:
        at_idx = pkg.index("@", 1)
        pkg = pkg[:at_idx]
    # Python: requests==2.31 → requests
    if "==" in pkg:
        pkg = pkg.split("==")[0]
    if ">=" in pkg:
        pkg = pkg.split(">=")[0]

    return pkg if pkg else None


def docker_available() -> bool:
    """Check if Docker is installed and the daemon is running."""
    try:
        result = subprocess.run(
            [_docker(), "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def detect_image(cmd: list[str]) -> str:
    """Detect the appropriate Docker image for a package manager command."""
    if not cmd:
        return "node:alpine"
    tool = cmd[0].lower()
    return _IMAGES.get(tool, "node:alpine")


class ContainerMonitor:
    """Monitor a Docker container's network connections."""

    def __init__(self, container_id: str, deep_map: DeepMap,
                 tool_id: str, poll_interval: float = 0.5) -> None:
        self._container_id = container_id
        self._deep_map = deep_map
        self._tool_id = tool_id
        self._poll_interval = poll_interval
        self._alerts: List[Alert] = []
        self._seen: set[Tuple[str, int]] = set()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start monitoring in a background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()

    def stop(self) -> List[Alert]:
        """Stop monitoring and return collected alerts."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        return list(self._alerts)

    def _poll(self) -> None:
        """Background loop: poll container connections via docker exec."""
        while self._running:
            try:
                connections = self._get_container_connections()
                for conn in connections:
                    key = (conn.remote_ip, conn.remote_port)
                    if key in self._seen:
                        continue
                    self._seen.add(key)

                    alert = check_connection(conn, self._deep_map, self._tool_id)
                    if alert is not None:
                        self._alerts.append(alert)
            except Exception:
                pass

            time.sleep(self._poll_interval)

    def _get_container_connections(self) -> List[Connection]:
        """Get network connections from inside the container via docker exec.

        Uses netstat (available in Alpine via busybox) since ss is not
        installed by default in Alpine images.
        """
        try:
            result = subprocess.run(
                [_docker(), "exec", self._container_id, "netstat", "-tnp"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        return parse_netstat_output(result.stdout)


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

    Extracted as a standalone function so it can be reused and tested
    independently of the Docker exec mechanism.
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


class SandboxedInstall:
    """Run a package install inside a Docker container.

    The install command runs in an isolated container. Network connections
    are monitored from outside via `docker exec ss -tnp`. If suspicious
    connections are detected, the container is killed and artifacts are
    NOT copied to the host.

    Usage::

        sandbox = SandboxedInstall(deep_map)
        alerts, exit_code = sandbox.run(["npm", "install", "express"])
    """

    def __init__(self, deep_map: DeepMap, timeout: int = 300,
                 monitor_seconds: int = 60) -> None:
        self._deep_map = deep_map
        self._timeout = timeout
        self._monitor_seconds = monitor_seconds
        self._container_id: Optional[str] = None

    def run(self, cmd: list[str]) -> Tuple[List[Alert], int]:
        """Run the install command in a sandboxed container.

        Returns (alerts, exit_code). If alerts are found, artifacts
        are NOT copied to the host.

        The container runs the install command plus a monitoring period
        (default 10 seconds) during which network connections are observed.
        """
        image = detect_image(cmd)
        tool_id = cmd[0].lower() if cmd else "unknown"
        monitor_secs = self._monitor_seconds

        print(f"[fenceline] Sandbox: pulling {image}...")

        # Start container — run the command, then keep alive for monitoring
        try:
            start_result = subprocess.run(
                [
                    _docker(), "run", "-d",
                    "-w", "/app",
                    image,
                    "sh", "-c",
                    # Quote each argument to prevent shell interpretation of
                    # special characters (semicolons, quotes, etc.) in the
                    # user's command. Without this, JS code like
                    # node -e "require('net');..." gets split on ';' by sh.
                    f"{' '.join(shlex.quote(c) for c in cmd)} ; sleep {monitor_secs}",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            print(f"[fenceline] Failed to start container: {exc}", file=sys.stderr)
            return [], 1

        if start_result.returncode != 0:
            print(f"[fenceline] Docker error: {start_result.stderr.strip()}", file=sys.stderr)
            return [], 1

        self._container_id = start_result.stdout.strip()[:12]
        print(f"[fenceline] Sandbox: container {self._container_id} started")
        print(f"[fenceline] Sandbox: running {' '.join(cmd)} inside container...")

        # Start network monitor
        monitor = ContainerMonitor(
            self._container_id, self._deep_map, tool_id,
            poll_interval=0.5,
        )
        monitor.start()

        # Wait for the container to finish using Popen (non-blocking wait
        # via communicate) so the monitor thread can poll connections.
        print(f"[fenceline] Sandbox: monitoring network for ~{monitor_secs}s...")
        try:
            wait_proc = subprocess.Popen(
                [_docker(), "wait", self._container_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = wait_proc.communicate(timeout=self._timeout)
            try:
                exit_code = int(stdout.decode().strip())
            except (ValueError, TypeError):
                exit_code = 0
        except subprocess.TimeoutExpired:
            print(f"[fenceline] Sandbox: timeout after {self._timeout}s — killing container")
            self._kill_container()
            alerts = monitor.stop()
            return alerts, 124  # timeout exit code
        except KeyboardInterrupt:
            print("\n[fenceline] Interrupted — killing container")
            self._kill_container()
            alerts = monitor.stop()
            return alerts, 130

        # --- Stage 1 complete: check for install-time alerts ---
        stage1_alerts = list(monitor._alerts)

        if stage1_alerts:
            alerts = monitor.stop()
            self._print_alerts("Stage 1 (install)", alerts)
            print(f"\n[fenceline] Sandbox: BLOCKED — not installing on your machine.")
            self._kill_container()
            return alerts, 1

        # --- Stage 2: Import test ---
        # After install looks clean, try importing the package inside the
        # container. Many attacks activate on require()/import, not during
        # install. The container is still alive (sleep period).
        pkg_name = _extract_package_name(cmd)
        if pkg_name:
            print(f"[fenceline] Sandbox: Stage 2 — testing import of '{pkg_name}'...")
            try:
                if tool_id in ("npm", "npx", "yarn", "pnpm"):
                    subprocess.run(
                        [_docker(), "exec", self._container_id,
                         "node", "-e", f"require('{pkg_name}')"],
                        capture_output=True, timeout=30,
                    )
                elif tool_id in ("pip", "pip3"):
                    subprocess.run(
                        [_docker(), "exec", self._container_id,
                         "python3", "-c", f"import {pkg_name}"],
                        capture_output=True, timeout=30,
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Give monitor time to catch import-triggered connections
            time.sleep(5)

        # --- Final check: all alerts from both stages ---
        alerts = monitor.stop()

        if alerts:
            stage = "Stage 2 (import)" if pkg_name else "install"
            self._print_alerts(stage, alerts)
            print(f"\n[fenceline] Sandbox: BLOCKED — not installing on your machine.")
            self._kill_container()
            return alerts, 1

        # Clean install — copy artifacts to host
        print(f"[fenceline] Sandbox: install clean. Copying artifacts to host...")
        artifact_path = _ARTIFACT_PATHS.get(tool_id)
        if artifact_path:
            self._copy_artifacts(artifact_path, Path.cwd())

        self._kill_container()
        print(f"[fenceline] Sandbox: done. Install verified and applied.")
        return alerts, exit_code

    def _print_alerts(self, stage: str, alerts: List[Alert]) -> None:
        """Print alert details."""
        print(f"\n[fenceline] Sandbox: {len(alerts)} suspicious connection(s) in {stage}!")
        for alert in alerts:
            icon = "!!" if alert.severity == "critical" else "?"
            print(
                f"  {icon} [{alert.severity.upper()}] "
                f"{alert.connection.process_name} -> "
                f"{alert.connection.remote_ip}:{alert.connection.remote_port} "
                f"— {alert.reason}"
            )

    def _copy_artifacts(self, container_path: str, host_dir: Path) -> None:
        """Copy install artifacts from container to host."""
        dest = str(host_dir) + "/"
        try:
            subprocess.run(
                [_docker(), "cp", f"{self._container_id}:{container_path}", dest],
                capture_output=True,
                timeout=60,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[fenceline] Warning: failed to copy artifacts from container",
                  file=sys.stderr)

    def _kill_container(self) -> None:
        """Remove the container."""
        if self._container_id:
            try:
                subprocess.run(
                    [_docker(), "rm", "-f", self._container_id],
                    capture_output=True,
                    timeout=10,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            self._container_id = None
