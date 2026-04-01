"""Docker-sandboxed package install.

Runs package installs inside a Docker container so untrusted code never
executes on the host machine. Monitors the container's network activity
and filesystem changes from outside, and only copies install artifacts
to the host if no suspicious behavior is detected.

Requires Docker to be installed and running.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple

from fenceline.deepmap.models import DeepMap
from fenceline.install.fsdiff import snapshot_container, diff_snapshots, check_suspicious_files, FsAlert
from fenceline.install.http_logger import PROXY_SCRIPT, NODE_PROXY_SCRIPT, parse_http_log, check_http_behavior
from fenceline.install.matcher import check_connection
from fenceline.log import get_logger

logger = get_logger(__name__)
from fenceline.install.monitor import Alert, Connection


# Map package manager commands to Docker base images
# Node.js ecosystem is fully supported. Others are experimental.
_IMAGES = {
    # Fully supported
    "npm": "node:alpine",
    "npx": "node:alpine",
    "yarn": "node:alpine",
    "pnpm": "node:alpine",
    # Experimental — monitoring works but artifact copy is limited
    "pip": "python:3.12-alpine",
    "pip3": "python:3.12-alpine",
    "cargo": "rust:alpine",
    "gem": "ruby:alpine",
}

_EXPERIMENTAL_TOOLS = {"cargo", "gem"}

# Map package manager to the install directory inside the container.
_ARTIFACT_PATHS = {
    "npm": "/app/node_modules",
    "yarn": "/app/node_modules",
    "pnpm": "/app/node_modules",
    # pip uses _copy_pip_artifacts() instead — needs before/after diff
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


_VALID_PKG_NAME = re.compile(r'^[@a-zA-Z0-9._/-]+$')


def _safe_package_name(name: str) -> bool:
    """Validate package name contains only safe characters.

    Prevents injection when name is interpolated into require()/import.
    """
    return bool(_VALID_PKG_NAME.match(name)) and '..' not in name


def _host_pip_destination() -> Path:
    """Determine where to copy pip packages on the host.

    Uses the active virtualenv's site-packages if available,
    otherwise falls back to the current directory.
    """
    import sysconfig
    try:
        site_packages = sysconfig.get_path('purelib')
        if site_packages and Path(site_packages).is_dir():
            return Path(site_packages)
    except (KeyError, TypeError):
        pass
    logger.warning("No virtualenv detected, copying to current directory.")
    return Path.cwd()


def _validate_container_path(path: str) -> bool:
    """Validate that a container path is safe to copy from.

    Prevents path traversal and copying from sensitive locations.
    """
    # No path traversal
    if '..' in path:
        return False
    # Must be absolute
    if not path.startswith('/'):
        return False
    # Block sensitive host-mapped paths
    _blocked = {'/proc', '/sys', '/dev'}
    for blocked in _blocked:
        if path.startswith(blocked):
            return False
    return True


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
        """Stop monitoring and return collected alerts.

        After stopping the polling thread, does a final sweep of the
        iptables LOG (via dmesg) to catch any connections that were
        too short-lived for polling to detect.
        """
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

        # Post-hoc sweep: check iptables LOG for connections missed by polling
        self._sweep_iptables_log()

        return list(self._alerts)

    def _sweep_iptables_log(self) -> None:
        """Read iptables LOG from container dmesg for complete connection history."""
        try:
            result = subprocess.run(
                [_docker(), "exec", self._container_id, "dmesg"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return  # iptables not available, silent fallback

            connections = parse_iptables_log(result.stdout)
            for conn in connections:
                key = (conn.remote_ip, conn.remote_port)
                if key in self._seen:
                    continue
                self._seen.add(key)

                alert = check_connection(conn, self._deep_map, self._tool_id)
                if alert is not None:
                    self._alerts.append(alert)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass  # Silent fallback to polling-only results

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
            except Exception as exc:
                logger.warning(f"Container monitor error: {exc}")

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


class SandboxedInstall:
    """Run a package install inside a Docker container.

    The install command runs in an isolated container. Network connections
    are monitored from outside via docker exec and iptables LOG. If suspicious
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

        if tool_id in _EXPERIMENTAL_TOOLS:
            logger.warning(f"{tool_id} sandbox support is experimental.")
            logger.warning(f"Network monitoring works but artifact copy is limited.")
            logger.warning(f"If clean, re-run '{' '.join(cmd)}' on host to install.")

        logger.info(f"Sandbox: pulling {image}...")

        # Start a long-lived container with iptables setup, proxy, and sleep.
        # The install runs via docker exec so the container stays alive for
        # post-install checks (Stage 2, filesystem diff, DNS/HTTP analysis,
        # artifact copy). Without this, docker exec fails on a stopped container.
        iptables_setup = (
            "iptables -A OUTPUT -p tcp --syn -j LOG "
            "--log-prefix 'FENCELINE:' --log-level 4 2>/dev/null ; "
            "iptables -A OUTPUT -p udp --dport 53 -j LOG "
            "--log-prefix 'FENCELINE_DNS:' --log-level 4 2>/dev/null ; "
        )

        # HTTP logging proxy setup — captures CONNECT targets and HTTP methods.
        # Python containers use a Python proxy script; Node containers use a
        # Node.js proxy script. Both log to /tmp/fenceline-http.log.
        is_pip = tool_id in ("pip", "pip3")
        is_node = tool_id in ("npm", "npx", "yarn", "pnpm")
        proxy_setup = ""
        if is_pip:
            escaped_script = PROXY_SCRIPT.replace("'", "'\\''")
            proxy_setup = (
                f"echo '{escaped_script}' > /tmp/fenceline-proxy.py ; "
                "python3 /tmp/fenceline-proxy.py & "
                "export HTTP_PROXY=http://127.0.0.1:8899 ; "
                "export HTTPS_PROXY=http://127.0.0.1:8899 ; "
            )
        elif is_node:
            escaped_script = NODE_PROXY_SCRIPT.replace("'", "'\\''")
            proxy_setup = (
                f"echo '{escaped_script}' > /tmp/fenceline-proxy.js ; "
                "node /tmp/fenceline-proxy.js & "
                "sleep 0.2 ; "  # brief wait for proxy to bind
                "export HTTP_PROXY=http://127.0.0.1:8899 ; "
                "export HTTPS_PROXY=http://127.0.0.1:8899 ; "
            )

        # The container runs setup (iptables, proxy, pre-install snapshot)
        # then stays alive with sleep. Install runs via docker exec.
        pip_pre = ""
        if is_pip:
            pip_pre = "pip list --format=json > /tmp/.fenceline-pre-packages.json 2>/dev/null ; "

        setup_cmd = iptables_setup + proxy_setup + pip_pre + "sleep 86400"

        try:
            start_result = subprocess.run(
                [
                    _docker(), "run", "-d",
                    "--cap-add=NET_ADMIN",
                    "-w", "/app",
                    image,
                    "sh", "-c", setup_cmd,
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.error(f"Failed to start container: {exc}")
            return [], 1

        if start_result.returncode != 0:
            logger.error(f"Docker error: {start_result.stderr.strip()}")
            return [], 1

        self._container_id = start_result.stdout.strip()[:12]
        logger.info(f"Sandbox: container {self._container_id} started")
        logger.info(f"Sandbox: running {' '.join(cmd)} inside container...")

        # Snapshot filesystem before install for diffing
        pre_snapshot = snapshot_container(_docker(), self._container_id)

        # Start network monitor
        monitor = ContainerMonitor(
            self._container_id, self._deep_map, tool_id,
            poll_interval=0.5,
        )
        monitor.start()

        # Run the install command inside the running container.
        # The container stays alive after this, so docker exec works
        # for all post-install checks.
        logger.info(f"Sandbox: monitoring network for ~{monitor_secs}s...")
        install_cmd_str = ' '.join(shlex.quote(c) for c in cmd)
        # docker exec starts a new shell — proxy env vars from the setup
        # shell aren't inherited, so set them explicitly.
        proxy_env = ""
        if is_pip or is_node:
            proxy_env = (
                "export HTTP_PROXY=http://127.0.0.1:8899 ; "
                "export HTTPS_PROXY=http://127.0.0.1:8899 ; "
            )
        exec_cmd = proxy_env + install_cmd_str
        try:
            install_result = subprocess.run(
                [_docker(), "exec", self._container_id,
                 "sh", "-c", exec_cmd],
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            exit_code = install_result.returncode
        except subprocess.TimeoutExpired:
            logger.warning(f"Sandbox: timeout after {self._timeout}s — killing container")
            self._kill_container()
            alerts = monitor.stop()
            return alerts, 124  # timeout exit code
        except KeyboardInterrupt:
            print("\n[fenceline] Interrupted — killing container")
            self._kill_container()
            alerts = monitor.stop()
            return alerts, 130

        # Brief monitoring period after install completes
        time.sleep(min(monitor_secs, 5))

        # --- Stage 1 complete: check for install-time alerts ---
        stage1_alerts = list(monitor._alerts)

        if stage1_alerts:
            alerts = monitor.stop()
            self._print_alerts("Stage 1 (install)", alerts)
            print(f"\n[fenceline] Sandbox: BLOCKED — not installing on your machine.")
            print(f"[fenceline] ACTION: Do not retry or bypass. Investigate the package before use.")
            self._kill_container()
            return alerts, 1

        # --- Filesystem diff: check for suspicious file changes ---
        if pre_snapshot:
            post_snapshot = snapshot_container(_docker(), self._container_id)
            if post_snapshot:
                added, _, modified = diff_snapshots(pre_snapshot, post_snapshot)
                fs_alerts = check_suspicious_files(added, modified, tool_id)
                if fs_alerts:
                    alerts = monitor.stop()
                    self._print_fs_alerts(fs_alerts)
                    print(f"\n[fenceline] Sandbox: BLOCKED — suspicious filesystem changes.")
                    print(f"[fenceline] ACTION: Do not retry or bypass. Investigate the package before use.")
                    self._kill_container()
                    return alerts, 1

        # --- Stage 2: Import test ---
        # After install looks clean, try importing the package inside the
        # container. Many attacks activate on require()/import, not during
        # install. The container is still alive (sleep period).
        pkg_name = _extract_package_name(cmd)
        if pkg_name and not _safe_package_name(pkg_name):
            logger.warning("Skipping import test — unusual package name")
            pkg_name = None
        if pkg_name:
            logger.info(f"Sandbox: Stage 2 — testing import of '{pkg_name}'...")
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
            print(f"[fenceline] ACTION: Do not retry or bypass. Investigate the package before use.")
            self._kill_container()
            return alerts, 1

        # --- DNS activity check (informational) ---
        from fenceline.install.dns_monitor import get_dns_queries_from_container, check_dns_activity
        dns_servers = get_dns_queries_from_container(_docker(), self._container_id)
        dns_warning = check_dns_activity(dns_servers)
        if dns_warning:
            logger.warning(f"DNS: {dns_warning}")

        # --- HTTP behavior check (for containers with proxy) ---
        if is_pip or is_node:
            try:
                http_result = subprocess.run(
                    [_docker(), "exec", self._container_id,
                     "cat", "/tmp/fenceline-http.log"],
                    capture_output=True, text=True, timeout=5,
                )
                if http_result.returncode == 0 and http_result.stdout.strip():
                    http_entries = parse_http_log(http_result.stdout)
                    http_warnings = check_http_behavior(http_entries, tool_id, self._deep_map)
                    for w in http_warnings:
                        logger.warning(f"HTTP: {w}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Clean install — copy artifacts to host
        logger.info("Sandbox: install clean. Copying artifacts to host...")
        copy_ok = True
        if is_pip:
            copy_ok = self._copy_pip_artifacts()
        else:
            artifact_path = _ARTIFACT_PATHS.get(tool_id)
            if artifact_path:
                copy_ok = self._copy_artifacts(artifact_path, Path.cwd())

        if not copy_ok:
            print("[fenceline] Error: sandbox verified clean, but failed to copy "
                  "artifacts to host.", file=sys.stderr)
            self._kill_container()
            return alerts, 1

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

    def _print_fs_alerts(self, fs_alerts: List[FsAlert]) -> None:
        """Print filesystem diff alerts."""
        print(f"\n[fenceline] Sandbox: {len(fs_alerts)} suspicious filesystem change(s)!")
        for alert in fs_alerts:
            icon = "!!" if alert.severity == "critical" else "?"
            print(f"  {icon} [{alert.severity.upper()}] {alert.path} — {alert.reason}")

    def _copy_pip_artifacts(self) -> bool:
        """Copy newly installed pip packages from container to host.

        Diffs pre-install and post-install pip list to find new packages,
        then copies only those packages' directories.
        """
        import json as _json

        # Read pre-install package list saved by the container startup command
        try:
            pre_result = subprocess.run(
                [_docker(), "exec", self._container_id,
                 "cat", "/tmp/.fenceline-pre-packages.json"],
                capture_output=True, text=True, timeout=10,
            )
            pre_packages = {
                p["name"].lower() for p in _json.loads(pre_result.stdout)
            } if pre_result.returncode == 0 and pre_result.stdout.strip() else set()
        except (subprocess.TimeoutExpired, FileNotFoundError, _json.JSONDecodeError):
            pre_packages = set()

        # Get post-install package list
        try:
            post_result = subprocess.run(
                [_docker(), "exec", self._container_id,
                 "pip", "list", "--format=json"],
                capture_output=True, text=True, timeout=10,
            )
            post_packages = {
                p["name"].lower(): p["name"] for p in _json.loads(post_result.stdout)
            } if post_result.returncode == 0 and post_result.stdout.strip() else {}
        except (subprocess.TimeoutExpired, FileNotFoundError, _json.JSONDecodeError):
            logger.warning("Could not list pip packages in container")
            return False

        new_packages = {
            name: original for name, original in post_packages.items()
            if name not in pre_packages
        }

        if not new_packages:
            logger.info("No new pip packages detected to copy.")
            return True

        # Find the site-packages directory inside the container
        try:
            sp_result = subprocess.run(
                [_docker(), "exec", self._container_id,
                 "python3", "-c", "import site; print(site.getsitepackages()[0])"],
                capture_output=True, text=True, timeout=10,
            )
            site_packages = sp_result.stdout.strip() if sp_result.returncode == 0 else ""
        except (subprocess.TimeoutExpired, FileNotFoundError):
            site_packages = ""

        if not site_packages:
            logger.warning("Could not determine site-packages path")
            return False

        # Determine host destination — virtualenv site-packages if active, else cwd
        host_dest = _host_pip_destination()
        logger.info(f"Copying {len(new_packages)} new pip package(s) to {host_dest}...")
        all_ok = True
        for pkg_lower, pkg_original in new_packages.items():
            # pip normalizes names: requests -> requests/, but some use
            # the original case or replace - with _
            copied_pkg = False
            for candidate in [pkg_lower, pkg_original, pkg_lower.replace("-", "_"),
                              pkg_original.replace("-", "_")]:
                container_path = f"{site_packages}/{candidate}"
                result = subprocess.run(
                    [_docker(), "exec", self._container_id, "test", "-d", container_path],
                    capture_output=True, timeout=5,
                )
                if result.returncode == 0:
                    if not self._copy_artifacts(container_path, host_dest):
                        all_ok = False
                    copied_pkg = True
                    # Also copy .dist-info directory if it exists
                    self._copy_dist_info(site_packages, candidate, host_dest)
                    break
            if not copied_pkg:
                logger.warning(f"Could not find package directory for {pkg_original}")

        return all_ok

    def _copy_dist_info(self, site_packages: str, pkg_name: str, host_dest: Path) -> None:
        """Copy .dist-info metadata directory for a package.

        This preserves package metadata (version, entry points, etc.)
        needed by pip to track installed packages on the host.
        """
        # dist-info dirs use normalized names: requests-2.31.0.dist-info
        # Try to find matching dist-info directory
        normalized = pkg_name.replace("-", "_")
        try:
            result = subprocess.run(
                [_docker(), "exec", self._container_id,
                 "sh", "-c", f"ls -d {site_packages}/{normalized}-*.dist-info 2>/dev/null"
                              f" || ls -d {site_packages}/{pkg_name}-*.dist-info 2>/dev/null"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                for dist_dir in result.stdout.strip().splitlines():
                    dist_dir = dist_dir.strip()
                    if dist_dir and ".dist-info" in dist_dir:
                        self._copy_artifacts(dist_dir, host_dest)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass  # dist-info copy is best-effort

    def _copy_artifacts(self, container_path: str, host_dir: Path) -> bool:
        """Copy install artifacts from container to host.

        Returns True if artifacts were copied successfully, False otherwise.
        Validates container_path before copying to prevent path traversal.
        """
        if not _validate_container_path(container_path):
            logger.error(f"Refusing to copy from unsafe path: {container_path}")
            return False
        dest = str(host_dir) + "/"
        try:
            result = subprocess.run(
                [_docker(), "cp", f"{self._container_id}:{container_path}", dest],
                capture_output=True,
                timeout=60,
            )
            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace").strip()
                logger.error(f"docker cp failed (exit {result.returncode})")
                if stderr:
                    logger.error(f"  {stderr}")
                return False
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.error("Failed to copy artifacts from container")
            return False

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
