"""Wrapper for monitored package installs.

Usage: fenceline install <command...>
       fenceline install --sandbox <command...>
"""

from __future__ import annotations

import subprocess
import sys
from typing import List

from fenceline.deepmap.loader import load_maps
from fenceline.install.monitor import NetworkMonitor


def run(args) -> int:
    """Run a package install command with network monitoring.

    If --sandbox is set, runs the install inside a Docker container
    and only copies artifacts to the host if no suspicious network
    activity is detected. Otherwise, monitors on the host machine
    (host-based monitoring only — code executes before alerts fire).
    """
    sandbox = getattr(args, 'sandbox', False)

    cmd = args.command if hasattr(args, 'command') else args
    if not cmd:
        print("Usage: fenceline install [--sandbox] <command...>", file=sys.stderr)
        print("Example: fenceline install --sandbox npm install express", file=sys.stderr)
        return 1

    # Strip leading '--' if present
    if cmd and cmd[0] == '--':
        cmd = cmd[1:]

    if not cmd:
        print("Usage: fenceline install [--sandbox] <command...>", file=sys.stderr)
        return 1

    monitor_time = getattr(args, 'monitor_time', 60)

    if sandbox:
        return _run_sandboxed(cmd, monitor_time)
    else:
        return _run_host(cmd)


def _run_sandboxed(cmd: list[str], monitor_time: int = 60) -> int:
    """Run install in a Docker container (preventive — blocks if suspicious)."""
    from fenceline.install.sandbox import SandboxedInstall, docker_available

    if not docker_available():
        print(
            "[fenceline] Error: Docker is not installed or not running.\n"
            "[fenceline] Install Docker: https://docs.docker.com/get-docker/\n"
            "[fenceline] Or run without --sandbox for host-based monitoring.",
            file=sys.stderr,
        )
        return 1

    deep_map = load_maps()
    sandbox = SandboxedInstall(deep_map, monitor_seconds=monitor_time)
    alerts, exit_code = sandbox.run(cmd)
    return exit_code


def _run_host(cmd: list[str]) -> int:
    """Run install on host with network monitoring (host-based monitoring, without Docker)."""
    command_name = cmd[0]
    supported = {"npm", "pip", "pip3", "yarn", "pnpm", "cargo", "brew"}
    if command_name not in supported:
        print(
            f"Warning: '{command_name}' is not a recognized package manager. "
            f"Monitoring anyway.",
            file=sys.stderr,
        )

    deep_map = load_maps()
    monitor = NetworkMonitor(deep_map)

    print(f"[fenceline] Monitoring network during: {' '.join(cmd)}")
    print(f"[fenceline] Note: running on your machine (use --sandbox for isolation)")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        monitor.set_watch_pid(proc.pid)
        monitor.start()
        exit_code = proc.wait()

    except KeyboardInterrupt:
        print("\n[fenceline] Interrupted — stopping monitor...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        exit_code = 130

    except FileNotFoundError:
        print(f"Error: command '{command_name}' not found.", file=sys.stderr)
        monitor.stop()
        return 127

    alerts = monitor.stop()

    if alerts:
        print(f"\n[fenceline] {len(alerts)} network alert(s) during install:\n")
        for alert in alerts:
            icon = "!!" if alert.severity == "critical" else "?"
            print(
                f"  {icon} [{alert.severity.upper()}] "
                f"{alert.connection.process_name} -> "
                f"{alert.connection.remote_ip}:{alert.connection.remote_port} "
                f"— {alert.reason}"
            )
        print()
    else:
        print("[fenceline] No unexpected network activity detected.")

    return exit_code
