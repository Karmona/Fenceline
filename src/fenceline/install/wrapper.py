"""Wrapper for monitored package installs.

Usage: fenceline install <command...>
Example: fenceline install npm install express
"""

from __future__ import annotations

import subprocess
import sys
from typing import List

from fenceline.deepmap.loader import load_maps
from fenceline.install.monitor import NetworkMonitor


def run(args) -> int:
    """Run a package install command with network monitoring."""
    cmd = args.command if hasattr(args, 'command') else args
    if not cmd:
        print("Usage: fenceline install <command...>", file=sys.stderr)
        print("Example: fenceline install npm install express", file=sys.stderr)
        return 1

    # Strip leading '--' if present
    if cmd and cmd[0] == '--':
        cmd = cmd[1:]

    if not cmd:
        print("Usage: fenceline install <command...>", file=sys.stderr)
        return 1

    # Detect package manager from the first argument
    args_list = cmd
    command_name = args_list[0]
    supported = {"npm", "pip", "pip3", "yarn", "pnpm", "cargo", "brew"}
    if command_name not in supported:
        print(
            f"Warning: '{command_name}' is not a recognized package manager. "
            f"Monitoring anyway.",
            file=sys.stderr,
        )

    # Load deep map
    deep_map = load_maps()

    # Create monitor (don't start yet — need PID first)
    monitor = NetworkMonitor(deep_map)

    print(f"[fenceline] Monitoring network during: {' '.join(args_list)}")

    try:
        # Start the command
        proc = subprocess.Popen(
            args_list,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        # Now start monitoring scoped to this process
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
        exit_code = 130  # Standard Ctrl+C exit code

    except FileNotFoundError:
        print(f"Error: command '{command_name}' not found.", file=sys.stderr)
        monitor.stop()
        return 127

    # Stop monitor and collect alerts
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
