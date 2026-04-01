"""Minimal HTTP logging proxy for sandbox installs.

This script runs INSIDE the Docker container on port 8899 and logs
all HTTP/HTTPS requests made by package managers. It supports:

- CONNECT method (HTTPS tunneling): logs the target host:port
- Plain HTTP: logs method, host, and path

The proxy writes structured log lines to /tmp/fenceline-http.log
in the format: METHOD HOST PATH

This file is copied into the container by sandbox.py and started
as a background process before the package install runs.

Designed to be standalone Python with no external dependencies
(must work in python:3.12-alpine and node:alpine with python3).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

from fenceline.log import get_logger

logger = get_logger(__name__)


# The actual proxy script that runs inside the container.
# Kept as a string so sandbox.py can write it to /tmp/fenceline-proxy.py
PROXY_SCRIPT = '''\
#!/usr/bin/env python3
"""Fenceline HTTP logging proxy — runs inside the container."""
import socket
import threading
import sys
import os

LOG_FILE = "/tmp/fenceline-http.log"
LISTEN_PORT = 8899

def log_request(method, host, path=""):
    with open(LOG_FILE, "a") as f:
        f.write(f"{method} {host} {path}\\n")

def handle_connect(client, host, port):
    """Handle HTTPS CONNECT — log and tunnel."""
    log_request("CONNECT", f"{host}:{port}")
    try:
        remote = socket.create_connection((host, port), timeout=30)
        client.sendall(b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n")
        # Tunnel bytes in both directions
        def relay(src, dst):
            try:
                while True:
                    data = src.recv(8192)
                    if not data:
                        break
                    dst.sendall(data)
            except (OSError, ConnectionError):
                pass
            finally:
                try: src.close()
                except OSError: pass
                try: dst.close()
                except OSError: pass
        t1 = threading.Thread(target=relay, args=(client, remote), daemon=True)
        t2 = threading.Thread(target=relay, args=(remote, client), daemon=True)
        t1.start()
        t2.start()
        t1.join(timeout=60)
    except Exception as e:
        try:
            client.sendall(f"HTTP/1.1 502 Bad Gateway\\r\\n\\r\\n{e}".encode())
        except OSError:
            pass

def handle_client(client):
    try:
        data = client.recv(8192)
        if not data:
            client.close()
            return
        first_line = data.split(b"\\r\\n")[0].decode("utf-8", errors="replace")
        parts = first_line.split()
        if len(parts) < 2:
            client.close()
            return
        method = parts[0]
        target = parts[1]
        if method == "CONNECT":
            host_port = target.split(":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
            handle_connect(client, host, port)
        else:
            # Plain HTTP — extract host from URL or Host header
            host = ""
            path = target
            for line in data.split(b"\\r\\n"):
                if line.lower().startswith(b"host:"):
                    host = line.split(b":", 1)[1].strip().decode()
                    break
            log_request(method, host, path)
            client.close()
    except (OSError, ConnectionError, ValueError):
        try:
            client.close()
        except OSError:
            pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", LISTEN_PORT))
    server.listen(64)
    server.settimeout(1.0)
    while True:
        try:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client,), daemon=True).start()
        except socket.timeout:
            continue
        except Exception:
            break

if __name__ == "__main__":
    main()
'''


# Node.js equivalent of PROXY_SCRIPT for Node containers (npm, yarn, pnpm).
# Uses only built-in modules (http, net, fs) — no npm install needed.
NODE_PROXY_SCRIPT = '''\
const http = require("http");
const net = require("net");
const fs = require("fs");
const LOG = "/tmp/fenceline-http.log";
function log(method, host, path) {
  fs.appendFileSync(LOG, method + " " + host + " " + (path || "") + "\\n");
}
const server = http.createServer(function(req, res) {
  // Plain HTTP request — log method + host + path
  var host = req.headers.host || "";
  log(req.method, host, req.url);
  res.writeHead(502);
  res.end("Fenceline: plain HTTP not proxied");
});
server.on("connect", function(req, socket, head) {
  // HTTPS CONNECT — log target, then tunnel
  var target = req.url;
  log("CONNECT", target);
  var parts = target.split(":");
  var host = parts[0];
  var port = parseInt(parts[1]) || 443;
  var remote = net.createConnection(port, host, function() {
    socket.write("HTTP/1.1 200 Connection Established\\r\\n\\r\\n");
    if (head && head.length) remote.write(head);
    remote.pipe(socket);
    socket.pipe(remote);
  });
  remote.on("error", function(err) {
    try { socket.end(); } catch(ignored) { /* socket already closed */ }
  });
  socket.on("error", function(err) {
    try { remote.end(); } catch(ignored) { /* remote already closed */ }
  });
});
server.listen(8899, "127.0.0.1", function() {
  // Proxy ready
});
'''


@dataclass
class HttpLogEntry:
    """A parsed HTTP proxy log entry."""
    method: str
    host: str
    path: str = ""


def parse_http_log(output: str) -> List[HttpLogEntry]:
    """Parse the HTTP proxy log file output.

    Each line is: METHOD HOST [PATH]
    """
    entries: List[HttpLogEntry] = []
    for line in output.strip().splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        method = parts[0]
        host = parts[1]
        path = parts[2] if len(parts) > 2 else ""
        entries.append(HttpLogEntry(method=method, host=host, path=path))
    return entries


def check_http_behavior(
    entries: List[HttpLogEntry],
    tool_id: str,
    deep_map,
) -> List[str]:
    """Check HTTP log entries for suspicious behavior.

    Returns a list of warning messages.
    """
    warnings: List[str] = []

    tool_map = deep_map.get_tool_for_command(tool_id) if deep_map else None
    if tool_map is None:
        return warnings

    # Get expected domains for this tool
    expected_domains: set[str] = set()
    for d in tool_map.primary_domains + tool_map.provenance_domains:
        if d.domain:
            expected_domains.add(d.domain.lower())

    # Check for unexpected CONNECT targets
    for entry in entries:
        if entry.method == "CONNECT":
            host = entry.host.split(":")[0].lower()
            if host not in expected_domains:
                # Check if it's a subdomain of an expected domain
                is_subdomain = any(
                    host.endswith(f".{d}") for d in expected_domains
                )
                if not is_subdomain:
                    warnings.append(
                        f"HTTPS connection to unexpected domain: {entry.host}"
                    )

    # Check for POST/PUT to non-upload domains
    uploads_ok = tool_map.uploads_during_install
    upload_domains = {d.domain.lower() for d in tool_map.upload_domains if d.domain}

    for entry in entries:
        if entry.method in ("POST", "PUT", "PATCH"):
            host = entry.host.split(":")[0].lower()
            if not uploads_ok and host not in upload_domains:
                warnings.append(
                    f"Suspicious {entry.method} request to {entry.host}{entry.path}"
                )

    return warnings
