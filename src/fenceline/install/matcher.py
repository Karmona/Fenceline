"""Connection matcher — checks connections against the deep map."""

from __future__ import annotations

import ipaddress
from typing import Optional

from fenceline.deepmap.models import DeepMap
from fenceline.install.monitor import Alert, Connection


def check_connection(
    conn: Connection, deep_map: DeepMap, tool_id: str
) -> Optional[Alert]:
    """Check a connection against the deep map and return an Alert if suspicious.

    Alert conditions (checked in order):
    1. Non-standard port (not 443) -> critical
    2. IP not in any known CDN CIDR range -> warning
    3. IP in a CDN range but that CDN isn't used by this tool -> warning
    """
    # 1. Non-standard port
    if conn.remote_port != 443:
        return Alert(
            connection=conn,
            reason=f"Non-standard port {conn.remote_port}",
            severity="critical",
        )

    # 2 & 3. Check IP against CDN ranges
    try:
        addr = ipaddress.ip_address(conn.remote_ip)
    except ValueError:
        return Alert(
            connection=conn,
            reason=f"Invalid IP address {conn.remote_ip}",
            severity="warning",
        )

    # Find which CDN (if any) this IP belongs to
    matched_cdn = None
    for cdn in deep_map.cdns:
        for prefix in cdn.ipv4_prefixes:
            if addr in prefix:
                matched_cdn = cdn
                break
        if matched_cdn is None:
            for prefix in getattr(cdn, 'ipv6_prefixes', []):
                if addr in prefix:
                    matched_cdn = cdn
                    break
        if matched_cdn is not None:
            break

    if matched_cdn is None:
        return Alert(
            connection=conn,
            reason=f"Unknown IP {conn.remote_ip}, not in known CDN ranges",
            severity="warning",
        )

    # IP is in a CDN range — check if the tool is expected to use this CDN
    tool_map = deep_map.get_tool_for_command(tool_id)
    if tool_map is None:
        # Unknown tool, can't verify CDN association
        return None

    # Collect CDN providers used by this tool
    expected_cdns: set[str] = set()
    for domain in (
        tool_map.primary_domains
        + tool_map.provenance_domains
        + tool_map.upload_domains
    ):
        if domain.cdn_provider:
            expected_cdns.add(domain.cdn_provider.lower())

    if matched_cdn.id.lower() not in expected_cdns and matched_cdn.name.lower() not in expected_cdns:
        return Alert(
            connection=conn,
            reason=(
                f"IP in {matched_cdn.name or matched_cdn.id} range "
                f"but {tool_id} uses {', '.join(sorted(expected_cdns)) or 'unknown CDN'}"
            ),
            severity="warning",
        )

    # 4. Check if the process making the connection is expected for this tool.
    # Catches curl, wget, bash etc. spawned by malicious install scripts.
    if (
        tool_map.expected_processes
        and conn.process_name
        and conn.process_name != "(iptables)"  # iptables log doesn't know process
    ):
        if conn.process_name not in tool_map.expected_processes:
            return Alert(
                connection=conn,
                reason=(
                    f"Unexpected process '{conn.process_name}' making network connection "
                    f"(expected: {', '.join(tool_map.expected_processes)})"
                ),
                severity="warning",
            )

    return None
