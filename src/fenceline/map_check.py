"""Map freshness checker — validates deep map data against live DNS.

Usage:
    fenceline map check    # check if map data matches live DNS
    fenceline map update   # update DNS snapshots and report changes
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

import yaml

from fenceline.deepmap.loader import find_map_dir, load_maps
from fenceline.log import get_logger

logger = get_logger(__name__)


def run(args) -> int:
    """Handle fenceline map subcommand."""
    check = getattr(args, 'check', False)
    update = getattr(args, 'update', False)

    if not (check or update):
        print("Usage: fenceline map --check | --update")
        return 1

    if check:
        return _check_freshness()
    elif update:
        return _update_maps()
    return 0


def _check_freshness() -> int:
    """Check if map data matches live DNS."""
    map_dir = find_map_dir()
    if map_dir is None:
        logger.error("Map directory not found.")
        return 1

    deep_map = load_maps(map_dir)
    issues: List[str] = []

    logger.info("Checking map freshness...")
    for tool in deep_map.tools:
        for domain_info in tool.primary_domains:
            domain = domain_info.domain
            if not domain:
                continue

            result = _check_domain(domain, domain_info, deep_map)
            if result:
                issues.append(result)
                print(f"  {tool.id}: {domain} — {result}")
            else:
                print(f"  {tool.id}: {domain} — OK")

    if issues:
        print(f"\n{len(issues)} issue(s) found. Run 'fenceline map --update' to fix.")
        return 1
    else:
        print(f"\nAll maps current.")
        return 0


def _check_domain(domain: str, domain_info, deep_map) -> Optional[str]:
    """Check a single domain against live DNS.

    Returns an issue description string, or None if OK.
    """
    try:
        live_ips = _resolve_dns(domain)
    except (socket.gaierror, OSError) as exc:
        return f"DNS resolution failed: {exc}"

    if not live_ips:
        return "DNS returned no IPs"

    # Check if at least one live IP falls in a known CDN range
    for ip_str in live_ips:
        if _ip_in_any_cdn(ip_str, deep_map):
            return None  # At least one IP is in a known CDN — OK

    return f"resolved IPs {live_ips} not in any known CDN range"


def _resolve_dns(domain: str) -> List[str]:
    """Resolve a domain to its IP addresses."""
    results = []
    try:
        for info in socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP):
            ip = info[4][0]
            if ip not in results:
                results.append(ip)
    except (socket.gaierror, OSError):
        pass
    return results


def _ip_in_any_cdn(ip_str: str, deep_map) -> bool:
    """Check if an IP is in any known CDN CIDR range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for cdn in deep_map.cdns:
        if isinstance(addr, ipaddress.IPv4Address):
            for prefix in cdn.ipv4_prefixes:
                if addr in prefix:
                    return True
        elif isinstance(addr, ipaddress.IPv6Address):
            for prefix in cdn.ipv6_prefixes:
                if addr in prefix:
                    return True
    return False


def _update_maps() -> int:
    """Update DNS snapshots in map YAML files."""
    map_dir = find_map_dir()
    if map_dir is None:
        logger.error("Map directory not found.")
        return 1

    tools_dir = map_dir / "tools"
    if not tools_dir.is_dir():
        logger.error("Tools directory not found.")
        return 1

    updated = 0
    logger.info("Updating map data...")

    for yaml_file in sorted(tools_dir.glob("*.yaml")):
        try:
            with open(yaml_file, "r") as f:
                data = yaml.safe_load(f)
            if not data:
                continue

            changed = False
            for domain_entry in data.get("primary_domains", []):
                domain = domain_entry.get("domain", "")
                if not domain:
                    continue

                new_ips = _resolve_dns(domain)
                old_ips = domain_entry.get("ips", [])

                if set(new_ips) != set(old_ips) and new_ips:
                    print(f"  {data.get('id', yaml_file.stem)}: {domain} "
                          f"IPs changed {old_ips} → {new_ips}")
                    domain_entry["ips"] = new_ips
                    changed = True

            if changed:
                with open(yaml_file, "w") as f:
                    yaml.dump(data, f, default_flow_style=False, sort_keys=False)
                updated += 1

        except Exception as exc:
            print(f"  Warning: failed to process {yaml_file.name}: {exc}",
                  file=sys.stderr)

    if updated:
        print(f"\n[fenceline] Updated {updated} file(s). Run tests to verify.")
    else:
        print(f"\n[fenceline] All maps already current.")
    return 0
