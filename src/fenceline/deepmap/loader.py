"""Load deep map YAML files into structured models."""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from ipaddress import IPv6Network
from typing import List, Optional

import yaml

from .models import AllowedDomain, CDNMap, DeepMap, ToolMap


def find_map_dir() -> Optional[Path]:
    """Walk up from this file looking for map/tools/npm.yaml."""
    current = Path(__file__).resolve().parent
    # Walk up at most 10 levels
    for _ in range(10):
        candidate = current / "map" / "tools" / "npm.yaml"
        if candidate.exists():
            return current / "map"
        current = current.parent
    return None


def _parse_domain(raw: dict) -> AllowedDomain:
    """Parse a single domain entry from YAML."""
    return AllowedDomain(
        domain=raw.get("domain", ""),
        purpose=raw.get("purpose", ""),
        ips=raw.get("ips", []),
        cdn_provider=raw.get("cdn_provider", ""),
        asn=raw.get("asn", ""),
        cdn_range=raw.get("cdn_range", ""),
        port=raw.get("port", 443),
        notes=raw.get("notes", ""),
    )


def load_tool(path: Path) -> ToolMap:
    """Parse a single tool YAML file into a ToolMap."""
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    if not data:
        raise ValueError(f"Empty or invalid YAML: {path}")

    primary = [_parse_domain(d) for d in data.get("primary_domains", [])]
    provenance = [_parse_domain(d) for d in data.get("provenance_domains", [])]
    uploads = [_parse_domain(d) for d in data.get("upload_domains", [])]

    return ToolMap(
        id=data.get("id", path.stem),
        description=data.get("description", ""),
        primary_domains=primary,
        provenance_domains=provenance,
        upload_domains=uploads,
        port=data.get("port", 443),
        uploads_during_install=data.get("uploads_during_install", False),
        telemetry=data.get("telemetry", {}),
        known_mirrors=data.get("known_mirrors", []),
        notes=data.get("notes", ""),
    )


def load_cdn(path: Path) -> CDNMap:
    """Parse a single CDN YAML file into a CDNMap."""
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    if not data:
        raise ValueError(f"Empty or invalid YAML: {path}")

    prefixes: List[ipaddress.IPv4Network] = []
    for cidr in data.get("ipv4_prefixes", []):
        try:
            prefixes.append(ipaddress.IPv4Network(cidr, strict=False))
        except (ValueError, TypeError):
            # Skip malformed entries
            pass

    v6_prefixes: List[ipaddress.IPv6Network] = []
    for cidr in data.get("ipv6_prefixes", []):
        try:
            v6_prefixes.append(ipaddress.IPv6Network(cidr, strict=False))
        except (ValueError, TypeError):
            pass

    return CDNMap(
        id=data.get("id", path.stem),
        name=data.get("name", ""),
        asn=data.get("asn", ""),
        ipv4_prefixes=prefixes,
        ipv6_prefixes=v6_prefixes,
    )


def load_maps(map_dir: Optional[Path] = None) -> DeepMap:
    """Load all tool and CDN YAML files into a DeepMap."""
    if map_dir is None:
        map_dir = find_map_dir()
    if map_dir is None:
        raise FileNotFoundError(
            "Could not find map directory. "
            "Expected map/tools/npm.yaml relative to the project root."
        )

    tools: List[ToolMap] = []
    cdns: List[CDNMap] = []

    tools_dir = map_dir / "tools"
    if tools_dir.is_dir():
        for yaml_file in sorted(tools_dir.glob("*.yaml")):
            try:
                tools.append(load_tool(yaml_file))
            except Exception as exc:
                logging.getLogger("fenceline").warning(f"Failed to parse {yaml_file.name}: {exc}")

    cdns_dir = map_dir / "cdns"
    if cdns_dir.is_dir():
        for yaml_file in sorted(cdns_dir.glob("*.yaml")):
            try:
                cdns.append(load_cdn(yaml_file))
            except Exception as exc:
                logging.getLogger("fenceline").warning(f"Failed to parse {yaml_file.name}: {exc}")

    return DeepMap(tools=tools, cdns=cdns)
