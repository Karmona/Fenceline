"""Data models for Fenceline deep maps."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network
from typing import List, Optional


@dataclass
class AllowedDomain:
    """A domain that a tool is expected to contact."""

    domain: str
    purpose: str = ""
    ips: List[str] = field(default_factory=list)
    cdn_provider: str = ""
    asn: str = ""
    cdn_range: str = ""
    port: int = 443
    notes: str = ""


@dataclass
class ToolMap:
    """Network map for a single package manager / build tool."""

    id: str
    description: str = ""
    primary_domains: List[AllowedDomain] = field(default_factory=list)
    provenance_domains: List[AllowedDomain] = field(default_factory=list)
    upload_domains: List[AllowedDomain] = field(default_factory=list)
    port: int = 443
    uploads_during_install: bool = False
    telemetry: dict = field(default_factory=dict)
    known_mirrors: List[str] = field(default_factory=list)
    expected_processes: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class CDNMap:
    """IP prefix map for a CDN provider."""

    id: str
    name: str = ""
    asn: str = ""
    ipv4_prefixes: List[ipaddress.IPv4Network] = field(default_factory=list)
    ipv6_prefixes: List[ipaddress.IPv6Network] = field(default_factory=list)


@dataclass
class DeepMap:
    """Aggregated map of all tools and CDNs."""

    tools: List[ToolMap] = field(default_factory=list)
    cdns: List[CDNMap] = field(default_factory=list)

    def _all_domains(self) -> List[str]:
        """Return every known domain across all tools."""
        domains: List[str] = []
        for tool in self.tools:
            for d in tool.primary_domains:
                domains.append(d.domain)
            for d in tool.provenance_domains:
                domains.append(d.domain)
            for d in tool.upload_domains:
                domains.append(d.domain)
        return domains

    def is_known_domain(self, domain: str) -> bool:
        """Check if a domain appears in any tool map."""
        target = domain.lower().strip(".")
        for known in self._all_domains():
            if target == known.lower().strip("."):
                return True
        return False

    def is_known_ip(self, ip: str) -> bool:
        """Check if an IP falls within any known CDN CIDR range."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for cdn in self.cdns:
            for prefix in cdn.ipv4_prefixes:
                if addr in prefix:
                    return True
            for prefix in cdn.ipv6_prefixes:
                if addr in prefix:
                    return True
        return False

    def get_tool_for_command(self, cmd: str) -> Optional[ToolMap]:
        """Map a CLI command name to its tool map.

        Examples: "npm" -> npm tool, "pip" / "pip3" -> pip tool,
        "cargo" -> cargo tool, "brew" -> homebrew tool.
        """
        # Command name -> tool id mapping
        aliases = {
            "npm": "npm",
            "npx": "npm",
            "pip": "pip_pypi",
            "pip3": "pip_pypi",
            "cargo": "cargo",
            "yarn": "yarn",
            "brew": "homebrew",
            "go": "go_modules",
            "gem": "rubygems",
            "bundle": "rubygems",
            "bundler": "rubygems",
            "composer": "composer",
        }

        tool_id = aliases.get(cmd.lower())
        if tool_id:
            for tool in self.tools:
                if tool.id == tool_id:
                    return tool

        # Fallback: match tool.id directly
        for tool in self.tools:
            if tool.id == cmd.lower():
                return tool

        return None
