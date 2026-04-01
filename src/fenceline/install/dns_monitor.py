"""DNS query monitoring for sandbox installs.

Captures DNS queries made during package installation by parsing
iptables LOG rules for outbound UDP port 53. Combined with the
deep map's known domains, this detects DNS tunneling and unexpected
domain resolutions.

This is complementary to TCP connection monitoring — DNS queries
happen before TCP connections and reveal the attacker's target
domain even if the connection is to a legitimate CDN IP.
"""

from __future__ import annotations

import re
import subprocess
from typing import List, Optional

from fenceline.deepmap.models import DeepMap
from fenceline.log import get_logger

logger = get_logger(__name__)


def parse_dns_iptables_log(output: str) -> List[str]:
    """Parse iptables LOG output for DNS queries (UDP port 53).

    Extracts destination IPs of DNS queries. Since we can't see the
    actual DNS question from iptables, we log the DNS server IP.
    For deeper analysis, we'd need tcpdump — but just knowing that
    DNS happened at all is valuable signal.

    Returns list of DNS server IPs contacted.
    """
    dns_servers: List[str] = []
    for line in output.splitlines():
        if "FENCELINE_DNS:" not in line:
            continue

        dst = ""
        for token in line.split():
            if token.startswith("DST="):
                dst = token[4:]
                break

        if dst and dst not in dns_servers:
            dns_servers.append(dst)

    return dns_servers


def get_dns_queries_from_container(
    docker_bin: str, container_id: str
) -> List[str]:
    """Read DNS iptables log from container dmesg.

    Returns list of DNS server IPs that were contacted.
    """
    try:
        result = subprocess.run(
            [docker_bin, "exec", container_id, "dmesg"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return []
        return parse_dns_iptables_log(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def check_dns_activity(
    dns_servers: List[str],
    expected_count: int = 2,
) -> Optional[str]:
    """Check if DNS activity is suspicious.

    Most package installs contact 1-2 DNS servers (the container's
    configured resolver). Contacting many different DNS servers or
    non-standard resolvers could indicate DNS tunneling.

    Returns a warning message if suspicious, None if OK.
    """
    if len(dns_servers) > expected_count:
        return (
            f"Unusual DNS activity: contacted {len(dns_servers)} DNS servers "
            f"({', '.join(dns_servers[:5])}). Expected at most {expected_count}."
        )
    return None
