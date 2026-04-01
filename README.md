# Fenceline

[![CI](https://github.com/Karmona/Fenceline/actions/workflows/ci.yml/badge.svg)](https://github.com/Karmona/Fenceline/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://python.org)
[![v0.6.0](https://img.shields.io/badge/version-0.6.0-orange.svg)](CHANGELOG.md)

**A dependency firewall for developer machines.**

Detonates package installs in a Docker sandbox, monitors network connections, DNS queries, HTTP behavior, and filesystem changes, then only promotes artifacts to your host if everything is clean. Untrusted code never runs on your machine.

## Quick Start

```bash
pip install fenceline   # or: pip install -e . from source

# Activate the dependency firewall
fenceline wrap --enable
npm install express     # automatically sandboxed via Docker

# Or run a one-off sandboxed install
fenceline install --sandbox npm install express

# Try the example project
cd examples/safe-project && ./test.sh
```

Requires Docker. After `wrap --enable`, all npm/yarn/pnpm/pip install commands automatically route through the sandbox. Non-install commands (`npm test`, `npm run`, etc.) pass through unchanged.

```bash
fenceline wrap --status    # see what's wrapped
fenceline wrap --disable   # restore originals
```

## The Problem

Running `npm install` executes untrusted code on your machine. In 2025-2026 alone, compromised packages in axios, chalk, debug, and LiteLLM hit thousands of developer machines -- all during install or import. Other tools tell you a package *might* be risky. **Fenceline makes it prove itself first.**

<details>
<summary>Recent attacks that Fenceline would have caught</summary>

- **March 2026 -- Axios RAT**: Maintainer account phished, RAT injected via `plain-crypto-js`. C2 beaconing on port 8000. Fenceline Stage 1 catches non-standard port -> BLOCKED.
- **March 2026 -- TeamPCP**: Trivy, Checkmarx, LiteLLM compromised via `.pth` payload. Fenceline Stage 2 catches import-time activation -> BLOCKED.
- **2025 -- chalk/debug hijack**: 18-package compromise, 1-in-10 cloud environments in 2 hours. Fenceline Stage 2 catches require()-time C2 -> BLOCKED.

See [exploits/](exploits/) for 11 detailed case studies with IOCs and timelines.
</details>

## How It Works

```
fenceline install --sandbox npm install <pkg>

┌──────────────────────────────────────────────┐
│ Docker Container (--cap-add=NET_ADMIN)       │
│                                              │
│ iptables LOG: capture every TCP SYN + DNS    │
│                                              │
│ Stage 1: npm install <pkg>                   │
│   → real-time netstat polling (0.5s)         │
│   → iptables post-hoc sweep (zero-miss)      │
│   → expected-process check (curl? BLOCKED)   │
│                                              │
│ Filesystem diff: detect dropped binaries     │
│                                              │
│ Stage 2: node -e "require('<pkg>')"          │
│   → catch import-time payloads               │
│                                              │
│ DNS check: unusual resolver activity?        │
│                                              │
│ Suspicious? → KILL. Nothing installed.       │
│ Clean? → Copy node_modules to host.          │
└──────────────────────────────────────────────┘
```

### Detection layers

| Layer | What it catches | How |
|-------|----------------|-----|
| **Network monitoring** | C2 beacons, exfiltration to unknown servers | iptables LOG (every TCP SYN) + netstat polling |
| **Port enforcement** | Connections to non-443 ports | Any port != 443 -> CRITICAL |
| **CDN fingerprinting** | Connections to unexpected CDNs | IP checked against deep map CIDR ranges |
| **Process heuristic** | curl/wget/bash spawned by install scripts | Expected processes per tool (node/npm for npm installs) |
| **Filesystem diffing** | Dropped binaries, files in /etc, /root, /home | Pre/post snapshot comparison |
| **Import monitoring** | Lazy payloads that activate on require()/import | Stage 2 runs require() inside container |
| **DNS monitoring** | DNS tunneling, unusual resolver activity | iptables LOG on UDP port 53 |
| **HTTP behavior** | POST/PUT to unexpected domains | Logging proxy captures CONNECT targets and HTTP methods (pip containers; Node relies on iptables + process heuristic) |
| **Metadata scoring** | New packages, maintainer changes, missing provenance | Lockfile diff + registry lookup + risk scoring |
| **Capability escalation** | postinstall/preinstall added between versions | Version-to-version capability comparison |

## Why Fenceline?

Most supply chain security tools **analyze packages and assign risk scores**. Fenceline takes a different approach: **control execution**.

| Approach | Tools | What they do |
|----------|-------|-------------|
| Vulnerability scanning | Snyk, npm audit, Dependabot | Flag known CVEs in dependencies |
| Behavioral analysis | Socket, GuardDog | Score packages by signals (install scripts, network calls, etc.) |
| Age gating | Aikido SafeChain | Block packages newer than 48 hours |
| **Execution control** | **Fenceline** | **Sandbox the install. Verify behavior. Promote only if clean.** |

Other tools tell you a package is risky. Fenceline ensures risky packages never execute on your machine.

See [docs/landscape.md](docs/landscape.md) for a detailed comparison of 14+ tools.

## Against Real Attacks

Theoretical assessments -- not proven in-the-wild. See [exploits/](exploits/) for detailed analysis.

| Attack | Year | Sandbox |
|--------|------|---------|
| Axios RAT | 2026 | **Would block** -- C2 on port 8000 |
| TeamPCP: LiteLLM | 2026 | **Would block** -- Stage 2 catches .pth payload |
| chalk/debug | 2025 | **Would block** -- Stage 2 catches import C2 |
| Nx/s1ngularity | 2025 | **Would block** -- iptables catches outbound connection + process heuristic flags unexpected process |
| Ultralytics | 2024 | **Would block** -- mining pool on port 8080 |
| ua-parser-js | 2021 | **Would block** -- postinstall phones home + unexpected process (curl) |
| event-stream | 2018 | **Would block** -- Stage 2 catches import payload |
| colors.js | 2022 | **Contained** -- no network, but isolated in container |
| XZ Utils | 2024 | **Contained** -- passive backdoor, isolated |
| Codecov | 2021 | Outside scope -- CI/CD tool |
| Polyfill.io | 2024 | Outside scope -- client-side CDN |

8 blocked. 2 contained. 1 outside scope.

## What This Does NOT Catch

- Attacks with no network activity (logic bombs, sabotage)
- CI/CD pipeline attacks (use `fenceline audit-actions` for Actions)
- Code that only activates after being copied to host without network
- Steganographic payloads (.WAV files, etc.)
- Browser-side attacks (crypto hijacking in bundled JavaScript)

## Ecosystem Support

| Ecosystem | Sandbox | Artifact copy | Wrapping | Status |
|-----------|---------|---------------|----------|--------|
| **Node.js** (npm, yarn, pnpm) | Full | Full | Full | Production |
| **Python** (pip) | Full | Packages only¹ | Full | Supported |
| **Rust** (cargo) | Monitoring only | No | No | Experimental |
| **Ruby** (gem) | Monitoring only | No | No | Experimental |

¹ Copies package directories from site-packages. Console scripts (`bin/`) and `.dist-info` metadata are not yet promoted.

## Commands

| Command | What it does |
|---------|-------------|
| `fenceline wrap --enable` | Activate the dependency firewall for npm/yarn/pnpm/pip |
| `fenceline install --sandbox <cmd>` | One-off sandboxed install with full monitoring |
| `fenceline install --sandbox --format json <cmd>` | JSON output for CI integration |
| `fenceline check` | Scan lockfile diffs for risky changes (cached registry lookups) |
| `fenceline map --check` | Validate deep map data against live DNS |
| `fenceline map --update` | Refresh DNS snapshots in map YAML files |
| `fenceline audit-actions` | Scan GitHub Actions for unpinned tags |
| `fenceline init` | Git hooks that auto-run `fenceline check` on lockfile changes |

## Example Project

The [examples/safe-project/](examples/safe-project/) directory contains a minimal Node.js project with safe dependencies for testing Fenceline locally:

```bash
cd examples/safe-project
./test.sh   # runs sandboxed install + check + JSON output verification
```

## Learn More

| Resource | Description |
|----------|-------------|
| [Exploit Case Studies](exploits/) | 11 real attacks (2018-2026) with IOCs and sandbox assessments |
| [Deep Map](map/) | Network fingerprints for 8 package managers -- powers the detection engine |
| [Defense Playbook](docs/playbook.md) | Practical steps by role |
| [Tool Landscape](docs/landscape.md) | How Fenceline fits alongside Socket, Aikido, Phylum, and others |

## Roadmap

| Phase | Status | What |
|-------|--------|------|
| Core Engine | Done | Docker sandbox, 2-stage monitoring, filesystem diffing, iptables LOG capture |
| Detection | Done | CDN fingerprinting, expected-process heuristic, DNS monitoring, HTTP proxy analysis |
| CLI Tools | Done | wrap (npm + pip), install (--format json), check (cached), map, audit-actions, init. 289 tests. |
| Ecosystem | Done | Node.js production-ready, Python pip supported, others experimental |
| Knowledge Base | Done | 11 exploit case studies, defense playbook, tool landscape |
| Next | Planned | CI enforcement mode, deeper HTTP payload analysis, eBPF tracing |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

Best-effort, community-driven. **Does NOT guarantee protection against any attack.** See [DISCLAIMER.md](DISCLAIMER.md).

## License

Apache 2.0 -- [LICENSE](LICENSE). Copyright 2026 Fenceline Contributors.
