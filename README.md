# Fenceline

[![CI](https://github.com/Karmona/Fenceline/actions/workflows/ci.yml/badge.svg)](https://github.com/Karmona/Fenceline/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://python.org)
[![v0.5.0](https://img.shields.io/badge/version-0.5.0-orange.svg)](CHANGELOG.md)

**A dependency firewall for developer machines.**

Detonates package installs in a Docker sandbox and only promotes artifacts to your host if the network behavior is clean. Untrusted code never runs on your machine.

## Quick Start

```bash
pip install fenceline   # or: pip install -e . from source

# Activate the dependency firewall
fenceline wrap --enable
npm install express     # automatically sandboxed via Docker

# Or run a one-off sandboxed install
fenceline install --sandbox npm install express
```

Requires Docker. After `wrap --enable`, all npm/yarn/pnpm install commands automatically route through the sandbox. Non-install commands (`npm test`, `npm run`, etc.) pass through unchanged.

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

┌──────────────────────────────────────────┐
│ Docker Container (disposable)            │
│                                          │
│ Stage 1: npm install <pkg>               │
│   → monitor all outbound connections     │
│                                          │
│ Stage 2: node -e "require('<pkg>')"      │
│   → catch import-time payloads           │
│                                          │
│ Suspicious? → KILL. Nothing installed.   │
│ Clean? → Copy node_modules to host.      │
└──────────────────────────────────────────┘
```

**Malicious package blocked:**
```
[fenceline] Sandbox: 1 suspicious connection(s) in Stage 1 (install)!
  !! [CRITICAL] node -> 93.184.216.34:8080 — Non-standard port 8080
[fenceline] Sandbox: BLOCKED — not installing on your machine.
```

**Clean package verified:**
```
[fenceline] Sandbox: Stage 2 — testing import of 'is-odd'...
[fenceline] Sandbox: install clean. Copying artifacts to host...
[fenceline] Sandbox: done. Install verified and applied.
```

Both outputs above are from real Docker tests, not mockups.

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
| Nx/s1ngularity | 2025 | Partial -- exfils via legitimate domain |
| Ultralytics | 2024 | **Would block** -- mining pool on port 8080 |
| ua-parser-js | 2021 | **Would block** -- postinstall phones home |
| event-stream | 2018 | **Would block** -- Stage 2 catches import payload |
| colors.js | 2022 | **Contained** -- no network, but isolated in container |
| XZ Utils | 2024 | **Contained** -- passive backdoor, isolated |
| Codecov | 2021 | Outside scope -- CI/CD tool |
| Polyfill.io | 2024 | Outside scope -- client-side CDN |

7 blocked. 2 contained. 2 outside scope.

## What This Does NOT Catch

- Attacks with no network activity (logic bombs, sabotage)
- CI/CD pipeline attacks (use `fenceline audit-actions` for Actions)
- Code that only activates after being copied to host without network
- Exfiltration via legitimate domains without HTTP analysis (future work)
- Steganographic payloads (.WAV files, etc.)

## Ecosystem Support

Fenceline is optimized for **install-time and import-time network behavior on developer machines**. It is not a general-purpose package malware detector.

- **Node.js** (npm, yarn, pnpm): Fully supported -- sandbox + artifact copy
- **Python** (pip): Experimental -- sandbox monitoring works, artifact copy is limited
- **Others**: Network monitoring works, but no artifact handling yet

## Additional Commands

| Command | What it does |
|---------|-------------|
| `fenceline check` | Scan lockfile diffs for risky changes -- package age, maintainer changes, missing provenance. npm + PyPI (experimental). |
| `fenceline audit-actions` | Scan GitHub Actions for unpinned tags. The TeamPCP attack force-pushed Trivy's tags. |
| `fenceline init` | Git hooks that auto-run `fenceline check` on lockfile changes. |
| `tools/quick-check.sh` | One-command security posture report. No install needed. |

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
| Core Engine | Done | Docker sandbox, 2-stage monitoring (install + import), fail-closed wrapper |
| Detection | Done | Infrastructure fingerprinting (deep map), CDN matching, process tree tracking |
| CLI Tools | Done | wrap, install, check, audit-actions, init. 105 tests. |
| Knowledge Base | Done | 11 exploit case studies, defense playbook, tool landscape |
| Next | Planned | Filesystem diffing, HTTP behavioral analysis, Python artifact promotion, JSON output for CI |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

Best-effort, community-driven. **Does NOT guarantee protection against any attack.** See [DISCLAIMER.md](DISCLAIMER.md).

## License

Apache 2.0 -- [LICENSE](LICENSE). Copyright 2026 Fenceline Contributors.
