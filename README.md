# Fenceline

[![CI](https://github.com/Karmona/Fenceline/actions/workflows/ci.yml/badge.svg)](https://github.com/Karmona/Fenceline/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://python.org)
[![v0.5.0](https://img.shields.io/badge/version-0.5.0-orange.svg)](CHANGELOG.md)

**A dependency firewall for developer machines.**

Detonates package installs in a Docker sandbox and only promotes artifacts to your host if the network behavior is clean. Untrusted code never runs on your machine.

## The Problem

In March 2026, the `axios` npm package was compromised with a RAT. The same month, the TeamPCP campaign hit Trivy, Checkmarx, and LiteLLM — stealing credentials from over a thousand systems. In 2025, the `chalk`/`debug` hijack reached 1 in 10 cloud environments in under 2 hours.

Every one of these attacks ran code on developer machines during `npm install` or `pip install`. Other tools tell you a package is risky. **Fenceline makes it prove itself first.**

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

## Zero-Friction Mode

Don't want to remember `fenceline install --sandbox`? Wrap your package manager:

```bash
fenceline wrap --enable
```

Now `npm install express` automatically goes through the Docker sandbox. Non-install commands (`npm test`, `npm run`, etc.) pass through unchanged.

```bash
fenceline wrap --status    # see what's wrapped
fenceline wrap --disable   # restore originals
```

## Quick Start

```bash
git clone https://github.com/Karmona/Fenceline.git
cd Fenceline
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Sandboxed install (requires Docker)
fenceline install --sandbox npm install express

# Or wrap npm permanently
fenceline wrap --enable
npm install express    # now sandboxed automatically
```

## Other Tools

| Command | What it does |
|---------|-------------|
| `fenceline check` | Scan lockfile diffs for risky changes — package age, maintainer changes, missing provenance. npm + PyPI (experimental). |
| `fenceline audit-actions` | Scan GitHub Actions for unpinned tags. The TeamPCP attack force-pushed Trivy's tags. |
| `fenceline init` | Git hooks that auto-run `fenceline check` on lockfile changes. |
| `tools/quick-check.sh` | One-command security posture report. No install needed. |

## Against Real Attacks

Theoretical assessments — not proven in-the-wild. See [exploits/](exploits/) for detailed analysis.

| Attack | Year | Sandbox |
|--------|------|---------|
| Axios RAT | 2026 | **Would block** — C2 on port 8000 |
| TeamPCP: LiteLLM | 2026 | **Would block** — Stage 2 catches .pth payload |
| chalk/debug | 2025 | **Would block** — Stage 2 catches import C2 |
| Nx/s1ngularity | 2025 | Partial — exfils via legitimate domain |
| Ultralytics | 2024 | **Would block** — mining pool on port 8080 |
| ua-parser-js | 2021 | **Would block** — postinstall phones home |
| event-stream | 2018 | **Would block** — Stage 2 catches import payload |
| colors.js | 2022 | **Contained** — no network, but isolated in container |
| XZ Utils | 2024 | **Contained** — passive backdoor, isolated |
| Codecov | 2021 | Outside scope — CI/CD tool |
| Polyfill.io | 2024 | Outside scope — client-side CDN |

7 blocked. 2 contained. 2 outside scope.

## What This Does NOT Catch

- Attacks with no network activity (logic bombs, sabotage)
- CI/CD pipeline attacks (use `fenceline audit-actions` for Actions)
- Code that only activates after being copied to host without network
- Exfiltration via legitimate domains without HTTP analysis (future work)
- Steganographic payloads (.WAV files, etc.)

## Knowledge Base

| Resource | Description |
|----------|-------------|
| [11 Exploit Case Studies](exploits/) | Real attacks with IOCs, timelines, sandbox assessments |
| [Deep Map](map/) | Network fingerprints for 8 package managers (powers the detection engine) |
| [Defense Playbook](docs/playbook.md) | Practical steps by role |
| [Tools Landscape](docs/landscape.md) | Every supply chain tool, honestly assessed |
| [Newsroom](docs/newsroom.md) | Latest incidents and defenses |
| [Supply Chain Guide](docs/supply-chain-for-dummies.md) | Plain-English explainer |

## Scope and Focus

Fenceline is optimized for **install-time and import-time network behavior on developer machines**. It is not a general-purpose package malware detector.

- **Node.js** (npm, yarn, pnpm): Fully supported — sandbox + artifact copy
- **Python** (pip): Experimental — sandbox monitoring works, artifact copy is limited
- **Others**: Network monitoring works, but no artifact handling yet

See [docs/landscape.md](docs/landscape.md) for how Fenceline fits alongside Socket, Aikido, Phylum, OpenSSF, StepSecurity, and others.

## Roadmap

| Phase | Status | What |
|-------|--------|------|
| Knowledge Base | Done | 11 exploits, deep map, playbook, landscape |
| CLI Tools | Done | check, install, init, audit-actions, wrap. 83 tests. |
| Sandbox | Done | Docker isolation, 2-stage monitoring, verified end-to-end |
| Next | Planned | File system diffing, HTTP method analysis, CI enforcement, structured JSON output |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

Best-effort, community-driven. **Does NOT guarantee protection against any attack.** See [DISCLAIMER.md](DISCLAIMER.md).

## License

Apache 2.0 — [LICENSE](LICENSE). Copyright 2026 Fenceline Contributors.
