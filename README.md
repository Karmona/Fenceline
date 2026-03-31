# Fenceline

[![CI](https://github.com/Karmona/Fenceline/actions/workflows/ci.yml/badge.svg)](https://github.com/Karmona/Fenceline/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://python.org)
[![v0.5.0](https://img.shields.io/badge/version-0.5.0-orange.svg)](CHANGELOG.md)

**Sandboxed package installs. Untrusted code never runs on your machine.**

## Why

In March 2026, the `axios` npm package was compromised with a RAT that beaconed to a command server every 60 seconds. The same month, the TeamPCP campaign hit security tools themselves — Trivy, Checkmarx, LiteLLM — stealing credentials from over a thousand developer systems. In September 2025, a single phishing email compromised 18 npm packages including `chalk` and `debug`, reaching 1 in 10 cloud environments in under 2 hours.

Every one of these attacks executed code on developer machines during `npm install` or `pip install`. By the time anyone noticed, the damage was done.

**What if the install never ran on your machine in the first place?**

## How It Works

```bash
fenceline install --sandbox npm install <package>
```

```
┌─────────────────────────────────────────┐
│ Docker Container (disposable)           │
│                                         │
│ Stage 1: npm install <pkg>              │
│   → monitor all network connections     │
│                                         │
│ Stage 2: node -e "require('<pkg>')"     │
│   → monitor again (catches import-time  │
│     payloads like event-stream, chalk)  │
│                                         │
│ Suspicious? → KILL container.           │
│ Clean? → copy node_modules to host.     │
└─────────────────────────────────────────┘
```

Monitoring happens from **outside** the container. Your machine never touches untrusted code until it's been verified.

**Suspicious package blocked:**
```
[fenceline] Sandbox: container ef3dec started
[fenceline] Sandbox: running npm install sketchy-pkg inside container...
[fenceline] Sandbox: 1 suspicious connection(s) in Stage 1 (install)!
  !! [CRITICAL] node -> 93.184.216.34:8080 — Non-standard port 8080
[fenceline] Sandbox: BLOCKED — not installing on your machine.
```

**Clean package verified and installed:**
```
[fenceline] Sandbox: container 3fb093 started
[fenceline] Sandbox: running npm install is-odd inside container...
[fenceline] Sandbox: Stage 2 — testing import of 'is-odd'...
[fenceline] Sandbox: install clean. Copying artifacts to host...
[fenceline] Sandbox: done. Install verified and applied.
```

Both outputs above are from real Docker tests on macOS, not mockups.

## What Else Fenceline Does

The sandbox is the core tool. These support it:

| Command | What it does |
|---------|-------------|
| `fenceline check` | Scan lockfile diffs for risky changes (package age, maintainer changes, missing provenance). Supports npm + PyPI. |
| `fenceline audit-actions` | Scan GitHub Actions workflows for unpinned tags — the attack vector used by TeamPCP to compromise Trivy and Checkmarx. |
| `fenceline init` | Install git hooks that auto-run `fenceline check` on lockfile changes. |
| `tools/quick-check.sh` | One-command security posture report. No install needed. |

## Knowledge Base

| Resource | What's there |
|----------|-------------|
| [Exploit Case Studies](exploits/) | 11 real attacks (2018-2026) with IOCs, timelines, and honest sandbox assessments |
| [Deep Map](map/) | Expected network behavior for 8 package managers — domains, IPs, ASNs, CDNs, TLS certs. Powers the sandbox detection engine. |
| [Defense Playbook](docs/playbook.md) | Practical security steps organized by role (npm user, Python user, publisher, CI/CD) |
| [Supply Chain for Developers](docs/supply-chain-for-dummies.md) | Plain-English explainer + 5-minute security checklist |
| [Tools Landscape](docs/landscape.md) | Every supply chain security tool we know about, with honest assessments |
| [Newsroom](docs/newsroom.md) | Latest incidents and defenses |

## Quick Start

**No install needed — check your project's security posture:**
```bash
bash tools/quick-check.sh
```

**Install the CLI (requires Python 3.9+):**
```bash
git clone https://github.com/Karmona/Fenceline.git
cd Fenceline
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

**Run a sandboxed install (requires Docker):**
```bash
fenceline install --sandbox npm install express
```

**Scan lockfile for risky changes:**
```bash
fenceline check
```

**Audit GitHub Actions:**
```bash
fenceline audit-actions
```

## Against Real Attacks

Based on our analysis of 11 real supply chain attacks. These are theoretical assessments — not proven in-the-wild detections. See [exploits/](exploits/) for details on each.

| Attack | Year | Sandbox assessment |
|--------|------|--------------------|
| Axios RAT | 2026 | **Would block** — C2 beacon on non-standard port |
| TeamPCP: LiteLLM | 2026 | **Would block** — Stage 2 import triggers .pth credential harvesting |
| chalk/debug | 2025 | **Would block** — Stage 2 import triggers C2 connection |
| Nx/s1ngularity | 2025 | Partial — exfils via legitimate domain, needs HTTP method analysis |
| Ultralytics | 2024 | **Would block** — mining pool on non-standard port |
| ua-parser-js | 2021 | **Would block** — postinstall phones home |
| event-stream | 2018 | **Would block** — Stage 2 import triggers payload |
| XZ Utils | 2024 | **Contained** — passive backdoor, no network, but isolated in container |
| colors.js | 2022 | **Contained** — logic bomb, no network, but damage limited to container |
| Codecov | 2021 | Outside scope — CI/CD tool, not a package install |
| Polyfill.io | 2024 | Outside scope — client-side CDN, not a package install |

7 would be blocked. 2 would be contained. 2 are outside scope. No single tool catches everything — the sandbox catches attacks that phone home during install or import.

## What the Sandbox Does NOT Catch

Being honest about limitations:

- **Attacks with no network activity** (colors.js logic bomb, XZ Utils passive backdoor) — the sandbox contains them but cannot detect them
- **CI/CD pipeline attacks** (TeamPCP Trivy/Checkmarx tag tampering) — use `fenceline audit-actions` and SHA-pinned actions instead
- **Client-side attacks** (Polyfill.io domain takeover) — not a package install
- **Sophisticated evasion** (code that only activates after being copied to host, or steganographic payloads like TeamPCP Telnyx) — future work: file system diffing
- **Exfiltration via legitimate domains** (Nx using api.github.com) — future work: HTTP method analysis

## Roadmap

| Phase | Status | What |
|-------|--------|------|
| Knowledge Base | Done | 11 exploits, deep map, playbook, landscape, newsroom |
| CLI Tools | Done | `check`, `install`, `init`, `audit-actions`. 83 tests. |
| Sandbox | Done | Docker isolation, 2-stage monitoring, verified with real Docker |
| Next | Planned | File system diffing, HTTP method analysis, PyPI distribution |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Add exploit case studies, improve the map, build detection tools, or fix docs.

## Disclaimer

Fenceline is a community-driven, best-effort project provided "AS IS" without warranty. **It does NOT guarantee protection against any attack.** See [DISCLAIMER.md](DISCLAIMER.md).

## License

Apache 2.0 — [LICENSE](LICENSE). Copyright 2026 Fenceline Contributors.
