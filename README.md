# Fenceline

[![CI](https://github.com/Karmona/Fenceline/actions/workflows/ci.yml/badge.svg)](https://github.com/Karmona/Fenceline/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://python.org)
[![v0.5.0](https://img.shields.io/badge/version-0.5.0-orange.svg)](CHANGELOG.md)

**Create clarity in chaos.**

Open source tools for understanding and defending against software supply chain attacks. Sandboxes package installs in Docker so untrusted code never runs on your machine until verified. Documentation-first. Community-driven.

## The Problem

Supply chain attacks are the new normal. Compromised packages reach millions of developers before anyone notices. The `chalk`/`debug` hijack in 2025 hit 1 in 10 cloud environments in under 2 hours. The `axios` RAT in 2026 beaconed to a C2 server every 60 seconds.

Most developers have no idea what their dependencies do at the network level. The tools that exist are either enterprise-only, narrow in focus, or require security expertise.

**Fenceline exists to change that.**

## Sandboxed Package Installs

Run any package install inside a disposable Docker container. Network connections are monitored from outside. If anything suspicious is detected, the container is killed and nothing touches your machine:

```bash
fenceline install --sandbox npm install <pkg>
```

**Stage 1:** Run the install, monitor all network connections.
**Stage 2:** Import/require the package, monitor again.

If suspicious connections are detected -- the container is killed. Nothing reaches your machine.
If clean -- artifacts are copied to your host.

**Blocked install (malicious package phones home):**
```
[fenceline] Sandbox: container abc123 started
[fenceline] Sandbox: running npm install sketchy-pkg inside container...
[fenceline] Sandbox: 1 suspicious connection(s) detected!
  !! [CRITICAL] node -> 45.33.32.156:8080 — Non-standard port 8080
[fenceline] Sandbox: BLOCKED — not installing on your machine.
```

**Clean install (safe package verified):**
```
[fenceline] Sandbox: container abc123 started
[fenceline] Sandbox: running npm install express inside container...
[fenceline] Sandbox: install clean. Copying artifacts to host...
[fenceline] Sandbox: done. Install verified and applied.
```

## Start Here

**[5-Minute Security Checklist](docs/supply-chain-for-dummies.md#5-minute-checklist-what-you-can-do-right-now)** -- copy-paste commands to harden your project right now. No installs needed.

**[Quick Posture Report](docs/supply-chain-for-dummies.md#quick-posture-report)** -- one command that checks your project and tells you what to fix.

## What's Here

### Defend

- `fenceline install --sandbox` -- sandboxed installs via Docker (the headline feature)
- `fenceline check` -- scan lockfile diffs for risky dependency changes
- `fenceline audit-actions` -- scan GitHub Actions for tag-tampering risks (SHA pinning)
- `fenceline init` -- install git hooks for automatic checking
- [Testing](testing/) -- safe simulations of attack patterns
- [Quick posture check](tools/quick-check.sh) -- check your project's security settings now

### Learn

- [Exploit Case Studies](exploits/) -- 11 major attacks analyzed in detail
- [Supply Chain for Developers](docs/supply-chain-for-dummies.md) -- plain-English explainer
- [Why This Matters](docs/why-this-matters.md) -- the real cost, with real numbers
- [Defense Playbook](docs/playbook.md) -- practical security steps by role

### Map

- [The Deep Map](map/) -- expected network behavior for 8 package managers
- Key insight: no package manager should EVER upload data during install. Any upload = suspicious.
- The map powers the sandbox's detection engine.

### Landscape

- [Tools Landscape](docs/landscape.md) -- directory of every supply chain security tool we know about

### Stay Current

- [Newsroom](docs/newsroom.md) -- latest incidents, defenses, and package manager security updates

## Quick Start

### No install needed

```bash
bash tools/quick-check.sh
```

### Install the CLI

```bash
git clone https://github.com/Karmona/Fenceline.git
cd Fenceline
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

### The 4 commands

```bash
# Sandboxed install (recommended -- requires Docker)
fenceline install --sandbox npm install express
fenceline install --sandbox --monitor-time 30 pip install requests

# Scan lockfile for risky changes
fenceline check
fenceline check --base-ref main

# Audit GitHub Actions for unpinned tags
fenceline audit-actions

# Install git hooks for automatic checking
fenceline init
```

## How It Works

```
fenceline install --sandbox npm install <pkg>

┌─────────────────────────────────────────┐
│ Docker Container                        │
│                                         │
│ Stage 1: npm install <pkg>              │
│   ↓ monitor network                     │
│ Stage 2: node -e "require('<pkg>')"     │
│   ↓ monitor network                     │
│                                         │
│ If suspicious → KILL container           │
│ If clean → copy node_modules to host    │
└─────────────────────────────────────────┘
```

Network monitoring happens from **outside** the container via `docker exec ss`. The container is disposable. Your machine is never exposed to untrusted code until it has been verified.

Without Docker, `fenceline install` still works with host-based monitoring (without Docker) -- it monitors connections but cannot prevent execution.

## Detection Scorecard

Based on our analysis of 11 real supply chain attacks, here's what the sandbox approach would catch. These are theoretical assessments, not proven in-the-wild detections. See [exploits/](exploits/) for detailed analysis of each attack.

| Exploit | Year | Sandbox Assessment |
|---------|------|--------------------|
| event-stream | 2018 | **Would block** — Stage 2 import triggers payload, connection caught |
| ua-parser-js | 2021 | **Would block** — postinstall phones home to C2/mining pool |
| Codecov | 2021 | Outside scope — CI/CD tool, not a package install |
| colors.js | 2022 | **Contained** — no network activity, but damage limited to container |
| XZ Utils | 2024 | **Contained** — passive backdoor, no outbound to detect, but isolated |
| Polyfill.io | 2024 | Outside scope — client-side CDN, not a package install |
| Ultralytics | 2024 | **Would block** — mining pool connection on port 8080 |
| Nx/s1ngularity | 2025 | Partial — uses legitimate domain (api.github.com), needs HTTP analysis |
| chalk/debug | 2025 | **Would block** — Stage 2 import triggers C2 connection |
| Axios RAT | 2026 | **Would block** — C2 beacon on port 8000 |
| TeamPCP LiteLLM | 2026 | **Would block** — Stage 2 import triggers .pth credential harvesting |

**What this means:** The sandbox blocks attacks that phone home during install or import (7/11). It contains but doesn't detect attacks with no network activity (2/11). It doesn't apply to CI/CD or client-side attacks (2/11). No single tool catches everything.

## Roadmap

### Phase 1: Knowledge Base `done`
Exploit case studies, deep map, explainers, playbook, landscape, newsroom, posture check, test harness.

### Phase 2: CLI Tools `done`
`fenceline check`, `install`, `init`, `audit-actions`. 83 automated tests. CI on every push.

### Phase 3: Harden + Grow `in progress`
GitHub Action definition (done). PyPI distribution, OpenSSF Scorecard integration, behavioral HTTP analysis, plugin system (planned).

### Phase 4: Sandbox `done`
`fenceline install --sandbox` via Docker. Network monitoring from outside the container. Clean installs copied to host, suspicious installs killed.

### Phase 5: Next
File system diffing (before/after install comparison). HTTP method and path analysis. DNS monitoring for domain-reuse attacks.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to help. Every contribution matters -- add exploit case studies, improve the deep map, build detection tools, fix docs, or add test simulations.

## Tools We Build On

Fenceline stands on the shoulders of many excellent projects. See [docs/landscape.md](docs/landscape.md) for the full directory.

Key projects: [OpenSSF Scorecard](https://github.com/ossf/scorecard), [Datadog GuardDog](https://github.com/DataDog/guarddog), [OpenSSF Package Analysis](https://github.com/ossf/package-analysis), [Sigstore](https://sigstore.dev/), [Google Capslock](https://github.com/google/capslock), [GUAC](https://github.com/guacsec/guac).

## Disclaimer

Fenceline is a community-driven, best-effort project. It is provided "AS IS" without warranty of any kind.

- **This project does NOT guarantee protection against any attack**
- No liability is accepted for security incidents, data loss, or damages
- The information and tools here may be incomplete, outdated, or incorrect
- This is not a replacement for professional security review
- Use at your own risk

See [DISCLAIMER.md](DISCLAIMER.md) for the full legal disclaimer.

## License

Apache License 2.0 -- see [LICENSE](LICENSE).

Copyright 2026 Fenceline Contributors.
