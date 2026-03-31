# Fenceline

[![CI](https://github.com/Karmona/Fenceline/actions/workflows/ci.yml/badge.svg)](https://github.com/Karmona/Fenceline/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://python.org)
[![v0.2.0](https://img.shields.io/badge/version-0.2.0-orange.svg)](CHANGELOG.md)

**Create clarity in chaos.**

An open source project to understand, map, and defend against software supply chain attacks. Documentation-first. Community-driven. Best effort.

## The Problem

In September 2025, a single phishing email compromised 18 npm packages — including `chalk` and `debug` — with a combined 2.6 billion weekly downloads. The malicious code was live for about 2 hours before detection. In those 2 hours, it reached 1 in 10 cloud environments.

In March 2026, the `axios` package (400M monthly downloads) was compromised with a multi-platform RAT that beaconed to a command-and-control server every 60 seconds.

These are not edge cases. They are the new normal.

Most developers have no idea what their dependencies do at the network level. Supply chain attacks exploit this blind spot. The tools that exist are either enterprise-only, narrow in focus, or require security expertise to use.

**Fenceline exists to change that.**

## Start Here

**[5-Minute Security Checklist](docs/supply-chain-for-dummies.md#5-minute-checklist-what-you-can-do-right-now)** — copy-paste commands to harden your project right now. No installs needed.

**[Quick Posture Report](docs/supply-chain-for-dummies.md#quick-posture-report)** — one command that checks your project and tells you what to fix.

## What's Here

### Learn

Detailed case studies of real supply chain attacks — what happened, how it worked, what we can learn from each one, and whether our approach could have helped detect it.

- [Exploit Case Studies](exploits/) — 10 major attacks analyzed in detail
- [Supply Chain for Developers](docs/supply-chain-for-dummies.md) — plain-English explainer
- [Why This Matters](docs/why-this-matters.md) — the real cost, with real numbers

### Map

The Deep Map — infrastructure fingerprints of every major package manager's expected network behavior. Domains, IP ranges, ASNs, CDN providers, TLS certificates, expected ports, and expected behaviors. Built entirely from public data.

- [The Deep Map](map/) — expected network behavior for 8 package managers
- **Key insight:** No package manager should EVER upload data during install. Any upload = suspicious.
- **Validation:** Based on our analysis, this map could have detected anomalous network behavior in 7 out of 10 major attacks we studied. See [exploits/](exploits/) for details.

### Defend

Tools that use the map and other signals to detect anomalies.

- `fenceline check` — scan lockfile diffs for risky dependency changes
- `fenceline install` — monitor network connections during package installs
- `fenceline init` — install git hooks for automatic checking
- [Testing](testing/) — safe simulations of attack patterns
- [Quick posture check script](tools/quick-check.sh) — checks your project's security settings now

### Landscape

A comprehensive directory of every supply chain security tool we know about — open source and commercial, with honest assessments of what each catches and misses.

- [Tools Landscape](docs/landscape.md) — the full map of existing defenses

### Stay Current

Supply chain security moves fast. New attacks, new defenses, new package manager features.

- [Newsroom](docs/newsroom.md) — latest incidents, defenses, and package manager security updates
- [QUEST.md](QUEST.md) — what we're working on and where we think the gaps are

## Quick Start

### No install needed

Check your project's security posture in 30 seconds:

```bash
bash tools/quick-check.sh
```

### Install the CLI tools

Requires Python 3.9+:

```bash
git clone https://github.com/Karmona/Fenceline.git
cd Fenceline
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

### `fenceline check` — scan lockfile for risky dependency changes

Run in any npm project with a `package-lock.json`:

```bash
fenceline check
```

Compares your lockfile against the last git commit. For each new/updated package, checks: age, maintainer changes, install scripts, provenance. Outputs a risk score.

Example output:
```
[!] HIGH     ( 55) axios  (new) -> 1.14.0
         +30  very_new_version: Published 3d ago (< 7 days)
         +10  maintainer_added: New maintainers detected
         +10  no_provenance: No Sigstore provenance attestation
         + 5  new_package: Newly added dependency

[~] MEDIUM   ( 25) form-data  (new) -> 4.0.5
         +10  maintainer_added: New maintainers detected
         +10  no_provenance: No Sigstore provenance attestation
         + 5  new_package: Newly added dependency
```

Options:
```bash
fenceline check --base-ref main        # compare against a specific branch
fenceline check --format json          # output as JSON
fenceline check --format markdown      # output as markdown (for CI)
fenceline check --scorecard            # also query OpenSSF Scorecard API
```

### `fenceline install` — monitor network during package installs

Wraps any install command and watches for suspicious network connections:

```bash
fenceline install npm install express
```

Monitors outbound connections scoped to the install process. Compares against the [deep map](map/) (known domains, CDN IP ranges, expected ports). Alerts on unknown IPs, non-443 ports, or unexpected CDN usage.

Example output:
```
[fenceline] Monitoring network during: npm install express
added 65 packages in 2s
[fenceline] No unexpected network activity detected.
```

If something suspicious is found:
```
[fenceline] 1 network alert(s) during install:
  !! [CRITICAL] node -> 45.33.32.156:8080 — Non-standard port 8080
```

### `fenceline init` — install git hooks

Auto-check lockfiles on every commit and merge:

```bash
fenceline init
```

Installs `pre-commit` and `post-merge` hooks that run `fenceline check` whenever lockfiles change.

### Explore the knowledge base

```bash
ls exploits/                    # 10 real attack case studies
cat map/tools/npm.yaml          # npm's expected network behavior
cd testing && ./harness.sh      # run safe attack simulations
```

## Roadmap

We're building this in the open. Here's where we are and where we're going.

### Phase 1: Knowledge Base `v0.1 — done`

Build the educational foundation.

| Deliverable | Status |
|-------------|--------|
| [Exploit case studies](exploits/) (10 real attacks) | Done |
| [Deep Map](map/) (8 package managers, 4 CDNs) | Done |
| [Supply chain explainer](docs/supply-chain-for-dummies.md) for developers | Done |
| [Tools landscape directory](docs/landscape.md) | Done |
| [Newsroom](docs/newsroom.md) (ongoing incidents + defenses) | Done |
| [Quick posture check script](tools/quick-check.sh) | Done |
| [5-minute security checklist](docs/supply-chain-for-dummies.md#5-minute-checklist-what-you-can-do-right-now) with tested commands | Done |
| [Attack simulation test harness](testing/) | Done |

### Phase 2: CLI Tools `v0.2 — done`

Detection tools that use the map and other signals.

| Deliverable | Status |
|-------------|--------|
| [`fenceline check`](src/fenceline/check/) — lockfile diff scanner (package age, maintainer changes, capabilities, provenance) | Done |
| [`fenceline install`](src/fenceline/install/) — install-time network monitor (compare connections against deep map) | Done |
| [`fenceline init`](src/fenceline/init/) — git hooks for auto-checking on lockfile changes | Done |
| [25 automated tests](tests/) | Done |
| pip install distribution (`pip install -e .`) | Done |
| Integrate with OpenSSF Scorecard API | Planned |

### Phase 3: CI/CD Integration `v0.3 — in progress`

Make it run automatically on every PR.

| Deliverable | Status |
|-------------|--------|
| [GitHub Action definition](action/action.yml) | Done |
| [PR comment markdown formatter](src/fenceline/output/github.py) | Done |
| Plugin system for community detection rules | Planned |
| Behavioral layer for domain-reuse attacks (HTTP method/path analysis) | Planned |

### Phase 4: Expand `future`

| Deliverable | Status |
|-------------|--------|
| Cross-ecosystem capability analysis (Capslock-style, beyond Go) | Research |
| Slopsquatting detector (AI-hallucinated package names) | Research |
| Swift/Xcode ecosystem support (SPM, CocoaPods) | Research |
| Pre-install behavioral sandbox | Research |

Want to help with any of these? See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to help. Every contribution matters:

- Add or update exploit case studies
- Improve the deep map (new tools, updated IPs, cert fingerprints)
- Build or improve detection tools
- Fix errors in documentation
- Add test simulations for new attack patterns

## Tools We Build On

Fenceline stands on the shoulders of many excellent projects. See [docs/landscape.md](docs/landscape.md) for the full directory with credit to every tool and team.

Key projects we reference and integrate with:
- [OpenSSF Scorecard](https://github.com/ossf/scorecard) — project security scoring
- [Datadog GuardDog](https://github.com/DataDog/guarddog) — malicious package detection
- [OpenSSF Package Analysis](https://github.com/ossf/package-analysis) — dynamic sandbox analysis
- [Sigstore](https://sigstore.dev/) — package provenance attestation
- [Google Capslock](https://github.com/google/capslock) — capability analysis for Go
- [GUAC](https://github.com/guacsec/guac) — supply chain graph database

## Disclaimer

Fenceline is a community-driven, best-effort project. It is provided "AS IS" without warranty of any kind.

- **This project does NOT guarantee protection against any attack**
- No liability is accepted for security incidents, data loss, or damages
- The information and tools here may be incomplete, outdated, or incorrect
- This is not a replacement for professional security review
- Use at your own risk

See [DISCLAIMER.md](DISCLAIMER.md) for the full legal disclaimer.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2026 Fenceline Contributors.
