# Fenceline

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

**Check your project's security posture in 30 seconds:**

```bash
bash tools/quick-check.sh
```

This checks cooldown settings, install script protection, lockfile tracking, registry auth, provenance, Homebrew telemetry, and sensitive file protection. No installs needed.

**Explore the knowledge base:**

```bash
# Browse the exploit database
ls exploits/

# Read the deep map for npm
cat map/tools/npm.yaml

# Run attack simulations (safe, uses localhost only)
cd testing && ./harness.sh
```

## Roadmap

We're building this in the open. Here's where we are and where we're going.

### Phase 1: Knowledge Base `v0.1 — done`

Build the educational foundation.

| Deliverable | Status |
|-------------|--------|
| Exploit case studies (10 real attacks) | Done |
| Deep Map (8 package managers, 4 CDNs) | Done |
| Supply chain explainer for developers | Done |
| Tools landscape directory | Done |
| Newsroom (ongoing incidents + defenses) | Done |
| Quick posture check script | Done |
| 5-minute security checklist with tested commands | Done |
| Attack simulation test harness | Done |

### Phase 2: CLI Tools `v0.2 — done`

Detection tools that use the map and other signals.

| Deliverable | Status |
|-------------|--------|
| `fenceline check` — lockfile diff scanner (package age, maintainer changes, capabilities, provenance) | Done |
| `fenceline install` — install-time network monitor (compare connections against deep map) | Done |
| `fenceline init` — git hooks for auto-checking on lockfile changes | Done |
| 25 automated tests | Done |
| pip install distribution (`pip install -e .`) | Done |
| Integrate with OpenSSF Scorecard API | Planned |

### Phase 3: CI/CD Integration `v0.3 — in progress`

Make it run automatically on every PR.

| Deliverable | Status |
|-------------|--------|
| GitHub Action definition (action.yml) | Done |
| PR comment markdown formatter | Done |
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
