# Newsroom

Supply chain security moves fast. New attacks, new tools, new defenses — this page tracks what's happening so you don't have to monitor 20 different sources.

Last updated: March 2026

## Recent Incidents

| Date | What happened | Impact | Details |
|------|--------------|--------|---------|
| Mar 2026 | **TeamPCP campaign** — coordinated attacks on Trivy, Checkmarx, LiteLLM, Telnyx | Security tools weaponized against users | [Case study](../exploits/2026-teampcp-campaign.md) |
| Mar 2026 | axios npm compromise — multi-platform RAT | ~83M weekly downloads | [Case study](../exploits/2026-axios-rat.md) |
| Sep 2025 | chalk/debug/ansi-styles — phished maintainer, crypto drainer | 2.6B weekly downloads | [Case study](../exploits/2025-chalk-debug.md) |
| Aug 2025 | Nx/s1ngularity — GitHub Actions token theft | 2,349 credentials stolen | [Case study](../exploits/2025-nx-s1ngularity.md) |
| Dec 2024 | Ultralytics PyPI — Pwn Request, XMRig miner | ~60M total downloads | [Case study](../exploits/2024-ultralytics.md) |

## Recent Defenses

| Date | What shipped | Why it matters |
|------|-------------|----------------|
| Mar 2026 | Fenceline v0.5.0: Docker sandbox with 2-stage import monitoring | Sandboxed installs that block attacks phoning home during install or import |
| Mar 2026 | npm `min-release-age` stabilizing in v11.x | One config line blocks most account takeover attacks |
| Feb 2026 | npm deprecates classic tokens permanently | Forces migration to short-lived granular tokens or OIDC |
| Dec 2025 | npm deprecates TOTP 2FA, pushes WebAuthn | TOTP can be phished in real-time (chalk/debug proved this) |
| Oct 2025 | Bun v1.3 adds `minimumReleaseAge` | All major JS package managers now support cooldowns |
| Sep 2025 | pnpm v10.16 adds `minimumReleaseAge` | First package manager with built-in cooldown |
| Sep 2025 | Yarn v4.10 adds `npmMinimalAgeGate` | Yarn joins the cooldown movement |
| Jul 2025 | npm trusted publishing (OIDC) goes GA | Eliminates long-lived tokens for publishing |
| Jul 2025 | crates.io adopts trusted publishing | Rust joins npm, PyPI, RubyGems with OIDC publishing |

## Package Manager Security Roadmaps

### npm (GitHub)

npm is actively hardening its supply chain. Key changes:

- **Trusted publishing (OIDC)** — CI systems get short-lived, per-run credentials instead of stored tokens. [npm docs](https://docs.npmjs.com/trusted-publishers/)
- **Classic tokens deprecated** — all publishers must migrate to granular tokens (7-day lifetime) or OIDC
- **TOTP 2FA deprecated** — migrating to FIDO/WebAuthn hardware keys. [OpenJS guidance](https://openjsf.org/blog/publishing-securely-on-npm)
- **Provenance auto-generated** — packages published via trusted publishing get Sigstore attestations automatically. [npm docs](https://docs.npmjs.com/generating-provenance-statements/)
- **`min-release-age`** — cooldown before new versions can be installed. [npm CLI issue](https://github.com/npm/cli/issues/8570)
- **Publishing defaults to "disallow tokens"** — pushing all publishers toward OIDC
- **Deterministic dependency locking for GitHub Actions** — SHA pinning of all direct + transitive deps

Source: [npm's update to harden their supply chain](https://www.chainguard.dev/unchained/npm-update-to-harden-their-supply-chain-and-points-to-consider) | [GitHub's plan for a more secure npm](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)

### PyPI

- **Trusted publishing** via Sigstore — GA for GitHub Actions and GitLab CI/CD
- **Mandatory 2FA** for critical projects
- **Malware detection** — automated scanning for known patterns

### crates.io (Rust)

- **Trusted publishing** adopted July 2025
- **cargo-audit** for known CVE scanning

### pnpm

- **`minimumReleaseAge`** — first to ship cooldowns (Sep 2025)
- **`onlyBuiltDependencies`** — allowlist which packages can run install scripts
- [pnpm supply chain security docs](https://pnpm.io/supply-chain-security)

## Where to Follow Supply Chain News

These are the sources we monitor. Follow them to stay current:

### Security Research Teams

| Source | What they cover | Link |
|--------|----------------|------|
| Socket.dev blog | Real-time malware detection, incident analysis | [socket.dev/blog](https://socket.dev/blog) |
| Semgrep blog | Supply chain attack analysis, detection rules | [semgrep.dev/blog](https://semgrep.dev/blog) |
| Wiz blog | Cloud + supply chain threat research | [wiz.io/blog](https://www.wiz.io/blog) |
| Datadog Security Labs | Malware campaigns, package analysis | [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com) |
| Snyk blog | Vulnerability + supply chain research | [snyk.io/blog](https://snyk.io/blog) |
| ReversingLabs blog | Deep malware analysis | [reversinglabs.com/blog](https://www.reversinglabs.com/blog) |

### Organizations

| Source | What they cover | Link |
|--------|----------------|------|
| OpenSSF | Standards, scorecards, best practices | [openssf.org](https://openssf.org) |
| GitHub Security blog | npm changes, Dependabot, supply chain features | [github.blog/security](https://github.blog/security/) |
| npm status + blog | Registry incidents, new features | [status.npmjs.org](https://status.npmjs.org) |
| OpenJS Foundation | npm ecosystem security guidance | [openjsf.org](https://openjsf.org) |

### Individual Researchers

| Who | Known for | Where to follow |
|-----|-----------|----------------|
| Patrick Wardle (Objective-See) | macOS security tools (LuLu, KnockKnock) | [objective-see.org](https://objective-see.org) |
| Andrew Nesbitt | Package manager security, cooldown advocacy | [nesbitt.io](https://nesbitt.io) |
| Feross Aboukhadijeh (Socket) | npm security, supply chain detection | [socket.dev](https://socket.dev) |

## Contributing to the Newsroom

When a new supply chain incident or defense ships:

1. Add it to the relevant table above
2. If it's a major incident, create a case study in [exploits/](../exploits/) using the [template](../exploits/template.md)
3. If it's a new tool, add it to [landscape.md](landscape.md)
4. Update dates and keep entries chronological (newest first)

This page should be the first place someone checks to understand what's happening in supply chain security right now.
