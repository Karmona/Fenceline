# The Quest

> Create clarity in chaos.

Fenceline tracks its progress against real-world supply chain attacks. Every exploit we study becomes a test case. Every detection gap is a challenge to close.

## Detection Coverage

Based on analysis of 10 major supply chain attacks (2018-2026):

```
Progress: ██████░░░░ 7/10 attacks detectable with infrastructure map
```

| # | Attack | Year | Map Catches It? |
|---|--------|------|----------------|
| 1 | event-stream | 2018 | YES |
| 2 | ua-parser-js | 2021 | YES |
| 3 | Codecov | 2021 | YES |
| 4 | colors.js/faker.js | 2022 | NO (no network) |
| 5 | XZ Utils | 2024 | NO (passive backdoor) |
| 6 | Polyfill.io | 2024 | PARTIAL |
| 7 | Ultralytics | 2024 | YES |
| 8 | Nx/s1ngularity | 2025 | PARTIAL |
| 9 | chalk/debug | 2025 | YES |
| 10 | Axios RAT | 2026 | YES |

## Attack Pattern Coverage

- [x] Outbound connection to unknown domain
- [x] Connection on unusual port (non-443)
- [x] Data upload during package install
- [x] postinstall script exfiltration
- [x] Cryptocurrency mining pool connection
- [x] Fake/masqueraded domain (e.g., `packages.npm.org`)
- [x] Missing provenance attestation
- [ ] Domain reuse with anomalous HTTP behavior (e.g., Nx using `api.github.com` for exfil)
- [ ] No-network attacks (logic bombs, sabotage)
- [ ] Slopsquatting (AI-hallucinated package names)
- [ ] CDN/domain acquisition takeover

## Milestones

- [x] Deep map published for 8 package managers
- [x] 10 exploit case studies with full analysis
- [x] CLI: `fenceline check` (lockfile diff scanner)
- [x] CLI: `fenceline install` (install-time network monitor)
- [x] CLI: `fenceline init` (git hooks)
- [x] GitHub Action definition
- [x] Test harness with attack simulations
- [x] 35 automated tests (lockfile, scoring, monitor, matcher)
- [ ] OpenSSF Scorecard API integration
- [ ] Plugin system for community detection rules
- [ ] First external community contribution

## How You Can Help

Pick an unchecked item above and start working on it. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Every new exploit case study, every map update, every detection improvement gets us closer to full coverage.
