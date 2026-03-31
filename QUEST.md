# The Quest

> Create clarity in chaos.

Fenceline tracks its progress against real-world supply chain attacks. Every exploit we study becomes a test case. Every detection gap is a challenge to close.

## Detection Coverage

Based on analysis of 11 major supply chain attacks (2018-2026):

```
Progress: ███████░░░░ 7/11 attacks preventable with Docker sandbox
```

| # | Attack | Year | Sandbox Prevents It? |
|---|--------|------|---------------------|
| 1 | event-stream | 2018 | YES (Stage 2 catches import payload) |
| 2 | ua-parser-js | 2021 | YES (Stage 1 catches outbound) |
| 3 | Codecov | 2021 | Outside scope (CI/CD tool) |
| 4 | colors.js/faker.js | 2022 | NO (no network) — sandbox limits blast radius |
| 5 | XZ Utils | 2024 | NO (passive backdoor) — sandbox limits blast radius |
| 6 | Polyfill.io | 2024 | Outside scope (client-side CDN) |
| 7 | Ultralytics | 2024 | YES (Stage 1 catches mining port) |
| 8 | Nx/s1ngularity | 2025 | PARTIAL (legitimate domain) — sandbox isolates exfil |
| 9 | chalk/debug | 2025 | YES (Stage 2 catches import payload) |
| 10 | Axios RAT | 2026 | YES (Stage 1 catches outbound) |
| 11 | TeamPCP: LiteLLM | 2026 | YES (Stage 2 triggers .pth on import) |

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

- [x] Deep map published for 8 package managers (IPv4 + IPv6 + TLS certs)
- [x] 11 exploit case studies with full analysis
- [x] CLI: `fenceline check` (npm + PyPI lockfile scanner)
- [x] CLI: `fenceline install` (install-time network monitor, IPv4 + IPv6)
- [x] CLI: `fenceline install --sandbox` (Docker-sandboxed installs)
- [x] Stage 2 import monitoring (catches module-load payloads)
- [x] CLI: `fenceline init` (git hooks)
- [x] CLI: `fenceline audit-actions` (GitHub Actions SHA pinning audit)
- [x] GitHub Action definition
- [x] Defense playbook (practical steps by role)
- [x] Landscape with 9 defense approaches mapped (including sandbox + safety-without-detection)
- [x] Test harness with attack simulations
- [x] 83 automated tests
- [x] Weekly map freshness automation
- [ ] File system diffing (compare container state before/after install)
- [ ] HTTP method/path behavioral analysis (detect exfil via legitimate domains)
- [ ] PyPI distribution (`pip install fenceline`)
- [ ] OpenSSF Scorecard API integration
- [ ] Plugin system for community detection rules
- [ ] First external community contribution

## How You Can Help

Pick an unchecked item above and start working on it. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Every new exploit case study, every map update, every detection improvement gets us closer to full coverage.
