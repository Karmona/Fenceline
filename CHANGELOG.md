# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-03-31

### Added
- `fenceline check` — lockfile diff scanner with risk scoring
  - Package age detection (flags packages < 7 days old)
  - Maintainer change detection (account takeover signal)
  - Install script detection (postinstall/preinstall)
  - Provenance attestation check (Sigstore)
  - Risk scoring: LOW / MEDIUM / HIGH / CRITICAL with explanations
  - Output formats: text, json, markdown
- `fenceline install` — install-time network monitor
  - Polls lsof (macOS) / ss (Linux) scoped to install process PID
  - Compares connections against deep map YAML data
  - Alerts on unknown IPs, non-443 ports, wrong CDN ranges
- `fenceline init` — git hook installer
  - pre-commit hook: checks lockfile on staged changes
  - post-merge hook: checks lockfile after merge/pull
- GitHub Action definition (`action/action.yml`)
- PR comment markdown formatter
- 25 automated tests (lockfile, scoring, monitor, matcher)
- Python package with `pip install -e .` support

## [0.1.0] - 2026-03-31

### Added
- 10 exploit case studies (event-stream through Axios RAT, 2018-2026)
- Deep Map: infrastructure fingerprints for 8 package managers
  - npm, pip, cargo, yarn, homebrew, go-modules, rubygems, composer
  - 4 CDN IP range files (Cloudflare, Fastly, AWS, Google Cloud)
- Documentation
  - Supply Chain for Developers (plain-English explainer)
  - Why This Matters (numbers-driven case)
  - Tools Landscape (14 tools mapped with honest assessments)
  - Newsroom (ongoing incidents and defenses)
- Quick posture check script (`tools/quick-check.sh`)
- 5-minute security checklist with copy-paste commands
- Attack simulation test harness (5 safe localhost-only simulations)
- QUEST.md progress tracker
