# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-03-31

### Added
- `fenceline install --sandbox` — Docker-sandboxed package installs
  - Runs install inside a Docker container (node:alpine, python:alpine, etc.)
  - Monitors container network from outside via `docker exec ss -tnp`
  - If clean: copies artifacts (node_modules) to host machine
  - If suspicious: kills container, blocks install, shows alerts
  - Graceful degradation: clear error if Docker not installed
  - 21 new tests (83 total), all mock-based (no Docker required to test)

## [0.3.0] - 2026-03-31

### Added
- `fenceline audit-actions` — scans GitHub Actions workflows for unpinned actions
  - Classifies: SHA-pinned (pass), tag-pinned (warning), @main/@master (critical)
  - Motivated by TeamPCP campaign that force-pushed Trivy/Checkmarx action tags
- PyPI/pip support for `fenceline check`
  - Parses Pipfile.lock and requirements.txt
  - Queries PyPI registry API for package age and metadata
  - Auto-detects lockfile type (npm, pip, yarn, pnpm)
- Defense playbook (docs/playbook.md) — practical steps organized by role
- Landscape rewrite: 8 defense approaches taxonomy with honest positioning
- TeamPCP campaign case study (11th exploit — Trivy, Checkmarx, LiteLLM, Telnyx)
- IPv6 CIDR ranges for all 4 CDNs (fixes false positives in fenceline install)
- TLS certificate fingerprints for 7 registry domains
- Weekly map freshness automation (.github/workflows/map-freshness.yml)
- 27 new tests (62 total)

### Fixed
- `fenceline install` matcher now checks IPv6 ranges (was IPv4 only)
- Removed `--scorecard` no-op flag

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
