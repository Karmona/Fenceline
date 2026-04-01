# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Filesystem diffing in sandbox — detects dropped binaries, executables in unexpected locations, files in sensitive directories. Runs between Stage 1 (network) and Stage 2 (import).
- Python artifact promotion — pip installs now copy newly installed packages from sandbox to host using pre/post package list diff.
- `--format json` flag for `fenceline install` — structured JSON output for CI integration.
- Competitive positioning section in README ("Why Fenceline?").

### Changed
- README restructured for adoption: Quick Start first, wrapper-led, Problem section shortened.
- `wrap` command listed first in CLI help as hero workflow.
- CLI description updated to "Dependency firewall for developer machines".
- GitHub Action renamed from "Supply Chain Check" to "Dependency Check".
- Package metadata aligned to Node-first positioning.

### Fixed
- `docker cp` now checks returncode — failed copy no longer silently reports success.
- `fenceline install` (no args) now shows install-specific help, not top-level help.
- Package name validation before Stage 2 import (prevents injection inside container).
- Filesystem diff `/tmp` logic bug (was always marking files as harmless).
- URL-escape package names in registry lookups.

### Security
- Package names validated against safe character regex before shell interpolation in Stage 2 import tests.
- Registry URLs now escape special characters to prevent request manipulation.

## [0.5.0] - 2026-03-31

### Added
- Stage 2 import monitoring in Docker sandbox
  - After install, runs require()/import inside container
  - Catches attacks that activate on module load (event-stream, chalk/debug, TeamPCP)
- --monitor-time flag for fenceline install (default 60s, configurable)
- Detection scorecard in README (7/11 attacks prevented)

### Changed
- Documentation rewrite: sandbox is now the lead feature
- Homepage restructured around prevention, not just detection
- Landscape updated with "safety without detection" concept
- Playbook defaults to --sandbox for all install commands

### Fixed
- Shell quoting in Docker sandbox (shlex.quote)

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
