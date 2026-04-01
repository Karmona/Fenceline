# Changelog

All notable changes to this project will be documented in this file.

## [0.6.0] - 2026-04-01

### Added
- **iptables LOG monitoring** — captures every outbound TCP SYN and DNS query inside the container with zero race condition. Eliminates the 500ms polling gap.
- **Expected-process heuristic** — detects curl, wget, bash etc. making network connections during installs. Maps expected processes per tool via deep map YAML.
- **DNS query monitoring** — captures outbound UDP port 53 via iptables LOG. Detects DNS tunneling and unusual resolver activity.
- **HTTP behavior analysis** — logging proxy captures CONNECT targets and HTTP methods. Node.js proxy for npm/yarn/pnpm containers, Python proxy for pip containers. Detects POST/PUT to unexpected domains.
- **Node.js HTTP proxy** — standalone proxy using only built-in `http`/`net` modules. Runs inside Node containers on port 8899, provides L7 visibility for npm/yarn/pnpm installs.
- **Loopback connection filtering** — intra-container connections (127.0.0.1, ::1) are now ignored by the matcher. Prevents false positives from the HTTP proxy itself.
- **Registry caching** — 1-hour file cache for npm/PyPI lookups in `~/.cache/fenceline/`. Makes repeated `fenceline check` runs fast.
- **Capability diffing** — detects when postinstall/preinstall scripts are added between package versions. Common attack pattern.
- **Output formatters** — colored console output (ANSI, respects NO_COLOR) and GitHub markdown tables with emoji status indicators.
- **`--fail-on` flag for `fenceline check`** — configurable CI threshold (low/medium/high/critical). Default: high. Also implemented in GitHub Action.
- **PyPI provenance checking** — queries PyPI JSON API for PEP 740 Sigstore attestations. (Note: PyPI's `has_sig` field is deprecated and always false — we rely on PEP 740 only.)
- **PyPI capability analysis** — detects sdist-only packages (setup.py execution risk, +15 pts) and native extension classifiers (+10 pts). Signals scored in risk model.
- **Pip console script promotion** — newly installed console scripts (e.g., `black`, `flask`) are copied from container bin/ to host. Errors logged, not silently swallowed.
- **Pip import name resolution** — Stage 2 import test resolves distribution→import names via `top_level.txt`, well-known renames table (Pillow→PIL, PyYAML→yaml, etc.), and hyphen→underscore fallback.
- **pip/pip3 wrapping** — `fenceline wrap --enable` now wraps pip alongside npm/yarn/pnpm.
- **`fenceline map --check/--update`** — validate and refresh deep map data against live DNS.
- **`.pth` file detection** — filesystem diffing flags unknown `.pth` files as CRITICAL. These execute code on every Python startup (used in TeamPCP/LiteLLM attack).
- **`--dry-run` flag for `fenceline install`** — runs all 10 detection layers but skips artifact copy to host. Used for safe validation and testing.
- Filesystem diffing in sandbox — detects dropped binaries, executables in unexpected locations, files in sensitive directories.
- Python artifact promotion — pip installs copy newly installed packages from sandbox to host.
- `--format json` flag for `fenceline install` — structured JSON output for CI integration.
- Structured logging via `fenceline.log` module — all progress messages go to stderr, user-facing output to stdout.
- Docker integration tests (real end-to-end with containers, 4 tests).
- `__main__.py` — enables `python -m fenceline` usage.
- CLAUDE.md with instructions for AI coding tools.
- Example project in `examples/safe-project/` for local testing.
- Package validation script (`tools/validate-packages.sh`) — tests 10 npm + 10 pip packages through sandbox with `--dry-run`.
- 352 tests across 21 test files (up from 83 in v0.5.0).

### Changed
- README restructured for adoption: Quick Start first, wrapper-led, Problem section shortened.
- `wrap` command listed first in CLI help as hero workflow.
- CLI description updated to "Dependency firewall for developer machines".
- GitHub Action renamed from "Supply Chain Check" to "Dependency Check".
- Package metadata aligned to Node-first positioning.

### Fixed
- **Container lifecycle fix** — post-install checks (Stage 2, filesystem diff, DNS, HTTP, pip artifacts) now run while the container is still alive. Previously `docker wait` blocked until the container stopped, causing all `docker exec`-based checks to fail silently.
- **Install speed** — installs complete in ~10s instead of ~65s (no longer waits for unnecessary 60s sleep period).
- **GitHub Action non-PR fallback** — `action.yml` now falls back to `github.event.before` (push) and `HEAD~1` (workflow_dispatch) when `pull_request.base.sha` is empty.
- **Pip Stage 2 import names** — distribution names with hyphens (google-auth, python-dateutil) now correctly resolve to import names (google.auth, dateutil) via metadata lookup and known renames table.
- **Pip console script copy error handling** — failures are now logged individually instead of silently swallowed; return value checked by caller.
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
