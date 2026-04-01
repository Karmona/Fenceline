# Fenceline v0.6.0 Release Notes

**A dependency firewall for developer machines.**

This is a major release that makes Fenceline's Docker sandbox production-ready with 10 detection layers, full pip support, CI integration, and 352 tests (up from 83 in v0.5.0).

## Highlights

### Zero-miss network capture
iptables LOG rules inside the container capture **every** outbound TCP SYN and DNS query. The old 500ms polling gap that could miss fast connections is eliminated. Netstat polling remains as a real-time complement.

### Full pip support
pip installs are now first-class citizens:
- **Import name resolution** -- Stage 2 correctly resolves distribution names to import names (Pillow->PIL, PyYAML->yaml, etc.) via metadata lookup, well-known renames table, and hyphen->underscore fallback
- **Console script promotion** -- newly installed scripts (e.g., `black`, `flask`) are copied from container to host with proper error handling
- **PyPI risk scoring** -- provenance (PEP 740 attestations), capability analysis (sdist-only +15 pts, native extensions +10 pts), and all standard signals

### 10 detection layers running simultaneously
Every sandboxed install now runs all 10 layers:

1. **Network** -- iptables LOG captures every outbound TCP SYN
2. **Port enforcement** -- non-443 connections = CRITICAL
3. **CDN fingerprinting** -- IP must match expected CDN CIDR ranges
4. **Expected-process heuristic** -- curl/wget during npm install = WARNING
5. **Filesystem diffing** -- dropped binaries, `.pth` files (TeamPCP attack vector), files in sensitive directories
6. **Import monitoring** -- Stage 2 runs require()/import() inside container
7. **DNS monitoring** -- UDP port 53 capture via iptables LOG
8. **HTTP behavior** -- CONNECT proxy logs target domains; POST/PUT to unexpected domains flagged. Node.js proxy for npm/yarn/pnpm, Python proxy for pip.
9. **Metadata scoring** -- package age, maintainer changes, missing provenance
10. **Capability escalation** -- detects postinstall/preinstall added between versions

### `.pth` file detection
Filesystem diffing now flags unknown `.pth` files as CRITICAL. These files execute arbitrary code on every Python startup -- the exact technique used in the TeamPCP/LiteLLM supply chain attack (March 2026). Known legitimate `.pth` files (easy-install, setuptools) are allowlisted.

### CI enforcement mode
`fenceline check --fail-on medium` lets CI pipelines fail on configurable risk thresholds. Also wired into the GitHub Action via the `fail-on` input.

### `--dry-run` mode
`fenceline install --sandbox --dry-run` runs all 10 detection layers but skips artifact copy to host. Safe for validation and testing without changing anything on your machine.

## Breaking Changes

None. All existing commands work as before.

## Critical Bug Fix

**Container lifecycle** -- In previous versions, `docker wait` blocked until the container exited, causing all `docker exec`-based post-install checks (Stage 2, filesystem diff, DNS, HTTP, pip artifact copy) to **silently fail**. The container now starts with `sleep 86400`, installs run via `docker exec`, and the container stays alive for all checks. This fix makes half the detection layers actually functional.

## New Commands & Flags

| Command | Description |
|---------|-------------|
| `fenceline install --sandbox --dry-run <cmd>` | Run detection only, skip artifact copy |
| `fenceline check --fail-on <level>` | Set CI failure threshold (low/medium/high/critical) |
| `fenceline wrap --enable` | Now wraps pip/pip3 alongside npm/yarn/pnpm |

## Validation

- **352 tests** across 21 test files (348 unit + 4 Docker integration)
- **20/20 real-world packages validated** through Docker sandbox (10 npm + 10 pip, pinned versions, `--dry-run`)
- **Zero false positives** across all validated packages
- **All integration tests pass** -- real Docker end-to-end with clean install, JSON output, and blocked malicious package verification

## Against Real Attacks

| Attack | Year | Assessment |
|--------|------|------------|
| Axios RAT | 2026 | **Would block** -- C2 on port 8000 |
| TeamPCP: LiteLLM | 2026 | **Would block** -- `.pth` file detection + Stage 2 import monitoring |
| chalk/debug | 2025 | **Would block** -- Stage 2 catches import-time C2 |
| Nx/s1ngularity | 2025 | **Would block** -- HTTP proxy detects POST to unexpected domain |
| Ultralytics | 2024 | **Would block** -- mining pool on port 8080 |
| ua-parser-js | 2021 | **Would block** -- postinstall phones home + unexpected process |
| event-stream | 2018 | **Would block** -- Stage 2 catches import payload |

## What's Next (v0.7.0)

- CI enforcement mode (fail PR checks based on sandbox results)
- Deeper HTTP payload analysis
- eBPF tracing for syscall visibility

## Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for the complete list of changes.
