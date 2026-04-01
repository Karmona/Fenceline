# Fenceline v0.6.0

Dependency firewall for developer machines. Sandboxes package installs in Docker, monitors 10 detection layers (network, DNS, HTTP, filesystem, process, import, port, CDN, metadata, capability), and only promotes artifacts to the host if everything is clean.

## Git commit rules

- NEVER add Co-Authored-By lines to commits
- NEVER add your name (Claude) as author or co-author
- All commits should appear as the repo owner's work only

## Architecture overview

```
CLI (cli.py) → wrap.py (transparent interception)
             → install/wrapper.py → install/sandbox.py (Docker orchestration)
                                   → install/monitor.py (network polling + iptables LOG)
                                   → install/fsdiff.py (filesystem snapshots)
                                   → install/dns_monitor.py (DNS query capture)
                                   → install/http_logger.py (HTTP CONNECT proxy)
                                   → install/matcher.py (CDN + port + process checks)
             → check/scanner.py → check/registry.py (npm/PyPI, cached)
                                → check/scoring.py (risk model, 10 signals)
                                → check/capabilities.py (install scripts + diff)
                                → check/provenance.py (Sigstore attestation)
             → output/console.py (ANSI colors)
             → output/github.py (markdown tables)
             → map_check.py (DNS freshness validation)
             → deepmap/loader.py + models.py (YAML data models)
```

## Key technical details

- **Container runs with `--cap-add=NET_ADMIN`** for iptables LOG rules
- **iptables captures EVERY outbound TCP SYN and DNS query** — eliminates polling race condition
- **HTTP proxy runs on port 8899 inside all containers** — Node.js proxy for npm/yarn/pnpm, Python proxy for pip. Captures CONNECT targets + HTTP methods
- **Filesystem diff uses `docker exec find -printf`** — pre/post install comparison
- **Registry lookups cached in `~/.cache/fenceline/`** — 1-hour TTL, overridable via `FENCELINE_CACHE_DIR` env var
- **Package names validated** against `^[@a-zA-Z0-9._/-]+$` before Stage 2 import
- **Container paths validated** before `docker cp` — blocks traversal and /proc/sys/dev
- **Expected processes per tool** defined in `map/tools/*.yaml` (e.g., npm: node, npm, npx)

## Detection layers (10 total)

1. **Network (iptables LOG)** — every outbound TCP SYN captured, zero race condition
2. **Port enforcement** — anything not port 443 = CRITICAL alert
3. **CDN fingerprinting** — IP must be in expected CDN CIDR range for the tool
4. **Expected-process heuristic** — curl/wget/bash during npm install = WARNING
5. **Filesystem diffing** — dropped binaries, files in /etc, /root, /home, suspicious extensions
6. **Import monitoring** — Stage 2 runs require()/import() inside container
7. **DNS monitoring** — captures outbound UDP port 53, flags unusual resolver activity
8. **HTTP behavior** — CONNECT proxy logs target domains, POST/PUT to unexpected domains flagged (Node.js proxy for npm/yarn/pnpm, Python proxy for pip)
9. **Metadata scoring** — package age, maintainer changes, missing provenance, new package signal
10. **Capability escalation** — detects postinstall/preinstall added between versions (+20 pts each)

## Risk scoring model

Points-based accumulation:
- Very new version (<7 days): +30
- New version (<30 days): +15
- Maintainer removed: +25
- Maintainer added: +10
- Postinstall script: +20
- Preinstall script: +25
- Capability escalation (script added between versions): +20 each
- No Sigstore provenance: +10
- New package: +5

Levels: LOW (0-15), MEDIUM (16-35), HIGH (36-60), CRITICAL (61+)

## Development

```bash
pip install -e ".[dev]"
python3 -m pytest tests/ -v -m "not integration"   # 341 unit tests, ~17s
python3 -m pytest tests/integration/ -v             # Docker integration tests
cd examples/safe-project && ./test.sh               # local end-to-end
fenceline --version                                  # should show 0.6.0
```

## When installing packages

If `fenceline wrap` is enabled, all npm/yarn/pnpm/pip installs route through the Docker sandbox.

**If an install is BLOCKED:**
- The package triggered one or more detection layers
- Do NOT bypass by running npm/pip directly or disabling the wrapper
- Check the alert details — they explain exactly what was suspicious
- If false positive: `fenceline map --check` then `fenceline map --update`

**If Docker is not running:**
- Installs fail with "BLOCKED: Docker is not running"
- Start Docker, or temporarily `fenceline wrap --disable`

## Project structure

```
src/fenceline/
├── cli.py                    # Entry point (7 subcommands)
├── wrap.py                   # Shell wrapper for npm/yarn/pnpm/pip
├── log.py                    # Structured logging (stderr, respects --verbose)
├── map_check.py              # fenceline map --check/--update
├── install/
│   ├── wrapper.py            # Orchestrates sandboxed vs host installs
│   ├── sandbox.py            # Docker container lifecycle (~750 lines, largest file)
│   ├── monitor.py            # Network polling (lsof/ss, platform-aware)
│   ├── matcher.py            # CDN + port + process validation
│   ├── fsdiff.py             # Filesystem snapshot and diff
│   ├── dns_monitor.py        # DNS query capture via iptables LOG
│   └── http_logger.py        # HTTP CONNECT proxy + behavior analysis
├── check/
│   ├── scanner.py            # Check pipeline orchestrator
│   ├── lockfile.py           # npm/pip lockfile parsing
│   ├── registry.py           # npm/PyPI API (cached)
│   ├── scoring.py            # Risk model (10 signals)
│   ├── capabilities.py       # Install script detection + version diff
│   ├── provenance.py         # Sigstore attestation
│   └── cache.py              # File-based registry cache (1h TTL)
├── output/
│   ├── console.py            # Colored terminal output (NO_COLOR support)
│   └── github.py             # Markdown tables for PR comments
├── deepmap/
│   ├── models.py             # AllowedDomain, ToolMap, CDNMap, DeepMap
│   └── loader.py             # YAML parser
├── actions/audit.py          # GitHub Actions tag pinning audit
└── init/hooks.py             # Git hook installer

map/                          # Network baselines (8 tools, 4 CDNs)
tests/                        # 341 unit tests (19 files)
tests/integration/            # Docker integration tests (4 tests)
examples/safe-project/        # Local verification project
exploits/                     # 11 attack case studies (2018-2026)
docs/                         # Landscape, playbook, newsroom, guide
```

## Key commands

```bash
fenceline wrap --enable              # activate firewall for npm/yarn/pnpm/pip
fenceline wrap --status              # see what's wrapped
fenceline install --sandbox <cmd>    # one-off sandboxed install
fenceline install --sandbox --format json <cmd>  # JSON output for CI
fenceline check                      # scan lockfile (cached registry lookups)
fenceline check --format json        # JSON output
fenceline map --check                # validate deep map against live DNS
fenceline map --update               # refresh DNS snapshots
fenceline audit-actions              # scan GitHub Actions for unpinned tags
fenceline init                       # install git hooks
```

## Testing

```bash
python3 -m pytest tests/ -v -m "not integration"   # unit tests (no Docker needed)
python3 -m pytest tests/integration/ -v             # Docker tests (needs Docker)
cd examples/safe-project && ./test.sh               # full local end-to-end
ruff check src/ tests/                               # linting (line-length 100)
```

## Known limitations

- Browser-side attacks (chalk crypto hijack) — outside scope
- Logic bombs with no network/filesystem signal — contained but not detected
- 2-year slow-burn attacks (XZ utils) — no metadata anomaly until activation
- CI/CD pipeline compromise — happens in GitHub, not on dev machines
- HTTPS payload inspection requires MITM (not implemented, only CONNECT target logged)
- PyPI provenance checks PEP 740 attestations and PGP signatures (less mature than npm's Sigstore)
- Pip artifact copy promotes package dirs + .dist-info + console scripts (bin/)

## What's next (future work)

- CI enforcement mode (fail PR checks based on sandbox results)
- eBPF tracing for deeper syscall visibility
- HTTPS payload inspection via container CA injection
- Go/Rust/Ruby artifact promotion
