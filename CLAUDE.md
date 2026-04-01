# Fenceline

Dependency firewall for developer machines. Sandboxes package installs in Docker, monitors network connections, DNS queries, HTTP behavior, filesystem changes, and process activity, then promotes artifacts only if clean.

## Git commit rules

- NEVER add Co-Authored-By lines to commits
- NEVER add your name (Claude) as author or co-author
- All commits should appear as the repo owner's work only

## Development

```bash
pip install -e ".[dev]"
python3 -m pytest tests/ -v -m "not integration"   # 289 unit tests, ~17s
python3 -m pytest tests/integration/ -v             # Docker integration tests (requires Docker)
fenceline --version                                  # verify CLI works
```

## When installing packages

If `fenceline wrap` is enabled, all npm/yarn/pnpm/pip installs route through the Docker sandbox automatically.

**If an install is BLOCKED:**
- The package triggered one or more detection layers (network, filesystem, DNS, HTTP, process)
- Do NOT bypass the block by running npm/pip directly or disabling the wrapper
- Check the alert details — they explain exactly what was suspicious
- If it's a false positive, the deep map in `map/` may need updating (`fenceline map --check`)

**If Docker is not running:**
- Installs fail with "BLOCKED: Docker is not running"
- Start Docker, or temporarily `fenceline wrap --disable`

## Detection layers

The sandbox monitors 10 layers simultaneously:
1. **Network (iptables LOG)** — every outbound TCP connection captured, zero race condition
2. **Port enforcement** — anything not port 443 = CRITICAL
3. **CDN fingerprinting** — IP must be in expected CDN CIDR range for the tool
4. **Expected-process heuristic** — curl/wget/bash during npm install = WARNING
5. **Filesystem diffing** — dropped binaries, files in /etc, /root, /home
6. **Import monitoring** — Stage 2 runs require()/import() to catch lazy payloads
7. **DNS monitoring** — captures outbound UDP port 53, detects tunneling
8. **HTTP behavior** — CONNECT proxy logs target domains, POST/PUT to unexpected domains flagged
9. **Metadata scoring** — package age, maintainer changes, missing provenance
10. **Capability escalation** — postinstall/preinstall added between versions

## Project structure

- `src/fenceline/` -- main package
- `src/fenceline/install/` -- sandbox, network monitoring, filesystem diffing, DNS, HTTP proxy
- `src/fenceline/check/` -- lockfile analysis, registry lookups (cached), risk scoring, provenance
- `src/fenceline/output/` -- console (colored) and GitHub markdown formatters
- `src/fenceline/deepmap/` -- network fingerprint models and YAML loader
- `map/` -- network baselines for 8 package managers (YAML, includes expected_processes)
- `tests/` -- 289 unit tests (mock-based, no Docker)
- `tests/integration/` -- Docker integration tests (real containers)
- `examples/safe-project/` -- minimal test project for local verification
- `exploits/` -- 11 real-world attack case studies with IOCs

## Key commands

```bash
fenceline wrap --enable              # activate firewall for npm/yarn/pnpm/pip
fenceline install --sandbox <cmd>    # one-off sandboxed install
fenceline install --sandbox --format json <cmd>  # JSON output for CI
fenceline check                      # scan lockfile (cached registry lookups)
fenceline map --check                # validate deep map against live DNS
fenceline map --update               # refresh DNS snapshots
fenceline audit-actions              # scan GitHub Actions for unpinned tags
fenceline init                       # install git hooks
```

## Testing

```bash
python3 -m pytest tests/ -v -m "not integration"   # unit tests
python3 -m pytest tests/integration/ -v             # Docker tests
cd examples/safe-project && ./test.sh               # local end-to-end
```

## Map data

The `map/` directory contains network baselines. If a legitimate package triggers a false positive:
1. Check if the IP is in the expected CDN range (`map/cdns/*.yaml`)
2. Check if the domain is in the tool's primary_domains (`map/tools/*.yaml`)
3. Check if the process is in expected_processes (`map/tools/*.yaml`)
4. Run `fenceline map --check` to validate against live DNS
5. Run `fenceline map --update` to refresh if stale
