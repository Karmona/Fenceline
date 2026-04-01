# Fenceline

Dependency firewall for developer machines. Sandboxes package installs in Docker, monitors network + filesystem behavior, promotes artifacts only if clean.

## Development

```bash
pip install -e ".[dev]"
python3 -m pytest tests/ -v       # 183+ tests, ~18s, no Docker needed
fenceline --version                # verify CLI works
```

## When installing packages

If `fenceline wrap` is enabled, all npm/yarn/pnpm installs route through the Docker sandbox automatically.

**If an install is BLOCKED:**
- The package made suspicious network connections or filesystem changes
- Do NOT bypass the block by running npm directly or disabling the wrapper
- Check the alert details (non-standard ports, unknown IPs, dropped binaries)
- If it's a false positive, the deep map in `map/` may need updating

**If Docker is not running:**
- Installs fail with "BLOCKED: Docker is not running"
- Start Docker, or temporarily `fenceline wrap --disable`

## Project structure

- `src/fenceline/` -- main package
- `src/fenceline/install/` -- sandbox, network monitoring, filesystem diffing, artifact copy
- `src/fenceline/check/` -- lockfile analysis, registry lookups, risk scoring, provenance
- `src/fenceline/deepmap/` -- network fingerprint models and YAML loader
- `map/` -- network baselines for 8 package managers (YAML data files)
- `tests/` -- all mock-based, no Docker required
- `exploits/` -- 11 real-world attack case studies with IOCs

## Key commands

```bash
fenceline wrap --enable            # activate the firewall for npm/yarn/pnpm
fenceline install --sandbox <cmd>  # one-off sandboxed install
fenceline check                    # scan lockfile for risky changes
fenceline audit-actions            # scan GitHub Actions for unpinned tags
fenceline init                     # install git hooks
```

## Testing

Run `python3 -m pytest tests/ -v` after any code changes. All tests are mock-based.

Linting: `ruff check src/ tests/` (line-length 100, target Python 3.9).

## Map data

The `map/` directory contains network baselines. If a legitimate package triggers a false positive:
1. Check if the IP is in the expected CDN range (`map/cdns/*.yaml`)
2. Check if the domain is in the tool's primary_domains (`map/tools/*.yaml`)
3. TLS cert fingerprints may need refreshing (checked weekly by CI)
