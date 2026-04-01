# Fenceline Example Project

A minimal Node.js project for testing Fenceline locally with safe, well-known dependencies.

## What it tests

1. **Sandboxed npm install** — installs `is-odd` and `is-even` through Docker sandbox
2. **JSON output** — verifies `--format json` produces parseable structured output
3. **Lockfile check** — scans `package-lock.json` for risk signals
4. **Map freshness** — validates deep map data against live DNS
5. **Package verification** — confirms installed packages actually work

## Prerequisites

- Docker installed and running
- Fenceline installed (`pip install -e ../../`)
- Node.js (for the final verification step)

## Usage

```bash
./test.sh
```

## What you should see

A clean install looks like:

```
[fenceline] Sandbox: pulling node:alpine...
[fenceline] Sandbox: container abc123def456 started
[fenceline] Sandbox: running npm install is-odd is-even inside container...
[fenceline] Sandbox: monitoring network for ~60s...
[fenceline] Sandbox: install clean. Copying artifacts to host...
[fenceline] Sandbox: done. Install verified and applied.
```

A blocked install would show:

```
[fenceline] Sandbox: 1 suspicious connection(s) in Stage 1 (install)!
  !! [CRITICAL] node -> 93.184.216.34:8080 — Non-standard port 8080
[fenceline] Sandbox: BLOCKED — not installing on your machine.
[fenceline] ACTION: Do not retry or bypass. Investigate the package before use.
```
