# Fenceline Testing

Safe, localhost-only simulations of real supply chain attack patterns, plus documentation of what our tools detect and where the gaps are.

## Safety Guarantees

- **All simulations use localhost only** — no connections leave your machine
- **No real malware** — each test simulates the network pattern of a known attack, not the payload
- **Safe to run on any development machine** — nothing is installed, modified, or persisted

## Attack Simulations

Each simulation recreates the network behavior of a documented supply chain attack:

| Test | Attack Pattern | Real-World Example |
|------|---------------|-------------------|
| `test-outbound-exfil.sh` | Data exfiltration via outbound HTTP | event-stream, Codecov, Axios |
| `test-postinstall.sh` | Malicious postinstall script spawning processes | ua-parser-js, Nx |
| `test-mining-pool.sh` | Cryptocurrency mining pool connection | Ultralytics |
| `test-dns-exfil.sh` | DNS-based data exfiltration | Various |
| `test-child-process.sh` | Child process spawning outbound connections | Nx (node -> curl -> C2) |

### Running Simulations

```bash
cd testing && ./harness.sh
```

## What Our Tools Detect

Here's how `fenceline check` and `fenceline install --sandbox` perform against each attack pattern:

### Detection Matrix

| Attack | Map only (no sandbox) | With sandbox (Stage 1 + Stage 2) | Safety even if missed |
|--------|----------------------|----------------------------------|----------------------|
| event-stream | YES (metadata signals) | YES (Stage 2 catches import payload) | Sandbox isolates damage |
| ua-parser-js | YES (postinstall script) | YES (Stage 1 catches outbound) | Container killed on alert |
| Codecov | Outside scope | Outside scope | Outside scope (CI/CD tool, not a package install) |
| colors.js/faker.js | NO (no network) | NO (no network) | Sandbox limits blast radius to container |
| XZ Utils | NO (passive backdoor) | NO (passive backdoor) | Sandbox limits blast radius to container |
| Ultralytics | YES (non-443 port) | YES (Stage 1 catches mining port) | Container killed on alert |
| Nx/s1ngularity | PARTIAL (legitimate domain) | PARTIAL (legitimate domain) | Sandbox isolates exfiltrated data |
| chalk/debug | NO (runtime only) | YES (Stage 2 catches import payload) | Container killed on alert |
| Axios RAT | YES (unknown IP + port) | YES (Stage 1 catches outbound) | Container killed on alert |
| TeamPCP: LiteLLM | NO (.pth file) | YES (Stage 2 triggers .pth on import) | Container killed on alert |
| TeamPCP: Telnyx | NO (steganographic) | NO (steganographic) | Sandbox limits blast radius to container |

**Note:** Codecov and Polyfill.io are outside Fenceline's scope -- they are not package installs. Codecov was a CI/CD bash script compromise, and Polyfill.io was a client-side CDN domain takeover. You would never run `fenceline install --sandbox` on these.

### Detailed Tool Breakdown

### `fenceline check` (lockfile diff scanner)

Scans lockfile changes and queries npm registry. Catches risks **before install**.

| Signal | What it catches | Real attacks this would flag |
|--------|----------------|------------------------------|
| Package age < 7 days | Newly published malicious versions | Axios RAT (published hours before detection) |
| Maintainer change | Account takeover, handoff attacks | event-stream (new maintainer), chalk/debug (phished account) |
| postinstall/preinstall script | Primary attack execution vector | ua-parser-js, Nx, Axios RAT |
| Missing provenance | Package not built via trusted CI | Axios (missing Sigstore attestation) |
| New dependency added | Unexpected additions to dependency tree | event-stream added flatmap-stream |

**Example output** (tested on real npm project adding axios):
```
[!] HIGH     ( 55) axios  (new) -> 1.14.0
         +30  very_new_version: Published 3d ago (< 7 days)
         +10  maintainer_added: New maintainers detected
         +10  no_provenance: No Sigstore provenance attestation
         + 5  new_package: Newly added dependency
```

### `fenceline install --sandbox` (Docker sandbox + network monitor)

Runs package installs inside a Docker container and monitors network from outside. Two-stage detection:

- **Stage 1 (install):** Monitors outbound connections during `npm install` / `pip install` inside the container. Catches exfiltration, C2 beaconing, mining connections.
- **Stage 2 (import):** After install completes, runs `require()` / `import` inside the container to trigger module-load payloads. Catches attacks that activate on first import, not during install.

If anything suspicious is detected, the container is killed — nothing touches your host machine.

**Requires Docker.** Without Docker, falls back to host-based monitoring with a clear warning.

| Signal | Stage | What it catches | Real attacks this would flag |
|--------|-------|----------------|------------------------------|
| Connection to unknown IP | 1 | IP outside known CDN ranges | Codecov (178.62.86.114), Axios (142.11.206.73) |
| Non-443 port | 1 | Unusual port during install | Ultralytics (port 8080), Axios (port 8000), ua-parser-js (mining ports) |
| Wrong CDN for tool | 1 | npm connecting via non-Cloudflare IP | DNS poisoning, CDN hijack |
| Network on import | 2 | Module phones home when loaded | event-stream, chalk/debug, TeamPCP LiteLLM |

**Example output** (tested with `fenceline install npm install is-even`):
```
[fenceline] 1 network alert(s) during install:
  ? [WARNING] node -> 2606:4700::6810:722:443 — Unknown IP, not in known CDN ranges
```

## What We Don't Catch Yet (Known Gaps)

These are the attack patterns our tools cannot currently detect. Each gap is a target for future development.

### Gaps in `fenceline check`

| Gap | Why | Real attack example | What's needed |
|-----|-----|---------------------|---------------|
| Runtime malicious code (no install scripts) | We only check metadata, not package source code | chalk/debug (injected into source, no postinstall) | Source code analysis (Phase 4) |
| Typosquatting | We don't compare package names against known packages | Various npm typosquats | Package name similarity scoring |
| Slopsquatting | We don't check if a package name was AI-hallucinated | Emerging 2025+ | Registry existence + popularity check |

### Gaps in `fenceline install`

| Gap | Why | Real attack example | What's needed |
|-----|-----|---------------------|---------------|
| ~~IPv6 CDN ranges~~ | ~~Our map only has IPv4 CIDR ranges~~ | ~~Fixed~~ | ~~Done — IPv6 ranges added for all CDNs~~ |
| Domain reuse for exfiltration | Nx used `api.github.com` (a legitimate domain) for data theft | Nx/s1ngularity | HTTP method/path behavioral analysis (Phase 3) |
| No-network attacks | Logic bombs, sabotage with no outbound connections | colors.js/faker.js, XZ Utils | Code analysis, not network monitoring |
| Very short-lived connections | Polling every 500ms can miss sub-500ms connections | Theoretical | eBPF or dtrace for kernel-level capture |
| DNS exfiltration | Data encoded in DNS queries (long subdomains) | Various | DNS query monitoring |

### What we would NOT catch

Being honest about what's outside our detection capability is as important as showing what we catch.

| Attack | Why we miss it | What's needed |
|--------|---------------|---------------|
| **TeamPCP: Trivy/Checkmarx** (GitHub Actions tag tampering) | We don't monitor CI/CD pipelines or GitHub Actions | Action SHA pinning verification tool |
| **TeamPCP: Telnyx** (payload in `.WAV` file) | Steganographic payloads are invisible to network monitoring and metadata checks | Source code / binary analysis |
| **colors.js/faker.js** (logic bomb, no network) | No outbound connections to detect | Code analysis, not network monitoring |
| **XZ Utils** (passive SSH backdoor) | No outbound connections — waits for inbound trigger | Build system / binary analysis |
| **Nx/s1ngularity** (exfil via api.github.com) | Uses a legitimate domain we'd allowlist | HTTP method/path behavioral analysis |

### What the sandbox catches that we previously missed

Stage 2 import monitoring now detects attacks that activate on module load rather than during install:

| Attack | How it's caught |
|--------|----------------|
| **event-stream** | Malicious payload triggers on `require('event-stream')` — Stage 2 catches the outbound connection |
| **chalk/debug** (phished maintainer) | Injected code runs on import, not via install scripts — Stage 2 catches the network call |
| **TeamPCP: LiteLLM** (`.pth` file persistence) | `.pth` files execute on Python import — Stage 2 triggers them inside the container |

### Partially addressed

| Gap | Current status | What's needed to close it |
|-----|---------------|---------------------------|
| Non-npm ecosystems | `fenceline install` monitors any command; `fenceline check` parses npm lockfiles only | Lockfile parsers for pip, cargo, yarn, pnpm |
| CI/CD integration | [GitHub Action](../action/action.yml) is defined but not yet tested in production | End-to-end testing on real PRs |
| Supply chain attacks via GitHub Actions | Not addressed | Action pinning verification tool |

## Testing the Tools Against Simulations

You can manually test our tools against the attack simulations:

**Test `fenceline install` catches outbound exfiltration:**
```bash
# Terminal 1: start mock C2 server
python3 -m http.server 9999 &

# Terminal 2: run fenceline install with a command that phones home
fenceline install node -e "fetch('http://localhost:9999/exfil')"

# Expected: alert about non-443 port connection to localhost
```

**Test `fenceline check` catches risky packages:**
```bash
# In any npm project:
npm install some-new-package
fenceline check --base-ref HEAD

# Expected: risk report showing package age, maintainers, scripts
```

## Contributing New Tests

1. Name the file `test-<pattern>.sh`
2. Document which real attack it simulates
3. Use only localhost for all network activity
4. Add a row to the detection matrix above showing what tools should catch it
5. Note any gaps in the "What We Don't Catch" section

## License

Apache 2.0 — see [LICENSE](../LICENSE).
