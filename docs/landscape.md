# Supply Chain Security Tool Landscape

A comprehensive directory of tools, services, and built-in features for software supply chain security. Every tool listed here contributes something valuable to the ecosystem. This document aims to honestly assess what each covers and where gaps remain.

Last updated: March 2026

---

## Open Source Tools

| Tool | Type | License | What It Catches | What It Misses | Link |
|------|------|---------|----------------|----------------|------|
| OpenSSF Scorecard | Project hygiene scoring | Apache 2.0 | Poor security practices across 16+ checks | Hygiene does not equal security — a malicious project can score perfectly | [github.com/ossf/scorecard](https://github.com/ossf/scorecard) |
| Datadog GuardDog | Static rules (Semgrep/YARA) | Apache 2.0 | Known malicious patterns across 6 ecosystems | Novel obfuscation, multi-stage payloads | [github.com/DataDog/guarddog](https://github.com/DataDog/guarddog) |
| Aikido SafeChain | Install proxy + blocklist | Open source | Known malicious packages + 48hr age gate | Compromised legitimate packages | [github.com/AikidoSec/safe-chain](https://github.com/AikidoSec/safe-chain) |
| Heisenberg | Health scoring + incident response | MIT | Metadata anomalies, package health | No code analysis at all | [github.com/AppOmni-Labs/heisenberg-ssc-health-check](https://github.com/AppOmni-Labs/heisenberg-ssc-health-check) |
| SafeDep Vet | Policy engine + detection | Apache 2.0 | Policy violations via CEL, 7+ ecosystems | Advanced detection requires paid tier | [github.com/safedep/vet](https://github.com/safedep/vet) |
| Google Capslock | Capability analysis | BSD-3-Clause | Maps Go packages to system capabilities | Go only — nothing for npm/PyPI/Rust | [github.com/google/capslock](https://github.com/google/capslock) |
| StepSecurity Harden-Runner | CI/CD eBPF monitoring | Apache 2.0 | Runtime anomalies in GitHub Actions | GitHub Actions only, no local dev | [github.com/step-security/harden-runner](https://github.com/step-security/harden-runner) |
| OpenSSF Package Analysis | Dynamic sandbox (gVisor) | Open source | Behavioral analysis at registry scale | Not for individual dev use | [github.com/ossf/package-analysis](https://github.com/ossf/package-analysis) |
| GUAC | Supply chain graph database | Apache 2.0 | Aggregates SBOMs, SLSA, Scorecard, OSV | No detection — data aggregation only | [github.com/guacsec/guac](https://github.com/guacsec/guac) |
| OWASP dep-scan | Vulnerability + risk audit | MIT | Known CVEs + reachability across 12+ ecosystems | CVE-focused, not malware-focused | [github.com/owasp-dep-scan/dep-scan](https://github.com/owasp-dep-scan/dep-scan) |
| Phylum Birdcage | Sandbox library | GPL-3.0 | Process isolation (Linux namespaces, macOS Seatbelt) | Stale since Dec 2024 | [github.com/phylum-dev/birdcage](https://github.com/phylum-dev/birdcage) |

### Tool Details

**OpenSSF Scorecard** evaluates open source projects against 16+ automated checks including branch protection, dependency pinning, signed releases, CI tests, and vulnerability disclosure. It is widely adopted and integrated into OpenSSF's broader supply chain security efforts. However, a high score indicates good hygiene practices, not the absence of malicious intent — an attacker who follows all the best practices can still score a 10/10.

**Datadog GuardDog** uses Semgrep rules and YARA patterns to scan packages for known malicious behaviors like data exfiltration, code execution in install scripts, and obfuscated payloads. It covers npm, PyPI, Go, Ruby, crates.io, and Java. The rule-based approach means it catches known patterns reliably but cannot detect novel techniques, heavily obfuscated code, or multi-stage attacks where no single stage triggers a rule.

**Aikido SafeChain** acts as a proxy between your package manager and the registry, blocking known malicious packages and enforcing a 48-hour minimum age gate on new packages. This is a practical defense against fast-moving account takeover attacks. It cannot protect against compromised legitimate packages that pass through the age gate or slow-burn attacks where malicious code is introduced gradually.

**Heisenberg** (by AppOmni Labs) provides health scoring for packages based on metadata signals — publication frequency, maintainer count, age, download trends, and known incident history. It includes an incident response component for identifying affected packages when a compromise is disclosed. It performs no code analysis, so it cannot detect malicious behavior directly.

**SafeDep Vet** is a policy engine that lets you define rules (using CEL expressions) for which packages are acceptable in your projects. It supports 7+ ecosystems and can enforce policies like "no packages with fewer than 100 downloads" or "no packages with a single maintainer." Advanced malware detection capabilities require the paid tier.

**Google Capslock** performs static capability analysis on Go packages, mapping them to the system capabilities they use (network access, filesystem operations, process execution, etc.). This is genuinely useful for understanding what a Go dependency can do. The limitation is that it only works for Go — the npm, PyPI, and Rust ecosystems have no equivalent tool.

**StepSecurity Harden-Runner** uses eBPF to monitor GitHub Actions workflows at runtime, detecting anomalous network connections, file access, and process execution. It can catch CI/CD compromise attacks where build steps make unexpected outbound connections. It only works within GitHub Actions and provides no protection for local development or other CI platforms.

**OpenSSF Package Analysis** runs packages in a gVisor sandbox at registry scale, observing their runtime behavior during installation and execution. It catches behavioral anomalies that static analysis misses. However, it is designed as registry-scale infrastructure, not as a tool individual developers can run on their machines before installing a package.

**GUAC** (Graph for Understanding Artifact Composition) aggregates supply chain metadata from multiple sources — SBOMs, SLSA attestations, Scorecard results, OSV vulnerability data — into a queryable graph database. It is a powerful data integration layer but performs no detection itself. It tells you what you know about your supply chain; it does not tell you if something is malicious.

**OWASP dep-scan** scans project dependencies for known vulnerabilities across 12+ ecosystems, with reachability analysis to determine whether vulnerable code paths are actually called. It is thorough for CVE coverage. Its focus is on known vulnerabilities, not on detecting malicious packages that have no CVE.

**Phylum Birdcage** provides a Rust library for process sandboxing using Linux namespaces and macOS Seatbelt. It could be used to isolate package installation and limit what install scripts can access. Development appears to have stalled since December 2024.

---

## Commercial / SaaS Tools

| Tool | What It Does | Free Tier? |
|------|-------------|-----------|
| Socket.dev | 70+ behavioral signals, deep package inspection | Yes (limited) |
| Snyk | Vulnerability scanning + SBOM + remediation PRs | Yes (limited) |
| Endor Labs | Full call-graph reachability analysis | No |
| Chainguard | Distroless images built from source, zero CVEs at publish | No |

**Socket.dev** analyzes packages using 70+ behavioral signals including network access, filesystem operations, obfuscated code detection, install script analysis, and maintainer reputation. It is the most comprehensive package-level analysis tool available. The free tier covers limited scans; full integration with CI/CD and real-time monitoring requires a paid plan.

**Snyk** provides vulnerability scanning across multiple ecosystems with automated remediation pull requests. It generates SBOMs, monitors for new vulnerabilities in deployed dependencies, and integrates with most CI/CD platforms. The free tier covers basic scanning for individuals and small teams; advanced features like license compliance and priority scoring require paid tiers.

**Endor Labs** performs full call-graph reachability analysis, determining not just whether a dependency has a vulnerability, but whether your code actually reaches the vulnerable function. This dramatically reduces false positives. It also provides function-level SBOM and dependency risk scoring. No free tier is available.

**Chainguard** produces minimal container base images built from source with zero known CVEs at publish time. Rather than patching vulnerabilities after the fact, their images start clean. They maintain hardened variants of popular base images (Python, Node, Go, etc.). No free tier for production use.

---

## Built-in Package Manager Features

These require no additional tools — they are features of the package managers and registries you already use.

| Feature | Tool | What It Does |
|---------|------|-------------|
| min-release-age | npm v11.10+ | Blocks packages younger than N days, preventing fast-moving account takeover attacks from reaching your machine |
| minimumReleaseAge | pnpm v10.16+ | Same age-gating capability for pnpm users |
| Provenance attestations | npm + Sigstore | Cryptographic proof linking a published package to a specific commit and build in a specific repository |
| Trusted publishing | npm, PyPI, crates.io, RubyGems | OIDC-based publishing that eliminates long-lived API tokens, reducing account takeover risk |
| Dependabot | GitHub | Automated pull requests for known vulnerability fixes with configurable cooldown periods |
| npm audit | npm | Scans installed packages against the GitHub Advisory Database for known vulnerabilities |

---

## Approaches to Supply Chain Defense

Supply chain security is not one problem — it is several distinct problems, each addressed by different approaches. No single tool covers everything. Understanding the approaches helps you choose what combination makes sense for your situation.

> **Note:** This categorization is based on our research as of March 2026. Tools evolve rapidly. If any of this is outdated or incorrect, please [open an issue](https://github.com/Karmona/Fenceline/issues) — we want this to be accurate, not promotional.

### 1. Known Vulnerability Scanning

**What it does:** Matches your dependencies against databases of published CVEs and security advisories.

**Who does it:** Snyk, OWASP dep-scan, Dependabot, npm audit, GitHub Advisory Database

**Strengths:** Mature, well-understood, high coverage for known issues. Automated remediation PRs.

**Limitations:** Only catches vulnerabilities that have been discovered, reported, and catalogued. Cannot detect novel malicious packages or zero-day attacks. Often noisy — flags vulnerabilities in code paths your application never calls.

### 2. Behavioral / Static Code Analysis

**What it does:** Analyzes package source code for suspicious patterns — obfuscation, data exfiltration, credential harvesting, shell execution.

**Who does it:** Socket.dev (70+ signals), Datadog GuardDog (Semgrep/YARA rules), OpenSSF Package Analysis (gVisor sandbox)

**Strengths:** Can detect novel malicious packages that have no CVE. Socket's behavioral approach caught real attacks before any advisory existed.

**Limitations:** Rule-based approaches miss novel obfuscation. Sandbox approaches run at registry scale, not available to individual developers. Commercial tools require paid tiers for full coverage.

### 3. Package Metadata Analysis

**What it does:** Checks package metadata for risk signals — age, maintainer changes, install scripts, download counts, publication patterns.

**Who does it:** Heisenberg, SafeDep Vet, Fenceline (`fenceline check`), Aikido SafeChain (age gating)

**Strengths:** Fast, no code analysis needed. Catches account takeover signals (new maintainer), suspicious timing (brand-new package), and common attack vectors (postinstall scripts). Works before any code executes.

**Limitations:** Metadata can look normal even for malicious packages. A compromised maintainer account publishes under the same identity. Packages can be malicious without install scripts (runtime-only payloads like chalk/debug).

### 4. Capability Analysis

**What it does:** Maps packages to the system capabilities they can access — network, filesystem, process execution, environment variables.

**Who does it:** Google Capslock (Go only)

**Strengths:** Answers "what can this package actually do?" rather than "is this package bad?" If a logging library suddenly gains network access between versions, that is a strong signal regardless of whether any CVE exists.

**Limitations:** Currently only available for Go. No equivalent exists for npm, PyPI, Rust, Ruby, or any other ecosystem. Building call-graph analysis for dynamic languages like JavaScript is significantly harder than for Go.

### 5. Infrastructure Fingerprinting

**What it does:** Documents the expected network infrastructure of package managers — which domains, IP ranges, ASNs, CDN providers, TLS certificates, and ports each tool should connect to during normal operation. Detects when actual connections deviate from this baseline.

**Who does it:** Fenceline deep map ([map/](../map/))

**As far as we know**, no other project publishes this data as a structured, machine-readable, open dataset. StepSecurity Harden-Runner monitors network connections in CI at runtime, but does not publish the expected-good baseline as reusable data. If we are wrong about this, please [let us know](https://github.com/Karmona/Fenceline/issues) — we would love to link to other sources.

**Strengths:** Catches connections to unknown servers, non-standard ports, wrong CDN ranges, and unexpected uploads during install. Based on verifiable public data (DNS, certificate transparency, published CDN ranges). Works across all ecosystems.

**Limitations:** IP addresses rotate (CDNs change IPs regularly). IPv6 coverage is still growing. Cannot detect attacks that exfiltrate through legitimate domains (e.g., Nx using api.github.com). Cannot detect attacks with no network component (logic bombs, sabotage).

### 6. Runtime Network Monitoring (Local Dev)

**What it does:** Monitors outbound network connections during package installation on a developer's machine, comparing against expected behavior.

**Who does it:** Fenceline (`fenceline install`), Little Snitch / LuLu (general-purpose, not supply-chain-specific)

**StepSecurity Harden-Runner** does this for CI/CD (GitHub Actions), but not for local development. General-purpose firewalls like Little Snitch monitor all traffic but don't know what npm's normal behavior looks like.

**Strengths:** Catches exfiltration, C2 beaconing, and mining connections in real time during the install window.

**Limitations:** Polling-based (500ms interval, may miss very short connections). Cannot see inside encrypted traffic. Only monitors during the install command — runtime payloads that activate later are not caught.

### 7. Cooldown / Age Gating

**What it does:** Delays installation of newly published package versions, giving the community time to detect and report malicious releases.

**Who does it:** npm (`min-release-age`), pnpm (`minimumReleaseAge`), Yarn (`npmMinimalAgeGate`), Aikido SafeChain (48hr default)

**Strengths:** Extremely simple. One config line. Would have blocked most fast-moving account takeover attacks where malicious versions were detected within days.

**Limitations:** Does not help with slow-burn attacks (XZ Utils took 2 years). Does not help with compromised legitimate packages that pass the age threshold.

### 8. Provenance Verification

**What it does:** Cryptographically verifies that a published package was built from a specific source commit via a specific CI pipeline.

**Who does it:** npm + Sigstore, PyPI trusted publishing, crates.io trusted publishing, Fenceline (`fenceline check` checks for attestations)

**Strengths:** Detects tampered packages — if a malicious version was published from an attacker's machine rather than the project's CI, it will lack the provenance attestation. The axios attack was detectable this way.

**Limitations:** Adoption is still voluntary — most packages don't have provenance yet. Does not help if the CI pipeline itself is compromised (the malicious build would get a valid attestation).

### How These Approaches Complement Each Other

No single approach catches every attack. Here's how they layer:

| Attack type | What catches it |
|-------------|----------------|
| Known CVE in dependency | Vulnerability scanning (1) |
| Malicious code in new package | Behavioral analysis (2) + metadata (3) + cooldown (7) |
| Account takeover / phished maintainer | Metadata (3) + provenance (8) + cooldown (7) |
| Capability escalation between versions | Capability analysis (4) |
| Connection to C2 server during install | Infrastructure fingerprinting (5) + runtime monitoring (6) |
| DNS poisoning / CDN hijack | Infrastructure fingerprinting (5) |
| Logic bomb / sabotage (no network) | Behavioral analysis (2) — network monitoring cannot help |
| Exfiltration via legitimate domain | None fully — requires HTTP-level behavioral analysis |

The strongest defense combines approaches from multiple categories. Fenceline contributes to approaches 3, 5, 6, and 8, and aims to complement (not replace) tools covering approaches 1, 2, and 4.

## Remaining Gaps

Even with all approaches above, some gaps persist:

- **Cross-ecosystem capability analysis** — Capslock works for Go only. npm, PyPI, Rust have nothing equivalent.
- **Swift / Xcode ecosystem** — effectively zero supply chain security tooling exists for Apple developers.
- **Pre-install behavioral sandbox for individuals** — OpenSSF Package Analysis runs at registry scale, not on developer machines.
- **HTTP-level behavioral analysis** — detecting exfiltration through legitimate domains (like Nx using api.github.com) requires understanding expected HTTP methods and paths, not just domains.

> If you know of tools or approaches we've missed, please [open an issue](https://github.com/Karmona/Fenceline/issues). This landscape evolves weekly and we want it to be accurate.
