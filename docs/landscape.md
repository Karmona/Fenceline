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

## Gaps That Remain

Despite the breadth of tools listed above, significant gaps persist in the supply chain security ecosystem.

### 1. Cross-Ecosystem Capability Analysis

Google Capslock demonstrates that mapping packages to their system capabilities (network, filesystem, process execution) is a powerful security signal. But it only works for Go. There is no equivalent for npm, PyPI, Rust, Ruby, or any other ecosystem. Developers in those ecosystems have no way to ask "what can this package actually do on my system?" before installing it.

### 2. Infrastructure Fingerprinting

No tool publishes or verifies the expected infrastructure behind legitimate packages — the IP addresses packages should download from, the ASNs their registries should resolve to, the TLS certificates their CDNs should present. This would make domain takeover and CDN compromise attacks detectable at the network level, but the data does not exist in any structured form.

### 3. Swift / Xcode Ecosystem

The Apple developer ecosystem has effectively zero supply chain security tooling. No scanner covers Swift Package Manager packages. No tool analyzes Xcode project configurations for supply chain risks. No behavioral analysis exists for SPM packages. This is a blind spot for every macOS and iOS developer.

### 4. Multi-Signal Unified Scoring

Each tool produces its own signal: Scorecard gives a hygiene score, GuardDog flags pattern matches, Heisenberg rates metadata health, Socket analyzes behavior. No open-source project combines these signals into a unified risk assessment. Developers must run multiple tools and interpret the results themselves.

### 5. macOS Developer Workstation Protection

StepSecurity Harden-Runner monitors CI/CD (GitHub Actions only). Birdcage provides sandboxing primitives (stale). No tool monitors what packages do on a developer's local machine during `npm install` or `pip install`. Workstation compromise is the first step in many supply chain attacks, and it is unmonitored.

### 6. Pre-Install Behavioral Sandbox for Individual Developers

OpenSSF Package Analysis runs sandboxed analysis at registry scale, but individual developers cannot easily run a package in a sandbox before installing it. There is no `npm install --sandbox` or `pip install --analyze-first`. The closest option is manually running GuardDog or SafeDep Vet, which use static analysis rather than behavioral observation.
