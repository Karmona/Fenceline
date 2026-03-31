# Why Supply Chain Security Matters Now

## The Numbers Are Getting Worse

Software supply chain attacks are not theoretical. They are happening at scale, hitting packages that millions of developers depend on every day.

**Recent high-impact incidents:**

| Incident | Impact | Date |
|----------|--------|------|
| chalk/debug compromise | 2.6 billion weekly downloads affected — maintainer account hijacked, malicious code injected into one of npm's most depended-on packages | September 2025 |
| Axios RAT injection | 400 million monthly downloads — remote access trojan inserted into the most popular HTTP client for JavaScript | March 2026 |
| Codecov bash uploader | 29,000 customers' CI secrets leaked for 2 months before detection — attackers modified a shared CI script to exfiltrate environment variables | 2021 |
| Nx/s1ngularity | 2,349 credentials stolen from 1,079 systems — compromised build tooling used to harvest secrets from developer machines and CI pipelines | 2025 |

These are not fringe packages. These are foundational infrastructure that most modern applications depend on, directly or transitively.

## Why It Is Getting Worse

**More dependencies than ever.** A typical React application pulls in 1,000+ transitive dependencies. A Python ML project can easily exceed 500. Each dependency is a trust relationship with a maintainer you have never met.

**AI-generated code introduces slopsquatting risk.** Large language models hallucinate package names that do not exist. Attackers register those names and fill them with malicious code. The AI recommends the package, the developer installs it, and the attack succeeds without any social engineering.

**Attack tooling is more sophisticated.** Modern supply chain attacks use multi-stage payloads, conditional execution (only activate on CI, only on specific platforms), encrypted C2 channels, and polymorphic obfuscation. Simple pattern matching cannot keep up.

**CI/CD is the new high-value target.** Build systems have access to signing keys, deployment credentials, cloud tokens, and production infrastructure. Compromising a CI pipeline gives attackers everything — not just code, but the ability to ship that code to every user.

## Why Existing Tools Are Not Enough

**Enterprise-only solutions.** The most capable tools — Socket.dev, Endor Labs, Snyk's advanced tiers — are priced for organizations with security budgets. Individual developers and small teams are left unprotected.

**Narrow focus.** Datadog's GuardDog uses static rules (Semgrep and YARA patterns) to catch known malicious patterns. It works well for what it covers, but novel obfuscation and multi-stage payloads bypass rule-based detection entirely.

**Signature-based detection only.** GitHub's Dependabot and `npm audit` scan for known CVEs — vulnerabilities that have already been discovered, reported, and cataloged. They catch nothing on day zero. A compromised package with no CVE filed is invisible.

**No unified approach.** Each tool covers one slice of the problem. OpenSSF Scorecard measures project hygiene but not code behavior. Package Analysis sandboxes packages but is not designed for individual developer use. GUAC aggregates metadata but performs no detection. No tool combines multiple signals into a single assessment.

## What Fenceline Does Differently

**Documentation-first.** Before building detection tools, Fenceline maps the entire attack surface. Every known attack technique is documented with real examples, detection methods, and gaps. You cannot defend against what you have not cataloged.

**Deep infrastructure mapping.** Fenceline documents the infrastructure fingerprints of legitimate packages — expected download URLs, known maintainer accounts, typical CI configurations, publication patterns. This creates a baseline that makes anomalies visible.

**Community-driven.** Supply chain security knowledge should not be locked behind enterprise paywalls. Fenceline is Apache 2.0 licensed. Every exploit analysis, every detection technique, every infrastructure map is public and contributed by the community.

**Combines multiple approaches.** Rather than betting on a single detection method, Fenceline aims to layer static analysis, behavioral analysis, metadata scoring, infrastructure verification, and community intelligence. No single signal is reliable alone. Multiple weak signals combined produce strong detection.

## The Gap Is Clear

There are excellent tools in this space (see [landscape.md](landscape.md) for a full directory). But there is no open-source project that combines deep attack documentation, multi-signal detection, infrastructure fingerprinting, and cross-ecosystem coverage into a single framework accessible to every developer.

That is what Fenceline is building.
