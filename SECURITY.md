# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Fenceline itself (not in the packages or attacks we document), please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, use [GitHub's private vulnerability reporting](https://github.com/Karmona/Fenceline/security/advisories/new) to submit a report. This keeps the details private until a fix is available.

## What to Report

- Vulnerabilities in Fenceline's Python code (command injection, path traversal, etc.)
- Issues with the testing simulations that could cause harm beyond localhost
- Inaccurate IOCs in exploit case studies that could cause false accusations
- Sensitive data accidentally committed to the repository

## What NOT to Report Here

- Vulnerabilities in packages we document (report those to the package maintainers)
- General supply chain attack reports (add them as [exploit case studies](exploits/template.md) instead)
- Feature requests (use [GitHub Issues](https://github.com/Karmona/Fenceline/issues))

## Response Timeline

This is a community-maintained project. We aim to:

- Acknowledge reports within 48 hours
- Provide an initial assessment within 1 week
- Release a fix for confirmed vulnerabilities as quickly as possible

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Scope

Fenceline is a detection and educational tool. It does not handle secrets, credentials, or sensitive data. The primary attack surface is:

- The `fenceline install` command runs `lsof`/`ss` via subprocess
- The `fenceline check` command makes HTTP requests to `registry.npmjs.org`
- The testing simulations run localhost-only network operations
