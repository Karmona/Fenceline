# Supply Chain Security for Developers

A plain-English guide. No jargon, no fear-mongering, just what you need to know.

## What IS a Supply Chain Attack?

Think of it like cooking. You follow a recipe perfectly — fresh ingredients, clean kitchen, correct temperatures. But someone poisoned the flour at the mill before it reached your grocery store. Your cooking was flawless. The problem was upstream, in your supply chain.

Software works the same way. Your code might be perfectly written and thoroughly tested. But if one of the packages you depend on has been compromised, the attacker's code runs inside your application with full access to everything your app can touch.

You did nothing wrong. You trusted your supplier. That trust was exploited.

## How Your Code Depends on Strangers

When you run `npm install` for a typical React application, you are not just installing the 15 packages listed in your `package.json`. Each of those packages has its own dependencies, which have their own dependencies, and so on.

A typical React app ends up with **1,000+ transitive dependencies**. Each one is maintained by a person (or a small group) you have never met, have never vetted, and whose identity you have no way to verify.

Every one of those packages is a trust relationship. Every one is an attack surface.

## The 5 Main Attack Types

### 1. Account Takeover

Someone steals a maintainer's login credentials (phished password, leaked token, compromised email) and publishes a malicious version of a legitimate package.

**Real examples:** ua-parser-js (78M weekly downloads hijacked), chalk/debug (2.6B weekly downloads), Axios (400M monthly downloads). In each case, the attackers got access to the maintainer's npm account and pushed a new version containing malicious code.

**Why it works:** You already trust this package. Your lockfile updates automatically or you accept the update without reviewing the diff. The malicious code runs the next time you install or build.

### 2. Typosquatting

An attacker publishes a package with a name very similar to a popular one, hoping developers will mistype or not notice the difference.

**Example:** `lodash` (real) vs `lodahs` (fake). `electron` (real) vs `electorn` (fake). The fake package contains malicious code but may also include the real package's functionality so everything appears to work normally.

**Why it works:** One typo in a `package.json` or terminal command, and you have installed an attacker's code. AI code assistants make this worse by sometimes hallucinating package names that do not exist, which attackers then register.

### 3. Maintainer Handoff

A popular package's original maintainer loses interest or burns out. Someone offers to take over maintenance. The new maintainer seems helpful at first, then quietly adds malicious code in a later release.

**Real example:** event-stream — a popular npm package with millions of downloads. A new contributor gradually took over maintenance, then injected code specifically targeting a Bitcoin wallet application.

**Why it works:** The handoff looks legitimate. The new maintainer builds trust over weeks or months before striking. By the time the malicious code ships, the community trusts them.

### 4. CI/CD Compromise

Instead of poisoning the code directly, attackers compromise the build system — the infrastructure that compiles, tests, and deploys code.

**Real examples:** Codecov (attackers modified a shared CI script, causing 29,000 customers' CI systems to leak environment variables for 2 months), Ultralytics (GitHub Actions workflow compromised to inject crypto miners into Python releases), Nx/s1ngularity (build tooling used to steal 2,349 credentials from 1,079 systems).

**Why it works:** Developers review code changes carefully but rarely audit their CI configuration with the same rigor. Build systems have access to signing keys, deployment tokens, and production credentials.

### 5. Domain Takeover

An attacker acquires control of a domain that existing code references — either by buying an expired domain or exploiting DNS misconfigurations.

**Real example:** Polyfill.io — a CDN domain used by over 100,000 websites was sold to a new owner who injected malicious redirects into the JavaScript served to visitors.

**Why it works:** The code referencing the domain was written years ago and still works. No package was compromised, no account was stolen. The trust anchor (the domain) simply changed hands.

## 5-Minute Checklist: What You Can Do Right Now

These are concrete steps you can take today. None require special tools or paid services.

Start by making sure you're on a recent version of your package manager — the security features below require it:

Check your current version:
```bash
npm --version
```

Update to latest:
```bash
npm install -g npm@latest
```

The steps below assume npm v11+ (or pnpm v10.16+ / Yarn v4.10+). If you can't update, skip to step 2 — the other steps work on any version.

### 1. Enforce a minimum package age (cooldown)

Package managers now support delaying installation of newly published versions. This gives the community time to spot and report malicious releases before they reach your machine. Most supply chain attacks are detected within days.

Pick your package manager and run one command to set a 7-day cooldown:

**npm** (v11.10+) — value is in **days**:
```bash
npm config set min-release-age 7
```

Note: there is a [known bug](https://github.com/npm/cli/issues/9005) with `~` version ranges. If you hit errors, pin exact versions for now.

**pnpm** (v10.16+) — value is in **minutes** (10080 = 7 days):
```bash
pnpm config set minimumReleaseAge 10080
```

**Yarn** (v4.10+) — add this line to `.yarnrc.yml`:
```yaml
npmMinimalAgeGate: 10080
```

### 2. Disable install scripts for untrusted packages

Many supply chain attacks execute during `npm install` via postinstall scripts. You can disable this:

```bash
npm config set ignore-scripts true
```

Then explicitly allow scripts only for packages that need them (like `esbuild` or `sharp`) in your `.npmrc` or project config.

### 3. Review lockfile diffs in every PR

Your `package-lock.json` or `yarn.lock` records the exact versions and integrity hashes of every dependency. When a PR changes the lockfile, read the diff. Look for:
- New packages you did not expect
- Version jumps in packages not mentioned in the PR
- Changed integrity hashes without version changes

Quick one-liner to see what changed in your lockfile since last commit:

```bash
git diff HEAD~1 -- package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null | grep "^[+-]" | grep -E "resolved|integrity|version" | head -30
```

### 4. Enable 2FA on your npm/PyPI account

If you publish packages, enable two-factor authentication on your registry account. This is the single most effective defense against account takeover — the most common supply chain attack vector.

```bash
npm profile enable-2fa auth-and-writes
```

You must be logged in first (`npm login`). For PyPI: go to https://pypi.org/manage/account/ > Add 2FA.

Best practice: use hardware keys (WebAuthn/FIDO2) instead of TOTP apps — TOTP codes can be phished in real-time, as the chalk/debug attack showed.

### 5. Check npm provenance on critical packages

npm provenance uses Sigstore to cryptographically prove that a package was built from a specific commit in a specific repository. Check it:

```bash
npm audit signatures
```

If a package has provenance, you can verify it was not tampered with between the source repository and the registry.

### Bonus: Disable Homebrew telemetry

Homebrew is the **only** major package manager that sends analytics data (to InfluxDB in AWS Frankfurt). Every other tool -- npm, pip, cargo, yarn, Go modules, RubyGems -- sends zero telemetry.

```bash
brew analytics off && echo 'export HOMEBREW_NO_ANALYTICS=1' >> ~/.zshrc
```

## Quick Posture Report

Copy-paste this into your terminal to get an instant report of your project's supply chain security posture:

```bash
echo "=== Supply Chain Posture Report ===" && echo "" \
&& echo "npm version: $(npm --version 2>/dev/null || echo 'not installed')" \
&& echo "" \
&& echo "--- Cooldown ---" \
&& (grep -s "min-release-age" .npmrc ~/.npmrc 2>/dev/null && echo "PASS: min-release-age is set" || echo "FAIL: No cooldown set. Fix: npm config set min-release-age 7") \
&& echo "" \
&& echo "--- Install scripts ---" \
&& (grep -s "ignore-scripts" .npmrc ~/.npmrc 2>/dev/null && echo "PASS: ignore-scripts is configured" || echo "FAIL: Install scripts unrestricted. Fix: npm config set ignore-scripts true") \
&& echo "" \
&& echo "--- Lockfile ---" \
&& (ls package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null | head -1 | xargs -I{} echo "FOUND: {}" || echo "WARN: No lockfile found") \
&& echo "" \
&& echo "--- Provenance ---" \
&& (npm audit signatures 2>/dev/null | head -3 || echo "SKIP: No npm project or npm not available") \
&& echo "" \
&& echo "--- Homebrew telemetry ---" \
&& (brew analytics 2>/dev/null | head -1 || echo "SKIP: Homebrew not installed") \
&& echo "" \
&& echo "--- Sensitive files ---" \
&& (grep -q "\.env" .gitignore 2>/dev/null && echo "PASS: .env in .gitignore" || echo "WARN: .env not in .gitignore") \
&& echo "" \
&& echo "=== Done ==="
```

For a more detailed report with color-coded output and fix instructions, use our full check script:

```bash
curl -sL https://raw.githubusercontent.com/Karmona/Fenceline/main/tools/quick-check.sh | bash
```

The script checks: cooldown settings, install script protection, lockfile tracking, registry auth, package provenance, Homebrew telemetry, and sensitive file protection. It produces a pass/fail report with specific fix instructions.

## Where to Learn More

- **[Exploit analyses](../exploits/)** -- Detailed breakdowns of real supply chain attacks, how they worked, how they were detected, and what defenses existed
- **[Security tool landscape](landscape.md)** -- Comprehensive directory of every known supply chain security tool, what it catches, and what it misses
