# Defense Playbook

Practical supply chain security steps organized by what you do. Each section is self-contained -- jump to what applies to you.

> **Disclaimer:** This is best-effort guidance from the Fenceline community, not professional security advice. See [DISCLAIMER.md](../DISCLAIMER.md) for full terms.

## If You Use npm/Node.js

**Require a cooldown on new package versions** (blocks packages published in the last 3 days):

```bash
npm config set min-release-age 3
```

**Disable install scripts globally** (prevents postinstall malware):

```bash
npm config set ignore-scripts true
```

Then explicitly allow scripts for packages that need them in `.npmrc`:

```ini
; .npmrc — allow install scripts only for known packages
ignore-scripts=true
script-allow[]=node-gyp
script-allow[]=esbuild
```

**Check lockfile diffs before merging:**

```bash
fenceline check
fenceline check --base-ref main    # compare against main branch
```

**Monitor network during installs:**

```bash
fenceline install npm install <pkg>
```

**Verify provenance signatures:**

```bash
npm audit signatures
```

**Pin your GitHub Actions to SHAs:**

```bash
fenceline audit-actions
```

See also: [Supply Chain for Developers](supply-chain-for-dummies.md) for the full npm hardening checklist.

## If You Use Python/pip

**Pin exact versions in requirements.txt** -- never use `>=` ranges in production:

```
# Bad — allows any future version
requests>=2.28

# Good — locked to a known version
requests==2.31.0
```

**Use a lockfile and commit it:**

```bash
pip install pipenv
pipenv lock
git add Pipfile.lock
```

Or with pip-tools:

```bash
pip install pip-tools
pip-compile requirements.in    # generates requirements.txt with pinned versions
pip-sync                       # installs exactly what's in requirements.txt
```

**Scan new packages before installing:**

```bash
fenceline install pip install <pkg>
```

**Enable 2FA on PyPI:** Go to https://pypi.org/manage/account/ and enable two-factor authentication.

**Watch for .pth files** -- the TeamPCP campaign used `.pth` files in packages to execute code at Python startup. After installing a package, check:

```bash
find $(python -c "import site; print(site.getsitepackages()[0])") -name "*.pth" -newer /tmp/before-install
```

## If You Use GitHub Actions

**ALWAYS pin actions to full SHA, never tags.**

Tags can be force-pushed to point to malicious code. The TeamPCP campaign (March 2026) did exactly this to Trivy and Checkmarx actions. A tag like `@v4` is just a pointer -- the maintainer (or attacker) can change what it points to at any time.

```yaml
# DANGEROUS — tag can be force-pushed
- uses: actions/checkout@v4

# SAFE — SHA is immutable
- uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
```

**Audit your workflows:**

```bash
fenceline audit-actions
fenceline audit-actions --path /path/to/repo
```

**Use least-privilege GITHUB_TOKEN permissions:**

```yaml
permissions:
  contents: read    # only what you need
  pull-requests: read
```

**Never use `pull_request_target` with code from forks** -- this gives fork PRs access to secrets.

**Audit what secrets your workflows can access:**

```bash
# List all secrets referenced in workflows
grep -rh 'secrets\.' .github/workflows/ | sort -u
```

## If You Publish Packages

**Use trusted publishing (OIDC) instead of long-lived tokens:**

- npm: https://docs.npmjs.com/generating-provenance-statements
- PyPI: https://docs.pypi.org/trusted-publishers/

**Switch to WebAuthn 2FA** -- TOTP can be phished (the chalk/debug attack proved this):

- npm: `npm profile enable-2fa auth-and-writes`
- PyPI: Add a security key at https://pypi.org/manage/account/

**Remove old tokens:**

```bash
# npm — list and revoke unused tokens
npm token list
npm token revoke <token-id>
```

**Enable provenance so users can verify your packages:**

```bash
npm config set provenance true
```

## If You Run CI/CD

**Pin ALL dependencies to SHAs, not tags** -- this applies to actions, Docker images, and any external tools your CI pulls.

**Minimize secrets available to each workflow:**

```yaml
# Only expose secrets to jobs that need them
jobs:
  build:
    # No secrets needed for build
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29

  deploy:
    needs: build
    environment: production    # secrets scoped to this environment
    steps:
      - run: deploy.sh
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
```

**Use StepSecurity Harden-Runner for network monitoring:**

```yaml
steps:
  - uses: step-security/harden-runner@17d0e2bd7d51742c71671bd19fa12bdc9d40a3d6
    with:
      egress-policy: audit    # start with audit, move to block
```

**Review Dependabot PRs manually for major version bumps** -- automated merging of major version changes is risky.

**Set npm min-release-age in CI:**

```bash
# In your CI setup step
npm config set min-release-age 7
```

## If a Supply Chain Attack Happens (Incident Response)

**1. Check if you are affected:**

```bash
# Search lockfiles for the compromised package
grep "compromised-package" package-lock.json
grep "compromised-package" requirements.txt

# Check if you installed a specific version
npm ls compromised-package
pip show compromised-package
```

**2. Rotate ALL secrets** that were available in CI during the exposure window. This means every secret in every workflow that ran while the compromised dependency was installed.

**3. Check if the compromised package had postinstall scripts:**

```bash
# npm — check if scripts ran
npm show compromised-package scripts
cat node_modules/compromised-package/package.json | grep -A5 '"scripts"'
```

**4. Review git history** for unexpected lockfile changes:

```bash
git log --oneline --all -- package-lock.json
git log --oneline --all -- requirements.txt
```

**5. Report** to your team and downstream users. If your package consumed the compromised dependency, your users may be affected too.

**6. Document** what happened -- consider contributing a case study to [Fenceline exploits/](../exploits/).

## Quick Reference

| Threat | Defense | Command |
|--------|---------|---------|
| New malicious package | Cooldown period | `npm config set min-release-age 7` |
| Phished maintainer | Provenance check | `npm audit signatures` |
| Malicious postinstall | Disable scripts | `npm config set ignore-scripts true` |
| Actions tag tampering | SHA pinning | `fenceline audit-actions` |
| Unknown network calls | Monitor install | `fenceline install npm install <pkg>` |
| Risky lockfile changes | Check before merge | `fenceline check` |
| Stale tokens | Revoke unused | `npm token list` then `npm token revoke` |

## Further Reading

- [Supply Chain for Developers](supply-chain-for-dummies.md) -- the full plain-English explainer
- [Exploit Case Studies](../exploits/) -- 10 real attacks analyzed in detail
- [Tools Landscape](landscape.md) -- every supply chain security tool we know about
- [Why This Matters](why-this-matters.md) -- the real cost, with real numbers
