#!/bin/bash
# Fenceline Quick Check
# Run this in any project directory to see your supply chain security posture.
# No installs needed. Just copy-paste and run.
#
# Usage: bash quick-check.sh
#
# License: Apache 2.0 — https://github.com/Karmona/Fenceline

set -euo pipefail

echo "============================================"
echo "  Fenceline Quick Check"
echo "  Supply chain security posture report"
echo "============================================"
echo ""

SCORE=0
TOTAL=0
WARNINGS=""

# Colors (if terminal supports them)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

pass() { echo -e "  ${GREEN}PASS${NC}  $1"; SCORE=$((SCORE + 1)); TOTAL=$((TOTAL + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; TOTAL=$((TOTAL + 1)); }
warn() { echo -e "  ${YELLOW}WARN${NC}  $1"; TOTAL=$((TOTAL + 1)); }
info() { echo -e "  ${BOLD}INFO${NC}  $1"; }
skip() { echo -e "  ${BOLD}SKIP${NC}  $1"; }

# ============================================
# 1. PACKAGE MANAGER COOLDOWN
# ============================================
echo -e "${BOLD}1. Package cooldown (minimum release age)${NC}"
echo "   Delays installing newly published packages, giving the community"
echo "   time to spot malicious releases before they reach your machine."
echo ""

if [ -f "pnpm-workspace.yaml" ] || [ -f "pnpm-lock.yaml" ]; then
    if grep -q "minimumReleaseAge" pnpm-workspace.yaml 2>/dev/null || grep -q "min-release-age" .npmrc 2>/dev/null; then
        pass "pnpm minimumReleaseAge is configured"
    else
        fail "pnpm detected but minimumReleaseAge is not set"
        echo "        Fix: Add 'minimumReleaseAge: 10080' to pnpm-workspace.yaml (7 days in minutes)"
    fi
elif [ -f ".yarnrc.yml" ]; then
    if grep -q "npmMinimalAgeGate" .yarnrc.yml 2>/dev/null; then
        pass "Yarn npmMinimalAgeGate is configured"
    else
        fail "Yarn detected but npmMinimalAgeGate is not set"
        echo "        Fix: Add 'npmMinimalAgeGate: 10080' to .yarnrc.yml"
    fi
elif [ -f "package-lock.json" ] || [ -f "package.json" ]; then
    if grep -q "min-release-age" .npmrc 2>/dev/null; then
        pass "npm min-release-age is configured"
    else
        NPM_VERSION=$(npm --version 2>/dev/null || echo "0")
        NPM_MAJOR=$(echo "$NPM_VERSION" | cut -d. -f1)
        if [ "$NPM_MAJOR" -ge 11 ] 2>/dev/null; then
            fail "npm $NPM_VERSION detected but min-release-age is not set"
            echo "        Fix: Add 'min-release-age=7' to your .npmrc file"
        else
            warn "npm $NPM_VERSION does not support min-release-age (requires v11+)"
            echo "        Fix: Update npm with 'npm install -g npm@latest', then add 'min-release-age=7' to .npmrc"
        fi
    fi
elif [ -f "Pipfile.lock" ] || [ -f "requirements.txt" ]; then
    skip "Python/pip detected — no built-in cooldown feature yet"
elif [ -f "Cargo.lock" ]; then
    skip "Rust/cargo detected — no built-in cooldown feature yet"
else
    skip "No recognized package manager lockfile found"
fi
echo ""

# ============================================
# 2. INSTALL SCRIPTS
# ============================================
echo -e "${BOLD}2. Install scripts protection${NC}"
echo "   Most supply chain attacks run malicious code during 'npm install'"
echo "   via postinstall scripts. Disabling them blocks this attack vector."
echo ""

if [ -f ".npmrc" ]; then
    if grep -q "ignore-scripts" .npmrc 2>/dev/null; then
        IGNORE_VAL=$(grep "ignore-scripts" .npmrc | head -1 | cut -d= -f2 | tr -d ' ')
        if [ "$IGNORE_VAL" = "true" ]; then
            pass "ignore-scripts=true is set in .npmrc"
        else
            fail "ignore-scripts is set but not to 'true' in .npmrc"
        fi
    else
        fail "ignore-scripts is not set in .npmrc"
        echo "        Fix: Add 'ignore-scripts=true' to .npmrc"
        echo "        Then allow specific packages that need scripts (esbuild, sharp, etc.)"
    fi
elif [ -f "package.json" ]; then
    fail "No .npmrc found — install scripts are running unrestricted"
    echo "        Fix: Create .npmrc with 'ignore-scripts=true'"
else
    skip "Not an npm/Node.js project"
fi
echo ""

# ============================================
# 3. LOCKFILE IN VERSION CONTROL
# ============================================
echo -e "${BOLD}3. Lockfile tracking${NC}"
echo "   Your lockfile pins exact versions and integrity hashes."
echo "   It must be committed to git so changes are reviewable in PRs."
echo ""

LOCKFILE=""
if [ -f "package-lock.json" ]; then LOCKFILE="package-lock.json"; fi
if [ -f "yarn.lock" ]; then LOCKFILE="yarn.lock"; fi
if [ -f "pnpm-lock.yaml" ]; then LOCKFILE="pnpm-lock.yaml"; fi
if [ -f "Pipfile.lock" ]; then LOCKFILE="Pipfile.lock"; fi
if [ -f "Cargo.lock" ]; then LOCKFILE="Cargo.lock"; fi
if [ -f "Gemfile.lock" ]; then LOCKFILE="Gemfile.lock"; fi
if [ -f "composer.lock" ]; then LOCKFILE="composer.lock"; fi

if [ -n "$LOCKFILE" ]; then
    if git ls-files --error-unmatch "$LOCKFILE" >/dev/null 2>&1; then
        pass "$LOCKFILE is tracked in git"
    else
        fail "$LOCKFILE exists but is NOT tracked in git"
        echo "        Fix: git add $LOCKFILE && git commit -m 'Track lockfile'"
    fi

    # Check for recent lockfile changes
    if git log --oneline -1 -- "$LOCKFILE" >/dev/null 2>&1; then
        LAST_CHANGE=$(git log --oneline -1 -- "$LOCKFILE" 2>/dev/null)
        info "Last lockfile change: $LAST_CHANGE"
    fi

    # Check if lockfile has uncommitted changes
    if ! git diff --quiet -- "$LOCKFILE" 2>/dev/null; then
        warn "$LOCKFILE has uncommitted changes — review before committing"
        echo ""
        echo "        Uncommitted lockfile diff summary:"
        ADDED=$(git diff -- "$LOCKFILE" 2>/dev/null | grep "^+" | grep -v "^+++" | wc -l | tr -d ' ')
        REMOVED=$(git diff -- "$LOCKFILE" 2>/dev/null | grep "^-" | grep -v "^---" | wc -l | tr -d ' ')
        echo "        +$ADDED lines / -$REMOVED lines changed"
    fi
else
    if [ -f "package.json" ] || [ -f "Pipfile" ] || [ -f "Cargo.toml" ] || [ -f "Gemfile" ]; then
        fail "Package manager config found but no lockfile exists"
        echo "        Fix: Run your package manager's install command to generate a lockfile"
    else
        skip "No package manager detected"
    fi
fi
echo ""

# ============================================
# 4. REGISTRY AUTHENTICATION
# ============================================
echo -e "${BOLD}4. Registry account security${NC}"
echo "   If you publish packages, 2FA on your registry account is critical."
echo "   Account takeover is the #1 supply chain attack vector."
echo ""

if command -v npm >/dev/null 2>&1; then
    # Check if logged in
    NPM_USER=$(npm whoami 2>/dev/null || echo "")
    if [ -n "$NPM_USER" ]; then
        info "Logged into npm as: $NPM_USER"
        echo "        Verify 2FA is enabled: https://www.npmjs.com/settings/$NPM_USER/tfa"
        echo "        Best practice: Use hardware keys (WebAuthn) instead of TOTP apps"
        TOTAL=$((TOTAL + 1))
        SCORE=$((SCORE + 1))
    else
        info "Not logged into npm (run 'npm login' if you publish packages)"
        info "If you publish packages, enable 2FA at https://www.npmjs.com/settings"
    fi
else
    skip "npm not installed"
fi

if command -v pip >/dev/null 2>&1 || command -v pip3 >/dev/null 2>&1; then
    info "Python/pip detected — if you publish to PyPI, enable 2FA at https://pypi.org/manage/account/"
fi
echo ""

# ============================================
# 5. PROVENANCE VERIFICATION
# ============================================
echo -e "${BOLD}5. Package provenance${NC}"
echo "   npm provenance uses Sigstore to cryptographically prove a package"
echo "   was built from a specific commit. Missing provenance is a red flag."
echo ""

if [ -f "package-lock.json" ] && command -v npm >/dev/null 2>&1; then
    echo "   Running: npm audit signatures ..."
    AUDIT_RESULT=$(npm audit signatures 2>&1 || true)
    if echo "$AUDIT_RESULT" | grep -q "verified"; then
        VERIFIED=$(echo "$AUDIT_RESULT" | grep -o '[0-9]* packages have verified' | head -1 || echo "")
        pass "npm audit signatures: $VERIFIED attestations"
    elif echo "$AUDIT_RESULT" | grep -q "no matching signatures"; then
        warn "Some packages lack provenance signatures"
        echo "        This is common — many packages don't publish with provenance yet"
    elif echo "$AUDIT_RESULT" | grep -q "error"; then
        warn "npm audit signatures encountered an error"
        echo "        $AUDIT_RESULT" | head -3
    else
        info "npm audit signatures result:"
        echo "        $AUDIT_RESULT" | head -5
    fi
else
    skip "Not an npm project or npm not available"
fi
echo ""

# ============================================
# 6. HOMEBREW TELEMETRY
# ============================================
echo -e "${BOLD}6. Homebrew telemetry${NC}"
echo "   Homebrew is the ONLY major package manager that sends analytics."
echo "   Every other tool (npm, pip, cargo, yarn, Go, RubyGems) sends zero."
echo ""

if command -v brew >/dev/null 2>&1; then
    if brew analytics 2>/dev/null | grep -qi "disabled"; then
        pass "Homebrew analytics are disabled"
    else
        warn "Homebrew analytics are enabled (sends install data to InfluxDB in AWS Frankfurt)"
        echo "        Fix: Run 'brew analytics off' or add 'export HOMEBREW_NO_ANALYTICS=1' to your shell profile"
    fi
else
    skip "Homebrew not installed"
fi
echo ""

# ============================================
# 7. BONUS: .gitignore check
# ============================================
echo -e "${BOLD}7. Sensitive file protection${NC}"
echo "   .env files, credentials, and tokens should never be committed."
echo ""

if [ -f ".gitignore" ]; then
    if grep -q "\.env" .gitignore 2>/dev/null; then
        pass ".env files are in .gitignore"
    else
        fail ".env is NOT in .gitignore — secrets could leak"
        echo "        Fix: Add '.env' and '.env.*' to .gitignore"
    fi
    if grep -q "node_modules" .gitignore 2>/dev/null || ! [ -d "node_modules" ]; then
        pass "node_modules handled correctly"
    else
        fail "node_modules not in .gitignore"
    fi
else
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        warn "No .gitignore file found"
        echo "        Fix: Create a .gitignore — see https://github.com/github/gitignore"
    else
        skip "Not a git repository"
    fi
fi
echo ""

# ============================================
# REPORT
# ============================================
echo "============================================"
echo -e "${BOLD}  RESULTS: $SCORE / $TOTAL checks passed${NC}"
echo "============================================"

if [ "$TOTAL" -gt 0 ]; then
    PCT=$((SCORE * 100 / TOTAL))
else
    PCT=0
fi

if [ "$PCT" -ge 80 ]; then
    echo -e "  ${GREEN}Good posture.${NC} Keep your lockfile reviewed and dependencies updated."
elif [ "$PCT" -ge 50 ]; then
    echo -e "  ${YELLOW}Room for improvement.${NC} Review the FAIL items above."
else
    echo -e "  ${RED}Significant gaps.${NC} Address the FAIL items above — start with the easiest ones."
fi

echo ""
echo "  Learn more:"
echo "    Supply chain basics:  https://github.com/Karmona/Fenceline/blob/main/docs/supply-chain-for-dummies.md"
echo "    Real attack examples: https://github.com/Karmona/Fenceline/blob/main/exploits/"
echo "    Tools landscape:      https://github.com/Karmona/Fenceline/blob/main/docs/landscape.md"
echo ""
echo "  This is a point-in-time check. Run it regularly."
echo "  Fenceline is a best-effort community project — see DISCLAIMER.md."
echo ""
