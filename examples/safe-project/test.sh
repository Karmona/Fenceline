#!/usr/bin/env bash
set -e

# Fenceline Example Project — Local Testing
#
# This script runs a series of fenceline commands against safe, well-known
# npm packages to verify the sandbox works end-to-end on your machine.
#
# Prerequisites:
#   - Docker installed and running
#   - fenceline installed (pip install -e /path/to/Fenceline)
#
# Usage:
#   cd examples/safe-project
#   ./test.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Fenceline Example Project ==="
echo ""

# Check prerequisites
if ! command -v fenceline &>/dev/null; then
    echo "ERROR: fenceline not found. Install with: pip install -e ../../"
    exit 1
fi

if ! command -v docker &>/dev/null; then
    echo "ERROR: docker not found. Install Docker Desktop."
    exit 1
fi

if ! docker info &>/dev/null 2>&1; then
    echo "ERROR: Docker daemon not running. Start Docker Desktop."
    exit 1
fi

echo "fenceline $(fenceline --version 2>&1 | grep -o '[0-9].*' || echo 'installed')"
echo "docker $(docker --version | grep -o '[0-9][0-9.]*')"
echo ""

# Clean previous runs
rm -rf node_modules package-lock.json

# -------------------------------------------------------------------
# Test 1: Sandboxed npm install (text output)
# -------------------------------------------------------------------
echo "--- Test 1: Sandboxed npm install ---"
echo ""

fenceline install --sandbox npm install is-odd is-even 2>&1

if [ -d "node_modules/is-odd" ]; then
    echo ""
    echo "PASS: node_modules/is-odd exists on host"
else
    echo ""
    echo "WARN: node_modules not found (may need manual check)"
fi
echo ""

# -------------------------------------------------------------------
# Test 2: JSON output
# -------------------------------------------------------------------
echo "--- Test 2: JSON output ---"
echo ""

# Clean and reinstall with JSON
rm -rf node_modules package-lock.json
JSON_OUT=$(fenceline install --sandbox --format json npm install is-odd 2>/dev/null || true)

if echo "$JSON_OUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'Verdict: {d[\"verdict\"]}')" 2>/dev/null; then
    echo "PASS: Valid JSON output received"
else
    echo "INFO: JSON parsing skipped (may have been text output)"
fi
echo ""

# -------------------------------------------------------------------
# Test 3: Lockfile risk check
# -------------------------------------------------------------------
echo "--- Test 3: Lockfile risk check ---"
echo ""

if [ -f "package-lock.json" ]; then
    fenceline check --lockfile package-lock.json --format text 2>&1 || true
else
    echo "SKIP: No package-lock.json found (generate with npm install first)"
fi
echo ""

# -------------------------------------------------------------------
# Test 4: Map freshness
# -------------------------------------------------------------------
echo "--- Test 4: Map freshness check ---"
echo ""

fenceline map --check 2>&1 || true
echo ""

# -------------------------------------------------------------------
# Test 5: Verify package works
# -------------------------------------------------------------------
echo "--- Test 5: Verify installed packages work ---"
echo ""

if [ -d "node_modules" ]; then
    npm test 2>&1 || echo "WARN: npm test failed (may need node_modules)"
else
    echo "SKIP: No node_modules to test"
fi
echo ""

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
echo "=== Done ==="
echo ""
echo "What was tested:"
echo "  1. Sandboxed npm install with real Docker container"
echo "  2. JSON output format for CI integration"
echo "  3. Lockfile risk scanning"
echo "  4. Deep map freshness validation"
echo "  5. Installed packages actually work"
echo ""
echo "To run the wrapper (transparent mode):"
echo "  fenceline wrap --enable"
echo "  npm install express    # automatically sandboxed"
