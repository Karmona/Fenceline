#!/usr/bin/env bash
# validate-packages.sh — Run popular packages through Fenceline sandbox
# to find false positives and verify real-world compatibility.
#
# Usage: ./tools/validate-packages.sh [--npm-only | --pip-only]
#
# Requires: Docker running, fenceline installed (pip install -e .)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../validation-results"
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT="${RESULTS_DIR}/report-${TIMESTAMP}.md"

# Colors (respect NO_COLOR)
if [ -z "${NO_COLOR:-}" ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    GREEN='' RED='' YELLOW='' NC=''
fi

NPM_PACKAGES=(
    "is-odd"
    "express"
    "lodash"
    "axios"
    "typescript"
    "eslint"
    "prettier"
    "react"
    "chalk"
    "debug"
)

PIP_PACKAGES=(
    "six"
    "requests"
    "flask"
    "black"
    "pytest"
    "click"
    "fastapi"
    "pydantic"
    "rich"
    "httpx"
)

run_npm=true
run_pip=true
if [ "${1:-}" = "--npm-only" ]; then run_pip=false; fi
if [ "${1:-}" = "--pip-only" ]; then run_npm=false; fi

# Check prerequisites
if ! command -v fenceline &>/dev/null; then
    echo "Error: fenceline not found. Run: pip install -e ."
    exit 1
fi
if ! docker info &>/dev/null 2>&1; then
    echo "Error: Docker not running."
    exit 1
fi

passed=0
failed=0
blocked=0
total=0

echo "# Fenceline Package Validation Report" > "$REPORT"
echo "" >> "$REPORT"
echo "Date: $(date -u '+%Y-%m-%d %H:%M UTC')" >> "$REPORT"
echo "Fenceline: $(fenceline --version 2>&1 || echo 'unknown')" >> "$REPORT"
echo "" >> "$REPORT"

validate_package() {
    local tool="$1"
    local pkg="$2"
    local tmpdir
    tmpdir=$(mktemp -d)

    total=$((total + 1))

    if [ "$tool" = "npm" ]; then
        echo '{"name": "validate-test", "version": "1.0.0"}' > "$tmpdir/package.json"
        local cmd="npm install $pkg"
    else
        local cmd="pip install $pkg"
    fi

    echo -n "  [$tool] $pkg ... "

    local start_time=$SECONDS
    local output
    local exit_code

    output=$(fenceline install --sandbox --format json $cmd 2>&1) && exit_code=0 || exit_code=$?
    local duration=$((SECONDS - start_time))

    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}PASS${NC} (${duration}s)"
        passed=$((passed + 1))
        echo "| $tool | $pkg | PASS | ${duration}s | — |" >> "$REPORT"
    else
        # Check if BLOCKED or error
        if echo "$output" | grep -q "BLOCKED"; then
            echo -e "${RED}BLOCKED${NC} (${duration}s)"
            blocked=$((blocked + 1))
            # Extract reason
            local reason
            reason=$(echo "$output" | grep -oE '\[.*\].*—.*' | head -1 || echo "unknown")
            echo "| $tool | $pkg | BLOCKED | ${duration}s | $reason |" >> "$REPORT"
        else
            echo -e "${YELLOW}FAIL${NC} (${duration}s)"
            failed=$((failed + 1))
            echo "| $tool | $pkg | FAIL | ${duration}s | exit code $exit_code |" >> "$REPORT"
        fi
    fi

    # Save full output for debugging
    echo "$output" > "${RESULTS_DIR}/${tool}-${pkg}-${TIMESTAMP}.log"

    rm -rf "$tmpdir"
}

echo ""
echo "=== Fenceline Package Validation ==="
echo ""

# Header for results table
echo "## Results" >> "$REPORT"
echo "" >> "$REPORT"
echo "| Tool | Package | Result | Time | Notes |" >> "$REPORT"
echo "|------|---------|--------|------|-------|" >> "$REPORT"

if $run_npm; then
    echo "--- npm packages ---"
    for pkg in "${NPM_PACKAGES[@]}"; do
        validate_package "npm" "$pkg"
    done
    echo ""
fi

if $run_pip; then
    echo "--- pip packages ---"
    for pkg in "${PIP_PACKAGES[@]}"; do
        validate_package "pip" "$pkg"
    done
    echo ""
fi

echo "" >> "$REPORT"
echo "## Summary" >> "$REPORT"
echo "" >> "$REPORT"
echo "- Total: $total" >> "$REPORT"
echo "- Passed: $passed" >> "$REPORT"
echo "- Failed: $failed" >> "$REPORT"
echo "- Blocked: $blocked" >> "$REPORT"

echo "=== Summary ==="
echo "  Total:   $total"
echo -e "  Passed:  ${GREEN}${passed}${NC}"
echo -e "  Failed:  ${YELLOW}${failed}${NC}"
echo -e "  Blocked: ${RED}${blocked}${NC}"
echo ""
echo "Report: $REPORT"
echo "Logs:   $RESULTS_DIR/"
