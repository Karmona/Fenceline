#!/usr/bin/env bash
# validate-packages.sh — Run popular packages through Fenceline sandbox
# to verify detection layers work end-to-end with real Docker.
#
# Safety: Uses --dry-run so NO artifacts are copied to the host machine.
# All 10 detection layers run normally; only artifact promotion is skipped.
# Containers are killed and verified gone after each package.
#
# Packages chosen: old, stable, widely-used, never-compromised versions.
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

# Safe, old, widely-used npm packages (pinned to known-good versions)
NPM_PACKAGES=(
    "is-odd@3.0.1"          # 2018, trivial, 0 deps
    "lodash@4.17.21"        # 2021, stable for years
    "debug@4.3.4"           # 2022, minimal
    "ms@2.1.3"              # 2021, 0 deps
    "uuid@9.0.0"            # 2023, well-audited
    "minimist@1.2.8"        # 2023, 0 deps
    "semver@7.5.4"          # 2023, well-audited
    "yallist@4.0.0"         # 2020, 0 deps
    "balanced-match@1.0.2"  # 2020, 0 deps
    "concat-map@0.0.1"      # 2014, 0 deps, ancient
)

# Safe, old, widely-used pip packages (pinned to known-good versions)
PIP_PACKAGES=(
    "six==1.16.0"           # 2021, compatibility shim
    "click==8.1.7"          # 2023, well-audited
    "idna==3.6"             # 2023, encoding lib
    "certifi==2023.11.17"   # 2023, CA bundle
    "charset-normalizer==3.3.2"  # 2023, encoding
    "colorama==0.4.6"       # 2022, terminal colors
    "typing-extensions==4.9.0"  # 2023, backport
    "pyparsing==3.1.1"      # 2023, parser
    "packaging==23.2"       # 2023, version parsing
    "pytz==2023.3.post1"    # 2023, timezone data
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

# Verify no leftover fenceline containers from previous runs
orphans=$(docker ps -q --filter "ancestor=node:alpine" --filter "ancestor=python:3.12-alpine" 2>/dev/null || true)
if [ -n "$orphans" ]; then
    echo -e "${YELLOW}Warning: found existing containers that may be from a previous run.${NC}"
    echo "  IDs: $orphans"
    echo "  Run: docker kill $orphans"
    echo ""
fi

passed=0
failed=0
blocked=0
total=0

echo "# Fenceline Package Validation Report" > "$REPORT"
echo "" >> "$REPORT"
echo "Date: $(date -u '+%Y-%m-%d %H:%M UTC')" >> "$REPORT"
echo "Fenceline: $(fenceline --version 2>&1 || echo 'unknown')" >> "$REPORT"
echo "Mode: --dry-run (no artifacts copied to host)" >> "$REPORT"
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

    # Count containers before
    local containers_before
    containers_before=$(docker ps -q | wc -l | tr -d ' ')

    local start_time=$SECONDS
    local output
    local exit_code

    # --dry-run: all 10 detection layers run, but NO artifacts copied to host
    cd "$tmpdir"
    output=$(fenceline install --sandbox --dry-run --format json $cmd 2>&1) && exit_code=0 || exit_code=$?
    cd - > /dev/null
    local duration=$((SECONDS - start_time))

    # Verify container was cleaned up
    local containers_after
    containers_after=$(docker ps -q | wc -l | tr -d ' ')
    local container_leak=""
    if [ "$containers_after" -gt "$containers_before" ]; then
        container_leak=" [CONTAINER LEAK!]"
    fi

    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}PASS${NC} (${duration}s)${container_leak}"
        passed=$((passed + 1))
        echo "| $tool | $pkg | PASS | ${duration}s | ${container_leak:-clean} |" >> "$REPORT"
    else
        # Check if BLOCKED or error
        if echo "$output" | grep -q "BLOCKED"; then
            echo -e "${RED}BLOCKED${NC} (${duration}s)${container_leak}"
            blocked=$((blocked + 1))
            local reason
            reason=$(echo "$output" | grep -oE '\[.*\].*' | head -1 || echo "unknown")
            echo "| $tool | $pkg | BLOCKED | ${duration}s | $reason ${container_leak} |" >> "$REPORT"
        else
            echo -e "${YELLOW}FAIL${NC} (${duration}s)${container_leak}"
            failed=$((failed + 1))
            echo "| $tool | $pkg | FAIL | ${duration}s | exit code $exit_code ${container_leak} |" >> "$REPORT"
        fi
    fi

    # Save full output for debugging
    local safe_pkg
    safe_pkg=$(echo "$pkg" | tr '=@' '-')
    echo "$output" > "${RESULTS_DIR}/${tool}-${safe_pkg}-${TIMESTAMP}.log"

    rm -rf "$tmpdir"
}

echo ""
echo "=== Fenceline Package Validation (--dry-run) ==="
echo "=== No artifacts will be copied to your machine ==="
echo ""

# Header for results table
echo "## Results" >> "$REPORT"
echo "" >> "$REPORT"
echo "| Tool | Package | Result | Time | Notes |" >> "$REPORT"
echo "|------|---------|--------|------|-------|" >> "$REPORT"

if $run_npm; then
    echo "--- npm packages (pinned versions) ---"
    for pkg in "${NPM_PACKAGES[@]}"; do
        validate_package "npm" "$pkg"
    done
    echo ""
fi

if $run_pip; then
    echo "--- pip packages (pinned versions) ---"
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

# Final container leak check
final_orphans=$(docker ps -q --filter "ancestor=node:alpine" --filter "ancestor=python:3.12-alpine" 2>/dev/null || true)
if [ -n "$final_orphans" ]; then
    echo ""
    echo -e "${RED}WARNING: Leftover containers detected! Killing them now.${NC}"
    docker kill $final_orphans 2>/dev/null || true
fi
