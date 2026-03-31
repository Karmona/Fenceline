#!/bin/bash
# =============================================================================
# Fenceline Test Harness
# =============================================================================
# Master test runner that executes all supply chain attack simulations
# and generates a summary report.
#
# Usage:
#   ./harness.sh              # Run all tests
#   ./harness.sh --report     # Run all tests and save report to reports/
#
# All tests use localhost only. Safe to run on any development machine.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="$SCRIPT_DIR/simulations"
REPORT_DIR="$SCRIPT_DIR/reports"

TOTAL=0
PASSED=0
FAILED=0
ERRORS=()
SAVE_REPORT=false

if [[ "${1:-}" == "--report" ]]; then
    SAVE_REPORT=true
fi

# Header
echo "============================================="
echo "  Fenceline Test Harness"
echo "  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================="
echo ""

# Check prerequisites
echo "[CHECK] Prerequisites..."
PREREQS_OK=true

if ! command -v python3 &>/dev/null; then
    echo "  [WARN] python3 not found — some tests may skip features"
fi

if ! command -v curl &>/dev/null; then
    echo "  [FAIL] curl not found — required for most tests"
    PREREQS_OK=false
fi

if ! command -v dig &>/dev/null; then
    echo "  [WARN] dig not found — DNS exfil test may skip features"
fi

if ! command -v nc &>/dev/null; then
    echo "  [WARN] nc (netcat) not found — mining pool test may skip features"
fi

if ! command -v node &>/dev/null; then
    echo "  [WARN] node not found — some Node.js-specific simulations will use fallbacks"
fi

if [ "$PREREQS_OK" = false ]; then
    echo ""
    echo "[ERROR] Missing required prerequisites. Install curl and try again."
    exit 1
fi

echo "  [OK] Prerequisites satisfied"
echo ""

# Discover tests
TESTS=()
for test_file in "$SIM_DIR"/test-*.sh; do
    if [ -f "$test_file" ]; then
        TESTS+=("$test_file")
    fi
done

if [ ${#TESTS[@]} -eq 0 ]; then
    echo "[ERROR] No test files found in $SIM_DIR"
    exit 1
fi

echo "[INFO] Found ${#TESTS[@]} test simulations"
echo ""

# Run each test
for test_file in "${TESTS[@]}"; do
    test_name=$(basename "$test_file" .sh)
    TOTAL=$((TOTAL + 1))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Running: $test_name ($TOTAL/${#TESTS[@]})"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if [ ! -x "$test_file" ]; then
        chmod +x "$test_file"
    fi

    START_TIME=$(date +%s)

    if bash "$test_file" 2>&1; then
        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))
        PASSED=$((PASSED + 1))
        echo ""
        echo "  [PASS] $test_name (${DURATION}s)"
    else
        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))
        FAILED=$((FAILED + 1))
        ERRORS+=("$test_name")
        echo ""
        echo "  [FAIL] $test_name (${DURATION}s)"
    fi

    echo ""
done

# Summary
echo "============================================="
echo "  SUMMARY"
echo "============================================="
echo ""
echo "  Total:   $TOTAL"
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo ""

if [ ${#ERRORS[@]} -gt 0 ]; then
    echo "  Failed tests:"
    for err in "${ERRORS[@]}"; do
        echo "    - $err"
    done
    echo ""
fi

TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# Generate report if requested
if [ "$SAVE_REPORT" = true ]; then
    mkdir -p "$REPORT_DIR"
    REPORT_FILE="$REPORT_DIR/report-$(date -u '+%Y%m%d-%H%M%S').md"

    cat > "$REPORT_FILE" << REPORT_EOF
# Fenceline Test Report

- **Date:** $TIMESTAMP
- **Tests run:** $TOTAL
- **Passed:** $PASSED
- **Failed:** $FAILED

## Results

| Test | Status |
|------|--------|
REPORT_EOF

    for test_file in "${TESTS[@]}"; do
        test_name=$(basename "$test_file" .sh)
        STATUS="PASS"
        for err in "${ERRORS[@]}"; do
            if [ "$err" = "$test_name" ]; then
                STATUS="FAIL"
                break
            fi
        done
        echo "| $test_name | $STATUS |" >> "$REPORT_FILE"
    done

    echo "" >> "$REPORT_FILE"
    echo "## Environment" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "- OS: $(uname -s) $(uname -r)" >> "$REPORT_FILE"
    echo "- Arch: $(uname -m)" >> "$REPORT_FILE"
    echo "- Shell: $SHELL" >> "$REPORT_FILE"

    echo "  Report saved: $REPORT_FILE"
    echo ""
fi

# Exit code
if [ "$FAILED" -gt 0 ]; then
    echo "[RESULT] $FAILED test(s) failed."
    exit 1
else
    echo "[RESULT] All $TOTAL tests passed."
    exit 0
fi
