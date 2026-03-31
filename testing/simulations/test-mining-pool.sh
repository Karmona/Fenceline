#!/bin/bash
# =============================================================================
# Fenceline Test: Cryptocurrency Mining Pool Connection
# =============================================================================
# Simulates: Package that connects to a mining pool on non-standard port
# Real-world examples: Ultralytics PyPI compromise (2024)
#
# Attack pattern:
#   1. Compromised package installs normally
#   2. Postinstall or runtime code connects to mining pool
#   3. Connection uses non-standard ports (3333, 4444, 5555, 8333, 14433)
#   4. Stratum mining protocol over TCP
#
# Safety: All connections to localhost only. Uses nc (netcat) to simulate
#         the mining pool listener.
# =============================================================================

set -euo pipefail

MINING_PORT=3333
LISTENER_PID=""

cleanup() {
    echo ""
    echo "[CLEANUP] Stopping mock mining pool..."
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
    fi
    echo "[CLEANUP] Done."
}
trap cleanup EXIT

echo "============================================="
echo "  Fenceline Test: Mining Pool Connection"
echo "============================================="
echo ""

# --- SETUP ---
echo "[SETUP] Starting mock mining pool listener on localhost:$MINING_PORT..."

# Use Python as a simple TCP listener (more portable than nc variants)
python3 -c "
import socket, threading, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $MINING_PORT))
s.listen(1)
s.settimeout(10)
try:
    conn, addr = s.accept()
    data = conn.recv(1024)
    sys.stdout.write(f'  [POOL] Received connection from {addr}\n')
    sys.stdout.write(f'  [POOL] Data: {data.decode(errors=\"replace\")[:100]}\n')
    conn.send(b'{\"id\":1,\"result\":true}\n')
    conn.close()
except socket.timeout:
    sys.stdout.write('  [POOL] No connection received (timeout)\n')
s.close()
" &
LISTENER_PID=$!
sleep 1
echo "[SETUP] Mock mining pool running (PID $LISTENER_PID)"
echo ""

# --- SIMULATION ---
echo "[SIMULATION] Simulating mining pool connection patterns..."
echo ""

# Pattern 1: Stratum protocol login (what a miner sends to a pool)
echo "[SIM 1/2] Sending Stratum mining protocol login to localhost:$MINING_PORT"
STRATUM_LOGIN='{"id":1,"method":"mining.subscribe","params":["simulated-miner/1.0"]}'
echo "$STRATUM_LOGIN" | nc -w 2 127.0.0.1 "$MINING_PORT" 2>/dev/null || true
echo "  -> Stratum subscribe sent to port $MINING_PORT"
echo ""

sleep 2

# Pattern 2: Check well-known mining ports
echo "[SIM 2/2] Scanning well-known mining ports (localhost only)"
MINING_PORTS=(3333 4444 5555 8333 14433 14444)
for p in "${MINING_PORTS[@]}"; do
    if [ "$p" -eq "$MINING_PORT" ]; then
        echo "  -> Port $p: OPEN (our mock listener)"
    else
        # Just attempt connection, will fail immediately (no listener)
        nc -z -w 1 127.0.0.1 "$p" 2>/dev/null && echo "  -> Port $p: OPEN" || echo "  -> Port $p: closed (expected)"
    fi
done
echo ""

# --- DETECTION POINTS ---
echo "============================================="
echo "  DETECTION POINTS"
echo "============================================="
echo ""
echo "A supply chain detector should flag ALL of the following:"
echo ""
echo "  1. NON-STANDARD PORT CONNECTION"
echo "     -> Port $MINING_PORT is NOT 443 (the only legitimate install port)"
echo "     -> Any TCP connection on ports 3333, 4444, 5555, 8333, 14433, 14444"
echo "     -> These are well-known cryptocurrency mining pool ports"
echo ""
echo "  2. STRATUM PROTOCOL PATTERN"
echo "     -> JSON-RPC with method 'mining.subscribe' or 'mining.authorize'"
echo "     -> Persistent TCP connection (not HTTP request/response)"
echo "     -> Binary or JSON data over raw TCP"
echo ""
echo "  3. UNEXPECTED PROCESS BEHAVIOR"
echo "     -> Package install process opening raw TCP sockets"
echo "     -> Long-lived connections during what should be a quick install"
echo "     -> CPU usage spike after package installation"
echo ""
echo "  4. DESTINATION NOT IN KNOWN MAP"
echo "     -> Mining pools are never in the deep map"
echo "     -> Any connection to an IP not in the CDN range files is suspect"
echo ""
echo "[RESULT] Test simulation complete."
