#!/usr/bin/env bash
# Live escrow e2e against the verdict-enforced settle-core on Stellar testnet.
#
#   ./run-escrow-e2e.sh clean   # USDC -> seller  (provably-clean artifact, claimed)
#   ./run-escrow-e2e.sh dirty   # USDC -> buyer   (dirty artifact declined, reclaimed)
#   ./run-escrow-e2e.sh both    # run clean then dirty
#
# Prerequisites (real USDC path):
#   1. The seller server is running with a built m0-host + Docker available:
#        cargo build --release --manifest-path ../proofreceipt-m0/Cargo.toml
#        cargo run   --release --manifest-path ../proofreceipt-server/Cargo.toml
#   2. The buyer identity (BUYER_KEY, default e2e-seller's counterpart e2e-buyer) is
#      funded with testnet XLM *and* holds USDC (Circle faucet: https://faucet.circle.com,
#      select Stellar testnet) with a USDC trustline.
#   3. The seller identity (SELLER_KEY, default e2e-seller) is funded with testnet XLM.
#
# Override any default via env, e.g. RECLAIM_SECS=60 BUYER_KEY=my-buyer ./run-escrow-e2e.sh both
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-both}"
SERVER_URL="${SERVER_URL:-http://127.0.0.1:8081}"
BUYER_KEY="${BUYER_KEY:-e2e-buyer}"
SELLER_KEY="${SELLER_KEY:-e2e-seller}"

command -v stellar >/dev/null || { echo "❌ stellar CLI not found on PATH"; exit 1; }
command -v node >/dev/null    || { echo "❌ node not found on PATH"; exit 1; }

echo "→ checking seller server at $SERVER_URL …"
curl -fsS "$SERVER_URL/health" >/dev/null 2>&1 \
  || { echo "❌ seller server not reachable at $SERVER_URL/health — start proofreceipt-server first"; exit 1; }
echo "✅ server up"

echo "→ buyer=$(stellar keys address "$BUYER_KEY" 2>/dev/null || echo '<unknown identity '"$BUYER_KEY"'>')"
echo "→ seller=$(stellar keys address "$SELLER_KEY" 2>/dev/null || echo '<unknown identity '"$SELLER_KEY"'>')"
echo "   (the buyer must hold testnet USDC with a trustline; the dirty path needs no prove/Docker)"

run() { echo; echo "════════ $1 path ════════"; npm run --silent escrow:run -- "$1"; }

case "$MODE" in
  clean) run clean ;;
  dirty) run dirty ;;
  both)  run clean; run dirty ;;
  *) echo "usage: $0 <clean|dirty|both>"; exit 2 ;;
esac

echo; echo "✅ e2e ($MODE) complete — tx hashes + explorer links are in the stellar output above."
