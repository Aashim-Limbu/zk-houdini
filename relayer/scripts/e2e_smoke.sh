#!/usr/bin/env bash
# e2e relayer-plumbing smoke. Proves the backing daemon + withdrawal server
# against the LIVE testnet using the existing known-good proof artifacts.
# Prereqs: relayer/config.toml present; `cast` (foundry) + `stellar` on PATH;
# a recipient account with a zUSDC trustline; env vars below.
#
#   RECIPIENT   : G... account that holds a zUSDC trustline (mint destination)
#   BASE        : relayer base URL (default http://127.0.0.1:8080)
set -euo pipefail
cd "$(dirname "$0")/../.."   # run from repo root so artifacts/ paths resolve
BASE="${BASE:-http://127.0.0.1:8080}"
RECIPIENT="${RECIPIENT:?set RECIPIENT to a G-address holding a zUSDC trustline}"
ART="artifacts/circuit"

echo "== 1. health =="
curl -fsS "$BASE/health" | tee /dev/stderr | grep -q '"status":"ok"'

echo "== 2. path for denom 10 leaf 0 =="
curl -fsS "$BASE/path?denom=10&leaf_index=0" | tee /tmp/path.json

echo "== 3. withdraw using known-good artifacts (root already anchored on-chain) =="
PROOF=$(cat "$ART/proof.json")
ROOT="0012f4149c6840973c2dee91e8ecd7dd2839be83b143607114e7b4cd70bd86d4"
# nullifier_hash + recipient_fr come from the artifacts' public signals (public.json:
#   [root, nullifierHash, recipient, denomination]).
NH=$(python3 -c "import json;print(f'{int(json.load(open(\"$ART/public.json\"))[1]):064x}')")
RFR=$(python3 -c "import json;print(f'{int(json.load(open(\"$ART/public.json\"))[2]):064x}')")
curl -fsS -X POST "$BASE/withdraw" -H 'content-type: application/json' -d @- <<JSON | tee /tmp/withdraw.json
{
  "proof": $PROOF,
  "root": "$ROOT",
  "nullifier_hash": "$NH",
  "recipient_fr": "$RFR",
  "recipient": "$RECIPIENT",
  "denom": 10
}
JSON

echo "== 4. assert a tx hash came back =="
grep -q '"tx_hash"' /tmp/withdraw.json && echo "SMOKE OK"
