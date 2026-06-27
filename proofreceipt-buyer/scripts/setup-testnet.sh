#!/usr/bin/env bash
set -euo pipefail
RPC="https://soroban-testnet.stellar.org"; PASS='Test SDF Network ; September 2015'
USDC_ISSUER="GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
BUYER=$(stellar keys address e2e-buyer); SELLER=$(stellar keys address e2e-seller)
echo "buyer=$BUYER seller=$SELLER"
# 1. Fund both with XLM (idempotent; ignore already-funded errors).
curl -s "https://friendbot.stellar.org/?addr=$BUYER" >/dev/null || true
curl -s "https://friendbot.stellar.org/?addr=$SELLER" >/dev/null || true
# 2. USDC trustline on BOTH (seller payTo must hold it or settle's SAC transfer fails).
for who in e2e-buyer e2e-seller; do
  stellar tx new change-trust --source-account "$who" --line "USDC:$USDC_ISSUER" \
    --rpc-url "$RPC" --network-passphrase "$PASS" || true
done
# 3. OZ facilitator key.
echo "OZ_API_KEY=$(curl -s https://channels.openzeppelin.com/testnet/gen | python3 -c 'import sys,json;print(json.load(sys.stdin)["apiKey"])')"
echo "NOW fund the BUYER ($BUYER) with testnet USDC at https://faucet.circle.com (select Stellar testnet, asset USDC)."
