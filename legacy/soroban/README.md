# Soroban contracts (bridge)

- `contracts/bridge-pool/` — the bridge pool: per-denom 30-root window, relayer-gated `update_root`,
  and `withdraw` (cross-contract Groth16 verify -> nullifier spend -> SAC mint to recipient). 9 tests pass.
- The Groth16 verifier is the upstream `circom-groth16-verifier` (vendored), built with our circuit's
  VK embedded (`VERIFIER_VK_JSON=artifacts/circuit/verification_key.json`).

Build/test from inside the vendored workspace (shares soroban-sdk 26 + contract-types + verifier):
  cd vendor/stellar-private-payments
  VERIFIER_VK_JSON=$PWD/../../circuits/build/verification_key.json cargo test -p bridge-pool
