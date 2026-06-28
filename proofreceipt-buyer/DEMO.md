# ProofReceipt — agent demo (Claude Desktop)

## One-time setup
1. Build the prover + start the auditor (keep it running):
   cargo build --release --manifest-path proofreceipt-m0/Cargo.toml
   cargo run   --release --manifest-path proofreceipt-server/Cargo.toml -- proofreceipt-server/proofreceipt-server.toml
2. Pre-warm the Groth16 prover (pulls the Docker image, ~once) so the live clean path is ~90s:
   cd proofreceipt-buyer && RECLAIM_SECS=120 ./run-escrow-e2e.sh clean
3. Fund the buyer (e2e-buyer) with testnet USDC + a trustline: https://faucet.circle.com (Stellar testnet).
4. Add proofreceipt to Claude Desktop: merge claude_desktop_config.example.json into your
   claude_desktop_config.json (set <ABS_PATH>), then restart Claude Desktop.

## Demo script (in Claude Desktop)
- Clean path — prompt:
  "I'm about to start using a Soroban token contract ('clean'). Before I trust it,
   get it audited and only proceed if it's provably clean against our policy."
  Expect: get_wallet -> request_audit('clean') -> check_receipt (Open -> Proven -> Claimed).
  The agent reports the proof tx + that the auditor was paid.
- Dirty path — prompt:
  "Now check this other contract ('denylisted') the same way."
  Expect: request_audit('denylisted') -> check_receipt stays Open -> after ~120s the agent
  calls reclaim -> Reclaimed. The agent refuses the contract and shows the refund tx.

## Honesty note
"Clean" = verdict 0 = provably clean against the agreed import/capability policy.
It is NOT a general "safe" guarantee; the proof gives integrity, not privacy.
