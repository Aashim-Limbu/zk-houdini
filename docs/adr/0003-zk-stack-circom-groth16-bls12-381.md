# ZK stack & curve: circom + Groth16 over BLS12-381 (fork ymcrcat/soroban-privacy-pools)

> **Status: superseded by [ADR-0004](./0004-flip-to-bn254-onchain-evm-tree.md).** The curve was later flipped from BLS12-381 to BN254 because the decision to maintain the commitment tree on-chain on EVM requires a Solidity Poseidon, which only exists for BN254. The proving-system choice (Groth16, circom-authored, Rust-owned verifier/relayer) and the Noir rejection below still stand; only the curve and fork target changed.

We verify withdrawals with **Groth16 over BLS12-381** on Soroban (CAP-0059 host functions, live since Protocol 22 / Dec 2024), authoring the circuit in **circom** and forking the Stellar Foundation reference `ymcrcat/soroban-privacy-pools` (plus `stellar/soroban-examples/groth16_verifier`). Rust still owns the on-chain verifier, the relayer, and the off-chain Merkle/commitment tooling; only the circuit is circom.

**Decisive factors:** a *verified* within-budget cost (~41M instructions, ~59% headroom on the ~100M per-tx limit) and a fork-able, same-shape (commitment + Merkle membership + nullifier) reference.

**Rejected alternatives:**
- **Noir + UltraHonk** — best circuit DX, and Protocol 26 / CAP-0080 (mainnet 2026-05-06) genuinely made UltraHonk verification cheaper (native BN254 MSM + Fr arithmetic). But CAP-0080 does not cut the pairing-cost floor; the best measured UltraHonk verifier is still ~112M instructions (over the ~100M budget); and there is no within-budget on-network verify today (the only repo is localnet-only, `--limits unlimited`, SDK-v25-pinned, unaudited). Kept only as a localnet-demo fallback. The Noir→BLS12-381-Groth16 backend ("Interstellar") is an unshipped grant proposal.
- **arkworks all-Rust (BLS12-381)** — same curve/budget and single-language, but no fork-able mixer and more hand-written constraints / soundness ownership. Kept as the in-Rust fallback if circom tooling drifts.
- **BN254 (fork NethermindEth/stellar-private-payments)** — multi-denom and deployed on testnet, but its verify cost is unpublished, whereas BLS12-381 has the hard verified number and the official reference.

**Day-1 spike (de-risk before building features):** full-clone the fork (record HEAD SHA), build the circuits with pinned tooling, deploy the verifier to Stellar testnet, and confirm one real proof verifies within budget. Green light = a sample proof passes `pairing_check` on testnet inside the 100M-instruction limit.
