# legacy/ — prior work (not part of ProofReceipt)

This directory holds an **earlier Stellar Hacks project** that preceded the pivot to
ProofReceipt: a **private cross-chain bridge** (codename *zk-houdini*) that deposited USDC
on Ethereum Sepolia and let you withdraw unlinkably on Stellar via a Groth16/BN254 proof
verified on Soroban.

It is kept for history and because ProofReceipt reuses the on-chain BN254 verification
experience gained here — but it is **not built, tested, or shipped as part of ProofReceipt**.

| Path | What it was |
|---|---|
| `circuits/` | Circom circuits (commitment / nullifier / Merkle) |
| `evm-tree/` | Solidity deposit contract + incremental Merkle tree (Sepolia) |
| `relayer/` | Off-chain relayer (EVM→Stellar proof conversion + path service) |
| `soroban/` | Bridge-side Soroban contracts (shielded pool) |
| `spike/` | Spikes / experiments |
| `artifacts/`, `deployments/` | Build artifacts + deployment records |
| `CONTEXT.md` | Bridge design context |

**The active project is at the repo root:** `proofreceipt-m0/`, `proofreceipt-contract/`,
`proofreceipt-server/`, `proofreceipt-buyer/`. See the top-level `README.md`.
