# Trust model: privacy is trustless, backing is a trusted relayer (1-of-1 for MVP)

We split trust into two orthogonal domains. **Privacy** — unlinkability of a deposit from its withdrawal — is enforced trustlessly by a zero-knowledge proof verified on-chain; no operator can break it. **Backing/solvency** — that a Stellar-side commitment is backed by a real Sepolia lock — is enforced by a **single trusted relayer (1-of-1)** that watches the Sepolia lock and inserts the backed commitment / submits the new root to the Soroban pool.

We chose a single trusted relayer over an M-of-N federation or a trust-minimized EVM light client because it concentrates scarce hackathon effort on the novel ZK privacy layer while leaving an honest, well-understood limitation. The intent-relay M-of-N threshold mechanism and an EVM light client / storage-proof are the documented upgrade paths.

**Consequence:** a compromised relayer key could insert an unbacked commitment (mint unbacked value). Acceptable for a testnet prototype; never frame this as securing real funds.
