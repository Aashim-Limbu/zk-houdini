# Private Cross-Chain Bridge (Stellar ZK)

A simplified, privacy-preserving cross-chain bridge for the Stellar Hacks: ZK hackathon, taking the ICON `intent-relay` (a federated cross-chain *message* relay) as architectural reference. The relay layer is kept thin; the novel work is a **private value layer** built on top of it using zero-knowledge proofs.

## Decided so far

- **Product shape: value on a (single typed) message.** The private value transfer is the product; the "message layer" is a *means*. **Not** a generic `ConnectionV3` relay — the relayer carries one typed message, `DepositInserted{denom, commitment}` (plus an optional return-leg `Release`). Smallest code + audit surface.
- **Privacy scope: unlinkable shielded pool, private from everyone (incl. the relayer/validators).** Deposit a commitment, withdraw by proving in zero-knowledge that you own an unspent deposit without revealing which one. Sender, recipient, amount, and the deposit↔withdrawal link are all hidden. **Consequence:** validators can no longer attest to plaintext message contents — they convey only public **commitments / Merkle roots**; correctness moves into a ZK proof verified on the withdrawal chain, plus a **nullifier** to prevent double-withdrawal.
- **Chains: Stellar = private/ZK side, EVM Sepolia = public side.** Stellar hosts the shielded pool + Soroban Groth16/BLS12-381 verifier (CAP-0059, live). Sepolia hosts a thin lock/release contract + deposit event. Primary direction: **lock on EVM → private claim on Stellar** (puts ZK verification on Soroban, on-theme for the hackathon).
- **Backing trust: single trusted relayer (1-of-1) for the MVP.** The relayer watches the Sepolia lock and inserts the backed commitment into the Stellar pool. Two orthogonal trust domains: *privacy is trustless* (ZK); *backing/solvency is trusted* (one relayer key can, in principle, insert an unbacked commitment). Documented limitation; M-of-N federation (intent-relay's threshold mechanism) is the stated upgrade path.
- **Value model: lock-and-mint, multi-denomination.** Lock test-USDC on Sepolia; the Stellar pool mints a bridged asset and releases on withdrawal. A small fixed set of **denominations** (e.g. 1 / 10 / 100); users combine notes for arbitrary totals. Each denomination is its own anonymity set. Withdrawal circuit stays minimal: **Merkle membership + nullifier only, no amount arithmetic**. (Rejected: arbitrary public amounts — they fingerprint and re-link withdrawals, breaking the chosen unlinkability. See ADR if recorded.)
- **Withdrawal submission: withdrawal relayer (meta-tx).** Recipient is a public input to the proof, so anyone may submit; a relayer submits the Soroban tx so the recipient needs no pre-funded/linkable account. MVP: relayer eats gas (no in-circuit fee split) → public inputs stay `{root, nullifierHash, recipient}`. Bridged asset is a Soroban token deliverable to a fresh address.
- **ZK system: Groth16 over BN254, circom-authored, verified on Soroban (CAP-0074 + CAP-0080 host fns, P25/P26).** Fork `NethermindEth/stellar-private-payments` (deployed BN254 verifier on testnet + circom circuits + ceremony tooling). Curve chosen as the consequence of the on-chain EVM tree (below): **BN254 is the only field with a working Solidity Poseidon**, so one Poseidon works across circom + Solidity + Rust + Soroban. Pin `soroban-sdk = 26` (`Bn254Fr` rename + CAP-0080). Rust owns the on-chain verifier + relayer + tooling; only the circuit is circom. Supersedes the earlier BLS12-381 lock — see ADR-0003 (superseded) → ADR-0004.
- **Noir: rejected for the on-chain verifier (kept as a localnet-only fallback).** Protocol 26 ("Yardstick", mainnet 2026-05-06) / CAP-0080 *genuinely* made UltraHonk verification cheaper (native BN254 MSM + Fr arithmetic) — but it does not cut the pairing floor, the best measured UltraHonk verifier is still ~112M instr (over budget), and no within-budget on-network UltraHonk verify exists today (the one repo is localnet-only, `--limits unlimited`, SDK-v25-pinned, unaudited). Great DX, no hackathon-safe on-network verifier. See ADR-0003.
- **Commitment tree: on-chain on EVM (Sepolia), root mirrored to Stellar.** The Sepolia deposit contract maintains the authoritative incremental Merkle tree on-chain (fork `tornado-core` `MerkleTreeWithHistory.sol`: configurable depth ~20, ring-buffer root history `ROOT_HISTORY_SIZE=30`). The **Backing Relayer** watches new-root events and anchors a recent EVM root into the Soroban pool's **Root Window**; the Soroban contract stores the root window + **Nullifier Set**, never hashes the tree. Withdrawal circuit proves membership against an EVM root the Soroban side trusts. (Chosen for EVM-as-source-of-truth + a path toward a trustless light client; cost = Poseidon in Solidity, which forced the BN254 curve.)
- **Circuit form: plain 2-input Tornado.** `commitment = H(nullifier, secret)`, `nullifierHash = H(nullifier)`. Drop ASP/association-set + labels (the prior art's compliance extensions) for the MVP. Multi-denomination via one independent pool/tree per denomination.
- **In-circuit hash: Poseidon2 over BN254 (HorizenLabs `zkhash`).** ⚠️ **KEYSTONE:** the Poseidon *instantiation* must be byte-identical across circom + Rust (`zkhash` `POSEIDON2_BN256_PARAMS_2`, compression `P(l,r)[0]+l`) + Solidity. NethermindEth is **Poseidon2, NOT classic Poseidon1** — stock `poseidon-solidity`/circomlib are Poseidon1 and will NOT match. Day-1: assert a shared `hash([1,2])` vector across all three before writing anything else. Fallback ladder if Poseidon2-in-Solidity is fiddly: Poseidon1 + `poseidon-solidity` for the EVM tree (extra membership sub-circuit) → stock tornado MiMCSponge.

## Language

These are the domain terms inherited from `intent-relay` that we expect to keep. Terms specific to the private/ZK layer will be added as they are resolved.

**Bridge**:
The whole system that moves value from a source chain to a destination chain privately. Note: in `intent-relay` there is no "bridge" in the value sense — it only moves messages — so the value semantics here are net-new.
_Avoid_: "relay" when you mean the value transfer (relay = the message transport only).

**Deposit Message**:
The single typed message the relayer carries EVM→Stellar: `DepositInserted{denom, commitment}`. (Replaces intent-relay's generic cleartext `{srcChainId, srcAddress, connSn, dstChainId, dstAddress, payload}` envelope — we are not building a generic relay.)

**Lock Contract** (Sepolia):
The thin EVM contract that locks test-USDC in a chosen **Denomination** and emits a deposit event carrying the user's **Commitment**. No payload interpretation, no validator set.

**Shielded Pool** (Stellar) — see Private value layer below — is the destination contract; there is no generic "connection contract" per chain in our design.

**Backing Relayer**:
The off-chain process that watches the Sepolia **Lock Contract** and inserts the backed **Commitment** into the Stellar tree / submits the new **Root** to the **Shielded Pool**. Trusted for solvency (1-of-1 in the MVP). Also maintains the off-chain Merkle tree.

**Withdrawal Relayer**:
An off-chain submitter that posts a user's withdrawal proof transaction to Stellar so the recipient stays unlinkable. Trusted for liveness only — it cannot steal (the proof binds the recipient) or forge.
_Avoid_: "the relayer" unqualified — there are two, with different trust.

**Verifier**:
An off-chain attestor that independently re-reads the source transaction, confirms the Message really was emitted, and produces a signature over it. (In `intent-relay` a verifier is also a signer.)

**Executor**:
The off-chain submitter that delivers a verified Message (plus its proofs/signatures) to the destination connection contract.

**Validator Set**:
The set of authorized signer public keys registered in a connection contract. Trust is collective: ≥ threshold of them can forge any message.

**Threshold** (M-of-N):
The minimum number of distinct valid attestations a destination contract requires before accepting a Message.

**connSn** (connection sequence number, a.k.a. **nonce**):
Per-connection monotonic counter assigned when a Message is sent. Together with `srcChainId` it is both the unique message id and the replay key.

**Receipt** (replay guard):
Destination-side record that `(srcChainId, connSn)` has already been executed, preventing replay. In our private design this is replaced by the **Nullifier Set**.

### Private value layer (new)

**Shielded Pool**:
The Soroban contract on Stellar that holds the bridged value, the set of valid commitment-tree roots, and the nullifier set. Deposits add commitments; withdrawals spend them via ZK proof.

**Commitment**:
A hiding, binding value (a hash of `{secret, nullifier-seed}`, scoped to a denomination) recorded when value is deposited. Reveals nothing about the depositor; later "opened" inside a ZK proof at withdrawal.

**Note**:
The secret data a user holds that opens one Commitment (secret + nullifier seed + which denomination). Possession of the Note authorizes withdrawing exactly that denomination.

**Denomination**:
One of a small fixed set of allowed transfer sizes (e.g. 1 / 10 / 100). Deposits and withdrawals happen in whole denominations; each denomination forms a separate Anonymity Set. Arbitrary totals are achieved by combining several Notes.

**Commitment Tree** (Merkle):
The append-only Merkle tree of all Commitments — maintained **on-chain on Sepolia** (one per denomination). Withdrawal proves membership of one leaf against a known **Root** without revealing which leaf.

**Pinned Hash** (Poseidon2-BN254):
The single Poseidon2 instantiation (HorizenLabs `zkhash` `POSEIDON2_BN256_PARAMS_2`, compression `P(l,r)[0]+l`) used identically in the circom circuit, the Rust relayer, and the Solidity tree. Its byte-for-byte agreement across all three surfaces is the project keystone. _Avoid_: "Poseidon" unqualified — Poseidon1 ≠ Poseidon2 and they do not interoperate.

**Root**:
The Merkle root of the Commitment Tree at a point in time. The Shielded Pool accepts proofs against a set of recent valid Roots.

**Root Window**:
The rolling on-chain set of the last ~30 valid Roots the Shielded Pool will accept a proof against. Tolerates deposits that move the tree tip between proof-generation and submission.

**Nullifier**:
A secret value inside a Note. Its public, deterministic image — the **Nullifier Hash** = `H(nullifier)` — is published at withdrawal and recorded in the **Nullifier Set** to prevent the same Note being withdrawn twice. The Nullifier Hash cannot be linked back to its Commitment.

**Anonymity Set**:
The set of deposits a given withdrawal is indistinguishable among. Larger = more privacy; equals 1 in a single-deposit demo (mechanism shown, privacy not yet meaningful).

## Relationships

- A **Bridge** is composed of a **Connection Contract** on each chain, plus an off-chain **Relayer**.
- The **Relayer** runs one or more **Verifiers** (source side) and one or more **Executors** (destination side).
- A **Verifier** produces attestations; a destination **Connection Contract** accepts a **Message** once it has ≥ **Threshold** attestations from the **Validator Set**.
- Each **Message** carries a **connSn**; the destination records a **Receipt** per `(srcChainId, connSn)` to block replay.

## Flagged ambiguities

Naming drift inherited from `intent-relay` — we will pick ONE name per concept in our build:

- **connSn vs nonce** — same field; pick one term. (Recommend: `nonce`.)
- **Receipt** has four names in the reference (`get_receipt` / `MessageReceived` / `query_has_receipt` / `verify_message`'s receipt write) — one concept.
- **recv_message / recvMessage / receive_message / recvMessageWithSignature** — destination delivery entrypoint, name varies per chain; pick one.
- **"KMS" signer** is a misnomer in the reference (keys live in SSM Parameter Store, not AWS KMS). We are not bound by that naming.
- **Threshold vs VALID_SIGNER_COUNT** — the reference has an on-chain threshold AND a separate off-chain count that must agree; a known footgun. We should keep a single source of truth.
- **srcAddress / dstAddress encoding differs per chain** (EVM packs 20 bytes; Stellar uses full XDR `Address`). The bytes hashed off-chain must match the bytes hashed on-chain exactly, or nothing verifies.
- **Signature curve is inconsistent in the reference** (on-chain `verify_signatures` uses secp256k1_recover, but Stellar is listed in `ed_supported_chains` for ed25519). To be resolved for our build.

## Example dialogue

> **Dev:** "When Alice deposits on Sepolia, how does Stellar know to let her withdraw?"
> **Domain expert:** "The **Backing Relayer** sees the Sepolia lock, inserts Alice's **Commitment** into the off-chain tree, and submits the new **Root** to the **Shielded Pool**. Later Alice (via a **Withdrawal Relayer**) proves in zero-knowledge that she owns a **Note** whose Commitment is under one of the Roots in the **Root Window**, and publishes a **Nullifier Hash** so she can't withdraw it twice. The pool never learns *which* deposit was hers."

## References (fork targets — Stack A, BN254)

- **`NethermindEth/stellar-private-payments`** — PRIMARY. BN254 Groth16 Soroban verifier (`contracts/circom-groth16-verifier/`, g1_mul+g1_add loop, VK G2 as compile-time constants), pool contract, circom circuits (Poseidon2 `zkhash`), ceremony tooling (`tools/ceremony-cli`). Deployed on testnet. Full-clone, record HEAD SHA, pin.
- **`tornadocash/tornado-core`** — `MerkleTreeWithHistory.sol` for the Sepolia on-chain tree (ring-buffer root history, configurable depth). Swap MiMCSponge → Poseidon to match the circuit's hash.
- **`HorizenLabs/poseidon2`** (`zkhash`) — Poseidon2-BN254 reference (`POSEIDON2_BN256_PARAMS_2`); the canonical source for the pinned hash on the Rust side. Use its test vectors to validate circom + Solidity parity.
- **`geovgy/poseidon-solidity`** (vendored mirror; upstream deleted) / **`zk-kit/zk-kit.solidity`** (LeanIMT) — Solidity Poseidon for the EVM tree. ⚠️ These are **Poseidon1** — only for the Poseidon1 fallback path, NOT a match for Nethermind's Poseidon2.
- **`ymcrcat/soroban-privacy-pools`** — Stack B (BLS12-381) only; not used unless the curve decision is reverted. Reference for `circom2soroban`.

⚠️ All references are demo/unaudited. This bridge is a hackathon prototype — never frame it as securing real funds.
