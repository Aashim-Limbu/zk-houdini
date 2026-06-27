# ProofReceipt M0 — RISC Zero prove → verify on Soroban

The thinnest possible end-to-end proof of life: a Rust guest program is **proven** with
RISC Zero (Groth16), and that proof is **verified on Stellar testnet** by the NethermindEth
RISC Zero verifier. No x402 — just the hardest part de-risked first: *does a real RISC Zero
proof verify on Soroban?*

This is isolated from the bridge (`soroban/`, `relayer/`, `frontend/`) — nothing here
touches it.

## What the guest does (M3 — current)

The M0 guest was originally a trivial squaring program — the thinnest possible proof to
de-risk the RISC Zero ↔ Soroban path. The guest has since been replaced (M3) by a real
**WASM capability-policy auditor** via the `wasm-policy` crate
(`methods/guest/wasm-policy/`). It parses the import section of a Soroban contract WASM and
produces a 36-byte journal:

```
sha256(wasm_bytes)  [32 bytes]  ‖  verdict  [4-byte LE u32]
```

The verdict bitmask encodes policy violations:
- `0` — clean (no violations)
- bit 0 (`1`) — allowlist violation (an imported host fn is not on the allowlist)
- bit 1 (`2`) — denylist hit (an imported host fn is on the denylist)
- bit 2 (`4`) — an auth host function is imported (import-level only; does not trace runtime paths)

Malformed WASM fails closed — no proof is produced. Live results on testnet: `clean.wasm` →
verdict 0; `denylisted.wasm` → verdict 2.

The on-chain verifier confirms that **this exact program** produced **this exact journal** —
the `verify(seal, image_id, journal)` call that ProofReceipt gates USDC settlement on.

## Layout

```
proofreceipt-m0/
├── methods/guest/   # the program whose execution is proven (Rust → RISC-V)
├── methods/         # build glue → M0_GUEST_ELF, M0_GUEST_ID
├── host/            # runs the guest, makes a Groth16 receipt, prints (seal, image_id, journal)
└── scripts/         # deploy the leaf verifier, then call verify() on testnet
```

## Prerequisites

- RISC Zero toolchain: `curl -L https://risczero.com/install | bash && rzup install`
- **Docker running** + **x86_64** (Groth16 proving requirement)
- Stellar CLI + a funded testnet identity:
  `stellar keys generate m0 --network testnet --fund`

## Run it

```bash
# 1. Build (compiles the guest to RISC-V)
cargo build --release

# 2. Prove — produces proof.json with seal/image_id/journal_digest.
#    Pass a real .wasm file to audit; first run pulls a Docker image (several minutes).
cargo run --release -p m0-host -- \
  --input methods/guest/wasm-policy/tests/fixtures/clean.wasm --out proof.json

# 3. Deploy the leaf RISC Zero verifier to testnet (clones the Nethermind repo)
SOURCE=m0 ./scripts/deploy_verifier.sh

# 4. Verify the proof on-chain — success = verify() returns without trapping
SOURCE=m0 ./scripts/verify_onchain.sh
```

## Version pin (important)

The deployed verifier's `parameters.json` targets RISC Zero **3.0.x**; this project pins
`risc0-zkvm = "3.0"` and the toolchain is **3.0.5**. They must stay on the same 3.0 line —
a mismatch changes the 4-byte seal selector and verification fails.

## Reproducing `image_id`

`image_id` (`M0_GUEST_ID`) is the program commitment that anchors the whole "this exact
program ran" guarantee, so it must be reproducible. The agreed value is
`ffc622e891883f70242e3dfea5ccb2b68b73136b30aed868f8f48242cc9eeddd`. To reproduce it:

- The **`Cargo.lock` files are committed** (workspace + `methods/guest` + `wasm-policy`), so the
  guest's dependency graph is pinned. The Soroban verifier interface is pinned by exact git
  `rev` in `proofreceipt-contract`.
- Build with **`cargo-risczero` / `r0vm` 3.0.5** and host **rustc 1.94.1** (the versions this
  image was built with), then `cargo build -p m0-host` — `risc0-build` compiles the guest with
  the RISC Zero RISC-V toolchain and bakes `M0_GUEST_ID`.

> No `rust-toolchain.toml` is added under `methods/guest/`: `risc0-build` selects the RISC Zero
> guest toolchain itself, and a stray channel pin there would fight it. Pin the host toolchain
> via your environment if you need byte-identical host artifacts.

## What M0 de-risks (done)

- ✅ Local Groth16 proving works on this machine (free, no Bonsai/SP1 credits).
- ✅ The Nethermind verifier accepts our seal on testnet.
- ✅ The version pin (prover 3.0.5 ↔ verifier 3.0.0) lines up.

M1–M3 are all shipped and live on testnet, building on this foundation:
- **M1** — settle-core escrow contract (`open_job` / `submit_proof` / `claim`) gates USDC release on a valid Groth16 seal.
- **M2** — x402 v2 audit server + buyer client; proof-as-receipt over real USDC.
- **M3** — guest replaced with the real bounded WASM capability-policy auditor (this crate, `wasm-policy`); image_id `ffc622e891883f70242e3dfea5ccb2b68b73136b30aed868f8f48242cc9eeddd`.
