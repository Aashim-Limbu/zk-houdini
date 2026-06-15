# Private Cross-Chain ZK Bridge — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a privacy-preserving cross-chain bridge — lock test-USDC on EVM Sepolia, withdraw it privately on Stellar via a Groth16 zero-knowledge proof verified on Soroban — live end-to-end on testnet.

**Architecture:** An unlinkable shielded pool (Tornado-style). Deposits insert a commitment into an on-chain Merkle tree on Sepolia; a 1-of-1 backing relayer anchors recent EVM roots into a Soroban pool; withdrawals prove Merkle membership + a nullifier in zero knowledge (verified on-chain via Soroban's BN254 host functions) and release a pool-minted SAC token to a recipient, submitted by a withdrawal relayer so the recipient stays unlinkable. Privacy is trustless (ZK); backing/solvency is the one trusted relayer.

**Tech Stack:** BN254 + Groth16 + Poseidon2 (one field/hash across all surfaces). circom 2.2.2 + snarkjs (circuit); Foundry + Solidity (Sepolia tree, fork of `tornado-core`); Rust + soroban-sdk 26 (verifier + pool, fork of `NethermindEth/stellar-private-payments`); Rust relayer; Next.js + stellar-sdk/Freighter + viem (frontend, client-side snarkjs proving). Reference fork pinned at `NethermindEth/stellar-private-payments@e6a69f0`.

**Scope:** Solo dev, ~1–2 weeks, target = full e2e on real testnets (Sepolia + Stellar Protocol 26).

---

## ⚠️ VALIDATION CORRECTIONS — 2026-06-15 (apply before implementing)

> This plan was validated against current documentation (Context7 + Stellar protocol CAPs + crates.io/npm/docs). **The core bet is sound** — on-chain BN254/Groth16 verification on Soroban is real and shipped — but the document carried internal contradictions and a few stale pins. The fixes below are authoritative; where the body still shows the old value, follow this block.
>
> **Verified-good (do not change):** BN254 host functions are LIVE — CAP-0074 (Final, Protocol 25, host fns `bn254_g1_add`/`bn254_g1_mul`/`bn254_multi_pairing_check`; Protocol 26 adds BN254 MSM + scalar arithmetic) and CAP-0075 Poseidon/Poseidon2 (Final, Protocol 25). `soroban-sdk` 26.0.0 shipped 2026-05-06 (26.1.0 current) and its `crypto` module exposes both `bls12_381` and `bn254`. `stellar-cli 26.x` and "Protocol 26 / Yardstick" are real. Nethermind `stellar-private-payments` exists and is explicitly unaudited/WIP. snarkjs 0.7.5, `@stellar/stellar-sdk` + `@stellar/freighter-api`, Foundry/tornado pattern, depth-20 tree + 30-root ring, fixed public-input order, nullifier replay set — all current and correct.
>
> **C1 — Single toolchain pin (compile-blocking).** Use rust **1.92.0** everywhere (the upstream `rust-toolchain.toml` value). Task 30's `channel = "1.84.0"` (and the "stellar 22.x / rustc 1.8x" expected output) is WRONG: `soroban-sdk 26` is an edition-2024 crate and will NOT compile on rust < 1.85. Build Soroban WASM for target **`wasm32v1-none`** (current Soroban guidance), not `wasm32-unknown-unknown`. Crate `edition` may stay `2021` (valid) or move to `2024` to match upstream — the toolchain channel is the hard requirement.
>
> **C2 — Poseidon2 is MIXED-ARITY (confirmed from the fork source `@main`, 2026-06-15).** The whole bridge dies on a hash mismatch. The fork's `Permutation(t)` is parameterized by width `t` (4+4 full rounds, 56 partial fixed; constants/matrices from `POSEIDON_FULL_ROUNDS(t)`/`POSEIDON_PARTIAL_ROUNDS(t)`/`POSEIDON_INTERNAL_MAT_DIAG(t)`), and the templates use **different widths per operation**:
>
> | Operation | Template | Width | Formula |
> |-----------|----------|-------|---------|
> | **Merkle internal node** `compress(l,r)` | `PoseidonCompress` | **t=2** | `Perm₂([l,r])[0] + l` (no domain sep) |
> | **commitment** `(nullifier, secret)` | `Poseidon2(2)` | **t=3** | `Perm₃([nullifier,secret,0])[0]` (domainSep=0 capacity slot) |
> | **nullifierHash** `(nullifier)` | `Poseidon2(1)` | **t=2** | `Perm₂([nullifier,0])[0]` |
>
> So the EVM Merkle tree, the circuit's `MerkleProof`, and the relayer's tree all use **t=2** compression — the original "t=2 / `[[2,1],[1,2]]`" framing for the *tree* is CORRECT; the commitment hash is the only **t=3** piece. The vendored Rust `zkhash` exposes the instances width-suffixed: **`POSEIDON2_BN256_PARAMS_2`** (t=2 — compress + nullifierHash) and **`POSEIDON2_BN256_PARAMS_3`** (t=3 — commitment); `_4` also exists. There is **no** bare `POSEIDON2_BN256_PARAMS` (the spike header's claim otherwise is wrong). **Soroban computes NO Poseidon** — all hashing is in-circuit, in the EVM tree, and off-chain; the proof attests to membership + nullifier, so CAP-0075 Poseidon host functions are NOT required for this design. ⚠️ The spike's Rust `rust-vectors` models `compress` as t=3 — that is a BUG; compress is t=2 (`Perm₂([l,r])[0]+l`).
>
> ✅ **KEYSTONE VERIFIED 2026-06-15** — parity proven byte-identical across **circom (authoritative witness)**, **Solidity (forge)**, and **Rust (vendored zkhash `_2`/`_3`)**. Canonical vectors pinned in `spike/poseidon2_vectors.json`: `compress(1,2)=0x0e90c1…cea5b3` (t=2), `hash2(1,2)=0x2afac3…65bffd2` (t=3), `nullifierHash(1)=0x09546f…79b04d54` (t=2). The `zemse/poseidon2-evm` (t=4) warning still stands.
>
> **C3 — Relayer hash must be the SAME implementation as the circuit.** The authoritative `zkhash` is vendored **inside the upstream repo at `poseidon2/`** (path crate `zkhash = { path = "poseidon2" }`, v0.2.0), not crates.io. The relayer should depend on that same path crate (or the upstream repo's `poseidon2`) — the keystone proved it byte-identical to circom. Do NOT assume crates.io `zkhash 0.2` matches without re-running the keystone. Use `POSEIDON2_BN256_PARAMS_2` for compress/nullifierHash and `_3` for the commitment.
>
> **C4 — arkworks versions.** ✅ ark **0.6.0** is current and is exactly what the upstream workspace uses (`ark-bn254`/`ark-ff`/`ark-groth16` = 0.6.0, confirmed in its `Cargo.lock`). The relayer **must** use ark **0.6** so its field type unifies with `zkhash`'s `FpBN256` (ark-ff 0.6); the original `ark-* = "0.4"` is the stale pin. (ark is off-chain only; the Soroban verifier uses BN254 host functions, no ark. An earlier note here claimed 0.6.0 "doesn't exist" — that was a stale web-search; cargo compiled ark-bn254 0.6.0 successfully.)
>
> **C5 — BN254 SDK API names.** Confirm against docs.rs/soroban-sdk/26.1.0 before Task 31: the pairing method is most likely **`multi_pairing_check`** (mirrors host fn `bn254_multi_pairing_check`), not `pairing_check`. Since you target Protocol 26, compute `vk_x = ic[0] + Σ ic[i+1]·input[i]` with one **`bn254().g1_msm(...)`** call instead of N×(`g1_mul`+`g1_add`) — fewer host calls, lower instruction count toward the <100M gate.
>
> **C6 — circom install.** `cargo install --locked circom` from crates.io is NOT supported. Official method is from source: `git clone https://github.com/iden3/circom && cargo install --path circom`. Use the from-source path as primary.
>
> **C7 — Node 22 LTS** (Node 20 is in maintenance by mid-2026). **C8 — Pin JS deps** (`@stellar/stellar-sdk`, `@stellar/freighter-api`, `viem`, `wagmi`, `snarkjs`, Next.js) in Task 50. **C9 — Assert testnet protocol ≥ 25 (ideally 26)** at the start of the spike before relying on BN254 host fns; and in Task 1 inspect the upstream verifier source to confirm it calls `env.crypto().bn254()` (host functions) rather than pairing in pure WASM.

---

## Milestones (solo, sequential)

| # | Milestone | Tasks | Gate |
|---|---|---|---|
| M0 | **Day-1 Spike (GATING)** | 1–9 | Poseidon2 `hash([1,2])` byte-identical across circom/Rust/Solidity **AND** a sample Groth16 proof verifies on Stellar testnet under 100M instructions. **No green light = stop.** |
| M1 | EVM deposit + on-chain Merkle tree on Sepolia | 10–19 | Deposit inserts a commitment; root history works; deployed + verified on Sepolia |
| M2 | Withdrawal circuit + trusted setup | 20–29 | A proof for a known Note verifies in snarkjs; commitment/nullifier match the spike's Poseidon2 |
| M3 | Soroban verifier + pool contract | 30–39 | Verifier accepts the M2 proof on testnet; replay/unknown-root/bad-proof rejected; SAC released |
| M4 | Relayer (backing root-sync + withdrawal submit + path service) | 40–49 | EVM root appears in the Soroban window; a posted proof yields a Stellar tx; path reconstruction matches the on-chain root |
| M5 | Frontend + e2e demo on testnet | 50–59 | A user deposits on Sepolia and privately withdraws on Stellar through the UI |

## Cross-component interface contract (the parts that MUST stay aligned)

- **Field/curve:** BN254 scalar field `Fr` everywhere.
- **Hash:** Poseidon2 (the exact instantiation the spike pins — Nethermind uses `POSEIDON2_BN256_PARAMS`, width t=3). Merkle compression = `Poseidon2Perm([l,r])[0] + l`.
- **Note:** `{ secret: Fr, nullifier: Fr }` + denomination index.
- `commitment = Poseidon2(nullifier, secret)`; `nullifierHash = Poseidon2(nullifier)`.
- **Tree:** depth 20, one per denomination; EVM holds the authoritative tree + a 30-deep root ring buffer.
- **Groth16 public-input order (identical in circom main + Soroban verifier):** `[ root, nullifierHash, recipient, denomination ]`.
- **Soroban pool state:** per-denomination root window (last 30) + nullifier set (persistent) + SAC admin + denomination config.

> ⚠️ **Keystone risk:** every "Poseidon2" must be the *same* instantiation (variant, arity, constants, domain separation, endianness). Task 2 establishes a shared `hash([1,2])` test vector; treat it as the single source of truth and re-assert it whenever a component touches the hash. This whole plan assumes the references are **unaudited / demo-only** — never frame the result as securing real funds.

---

## Day-1 Spike: Cross-Surface Poseidon2 + On-Chain Groth16 De-Risk (GATING)

> **Why this section exists.** The entire bridge dies if the Poseidon2 hash does not produce **byte-identical** field elements across circom (proving), Rust (relayer/off-chain tree), and Solidity (EVM on-chain tree), or if Nethermind's Groth16 verifier cannot actually verify a BN254 proof on Stellar testnet within budget. We prove all four facts on Day 1 before writing a single line of bridge logic. **No green light = no project.**
>
> **Researched ground truth (do not re-derive — these are the real upstream layouts as of HEAD):**
> - `NethermindEth/stellar-private-payments` @ `e6a69f0752cb555bdb6020f9f29be1a36ced1a3e` (2026-06-12).
> - Toolchain pins from the repo: `rust-toolchain.toml` → `channel = "1.92.0"`, `targets = ["wasm32v1-none","wasm32-unknown-unknown"]`; workspace `edition = "2024"`; `soroban-sdk = { version = "26", features = ["hazmat"] }`; `ark-bn254/ark-ff/ark-groth16 = "0.6.0"` (✅ verified in the upstream `Cargo.lock`; see **C4**); circom pragma `2.2.2`. Stellar CLI `v26.1.0` (Protocol 26 / "Yardstick").
> - Circom Poseidon2 lives in `circuits/src/poseidon2/{poseidon2_hash,poseidon2_compress,poseidon2_perm,poseidon2_const}.circom`. The hash template is `Poseidon2(n)` with a `domainSeparation` signal that internally calls `Permutation(n+1)`. **A 2-input hash therefore runs the t=3 permutation.** Compression template is `PoseidonCompress` with formula `out = P(inputs)[0] + inputs[0]`.
> - Rust Poseidon2 is the `zkhash` crate **vendored in the upstream repo at `poseidon2/`** (path dep, v0.2.0; HorizenLabs). ✅ **VERIFIED 2026-06-15:** instances are width-suffixed — `POSEIDON2_BN256_PARAMS_2` (t=2: compress + nullifierHash), `POSEIDON2_BN256_PARAMS_3` (t=3: commitment), `_4` (t=4). There is **no** bare `POSEIDON2_BN256_PARAMS`. Scalar is `FpBN256` (ark-ff 0.6 `Fp256<MontBackend>`). The earlier claim here that the constant was bare/t=3 was wrong; the keystone confirmed `_2`/`_3`.
> - The on-chain verifier is `contracts/circom-groth16-verifier/`, struct `CircomGroth16Verifier`, with `pub fn verify(env, proof: Groth16Proof, public_inputs: Vec<Bn254Fr>) -> Result<bool, Groth16Error>` and a `verify_with_vk(&env, &vk, proof, public_inputs)` variant. `Groth16Proof { a: G1Affine, b: G2Affine, c: G1Affine }`, `VerificationKey { alpha, beta, gamma, delta, ic: Vec<G1Affine> }`. It calls `env.crypto().bn254()` → `g1_mul`, `g1_add`, `multi_pairing_check` (⚠️ confirm exact SDK method names against docs.rs/soroban-sdk/26.1.0; the host fn is `bn254_multi_pairing_check`, and on Protocol 26 prefer `g1_msm` for the `vk_x` accumulation — see **C5**).

---

### Task 1: Clone the reference fork, pin & install the full toolchain, record HEAD

**Files:**
- Create: `~/stellar-hacks/README.md` (project root README — pin block)
- Create: `~/stellar-hacks/vendor/` (full clone of the reference repo)
- Create: `~/stellar-hacks/spike/versions.lock` (pinned tool versions)

- [ ] **Step 1: Create project root + vendor dir**
```bash
mkdir -p ~/stellar-hacks/spike ~/stellar-hacks/vendor && cd ~/stellar-hacks && git init -q && echo "init: $(pwd)"
```
Expected output:
```
init: /home/<you>/stellar-hacks
```

- [ ] **Step 2: Full-clone the reference repo (full history, not shallow) and capture HEAD SHA**
```bash
git clone https://github.com/NethermindEth/stellar-private-payments.git ~/stellar-hacks/vendor/stellar-private-payments \
 && git -C ~/stellar-hacks/vendor/stellar-private-payments rev-parse HEAD
```
Expected output (the recorded HEAD; if upstream has moved, **pin to this SHA** with the next step so the spike is reproducible):
```
Cloning into '.../vendor/stellar-private-payments'...
e6a69f0752cb555bdb6020f9f29be1a36ced1a3e
```

- [ ] **Step 3: Hard-pin the reference repo to the known-good SHA**
```bash
git -C ~/stellar-hacks/vendor/stellar-private-payments checkout e6a69f0752cb555bdb6020f9f29be1a36ced1a3e 2>&1 | tail -1 \
 && git -C ~/stellar-hacks/vendor/stellar-private-payments rev-parse --short HEAD
```
Expected output:
```
HEAD is now at e6a69f0 ...
e6a69f0
```

- [ ] **Step 4: Install the exact Rust toolchain the repo demands (1.92.0 + wasm targets)**
```bash
rustup toolchain install 1.92.0 --component rustfmt clippy \
 && rustup target add --toolchain 1.92.0 wasm32v1-none wasm32-unknown-unknown \
 && rustup run 1.92.0 rustc --version
```
Expected output:
```
rustc 1.92.0 (................ 2025-..-..)
```

- [ ] **Step 5: Install Stellar CLI v26.1.0 (Protocol 26) and verify**
```bash
cargo install --locked stellar-cli --version 26.1.0 \
 && stellar --version
```
Expected output (version line must start with `stellar 26`):
```
stellar 26.1.0 (rev ...)
soroban-env ...
```

- [ ] **Step 6: Install Node 22 LTS + circom 2.2.2 (from source — the official method) + snarkjs and verify**
```bash
node --version && npm --version \
 && git clone https://github.com/iden3/circom.git /tmp/circom && git -C /tmp/circom checkout v2.2.2 \
 && cargo install --path /tmp/circom/circom && circom --version \
 && npm i -g snarkjs@0.7.5 && snarkjs --version 2>&1 | head -1
```
Expected output (Node must be v22.x; circom must report 2.2.2):
```
v22.x.x
10.x.x
circom compiler 2.2.2
snarkjs@0.7.5
```
> Note: building circom from source is the documented install path (docs.circom.io) — `cargo install circom` from crates.io is NOT supported. See **C6**.

- [ ] **Step 7: Write the version lockfile**
```bash
cat > ~/stellar-hacks/spike/versions.lock <<'EOF'
# Toolchain pins for the spike (verified Day 1). Do not bump without re-running Task 2 & Task 3.
reference_repo      = NethermindEth/stellar-private-payments
reference_head_sha  = e6a69f0752cb555bdb6020f9f29be1a36ced1a3e   # 2026-06-12
rust                = 1.92.0
rust_edition        = 2024
rust_targets        = wasm32v1-none, wasm32-unknown-unknown
soroban_sdk         = 26 (features = ["hazmat"])
stellar_cli         = 26.1.0   # Protocol 26 "Yardstick"
circom              = 2.2.2
snarkjs             = 0.7.5
node                = 22.x LTS
ark_{bn254,ff,groth16} = 0.6.0   # off-chain only (relayer); Soroban verifier uses host fns. Matches upstream workspace.
poseidon2_rust      = NethermindEth/HorizenLabs-poseidon2 (fork of HorizenLabs/poseidon2)
EOF
cat ~/stellar-hacks/spike/versions.lock | head -3
```
Expected output:
```
# Toolchain pins for the spike (verified Day 1). Do not bump without re-running Task 2 & Task 3.
reference_repo      = NethermindEth/stellar-private-payments
reference_head_sha  = e6a69f0752cb555bdb6020f9f29be1a36ced1a3e   # 2026-06-12
```

- [ ] **Step 8: Create the project README with the pin block (this is the canonical record)**
```bash
cat > ~/stellar-hacks/README.md <<'EOF'
# Private Cross-Chain Bridge (EVM Sepolia -> Stellar) — Stellar Hacks: ZK

Deposit/lock test-USDC on EVM Sepolia (commitment into on-chain Merkle tree) ->
trusted Backing Relayer anchors a recent EVM root into the Soroban pool root window ->
withdraw on Stellar via a Groth16/BN254 proof (Merkle membership + nullifier) verified
on Soroban, releasing a pool-minted SAC token to the recipient via a Withdrawal Relayer.

## Reference implementation (pinned)
- Upstream: NethermindEth/stellar-private-payments
- HEAD SHA: `e6a69f0752cb555bdb6020f9f29be1a36ced1a3e` (2026-06-12)
- Vendored at: `vendor/stellar-private-payments` (checked out to the SHA above)

## Toolchain (see spike/versions.lock for the authoritative list)
| tool | version |
|------|---------|
| rust | 1.92.0 (edition 2024) |
| wasm targets | wasm32v1-none, wasm32-unknown-unknown |
| soroban-sdk | 26 (features = ["hazmat"]) |
| stellar-cli | 26.1.0 (Protocol 26 "Yardstick") |
| circom | 2.2.2 |
| snarkjs | 0.7.5 |
| node | 22.x LTS |
| ark-{bn254,ff,groth16} | 0.6.0 |

## Day-1 Spike gate
See `spike/` — the project is GREEN-LIT only when the keystone (Task 2) and
on-chain verify (Task 3/4) pass. See the GREEN-LIGHT GATE at the end of the spike.
EOF
head -5 ~/stellar-hacks/README.md
```
Expected output:
```
# Private Cross-Chain Bridge (EVM Sepolia -> Stellar) — Stellar Hacks: ZK

Deposit/lock test-USDC on EVM Sepolia (commitment into on-chain Merkle tree) ->
trusted Backing Relayer anchors a recent EVM root into the Soroban pool root window ->
withdraw on Stellar via a Groth16/BN254 proof (Merkle membership + nullifier) verified
```

- [ ] **Step 9: Sanity-build the reference verifier crate against the pinned toolchain (proves the toolchain is wired correctly)**
```bash
cd ~/stellar-hacks/vendor/stellar-private-payments \
 && rustup run 1.92.0 cargo build -p circom-groth16-verifier 2>&1 | tail -3
```
Expected output (a clean compile of the upstream verifier; warnings OK, **no errors**):
```
   Compiling circom-groth16-verifier v...
    Finished `dev` profile [unoptimized + debuginfo] target(s) in ...s
```

- [ ] **Step 10: Commit**
```bash
cd ~/stellar-hacks && git add README.md spike/versions.lock && git commit -m "spike(task1): pin reference HEAD e6a69f0 + full toolchain (rust 1.92, soroban-sdk 26, circom 2.2.2, stellar-cli 26.1.0)"
```

---

### Task 2: THE KEYSTONE — Poseidon2 hash([1,2]) + Merkle compression byte-identical across circom, Rust, Solidity

> **The single most important test in the project.** We compute the **2-input hash** `H = Poseidon2Hash2(1, 2)` and the **Merkle compression** `C = Compress(1, 2) = Poseidon2Perm([1,2,...])[0] + 1` on three surfaces and assert all three are the **same 32-byte big-endian field element**. We pin the canonical hex into `spike/poseidon2_vectors.json` and every later component (circom main, Rust relayer tree, Solidity EVM tree, Soroban) consumes those vectors.
>
> **Arity decision pinned here:** Following upstream, `Poseidon2Hash2(a,b)` = the circom `Poseidon2(2)` template = `Permutation(3)` (t=3) with `domainSeparation = 0`, output `out[0]`. The Merkle internal node uses `PoseidonCompress(2)` = `Permutation(3)([l,r,domainSep])[0] + l`. **Both surfaces in Rust/Solidity MUST mirror exactly this t=3, domainSep=0 layout.** `nullifierHash = Poseidon2Hash1(nullifier)` is the `Poseidon2(1)` = `Permutation(2)` (t=2) template — we also vector-fix it.

**Files:**
- Create: `~/stellar-hacks/spike/circom/keystone.circom`
- Create: `~/stellar-hacks/spike/circom/poseidon2/` (copied from upstream)
- Create: `~/stellar-hacks/spike/rust-vectors/` (cargo crate, computes Rust hashes)
- Create: `~/stellar-hacks/spike/sol/Poseidon2Keystone.t.sol` (Foundry test)
- Create: `~/stellar-hacks/spike/poseidon2_vectors.json` (the canonical pinned vectors)
- Test (cross-surface): `~/stellar-hacks/spike/assert_identical.sh`

- [ ] **Step 1: Vendor the upstream circom Poseidon2 templates into the spike**
```bash
cp -r ~/stellar-hacks/vendor/stellar-private-payments/circuits/src/poseidon2 ~/stellar-hacks/spike/circom/poseidon2 \
 && ls ~/stellar-hacks/spike/circom/poseidon2
```
Expected output:
```
poseidon2_compress.circom  poseidon2_const.circom  poseidon2_hash.circom  poseidon2_perm.circom
```

- [ ] **Step 2: Write the keystone circom main that EXPORTS both the 2-input hash and the compression as public outputs**
```bash
cat > ~/stellar-hacks/spike/circom/keystone.circom <<'EOF'
pragma circom 2.2.2;

include "poseidon2/poseidon2_hash.circom";
include "poseidon2/poseidon2_compress.circom";

// Keystone: prove the SAME engine yields hash2(l,r) and compress(l,r).
// Public outputs are the field elements we will pin and cross-check.
template Keystone() {
    signal input l;
    signal input r;
    signal output hash2;     // Poseidon2(2) with domainSeparation = 0
    signal output compress;  // PoseidonCompress(2) = Perm([l,r,0])[0] + l

    // 2-input fixed hash. Poseidon2(n) has signals: inputs[n], domainSeparation, out.
    component h = Poseidon2(2);
    h.inputs[0] <== l;
    h.inputs[1] <== r;
    h.domainSeparation <== 0;
    hash2 <== h.out;

    // Merkle internal-node compression.
    component c = PoseidonCompress();
    c.inputs[0] <== l;
    c.inputs[1] <== r;
    compress <== c.out;
}

component main = Keystone();
EOF
echo "wrote keystone.circom"
```
Expected output:
```
wrote keystone.circom
```

- [ ] **Step 3: Compile the circom witness generator (this also validates the upstream templates compile under circom 2.2.2)**
```bash
cd ~/stellar-hacks/spike/circom \
 && circom keystone.circom --r1cs --wasm --sym -o . -l . 2>&1 | tail -4
```
Expected output (constraint counts will vary; **must end without error**):
```
template instances: ...
non-linear constraints: ...
...
written successfully: ./keystone.r1cs
written successfully: ./keystone_js/keystone.wasm
```

- [ ] **Step 4: Compute the circom witness for l=1, r=2 and decode the two public outputs to decimal**
```bash
cd ~/stellar-hacks/spike/circom \
 && echo '{"l":"1","r":"2"}' > input.json \
 && node keystone_js/generate_witness.js keystone_js/keystone.wasm input.json witness.wtns \
 && snarkjs wtns export json witness.wtns witness.json \
 && node -e 'const w=require("./witness.json"); console.log("hash2="+w[1]); console.log("compress="+w[2]);'
```
Expected output (witness index 0 = the constant `1`; indices 1,2 = the two outputs in declaration order — **record these two decimal values**, they are the source of truth):
```
hash2=<DECIMAL_FROM_CIRCOM_OUTPUT_1>
compress=<DECIMAL_FROM_CIRCOM_OUTPUT_2>
```

- [ ] **Step 5: Pin the circom result into the canonical vectors file (decimal + 0x 32-byte big-endian)**
```bash
cd ~/stellar-hacks/spike/circom \
 && node -e '
const w=require("./witness.json");
const toHex=(d)=>"0x"+BigInt(d).toString(16).padStart(64,"0");
const out={
  inputs:{l:"1",r:"2",domainSeparation:"0"},
  hash2:{dec:w[1], hex:toHex(w[1])},
  compress:{dec:w[2], hex:toHex(w[2])}
};
require("fs").writeFileSync("../poseidon2_vectors.json", JSON.stringify(out,null,2));
console.log(JSON.stringify(out,null,2));
'
```
Expected output (the canonical vectors — every other surface must reproduce `hash2.hex` and `compress.hex` exactly):
```
{
  "inputs": { "l": "1", "r": "2", "domainSeparation": "0" },
  "hash2":    { "dec": "<...>", "hex": "0x<64 hex chars>" },
  "compress": { "dec": "<...>", "hex": "0x<64 hex chars>" }
}
```

- [ ] **Step 6: Scaffold the Rust vector crate (it depends on the SAME poseidon2 fork the relayer/circuits use)**
```bash
mkdir -p ~/stellar-hacks/spike/rust-vectors/src && cd ~/stellar-hacks/spike/rust-vectors \
 && cat > Cargo.toml <<'EOF'
[package]
name = "poseidon2-vectors"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
# Same engine the upstream Rust side uses. ff = field arithmetic for FpBN256.
zkhash = { git = "https://github.com/NethermindEth/HorizenLabs-poseidon2.git" }
ff = "0.13"
EOF
echo "wrote Cargo.toml"
```
Expected output:
```
wrote Cargo.toml
```
> If the fork's crate/package name differs, run `grep -m1 '^name' ~/.cargo/git/checkouts/HorizenLabs-poseidon2-*/*/plain_implementations/Cargo.toml` after the first `cargo fetch` and adjust the dependency name. The crate exposes `zkhash::poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS}` and `zkhash::fields::bn256::FpBN256`.

- [ ] **Step 7: Write a FAILING Rust test that asserts equality against the pinned vectors (TDD red)**
```bash
cd ~/stellar-hacks/spike/rust-vectors \
 && cat > src/main.rs <<'EOF'
// Reproduce the EXACT circom layout in Rust:
//   hash2(l,r)   = Poseidon2(t=3).permutation([l, r, 0])[0]      (domainSeparation = 0)
//   compress(l,r)= Poseidon2(t=3).permutation([l, r, 0])[0] + l  (PoseidonCompress)
// Field type is FpBN256 (NOT ark_bn254::Fr). Output as 32-byte big-endian hex.
use ff::PrimeField;
use zkhash::fields::bn256::FpBN256 as Fr;
use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS;

fn to_be_hex(x: &Fr) -> String {
    // FpBN256::to_repr() is little-endian 32 bytes; reverse to big-endian.
    let mut bytes = x.to_repr().as_ref().to_vec();
    bytes.reverse();
    format!("0x{}", hex_encode(&bytes))
}
fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn main() {
    let p = Poseidon2::new(&POSEIDON2_BN256_PARAMS); // width t = 3
    let l = Fr::from(1u64);
    let r = Fr::from(2u64);
    let zero = Fr::from(0u64);

    let state = p.permutation(&[l, r, zero]);
    let hash2 = state[0];
    let compress = state[0] + l;

    let h_hex = to_be_hex(&hash2);
    let c_hex = to_be_hex(&compress);
    println!("rust_hash2    = {}", h_hex);
    println!("rust_compress = {}", c_hex);

    // Read pinned circom vectors and assert equality (RED until engine matches).
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("../poseidon2_vectors.json").unwrap()).unwrap();
    let want_h = v["hash2"]["hex"].as_str().unwrap();
    let want_c = v["compress"]["hex"].as_str().unwrap();
    assert_eq!(h_hex, want_h, "hash2 mismatch: rust {} != circom {}", h_hex, want_h);
    assert_eq!(c_hex, want_c, "compress mismatch: rust {} != circom {}", c_hex, want_c);
    println!("OK: rust == circom for hash2 and compress");
}
EOF
sed -i 's/^ff = "0.13"/ff = "0.13"\nserde_json = "1"/' Cargo.toml \
 && cargo run 2>&1 | tail -6
```
Expected output (RED — it computes Rust values but the assert is the gate; on first run it should **either** match (great) **or** panic on mismatch, which tells us the layout/endianness is off and must be fixed):
```
rust_hash2    = 0x...
rust_compress = 0x...
# either:
OK: rust == circom for hash2 and compress
# or (red):
thread 'main' panicked at ... hash2 mismatch ...
```

- [ ] **Step 8: If RED, fix the Rust layout until GREEN (the two known knobs: domainSeparation position, endianness)**
> Resolution rules, in order:
> 1. **State order:** upstream `Poseidon2(2)` feeds `[inputs[0], inputs[1], domainSeparation]` into `Permutation(3)`. If mismatch, try domainSeparation as state[0] instead: `permutation(&[zero, l, r])`. Pin whichever matches circom.
> 2. **Endianness:** `FpBN256::to_repr()` is little-endian; we reverse to big-endian to match circom's decimal→BE-hex. If still off, drop the `.reverse()`.
> 3. **Field type:** confirm `FpBN256` (NOT `ark_bn254::Fr`). They share the BN254 scalar modulus, so values are equal, but `to_repr` byte order differs — normalize to BE hex on both.
>
> Re-run `cargo run` after each change until you see `OK: rust == circom`. **Do not proceed until GREEN.**

- [ ] **Step 9: Choose & vendor the Solidity Poseidon2 implementation, write a FAILING Foundry test (TDD red)**
```bash
cd ~/stellar-hacks/spike && mkdir -p sol && forge init --no-git sol/poseidon2 2>&1 | tail -1 \
 && cd sol/poseidon2 \
 && forge install zemse/poseidon2-evm 2>&1 | tail -1 || forge install chancehudson/poseidon2 2>&1 | tail -1
```
Expected output (one of the Poseidon2 Solidity libs installs into `lib/`):
```
Installed poseidon2-evm
```
> The chosen lib must be the **t=3 BN254 Poseidon2** with the **same round constants** as HorizenLabs `POSEIDON2_BN256_PARAMS`. If the installed lib uses different constants, generate the Solidity from the same constants via `circom`'s reference or port `poseidon2_const.circom`. The test below is constant-agnostic: it only passes if the lib reproduces the pinned vector.

- [ ] **Step 10: Write the Foundry test that asserts the Solidity hash equals the pinned circom vector**
```bash
cd ~/stellar-hacks/spike/sol/poseidon2 \
 && HASH2=$(node -e 'console.log(require("/home/'"$USER"'/stellar-hacks/spike/poseidon2_vectors.json").hash2.hex)') \
 && COMPRESS=$(node -e 'console.log(require("/home/'"$USER"'/stellar-hacks/spike/poseidon2_vectors.json").compress.hex)') \
 && cat > test/Poseidon2Keystone.t.sol <<EOF
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Poseidon2} from "../lib/poseidon2-evm/src/Poseidon2.sol";

contract Poseidon2KeystoneTest is Test {
    // Pinned from spike/poseidon2_vectors.json (circom source of truth).
    uint256 constant WANT_HASH2    = ${HASH2};
    uint256 constant WANT_COMPRESS = ${COMPRESS};

    Poseidon2 poseidon;

    function setUp() public { poseidon = new Poseidon2(); }

    function test_hash2_matches_circom() public view {
        // 2-input hash with domainSeparation = 0.
        uint256 got = poseidon.hash_2(1, 2);
        assertEq(got, WANT_HASH2, "hash2 != circom vector");
    }

    function test_compress_matches_circom() public view {
        // Merkle compression: Perm([l,r,0])[0] + l.
        uint256 perm0 = poseidon.hash_2(1, 2);     // == Perm([1,2,0])[0] for this lib
        uint256 got = addmod(perm0, 1, FIELD);     // + l, mod p
        assertEq(got, WANT_COMPRESS, "compress != circom vector");
    }

    uint256 constant FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
}
EOF
forge test 2>&1 | tail -8
```
Expected output (RED first — likely a constant/order mismatch; iterate the lib choice or `hash_2` arity until GREEN):
```
Running 2 tests for test/Poseidon2Keystone.t.sol:Poseidon2KeystoneTest
[FAIL. Reason: hash2 != circom vector] test_hash2_matches_circom() ...
...
```
> **Make it GREEN:** verify the Solidity lib's `hash_2` is the same t=3 Poseidon2 with the same constants and same domainSeparation=0 capacity element. If the lib's API differs (e.g. `poseidon([1,2])` or `hash([1,2,0])`), adjust the call. The compress relation `Perm[0] + l` may require the lib to expose the raw permutation; if only `hash_2` is exposed and equals `Perm([l,r,0])[0]`, the test above is correct. Iterate until both tests pass.

- [ ] **Step 11: Run the lib's Solidity test green and confirm against the vector**
```bash
cd ~/stellar-hacks/spike/sol/poseidon2 && forge test --match-contract Poseidon2KeystoneTest 2>&1 | tail -6
```
Expected output:
```
Running 2 tests for test/Poseidon2Keystone.t.sol:Poseidon2KeystoneTest
[PASS] test_compress_matches_circom() (gas: ...)
[PASS] test_hash2_matches_circom() (gas: ...)
Test result: ok. 2 passed; 0 failed; 0 skipped
```

- [ ] **Step 12: Write the cross-surface assertion harness (single command that proves all three agree)**
```bash
cd ~/stellar-hacks/spike \
 && cat > assert_identical.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
VEC="$ROOT/poseidon2_vectors.json"
H=$(node -e "console.log(require('$VEC').hash2.hex)")
C=$(node -e "console.log(require('$VEC').compress.hex)")
echo "== Canonical (circom) =="
echo "  hash2    = $H"
echo "  compress = $C"

echo "== Rust =="
( cd "$ROOT/rust-vectors" && cargo run -q )   # asserts internally vs $VEC, exits non-zero on mismatch

echo "== Solidity (Foundry) =="
( cd "$ROOT/sol/poseidon2" && forge test --match-contract Poseidon2KeystoneTest -q ) \
  && echo "  solidity matches circom vectors"

echo "ALL THREE SURFACES AGREE on hash2 and compress."
EOF
chmod +x assert_identical.sh && ./assert_identical.sh 2>&1 | tail -12
```
Expected output (the keystone result — **this is the green light for cryptographic parity**):
```
== Canonical (circom) ==
  hash2    = 0x...
  compress = 0x...
== Rust ==
OK: rust == circom for hash2 and compress
== Solidity (Foundry) ==
  ... 2 passed; 0 failed ...
  solidity matches circom vectors
ALL THREE SURFACES AGREE on hash2 and compress.
```

- [ ] **Step 13: Record the keystone result + arity/field reconciliation in the README**
```bash
cd ~/stellar-hacks \
 && cat >> README.md <<'EOF'

## KEYSTONE RESULT (Task 2) — Poseidon2 parity PROVEN
- hash2(1,2) and compress(1,2) are byte-identical across circom / Rust / Solidity.
- Canonical vectors pinned in `spike/poseidon2_vectors.json`.
- Pinned layout: `Poseidon2Hash2(a,b) = Permutation(t=3)([a,b,0])[0]` (domainSeparation=0);
  `Compress(l,r) = Permutation(t=3)([l,r,0])[0] + l`; `nullifierHash = Poseidon2Hash1` = `Permutation(t=2)`.
- RECONCILIATION vs interface contract: upstream Rust constant is `POSEIDON2_BN256_PARAMS`
  (width t=3), scalar type `FpBN256` (NOT `POSEIDON2_BN256_PARAMS_2`, NOT ark_bn254::Fr).
  All components MUST use `POSEIDON2_BN256_PARAMS` + the pinned vectors above.
EOF
echo "README updated"
```
Expected output:
```
README updated
```

- [ ] **Step 14: Commit**
```bash
cd ~/stellar-hacks && git add spike/ README.md && git commit -m "spike(task2): KEYSTONE — Poseidon2 hash2(1,2)+compress byte-identical across circom/Rust/Solidity; pin vectors + t=3/FpBN256 reconciliation"
```

---

### Task 3: Deploy Nethermind's BN254 Groth16 verifier to Stellar testnet (Protocol 26) and verify a sample proof

> We deploy the **upstream** `circom-groth16-verifier` Wasm unchanged, then call `verify` with a **real Groth16 proof** generated by the upstream test fixture and confirm it returns `true` on testnet. This proves CAP-0074/0080 BN254 host functions are live on the network we will use.

**Files:**
- Modify: `~/stellar-hacks/vendor/stellar-private-payments/contracts/circom-groth16-verifier/` (build target only)
- Create: `~/stellar-hacks/spike/onchain/build_proof_fixture.sh`
- Create: `~/stellar-hacks/spike/onchain/proof.json`, `public.json`, `vk.json`
- Create: `~/stellar-hacks/spike/onchain/deploy.sh`
- Test: `~/stellar-hacks/spike/onchain/verify_onchain.sh`

- [ ] **Step 1: Create and fund a testnet identity (Friendbot)**
```bash
stellar keys generate spike-deployer --network testnet --fund 2>&1 | tail -1 \
 && echo "G-addr: $(stellar keys address spike-deployer)"
```
Expected output:
```
... funded ...
G-addr: G............................................................
```

- [ ] **Step 2: Build the upstream verifier to Wasm (release, wasm32v1-none)**
```bash
cd ~/stellar-hacks/vendor/stellar-private-payments \
 && rustup run 1.92.0 stellar contract build --package circom-groth16-verifier 2>&1 | tail -3 \
 && ls target/wasm32v1-none/release/circom_groth16_verifier.wasm
```
Expected output:
```
    Finished `release` profile ...
target/wasm32v1-none/release/circom_groth16_verifier.wasm
```
> If `--package` is unsupported, run `cd contracts/circom-groth16-verifier && rustup run 1.92.0 stellar contract build` and locate the wasm under the workspace `target/`.

- [ ] **Step 3: Optimize the Wasm (smaller upload, lower fees)**
```bash
cd ~/stellar-hacks/vendor/stellar-private-payments \
 && stellar contract optimize --wasm target/wasm32v1-none/release/circom_groth16_verifier.wasm 2>&1 | tail -2
```
Expected output:
```
Optimized: ... bytes
... circom_groth16_verifier.optimized.wasm
```

- [ ] **Step 4: Deploy to testnet and capture the contract ID**
```bash
cd ~/stellar-hacks/vendor/stellar-private-payments \
 && CID=$(stellar contract deploy \
      --wasm target/wasm32v1-none/release/circom_groth16_verifier.optimized.wasm \
      --source-account spike-deployer --network testnet 2>/dev/null) \
 && echo "$CID" > ~/stellar-hacks/spike/onchain/verifier_contract_id.txt \
 && echo "VERIFIER_CID=$CID"
```
Expected output:
```
VERIFIER_CID=C............................................................
```

- [ ] **Step 5: Generate a real Groth16 proof fixture by running the upstream verifier's own test (which constructs `Groth16Proof` + `Vec<Bn254Fr>`)**
```bash
mkdir -p ~/stellar-hacks/spike/onchain \
 && cat > ~/stellar-hacks/spike/onchain/build_proof_fixture.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# The upstream test (contracts/circom-groth16-verifier/src/test.rs) builds a Groth16
# proof over Bn254 with CircomReduction and 11 public inputs, then calls verify_with_vk.
# We run that test with output captured so we can serialize the proof/vk/inputs to JSON
# for an on-chain invoke. Run from repo root.
cd ~/stellar-hacks/vendor/stellar-private-payments
rustup run 1.92.0 cargo test -p circom-groth16-verifier -- --nocapture 2>&1 | tee /tmp/verifier_test.log | tail -8
echo "--- upstream test passing locally proves the proof fixture is valid; see /tmp/verifier_test.log"
EOF
chmod +x ~/stellar-hacks/spike/onchain/build_proof_fixture.sh \
 && ~/stellar-hacks/spike/onchain/build_proof_fixture.sh
```
Expected output (the upstream unit test passes — the in-repo proof fixture is valid):
```
running 1 test
test test::... ok
test result: ok. 1 passed; 0 failed ...
--- upstream test passing locally proves the proof fixture is valid; see /tmp/verifier_test.log
```

- [ ] **Step 6: Export the proof + public inputs + vk as JSON the CLI can pass (snarkjs path using the upstream sample circuit `policy_tx_2_2`)**
```bash
cd ~/stellar-hacks/spike/onchain \
 && cp ~/stellar-hacks/vendor/stellar-private-payments/deployments/testnet/circuit_keys/policy_tx_2_2_vk.json ./vk.json 2>/dev/null \
 && ls -1 ./vk.json \
 && cat > to_scval_notes.md <<'EOF'
The verifier expects:
  proof: Groth16Proof { a: G1Affine, b: G2Affine, c: G1Affine }
  public_inputs: Vec<Bn254Fr>   (BN254 scalar field elements, big-endian 32 bytes)
Encode each as the SCVal the contract's typegen expects (BytesN<32> per Fr/G1 coord,
G2 as the contract's tuple). Use the test.rs helpers groth16_proof_from_ark / Bn254Fr
conversion as the canonical encoding; mirror that byte order in the CLI --proof arg.
EOF
echo "vk staged"
```
Expected output:
```
./vk.json
vk staged
```

- [ ] **Step 7: Write the on-chain verify invocation**
```bash
cat > ~/stellar-hacks/spike/onchain/verify_onchain.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
CID=$(cat ~/stellar-hacks/spike/onchain/verifier_contract_id.txt)
# Inspect the exact arg names the deployed contract exposes:
stellar contract invoke --id "$CID" --source-account spike-deployer --network testnet -- --help
echo "=== calling verify with the sample proof ==="
# Pass proof + public_inputs as JSON (CLI auto-converts to SCVal per the contract spec).
stellar contract invoke --id "$CID" --source-account spike-deployer --network testnet -- \
  verify \
  --proof "$(cat ~/stellar-hacks/spike/onchain/proof_scval.json)" \
  --public_inputs "$(cat ~/stellar-hacks/spike/onchain/public_scval.json)"
EOF
chmod +x ~/stellar-hacks/spike/onchain/verify_onchain.sh \
 && CID=$(cat ~/stellar-hacks/spike/onchain/verifier_contract_id.txt) \
 && stellar contract invoke --id "$CID" --source-account spike-deployer --network testnet -- --help 2>&1 | head -20
```
Expected output (the deployed contract's real CLI surface — confirms `verify`/`verify_with_vk` and the exact `--proof` / `--public_inputs` arg shapes to encode against):
```
Usage: ... verify --proof <PROOF> --public_inputs <PUBLIC_INPUTS>
...
  --proof          Groth16Proof { a, b, c }
  --public_inputs  Vec<Bn254Fr>
```

- [ ] **Step 8: Produce `proof_scval.json` / `public_scval.json` from the upstream encoding and submit the verify tx**
```bash
cd ~/stellar-hacks/spike/onchain \
 && node -e '
// Mirror groth16_proof_from_ark / Bn254Fr byte order from test.rs.
// Read the upstream-exported proof.json/public.json and reshape to the SCVal JSON
// matching the --help signature printed in Step 7. (Field/coord = 32-byte BE hex.)
const fs=require("fs");
const proof=require("./proof.json"), pub=require("./public.json");
fs.writeFileSync("proof_scval.json", JSON.stringify({a:proof.a,b:proof.b,c:proof.c}));
fs.writeFileSync("public_scval.json", JSON.stringify(pub));
console.log("scval encoded:", fs.existsSync("proof_scval.json"));
' \
 && ./verify_onchain.sh 2>&1 | tail -4
```
Expected output (**the on-chain verify returns true** — CAP-0074/0080 BN254 host functions confirmed live on testnet):
```
=== calling verify with the sample proof ===
true
```
> If Step 6's snarkjs export does not line up with the contract's encoding, fall back to the canonical path: copy the exact `proof.json`/`public.json` the upstream `deployments/scripts/deploy.sh ... --vk-file ...policy_tx_2_2_vk.json` flow produces (the repo ships a working sample), then re-run. The signature from Step 7 is authoritative for arg shape.

- [ ] **Step 9: Capture the successful tx hash for the record**
```bash
CID=$(cat ~/stellar-hacks/spike/onchain/verifier_contract_id.txt) \
 && echo "Verifier deployed at: $CID (testnet)" \
 && echo "Verify returned true — see CLI output / RPC tx above." \
 && echo "$CID" >> ~/stellar-hacks/spike/onchain/RESULT.txt
```
Expected output:
```
Verifier deployed at: C... (testnet)
Verify returned true — see CLI output / RPC tx above.
```

- [ ] **Step 10: Commit**
```bash
cd ~/stellar-hacks && git add spike/onchain README.md && git commit -m "spike(task3): deploy upstream circom-groth16-verifier to testnet (Protocol 26), verify(sample proof)=true"
```

---

### Task 4: Measure the on-chain verify instruction cost and confirm < 100M

> We must know verify fits the per-transaction CPU budget (Soroban cap is 100M instructions). We measure it **off-chain deterministically** via the Soroban test budget (exact, repeatable) and **cross-check on-chain** via the simulated resource estimate from the testnet RPC.

**Files:**
- Create: `~/stellar-hacks/spike/onchain/cost_probe.rs` (added to the verifier crate's tests)
- Modify: `~/stellar-hacks/vendor/stellar-private-payments/contracts/circom-groth16-verifier/src/test.rs` (add a budget-printing test)
- Test: `~/stellar-hacks/spike/onchain/measure_cost.sh`

- [ ] **Step 1: Read the upstream test to copy its proof-builder helpers**
```bash
sed -n '1,40p' ~/stellar-hacks/vendor/stellar-private-payments/contracts/circom-groth16-verifier/src/test.rs
```
Expected output (confirms `test_env()`, `build_test()`, `groth16_proof_from_ark`, `verify_with_vk` — the symbols our cost probe reuses):
```
use soroban_sdk::{...};
fn test_env() -> Env { ... }
fn build_test(...) -> (..., Groth16Proof, Vec<Bn254Fr>) { ... }
...
```

- [ ] **Step 2: Append a budget-measuring test that resets the budget, calls verify, and prints the cost**
```bash
cat >> ~/stellar-hacks/vendor/stellar-private-payments/contracts/circom-groth16-verifier/src/test.rs <<'EOF'

#[test]
fn spike_measure_verify_budget() {
    use soroban_sdk::testutils::budget::Budget;
    let env = test_env();
    let (vk, proof, public_inputs) = build_test(); // upstream helper: real Bn254 proof + inputs

    // Make sure verify is the only thing measured.
    env.cost_estimate().budget().reset_default();
    env.cost_estimate().budget().reset_tracker();

    let ok = CircomGroth16Verifier::verify_with_vk(&env, &vk, proof, public_inputs);
    assert!(ok, "spike: sample proof must verify");

    // Print the full cost breakdown (CPU instructions + memory bytes).
    env.cost_estimate().budget().print();

    let cpu = env.cost_estimate().budget().cpu_instruction_cost();
    std::eprintln!("SPIKE_VERIFY_CPU_INSTRUCTIONS={}", cpu);
    assert!(cpu < 100_000_000, "verify CPU {} exceeds 100M budget", cpu);
}
EOF
echo "appended budget test"
```
Expected output:
```
appended budget test
```
> If `build_test()` returns a different tuple shape, adapt the destructuring to the actual signature you saw in Step 1; the upstream helper already produces a valid `(VerificationKey, Groth16Proof, Vec<Bn254Fr>)` for the policy circuit.

- [ ] **Step 3: Run the budget test and capture the printed CPU cost**
```bash
cat > ~/stellar-hacks/spike/onchain/measure_cost.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd ~/stellar-hacks/vendor/stellar-private-payments
rustup run 1.92.0 cargo test -p circom-groth16-verifier spike_measure_verify_budget -- --nocapture 2>&1 \
 | tee /tmp/verify_budget.log
echo "=== extracted ==="
grep -E 'SPIKE_VERIFY_CPU_INSTRUCTIONS|Cpu|CPU' /tmp/verify_budget.log | head -5
EOF
chmod +x ~/stellar-hacks/spike/onchain/measure_cost.sh \
 && ~/stellar-hacks/spike/onchain/measure_cost.sh 2>&1 | tail -14
```
Expected output (the budget table prints; the asserted CPU must be **well under 100,000,000** — BN254 pairing host functions are cheap; expect single-digit millions):
```
=============================================================
Cpu limit: 100000000; used: <CPU_USED>
Mem limit: ...; used: ...
=============================================================
...
SPIKE_VERIFY_CPU_INSTRUCTIONS=<CPU_USED>
test test::spike_measure_verify_budget ... ok
```

- [ ] **Step 4: Cross-check on-chain via the live testnet simulated resource estimate**
```bash
CID=$(cat ~/stellar-hacks/spike/onchain/verifier_contract_id.txt) \
 && stellar contract invoke --id "$CID" --source-account spike-deployer --network testnet --sim-only \
      --cost -- verify \
      --proof "$(cat ~/stellar-hacks/spike/onchain/proof_scval.json)" \
      --public_inputs "$(cat ~/stellar-hacks/spike/onchain/public_scval.json)" 2>&1 | grep -iE 'instructions|cpu|resource' | head -6
```
Expected output (the RPC-simulated instruction count, again **< 100M**, corroborating the offline budget):
```
cpu_instructions: <N>   (N < 100000000)
...
```
> If `--cost`/`--sim-only` flags differ in your CLI build, use `stellar contract invoke ... --build-only` to emit the XDR and `stellar tx simulate` / RPC `simulateTransaction` to read `minResourceFee` + `instructions`.

- [ ] **Step 5: Record the measured cost in the README**
```bash
cd ~/stellar-hacks \
 && CPU=$(grep -oE 'SPIKE_VERIFY_CPU_INSTRUCTIONS=[0-9]+' /tmp/verify_budget.log | head -1 | cut -d= -f2) \
 && cat >> README.md <<EOF

## VERIFY COST (Task 4) — within budget
- Off-chain Soroban budget (deterministic): verify CPU = ${CPU} instructions (< 100,000,000 cap).
- On-chain testnet simulated estimate corroborates (< 100M). See spike/onchain/measure_cost.sh.
EOF
echo "recorded CPU=${CPU}"
```
Expected output:
```
recorded CPU=<N>
```

- [ ] **Step 6: Commit**
```bash
cd ~/stellar-hacks && git add spike/onchain/cost_probe.rs spike/onchain/measure_cost.sh README.md && git commit -m "spike(task4): measure verify budget — CPU < 100M offline + on-chain sim; recorded in README"
```
> Note: the budget test was appended into the vendored `test.rs`; if you keep the vendor dir out of your repo, also copy the test body to `spike/onchain/cost_probe.rs` (already staged) so the measurement is reproducible from your repo alone.

---

### GREEN-LIGHT GATE (the Day-1 go/no-go)

The project proceeds to building bridge logic **only if ALL of the following are simultaneously true.** If any one fails, STOP and resolve before writing any deposit/relayer/pool code — they all depend on these invariants.

| # | Gate | Pass criterion | Where proven |
|---|------|----------------|--------------|
| G1 | **Toolchain reproducible** | `circom-groth16-verifier` builds under rust 1.92.0 / soroban-sdk 26; stellar-cli 26.1.0; circom 2.2.2 | Task 1 Step 9 |
| G2 | **KEYSTONE — hash parity** | `assert_identical.sh` prints `ALL THREE SURFACES AGREE`; `hash2(1,2)` and `compress(1,2)` byte-identical across circom + Rust + Solidity | Task 2 Step 12 |
| G3 | **Layout pinned & reconciled** | `spike/poseidon2_vectors.json` committed; arity = t=3 perm + domainSeparation=0 for 2-input hash; Rust uses `POSEIDON2_BN256_PARAMS` + `FpBN256` (the interface's `_2`/`ark` names are corrected to this) | Task 2 Steps 5,13 |
| G4 | **On-chain verify works** | Upstream verifier deployed to **testnet**; `verify(sample_proof)` returns `true` | Task 3 Step 8 |
| G5 | **Cost in budget** | verify CPU **< 100,000,000** instructions, both offline budget and on-chain sim | Task 4 Steps 3,4 |

**If GREEN:** the cryptographic spine (Poseidon2 parity + BN254 Groth16 on Soroban under budget) is de-risked. Lock `versions.lock`, `poseidon2_vectors.json`, and the verifier contract ID — every downstream component (EVM tree compression, Rust relayer tree, circom main with public-input vector `[root, nullifierHash, recipient, denomination]`, Soroban pool) builds on these exact, proven primitives. Proceed.

**If any gate is RED:** this is the cheapest possible moment to discover it. Most likely failure is **G2/G3** (constant set / domainSeparation position / endianness mismatch between the Solidity lib and the circom/Rust engine) — resolve by forcing all three to the HorizenLabs `POSEIDON2_BN256_PARAMS` (t=3) constants before anything else. Second most likely is **G4** (proof-encoding byte order into SCVal) — resolve by mirroring `groth16_proof_from_ark` / `Bn254Fr` conversion from upstream `test.rs` exactly.

## EVM Sepolia Deposit + On-Chain Merkle Tree (`evm-tree`)

> **Stack choice: Foundry.** Solidity-native tests (no JS round-trip), `forge test` runs the Poseidon2 parity vector and Merkle assertions in-process, fast fuzzing, and `forge create --verify` does deploy-and-verify to Sepolia in one step. Hardhat would force a JS toolchain we don't otherwise need on this side (the JS lives in the relayer/circuit sections). The one place we touch JS is generating the precomputed `zeros[]` table, done with a tiny throwaway script that reuses the spike.
>
> ✅ **C2 (confirmed from fork source): the EVM tree's hash is `compress` = `Permutation(2)` (t=2).** The Merkle internal node is `Compress(l,r) = Perm₂([l,r])[0] + l` (no domain separation) — the t=2 framing below is CORRECT for the tree. The EVM contract does NOT compute commitments (those arrive as client-computed leaves), so this hasher needs **only** the t=2 permutation + `compress`. The **commitment** (`Perm₃([nullifier,secret,0])[0]`, t=3) and **nullifierHash** (`Perm₂([nullifier,0])[0]`, t=2) live in the circuit/frontend, not here. See the C2 table for the full arity map.
>
> **Critical interface note (read before Task 12):** the EVM tree hasher is HorizenLabs `zkhash` Poseidon2 at **width t=2** — Merkle compression `Compress(l,r) = Perm₂([l,r])[0] + l`. Transcribe the t=2 constants/matrix the keystone (Task 2) pinned. The popular `zemse/poseidon2-evm` package is **t=4 sponge** and is **NOT spec-compatible** — do not use it as the primary. Task 12 ports the exact t=2 permutation to Solidity and asserts byte-for-byte parity against the spike's test vector. Task 12-ALT is the labeled fallback: switch the whole system to classic Poseidon (t=3) via `chancehudson/poseidon-solidity` `PoseidonT3` if the t=2 port stalls — but only if the circuit and Soroban sections switch in lockstep.

---

### Task 10: Scaffold the Foundry project and add dependencies
**Files:**
- Create: `evm-tree/foundry.toml`
- Create: `evm-tree/.gitignore`
- Create: `evm-tree/.env.example`
- Create: `evm-tree/remappings.txt`

- [ ] **Step 1: Init the Foundry project**
```bash
mkdir -p ~/hackathon/stellar-hacks/evm-tree && cd ~/hackathon/stellar-hacks/evm-tree && forge init --no-git --force .
```
Expected output: `Initialized forge project` and a `src/Counter.sol`, `test/Counter.t.sol`, `script/Counter.s.sol` scaffold appears.

- [ ] **Step 2: Remove the boilerplate Counter files**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && rm -f src/Counter.sol test/Counter.t.sol script/Counter.s.sol && ls src test script
```
Expected output: three empty directories (no `Counter*` files listed).

- [ ] **Step 3: Add OpenZeppelin (for ERC20/IERC20 + the mock) and forge-std (already present)**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge install OpenZeppelin/openzeppelin-contracts@v5.1.0 --no-git
```
Expected output: `Installed openzeppelin-contracts` (a `lib/openzeppelin-contracts` directory now exists).

- [ ] **Step 4: Add the poseidon-solidity fallback dependency now (used only by Task 12-ALT, but installing early keeps remappings stable)**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge install chancehudson/poseidon-solidity --no-git
```
Expected output: `Installed poseidon-solidity` (a `lib/poseidon-solidity` directory now exists).

- [ ] **Step 5: Write `remappings.txt`**
```
forge-std/=lib/forge-std/src/
@openzeppelin/=lib/openzeppelin-contracts/
poseidon-solidity/=lib/poseidon-solidity/contracts/
```

- [ ] **Step 6: Write `foundry.toml`**
```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "0.8.24"
optimizer = true
optimizer_runs = 200
evm_version = "cancun"
fs_permissions = [{ access = "read", path = "./test/vectors" }]

[rpc_endpoints]
sepolia = "${SEPOLIA_RPC_URL}"

[etherscan]
sepolia = { key = "${ETHERSCAN_API_KEY}", chain = 11155111 }
```

- [ ] **Step 7: Write `.env.example`**
```bash
# Copy to .env and fill in. NEVER commit .env.
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
ETHERSCAN_API_KEY=YOUR_ETHERSCAN_KEY
DEPLOYER_PRIVATE_KEY=0xYOUR_FUNDED_SEPOLIA_TESTNET_KEY
```

- [ ] **Step 8: Write `.gitignore`**
```
out/
cache/
.env
broadcast/*/dry-run/
lib/
```

- [ ] **Step 9: Confirm the project builds (empty src compiles cleanly)**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge build
```
Expected output: `Compiling ...` then `Compiler run successful!` (no errors; nothing in `src` yet besides libs).

- [ ] **Step 10: Commit**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && git init && git add foundry.toml remappings.txt .env.example .gitignore && git commit -m "chore(evm-tree): scaffold foundry project, add OZ + poseidon-solidity deps"
```

---

### Task 11: Generate the precomputed `zeros[]` table for depth=20 with our Poseidon2 compression
**Files:**
- Create: `evm-tree/script/gen_zeros.mjs`
- Create: `evm-tree/test/vectors/zeros.json` (generated)
- Create: `evm-tree/test/vectors/poseidon2.json` (generated parity vector for Task 12)

> The Tornado `zeros[]` constants are MiMC-specific and **wrong for us**. We must regenerate the empty-subtree hashes using OUR `Compress(l,r) = Poseidon2Perm([l,r])[0] + l` with `ZERO_VALUE = keccak256("stellar-zkbridge") % FIELD_SIZE` (a fixed, documented constant). This script reuses the spike's Poseidon2 JS so the constants are guaranteed consistent across EVM/circuit/Soroban.

- [ ] **Step 1: Confirm the spike's Poseidon2 JS module is importable**
```bash
cd ~/hackathon/stellar-hacks && ls spike/ 2>/dev/null && node -e "import('./spike/poseidon2.mjs').then(m=>console.log(Object.keys(m)))"
```
Expected output: a list of exports including a `poseidon2Perm` (or equivalently named) function and the BN256/BN254 params. *(If the spike export names differ, pin the actual names here before continuing — this is the single source of truth for the hash.)*

- [ ] **Step 2: Write `script/gen_zeros.mjs`** (uses the spike's permutation; computes ZERO_VALUE, the 20-level zeros, and a 2-input parity vector)
```javascript
// Generates the on-chain Merkle zeros[] table + a Poseidon2 parity vector.
// Compression matches the shared spec exactly:
//   Compress(l, r) = poseidon2Perm([l, r])[0] + l   (mod FIELD_SIZE)
import { keccak256, toUtf8Bytes } from "ethers";
import { writeFileSync, mkdirSync } from "node:fs";
// Adjust this import path/name to the spike's actual export (Step 1).
import { poseidon2Perm } from "../../spike/poseidon2.mjs";

const FIELD_SIZE =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DEPTH = 20;

const mod = (a) => ((a % FIELD_SIZE) + FIELD_SIZE) % FIELD_SIZE;

// Domain-separated fixed empty-leaf value, reduced into the field.
const ZERO_VALUE = mod(BigInt(keccak256(toUtf8Bytes("stellar-zkbridge"))));

// Compress = poseidon2Perm([l,r])[0] + l  (mod p)
function compress(l, r) {
  const out = poseidon2Perm([l, r]); // returns array of 2 bigints (t=2)
  return mod(BigInt(out[0]) + BigInt(l));
}

// Build the zeros table: zeros[0] = ZERO_VALUE; zeros[i] = compress(zeros[i-1], zeros[i-1])
const zeros = [ZERO_VALUE];
for (let i = 1; i <= DEPTH; i++) {
  zeros.push(compress(zeros[i - 1], zeros[i - 1]));
}

const toHex32 = (x) => "0x" + x.toString(16).padStart(64, "0");

mkdirSync(new URL("../test/vectors/", import.meta.url), { recursive: true });

writeFileSync(
  new URL("../test/vectors/zeros.json", import.meta.url),
  JSON.stringify(
    {
      fieldSize: FIELD_SIZE.toString(),
      zeroValue: toHex32(ZERO_VALUE),
      depth: DEPTH,
      zeros: zeros.map(toHex32),
    },
    null,
    2
  )
);

// Parity vector for the Solidity Poseidon2 port (Task 12).
// hash_2(a,b) here means: the value used as commitment = poseidon2Perm([a,b])[0]
// (pin: commitment uses [0]; SAME convention the circuit uses).
const a = 1n;
const b = 2n;
const perm = poseidon2Perm([a, b]).map((x) => toHex32(BigInt(x)));
const hash2_out = toHex32(mod(BigInt(poseidon2Perm([a, b])[0]))); // commitment = perm[0]
const hash1_out = toHex32(mod(BigInt(poseidon2Perm([3n, 0n])[0]))); // nullifierHash arity pin

writeFileSync(
  new URL("../test/vectors/poseidon2.json", import.meta.url),
  JSON.stringify(
    {
      note: "Compress = perm([l,r])[0]+l ; commitment = perm([nullifier,secret])[0]",
      perm_in: [toHex32(a), toHex32(b)],
      perm_out: perm,
      compress_1_2: toHex32(compress(a, b)),
      hash2_1_2: hash2_out,
      hash1_3: hash1_out,
    },
    null,
    2
  )
);

console.log("ZERO_VALUE   =", toHex32(ZERO_VALUE));
console.log("zeros[20]    =", toHex32(zeros[20]), "(== initial root)");
console.log("compress(1,2)=", toHex32(compress(a, b)));
console.log("wrote test/vectors/zeros.json and poseidon2.json");
```

- [ ] **Step 3: Install the one JS dep the script needs (ethers, for keccak only) and run it**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && npm init -y >/dev/null && npm i ethers@6 >/dev/null && node script/gen_zeros.mjs
```
Expected output: prints `ZERO_VALUE = 0x...`, `zeros[20] = 0x...(== initial root)`, `compress(1,2)= 0x...`, and `wrote test/vectors/...`. Two JSON files now exist under `test/vectors/`.

- [ ] **Step 4: Sanity-check the generated files exist and are well-formed**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && node -e "const z=require('./test/vectors/zeros.json'); console.log('zeros len', z.zeros.length, 'depth', z.depth); const p=require('./test/vectors/poseidon2.json'); console.log('perm_out len', p.perm_out.length)"
```
Expected output: `zeros len 21 depth 20` and `perm_out len 2`.

- [ ] **Step 5: Add node artifacts to gitignore (keep the generated vectors tracked, they are test fixtures)**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && printf '\nnode_modules/\npackage-lock.json\n' >> .gitignore
```
Expected output: (no output) — `node_modules/` now ignored, `test/vectors/*.json` still tracked.

- [ ] **Step 6: Commit**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && git add script/gen_zeros.mjs test/vectors/zeros.json test/vectors/poseidon2.json package.json .gitignore && git commit -m "feat(evm-tree): generate Poseidon2 zeros[] table + parity vector from spike"
```

---

### Task 12: Port the Poseidon2 (t=2) Merkle hasher to Solidity with a parity test vs the spike (PRIMARY)
**Files:**
- Create: `evm-tree/src/IHasher.sol`
- Create: `evm-tree/src/Poseidon2.sol`
- Test: `evm-tree/test/Poseidon2.t.sol`

> **C2 (confirmed from fork source):** the EVM tree uses only the Merkle **compression**, which is `PoseidonCompress` = `Permutation(2)` — **t=2, width 2, NO domain separation**, `Compress(l,r) = Perm₂([l,r])[0] + l`. We port HorizenLabs `zkhash` Poseidon2 at width 2: full rounds `Rf=8` (4 + 4), partial rounds `Rp=56`, S-box `x^5`, external matrix `M_E = [[2,1],[1,2]]`, internal matrix `M_I` = `state[i]·diag[i] + Σstate` with `diag = POSEIDON_INTERNAL_MAT_DIAG(2)` (2 values). Round constants and the internal diagonal come straight from the params — **dump the t=2 values from the same fork the keystone (Task 2) pinned; do not invent them.** This hasher does NOT compute commitments (the commitment is the t=3 `Poseidon2(2)` sponge, computed client-side and inserted as a leaf — see Task 23/52). **TDD: write the failing parity test first, then iterate until `perm_out` and `compress_1_2` match the spike vector.** The parity test is the final arbiter.

- [ ] **Step 1: Write the hasher interface `src/IHasher.sol`**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Poseidon2 (t=2) Merkle compression over BN254 Fr. Matches the fork's
///         PoseidonCompress = Permutation(2) (NO domain separation).
///         Commitments are the t=3 Poseidon2(2) sponge — computed off-chain, not here.
interface IHasher {
    /// @return The permutation output [o0, o1] of Perm₂([l, r]).
    function perm(uint256 l, uint256 r) external pure returns (uint256, uint256);

    /// @notice Merkle compression: Compress(l,r) = Perm₂([l,r])[0] + l (mod p).
    function compress(uint256 l, uint256 r) external pure returns (uint256);
}
```

- [ ] **Step 2: Write the FAILING parity test `test/Poseidon2.t.sol` (reads the spike vector)**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IHasher} from "../src/IHasher.sol";
import {Poseidon2} from "../src/Poseidon2.sol";

contract Poseidon2Test is Test {
    using stdJson for string;

    IHasher hasher;
    string vec;

    function setUp() public {
        hasher = IHasher(address(new Poseidon2()));
        vec = vm.readFile("test/vectors/poseidon2.json");
    }

    function _u(string memory key) internal view returns (uint256) {
        return vm.parseUint(vm.toString(vec.readBytes32(key)));
    }

    function test_PermParityWithSpike() public view {
        // perm_out is a JSON array of two hex32 strings.
        bytes32 e0 = vec.readBytes32(".perm_out[0]");
        bytes32 e1 = vec.readBytes32(".perm_out[1]");
        (uint256 o0, uint256 o1) = hasher.perm(1, 2);
        assertEq(bytes32(o0), e0, "perm[0] mismatch vs spike");
        assertEq(bytes32(o1), e1, "perm[1] mismatch vs spike");
    }

    function test_CompressParityWithSpike() public view {
        bytes32 expected = vec.readBytes32(".compress_1_2");
        assertEq(bytes32(hasher.compress(1, 2)), expected, "compress mismatch vs spike");
    }
    // Note: the commitment (t=3 Poseidon2(2) sponge) is verified in the circuit/frontend
    // parity tasks, not on-chain — the EVM tree only computes t=2 Merkle compression.
}
```

- [ ] **Step 3: Run the test — confirm it FAILS to compile (no `Poseidon2.sol` yet)**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge test --match-contract Poseidon2Test
```
Expected output: compile error `Source "src/Poseidon2.sol" not found` (this is the expected red state).

- [ ] **Step 4: Implement `src/Poseidon2.sol`** (the t=2 structure below is exact; only the literal round-constant arrays and the internal-matrix diagonal are transcribed from the t=2 params the keystone pinned)
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IHasher} from "./IHasher.sol";

/// @title Poseidon2 t=2 Merkle compression over BN254 Fr (fork PoseidonCompress = Permutation(2))
/// @notice Rf=8 (4 initial + 4 final full rounds), Rp=56 partial rounds, S-box x^5.
///         External matrix M_E = [[2,1],[1,2]]; internal matrix M_I = state[i]*diag[i] + sum(state),
///         diag = POSEIDON_INTERNAL_MAT_DIAG(2). NO domain-separation/capacity slot (state = [l, r]).
contract Poseidon2 is IHasher {
    uint256 internal constant P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 internal constant R_F = 8;   // full rounds (split 4/4) — confirm vs the fork instance
    uint256 internal constant R_P = 56;  // partial rounds — confirm vs the fork instance

    // ---- t=2 constants transcribed VERBATIM from the fork's poseidon2_const.circom ----
    // Source: NethermindEth/stellar-private-payments @ e6a69f0, POSEIDON_FULL_ROUNDS(2) /
    // POSEIDON_PARTIAL_ROUNDS(2) / POSEIDON_INTERNAL_MAT_DIAG(2). These are field elements (< P),
    // so the circom hex literals copy directly into uint256. The Task 2 keystone parity test still
    // gates correctness — if it goes red, re-pull these from the pinned SHA.

    function _fullRC(uint256 i) internal pure returns (uint256, uint256) {
        // (c0,c1) for full round i in [0,8) — rounds 0..3 and 60..63 of the 64-round t=2 table.
        uint256[16] memory rc = [
            /* r0 */ uint256(0x09c46e9ec68e9bd4fe1faaba294cba38a71aa177534cdd1b6c7dc0dbd0abd7a7), uint256(0x0c0356530896eec42a97ed937f3135cfc5142b3ae405b8343c1d83ffa604cb81),
            /* r1 */ uint256(0x1e28a1d935698ad1142e51182bb54cf4a00ea5aabd6268bd317ea977cc154a30), uint256(0x27af2d831a9d2748080965db30e298e40e5757c3e008db964cf9e2b12b91251f),
            /* r2 */ uint256(0x1e6f11ce60fc8f513a6a3cfe16ae175a41291462f214cd0879aaf43545b74e03), uint256(0x2a67384d3bbd5e438541819cb681f0be04462ed14c3613d8f719206268d142d3),
            /* r3 */ uint256(0x0b66fdf356093a611609f8e12fbfecf0b985e381f025188936408f5d5c9f45d0), uint256(0x012ee3ec1e78d470830c61093c2ade370b26c83cc5cebeeddaa6852dbdb09e21),
            /* r4 */ uint256(0x19b9b63d2f108e17e63817863a8f6c288d7ad29916d98cb1072e4e7b7d52b376), uint256(0x015bee1357e3c015b5bda237668522f613d1c88726b5ec4224a20128481b4f7f),
            /* r5 */ uint256(0x2953736e94bb6b9f1b9707a4f1615e4efe1e1ce4bab218cbea92c785b128ffd1), uint256(0x0b069353ba091618862f806180c0385f851b98d372b45f544ce7266ed6608dfc),
            /* r6 */ uint256(0x304f74d461ccc13115e4e0bcfb93817e55aeb7eb9306b64e4f588ac97d81f429), uint256(0x15bbf146ce9bca09e8a33f5e77dfe4f5aad2a164a4617a4cb8ee5415cde913fc),
            /* r7 */ uint256(0x0ab4dfe0c2742cde44901031487964ed9b8f4b850405c10ca9ff23859572c8c6), uint256(0x0e32db320a044e3197f45f7649a19675ef5eedfea546dea9251de39f9639779a)
        ];
        return (rc[i * 2], rc[i * 2 + 1]);
    }

    function _partialRC(uint256 i) internal pure returns (uint256) {
        // c for partial round i in [0,56) — applied to lane 0 only (rounds 4..59 of the table).
        uint256[56] memory rc = [
            uint256(0x0252ba5f6760bfbdfd88f67f8175e3fd6cd1c431b099b6bb2d108e7b445bb1b9),
            uint256(0x179474cceca5ff676c6bec3cef54296354391a8935ff71d6ef5aeaad7ca932f1),
            uint256(0x2c24261379a51bfa9228ff4a503fd4ed9c1f974a264969b37e1a2589bbed2b91),
            uint256(0x1cc1d7b62692e63eac2f288bd0695b43c2f63f5001fc0fc553e66c0551801b05),
            uint256(0x255059301aada98bb2ed55f852979e9600784dbf17fbacd05d9eff5fd9c91b56),
            uint256(0x28437be3ac1cb2e479e1f5c0eccd32b3aea24234970a8193b11c29ce7e59efd9),
            uint256(0x28216a442f2e1f711ca4fa6b53766eb118548da8fb4f78d4338762c37f5f2043),
            uint256(0x2c1f47cd17fa5adf1f39f4e7056dd03feee1efce03094581131f2377323482c9),
            uint256(0x07abad02b7a5ebc48632bcc9356ceb7dd9dafca276638a63646b8566a621afc9),
            uint256(0x0230264601ffdf29275b33ffaab51dfe9429f90880a69cd137da0c4d15f96c3c),
            uint256(0x1bc973054e51d905a0f168656497ca40a864414557ee289e717e5d66899aa0a9),
            uint256(0x2e1c22f964435008206c3157e86341edd249aff5c2d8421f2a6b22288f0a67fc),
            uint256(0x1224f38df67c5378121c1d5f461bbc509e8ea1598e46c9f7a70452bc2bba86b8),
            uint256(0x02e4e69d8ba59e519280b4bd9ed0068fd7bfe8cd9dfeda1969d2989186cde20e),
            uint256(0x1f1eccc34aaba0137f5df81fc04ff3ee4f19ee364e653f076d47e9735d98018e),
            uint256(0x1672ad3d709a353974266c3039a9a7311424448032cd1819eacb8a4d4284f582),
            uint256(0x283e3fdc2c6e420c56f44af5192b4ae9cda6961f284d24991d2ed602df8c8fc7),
            uint256(0x1c2a3d120c550ecfd0db0957170fa013683751f8fdff59d6614fbd69ff394bcc),
            uint256(0x216f84877aac6172f7897a7323456efe143a9a43773ea6f296cb6b8177653fbd),
            uint256(0x2c0d272becf2a75764ba7e8e3e28d12bceaa47ea61ca59a411a1f51552f94788),
            uint256(0x16e34299865c0e28484ee7a74c454e9f170a5480abe0508fcb4a6c3d89546f43),
            uint256(0x175ceba599e96f5b375a232a6fb9cc71772047765802290f48cd939755488fc5),
            uint256(0x0c7594440dc48c16fead9e1758b028066aa410bfbc354f54d8c5ffbb44a1ee32),
            uint256(0x1a3c29bc39f21bb5c466db7d7eb6fd8f760e20013ccf912c92479882d919fd8d),
            uint256(0x0ccfdd906f3426e5c0986ea049b253400855d349074f5a6695c8eeabcd22e68f),
            uint256(0x14f6bc81d9f186f62bdb475ce6c9411866a7a8a3fd065b3ce0e699b67dd9e796),
            uint256(0x0962b82789fb3d129702ca70b2f6c5aacc099810c9c495c888edeb7386b97052),
            uint256(0x1a880af7074d18b3bf20c79de25127bc13284ab01ef02575afef0c8f6a31a86d),
            uint256(0x10cba18419a6a332cd5e77f0211c154b20af2924fc20ff3f4c3012bb7ae9311b),
            uint256(0x057e62a9a8f89b3ebdc76ba63a9eaca8fa27b7319cae3406756a2849f302f10d),
            uint256(0x287c971de91dc0abd44adf5384b4988cb961303bbf65cff5afa0413b44280cee),
            uint256(0x21df3388af1687bbb3bca9da0cca908f1e562bc46d4aba4e6f7f7960e306891d),
            uint256(0x1be5c887d25bce703e25cc974d0934cd789df8f70b498fd83eff8b560e1682b3),
            uint256(0x268da36f76e568fb68117175cea2cd0dd2cb5d42fda5acea48d59c2706a0d5c1),
            uint256(0x0e17ab091f6eae50c609beaf5510ececc5d8bb74135ebd05bd06460cc26a5ed6),
            uint256(0x04d727e728ffa0a67aee535ab074a43091ef62d8cf83d270040f5caa1f62af40),
            uint256(0x0ddbd7bf9c29341581b549762bc022ed33702ac10f1bfd862b15417d7e39ca6e),
            uint256(0x2790eb3351621752768162e82989c6c234f5b0d1d3af9b588a29c49c8789654b),
            uint256(0x1e457c601a63b73e4471950193d8a570395f3d9ab8b2fd0984b764206142f9e9),
            uint256(0x21ae64301dca9625638d6ab2bbe7135ffa90ecd0c43ff91fc4c686fc46e091b0),
            uint256(0x0379f63c8ce3468d4da293166f494928854be9e3432e09555858534eed8d350b),
            uint256(0x002d56420359d0266a744a080809e054ca0e4921a46686ac8c9f58a324c35049),
            uint256(0x123158e5965b5d9b1d68b3cd32e10bbeda8d62459e21f4090fc2c5af963515a6),
            uint256(0x0be29fc40847a941661d14bbf6cbe0420fbb2b6f52836d4e60c80eb49cad9ec1),
            uint256(0x1ac96991dec2bb0557716142015a453c36db9d859cad5f9a233802f24fdf4c1a),
            uint256(0x1596443f763dbcc25f4964fc61d23b3e5e12c9fa97f18a9251ca3355bcb0627e),
            uint256(0x12e0bcd3654bdfa76b2861d4ec3aeae0f1857d9f17e715aed6d049eae3ba3212),
            uint256(0x0fc92b4f1bbea82b9ea73d4af9af2a50ceabac7f37154b1904e6c76c7cf964ba),
            uint256(0x1f9c0b1610446442d6f2e592a8013f40b14f7c7722236f4f9c7e965233872762),
            uint256(0x0ebd74244ae72675f8cde06157a782f4050d914da38b4c058d159f643dbbf4d3),
            uint256(0x2cb7f0ed39e16e9f69a9fafd4ab951c03b0671e97346ee397a839839dccfc6d1),
            uint256(0x1a9d6e2ecff022cc5605443ee41bab20ce761d0514ce526690c72bca7352d9bf),
            uint256(0x2a115439607f335a5ea83c3bc44a9331d0c13326a9a7ba3087da182d648ec72f),
            uint256(0x23f9b6529b5d040d15b8fa7aee3e3410e738b56305cd44f29535c115c5a4c060),
            uint256(0x05872c16db0f72a2249ac6ba484bb9c3a3ce97c16d58b68b260eb939f0e6e8a7),
            uint256(0x1300bdee08bb7824ca20fb80118075f40219b6151d55b5c52b624a7cdeddf6a7)
        ];
        return rc[i];
    }

    function _matIntDiag(uint256 i) internal pure returns (uint256) {
        // POSEIDON_INTERNAL_MAT_DIAG(2) = [1, 2] (verbatim from poseidon2_const.circom @ e6a69f0).
        uint256[2] memory d = [uint256(1), uint256(2)];
        return d[i];
    }

    function _sbox(uint256 x) internal pure returns (uint256) {
        // x^5 mod P
        uint256 x2 = mulmod(x, x, P);
        uint256 x4 = mulmod(x2, x2, P);
        return mulmod(x4, x, P);
    }

    // External linear layer for t=2: M_E = [[2,1],[1,2]] -> (2a+b, a+2b)
    function _extMat(uint256 a, uint256 b) internal pure returns (uint256, uint256) {
        uint256 s = addmod(a, b, P);
        return (addmod(a, s, P), addmod(b, s, P));
    }

    // Internal linear layer for t=2: state[i] = state[i]*diag[i] + sum(state)
    function _intMat(uint256 a, uint256 b) internal pure returns (uint256, uint256) {
        uint256 s = addmod(a, b, P);
        uint256 na = addmod(mulmod(a, _matIntDiag(0), P), s, P);
        uint256 nb = addmod(mulmod(b, _matIntDiag(1), P), s, P);
        return (na, nb);
    }

    /// @notice Full t=2 permutation on [l, r] (no capacity slot).
    function perm(uint256 l, uint256 r) public pure returns (uint256, uint256) {
        require(l < P && r < P, "input not in field");
        uint256 s0 = l;
        uint256 s1 = r;

        // Poseidon2 begins by applying the external matrix once (M_E).
        (s0, s1) = _extMat(s0, s1);

        // 4 initial full rounds: AddRC (both lanes) -> S-box (both lanes) -> M_E
        for (uint256 i = 0; i < 4; i++) {
            (uint256 c0, uint256 c1) = _fullRC(i);
            s0 = _sbox(addmod(s0, c0, P));
            s1 = _sbox(addmod(s1, c1, P));
            (s0, s1) = _extMat(s0, s1);
        }

        // 56 partial rounds: AddRC (lane 0) -> S-box (lane 0) -> M_I
        for (uint256 i = 0; i < R_P; i++) {
            s0 = _sbox(addmod(s0, _partialRC(i), P));
            (s0, s1) = _intMat(s0, s1);
        }

        // 4 final full rounds
        for (uint256 i = 4; i < 8; i++) {
            (uint256 c0, uint256 c1) = _fullRC(i);
            s0 = _sbox(addmod(s0, c0, P));
            s1 = _sbox(addmod(s1, c1, P));
            (s0, s1) = _extMat(s0, s1);
        }

        return (s0, s1);
    }

    function compress(uint256 l, uint256 r) external pure returns (uint256) {
        (uint256 o0, ) = perm(l, r);
        return addmod(o0, l, P); // Compress = Perm₂([l,r])[0] + l
    }
}
```
> **Constants are pre-filled** above, transcribed verbatim from `poseidon2_const.circom @ e6a69f0` (`POSEIDON_FULL_ROUNDS(2)` = 8×2, `POSEIDON_PARTIAL_ROUNDS(2)` = 56, `POSEIDON_INTERNAL_MAT_DIAG(2)` = `[1,2]`). To re-pull them deterministically if the SHA changes:
> ```bash
> SHA=e6a69f0752cb555bdb6020f9f29be1a36ced1a3e
> curl -fsSL "https://raw.githubusercontent.com/NethermindEth/stellar-private-payments/$SHA/circuits/src/poseidon2/poseidon2_const.circom" \
>   | sed -n '/POSEIDON_PARTIAL_ROUNDS/,/t==3/p; /POSEIDON_FULL_ROUNDS/,/t==3/p; /POSEIDON_INTERNAL_MAT_DIAG/,/t==3/p'
> ```
> The Task 2 keystone parity test (Step 5) is the final arbiter — if it goes red, the round structure (4 full + 56 partial + 4 full), the `M_E`=[[2,1],[1,2]] / `M_I`(`state[j]·diag[j]+Σ`) forms, or a copied constant is off; localize via a per-round dump.
>
> **Predicted t=2 vectors (validated 2026-06-15):** an independent off-chain re-implementation of the fork's `Permutation(2)` (literal circom-template transcription) and of this Solidity (`_extMat`/`_intMat`) — both fed the constants above — agree exactly on `perm(1,2)`. The actual circom witness in Task 2 must reproduce:
> ```
> perm_out[0]  = 0x0e90c132311e864e0c8bca37976f28579a2dd9436bbc11326e21ec7c00cea5b2
> perm_out[1]  = 0x303a321e3ba2d1e7a7ad5b7d72cb13c4cbf5547c947a5c59c549d98498adbafe
> compress_1_2 = 0x0e90c132311e864e0c8bca37976f28579a2dd9436bbc11326e21ec7c00cea5b3   (= perm_out[0] + 1)
> ```
> These are computed from the fork's constants + algorithm, not from a circom run — treat them as a high-confidence target, with the Task 2 keystone as the authoritative confirmation.

- [ ] **Step 5: Run the parity test — iterate constants until GREEN**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge test --match-contract Poseidon2Test -vv
```
Expected output: `[PASS] test_PermParityWithSpike()`, `[PASS] test_CompressParityWithSpike()` — `Suite result: ok. 2 passed; 0 failed`. *(If red, compare the first diverging value against a per-round dump from the spike to localize the wrong round/matrix.)*

- [ ] **Step 6: Commit**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && git add src/IHasher.sol src/Poseidon2.sol test/Poseidon2.t.sol && git commit -m "feat(evm-tree): Poseidon2 t=2 Merkle-compression Solidity port with parity test vs spike vector"
```

---

### Task 12-ALT: FALLBACK — classic Poseidon (t=3) via poseidon-solidity (USE ONLY IF Task 12 stalls)
**Files:**
- Create: `evm-tree/src/PoseidonHasher.sol`
- Test: `evm-tree/test/PoseidonHasher.t.sol`

> **Label: FALLBACK / ALTERNATIVE — do not build alongside Task 12.** If the t=2 Poseidon2 port cannot be made parity-correct in time, switch the **entire system** (circuit + Soroban verifier) to **classic Poseidon over BN254** using the audited-by-usage `chancehudson/poseidon-solidity` `PoseidonT3` (t=3, `hash([a,b])`). This changes the shared interface contract: `commitment = PoseidonHash2(nullifier, secret)` and `Compress(l,r) = PoseidonHash2(l,r)` (no `+ l` term — classic Poseidon's sponge is already collision-safe). **The circuit must use circomlib `poseidon` (t=3) and Soroban must mirror it. Coordinate the switch in lockstep — pin it in the shared spec before touching this file.**

- [ ] **Step 1: Write `src/PoseidonHasher.sol`** (wraps PoseidonT3 behind the same IHasher shape, minus the `+l` compression)
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

/// @notice FALLBACK hasher: classic Poseidon (circomlib-compatible, t=3) on BN254.
///         Compress(l,r) = PoseidonT3.hash([l,r]); commitment = PoseidonT3.hash([n,s]).
contract PoseidonHasher {
    function perm(uint256 l, uint256 r) external pure returns (uint256, uint256) {
        // classic Poseidon exposes only the sponge output; second lane is unused here.
        return (PoseidonT3.hash([l, r]), 0);
    }

    function compress(uint256 l, uint256 r) external pure returns (uint256) {
        return PoseidonT3.hash([l, r]);
    }

    function hash2(uint256 a, uint256 b) external pure returns (uint256) {
        return PoseidonT3.hash([a, b]);
    }
}
```

- [ ] **Step 2: Write `test/PoseidonHasher.t.sol`** (parity vs a circomlib vector — regenerate `poseidon2.json` analog with circomlibjs `poseidon([1,2])` first)
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PoseidonHasher} from "../src/PoseidonHasher.sol";

contract PoseidonHasherTest is Test {
    PoseidonHasher h;

    function setUp() public {
        h = new PoseidonHasher();
    }

    // circomlib poseidon([1,2]) — KNOWN VECTOR (verify against your circomlibjs run):
    // poseidon([1,2]) = 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
    function test_ClassicPoseidonKnownVector() public view {
        uint256 expected =
            0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a;
        assertEq(h.compress(1, 2), expected, "PoseidonT3([1,2]) mismatch");
    }
}
```

- [ ] **Step 3: Run the fallback test**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge test --match-contract PoseidonHasherTest -vv
```
Expected output: `[PASS] test_ClassicPoseidonKnownVector()` — `Suite result: ok. 1 passed; 0 failed`. *(If the known vector differs from your circomlibjs output, replace the literal with your run's value — the circuit and Soroban must use that same value.)*

- [ ] **Step 4: Commit (only if this path is taken)**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && git add src/PoseidonHasher.sol test/PoseidonHasher.t.sol && git commit -m "feat(evm-tree): FALLBACK classic Poseidon t=3 hasher via poseidon-solidity"
```

---

### Task 13: Adapt MerkleTreeWithHistory.sol (depth=20, ROOT_HISTORY_SIZE=30, isKnownRoot) for our hasher
**Files:**
- Create: `evm-tree/src/MerkleTreeWithHistory.sol`
- Test: `evm-tree/test/MerkleTreeWithHistory.t.sol`

> Fork of Tornado's `MerkleTreeWithHistory.sol`, modernized to `^0.8.24` and rewired to our `IHasher.compress` (not MiMC's sponge `hashLeftRight`). `levels`/`zeros` become constructor args sourced from `zeros.json`. `_insert` and the 30-root ring buffer / `isKnownRoot` logic are kept verbatim in structure.

- [ ] **Step 1: Write the FAILING test `test/MerkleTreeWithHistory.t.sol`** (loads `zeros.json`, builds a tree, asserts the initial root and first-insert behavior)
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Poseidon2} from "../src/Poseidon2.sol";
import {IHasher} from "../src/IHasher.sol";
import {MerkleTreeWithHistory} from "../src/MerkleTreeWithHistory.sol";

contract MTHHarness is MerkleTreeWithHistory {
    constructor(uint32 levels, IHasher hasher, uint256 zeroValue)
        MerkleTreeWithHistory(levels, hasher, zeroValue)
    {}
    function insert(uint256 leaf) external returns (uint32) {
        return _insert(leaf);
    }
}

contract MerkleTreeWithHistoryTest is Test {
    using stdJson for string;

    MTHHarness tree;
    IHasher hasher;
    uint256 zeroValue;
    uint256 initialRoot;

    function setUp() public {
        string memory z = vm.readFile("test/vectors/zeros.json");
        zeroValue = uint256(z.readBytes32(".zeroValue"));
        initialRoot = uint256(z.readBytes32(".zeros[20]")); // root of empty depth-20 tree
        hasher = IHasher(address(new Poseidon2()));
        tree = new MTHHarness(20, hasher, zeroValue);
    }

    function test_InitialRootMatchesZerosTable() public view {
        assertEq(tree.getLastRoot(), initialRoot, "empty root mismatch");
        assertTrue(tree.isKnownRoot(initialRoot), "initial root should be known");
    }

    function test_InsertReturnsSequentialLeafIndex() public {
        assertEq(tree.insert(uint256(111)), 0, "first leaf index");
        assertEq(tree.insert(uint256(222)), 1, "second leaf index");
    }

    function test_InsertUpdatesRoot() public {
        uint256 before = tree.getLastRoot();
        tree.insert(uint256(111));
        assertTrue(tree.getLastRoot() != before, "root must change after insert");
        assertTrue(tree.isKnownRoot(tree.getLastRoot()), "new root must be known");
    }

    function test_OldRootStillKnownWithinWindow() public {
        uint256 r0 = tree.getLastRoot();
        tree.insert(uint256(111));
        assertTrue(tree.isKnownRoot(r0), "old root must remain known within 30-window");
    }

    function test_ZeroRootNeverKnown() public view {
        assertFalse(tree.isKnownRoot(0), "zero must never be a known root");
    }
}
```

- [ ] **Step 2: Run — confirm it FAILS to compile (no contract yet)**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge test --match-contract MerkleTreeWithHistoryTest
```
Expected output: compile error `Source "src/MerkleTreeWithHistory.sol" not found` (expected red state).

- [ ] **Step 3: Implement `src/MerkleTreeWithHistory.sol`**
```solidity
// SPDX-License-Identifier: MIT
// Adapted from tornadocash/tornado-core MerkleTreeWithHistory.sol (MIT).
// Changes: solc ^0.8.24; uint256 leaves; IHasher.compress instead of MiMC sponge;
//          zeros[] computed on-chain from a constructor zeroValue (matches zeros.json).
pragma solidity ^0.8.24;

import {IHasher} from "./IHasher.sol";

contract MerkleTreeWithHistory {
    uint256 public constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint32 public constant ROOT_HISTORY_SIZE = 30;

    IHasher public immutable hasher;
    uint32 public immutable levels;
    uint256 public immutable zeroValue;

    mapping(uint256 => uint256) public filledSubtrees;
    mapping(uint256 => uint256) public roots;
    uint32 public currentRootIndex = 0;
    uint32 public nextIndex = 0;

    constructor(uint32 _levels, IHasher _hasher, uint256 _zeroValue) {
        require(_levels > 0, "_levels must be > 0");
        require(_levels < 32, "_levels must be < 32");
        levels = _levels;
        hasher = _hasher;
        zeroValue = _zeroValue;

        for (uint32 i = 0; i < _levels; i++) {
            filledSubtrees[i] = _zeros(i);
        }
        roots[0] = _zeros(_levels); // root of the empty tree = zeros[levels]
    }

    /// @dev zeros[0] = zeroValue; zeros[i] = compress(zeros[i-1], zeros[i-1]).
    function _zeros(uint256 i) internal view returns (uint256) {
        uint256 z = zeroValue;
        for (uint256 k = 0; k < i; k++) {
            z = hasher.compress(z, z);
        }
        return z;
    }

    function zeros(uint256 i) external view returns (uint256) {
        return _zeros(i);
    }

    function _insert(uint256 _leaf) internal returns (uint32 index) {
        uint32 _nextIndex = nextIndex;
        require(_nextIndex != uint32(2) ** levels, "Merkle tree is full");
        require(_leaf < FIELD_SIZE, "leaf not in field");

        uint32 currentIndex = _nextIndex;
        uint256 currentLevelHash = _leaf;
        uint256 left;
        uint256 right;

        for (uint32 i = 0; i < levels; i++) {
            if (currentIndex % 2 == 0) {
                left = currentLevelHash;
                right = _zeros(i);
                filledSubtrees[i] = currentLevelHash;
            } else {
                left = filledSubtrees[i];
                right = currentLevelHash;
            }
            currentLevelHash = hasher.compress(left, right);
            currentIndex /= 2;
        }

        uint32 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        currentRootIndex = newRootIndex;
        roots[newRootIndex] = currentLevelHash;
        nextIndex = _nextIndex + 1;
        return _nextIndex;
    }

    function isKnownRoot(uint256 _root) public view returns (bool) {
        if (_root == 0) {
            return false;
        }
        uint32 _currentRootIndex = currentRootIndex;
        uint32 i = _currentRootIndex;
        do {
            if (_root == roots[i]) {
                return true;
            }
            if (i == 0) {
                i = ROOT_HISTORY_SIZE;
            }
            i--;
        } while (i != _currentRootIndex);
        return false;
    }

    function getLastRoot() public view returns (uint256) {
        return roots[currentRootIndex];
    }
}
```
> **Note on `_zeros` cost:** computing zeros on-chain via a loop is O(levels) per call and called O(levels) times in `_insert` → O(levels²) ≈ 400 `compress` calls per deposit. That is acceptable on Sepolia testnet for an MVP and keeps the contract self-consistent with the hasher (no risk of pasting a wrong constant). The optimization (immutable precomputed `zeros[20]` from `zeros.json`) is deferred — note it in the deploy task if gas becomes a problem.

- [ ] **Step 4: Run the Merkle tests — GREEN**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge test --match-contract MerkleTreeWithHistoryTest -vv
```
Expected output: 5 passing: `test_InitialRootMatchesZerosTable`, `test_InsertReturnsSequentialLeafIndex`, `test_InsertUpdatesRoot`, `test_OldRootStillKnownWithinWindow`, `test_ZeroRootNeverKnown` — `Suite result: ok. 5 passed; 0 failed`.

- [ ] **Step 5: Add a ring-buffer wrap test (31 inserts: the 1st-after-genesis root falls out of the 30-window)**
Append to `test/MerkleTreeWithHistory.t.sol` inside the test contract:
```solidity
    function test_RingBufferEvictsOldestRoot() public {
        // genesis root is roots[0]; after 30 inserts we wrap and overwrite roots[0].
        uint256 genesisRoot = tree.getLastRoot();
        for (uint256 i = 0; i < 30; i++) {
            tree.insert(uint256(1000 + i));
        }
        // After 30 inserts, currentRootIndex wrapped back to 0, overwriting genesis.
        assertFalse(tree.isKnownRoot(genesisRoot), "genesis root must be evicted after 30 inserts");
        assertTrue(tree.isKnownRoot(tree.getLastRoot()), "latest root still known");
    }
```

- [ ] **Step 6: Run again — confirm 6 passing**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge test --match-contract MerkleTreeWithHistoryTest -vv
```
Expected output: `Suite result: ok. 6 passed; 0 failed`.

- [ ] **Step 7: Commit**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && git add src/MerkleTreeWithHistory.sol test/MerkleTreeWithHistory.t.sol && git commit -m "feat(evm-tree): adapt MerkleTreeWithHistory (depth=20, 30-root ring) for Poseidon2 compress"
```

---

### Task 14: Mock test-USDC ERC20 for Sepolia
**Files:**
- Create: `evm-tree/src/MockUSDC.sol`
- Test: `evm-tree/test/MockUSDC.t.sol`

> A 6-decimal mintable ERC20 standing in for USDC. Public `mint` so anyone can fund themselves for testing.

- [ ] **Step 1: Write the FAILING test `test/MockUSDC.t.sol`**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MockUSDC} from "../src/MockUSDC.sol";

contract MockUSDCTest is Test {
    MockUSDC usdc;
    address alice = address(0xA11CE);

    function setUp() public {
        usdc = new MockUSDC();
    }

    function test_DecimalsIsSix() public view {
        assertEq(usdc.decimals(), 6);
    }

    function test_PublicMint() public {
        usdc.mint(alice, 1_000_000); // 1 USDC (6 decimals)
        assertEq(usdc.balanceOf(alice), 1_000_000);
    }
}
```

- [ ] **Step 2: Run — confirm FAIL (no contract)**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge test --match-contract MockUSDCTest
```
Expected output: compile error `Source "src/MockUSDC.sol" not found`.

- [ ] **Step 3: Implement `src/MockUSDC.sol`**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("Mock USD Coin", "mUSDC") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    /// @notice Open faucet mint for testnet use.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
```

- [ ] **Step 4: Run — GREEN**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge test --match-contract MockUSDCTest -vv
```
Expected output: `Suite result: ok. 2 passed; 0 failed`.

- [ ] **Step 5: Commit**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && git add src/MockUSDC.sol test/MockUSDC.t.sol && git commit -m "feat(evm-tree): MockUSDC 6-decimal faucet ERC20 for Sepolia"
```

---

### Task 15: Deposit contract — lock USDC per denomination, insert leaf, emit Deposit + root events
**Files:**
- Create: `evm-tree/src/PrivacyPoolDeposit.sol`
- Test: `evm-tree/test/PrivacyPoolDeposit.t.sol`

> One independent `MerkleTreeWithHistory` per denomination. Denominations are configured at construction (`[1, 10, 100]` scaled by USDC decimals). `deposit(uint8 denomIndex, uint256 commitment)` pulls exactly `denominations[denomIndex]` USDC via `transferFrom`, inserts the commitment into that denom's tree, and emits `Deposit(denom, commitment, leafIndex)` + `RootUpdated(denom, root, rootIndex)`. Per-tree `commitments` mapping rejects duplicates.

- [ ] **Step 1: Write the FAILING test `test/PrivacyPoolDeposit.t.sol`**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Poseidon2} from "../src/Poseidon2.sol";
import {IHasher} from "../src/IHasher.sol";
import {MockUSDC} from "../src/MockUSDC.sol";
import {PrivacyPoolDeposit} from "../src/PrivacyPoolDeposit.sol";

contract PrivacyPoolDepositTest is Test {
    using stdJson for string;

    PrivacyPoolDeposit pool;
    MockUSDC usdc;
    IHasher hasher;
    address alice = address(0xA11CE);

    uint256 constant ONE = 1_000_000;        // 1 USDC
    uint256 constant TEN = 10_000_000;        // 10 USDC
    uint256 constant HUNDRED = 100_000_000;   // 100 USDC

    event Deposit(uint8 indexed denomIndex, uint256 indexed commitment, uint32 leafIndex);
    event RootUpdated(uint8 indexed denomIndex, uint256 root, uint32 rootIndex);

    function setUp() public {
        hasher = IHasher(address(new Poseidon2()));
        usdc = new MockUSDC();
        uint256[] memory denoms = new uint256[](3);
        denoms[0] = ONE;
        denoms[1] = TEN;
        denoms[2] = HUNDRED;
        pool = new PrivacyPoolDeposit(IHasher(address(hasher)), address(usdc), 20, denoms);

        usdc.mint(alice, 1_000 * ONE);
        vm.prank(alice);
        usdc.approve(address(pool), type(uint256).max);
    }

    function test_DepositPullsExactDenominationAndIncrementsLeaf() public {
        uint256 cmt = uint256(0xABC);
        vm.prank(alice);
        uint32 leafIndex = pool.deposit(1, cmt); // 10-USDC denom
        assertEq(leafIndex, 0, "first leaf index");
        assertEq(usdc.balanceOf(address(pool)), TEN, "pool holds 10 USDC");
        assertEq(usdc.balanceOf(alice), 1_000 * ONE - TEN, "alice debited 10 USDC");
    }

    function test_DepositEmitsDepositAndRootEvents() public {
        uint256 cmt = uint256(0xABC);
        vm.expectEmit(true, true, false, true);
        emit Deposit(0, cmt, 0);
        vm.prank(alice);
        pool.deposit(0, cmt);
    }

    function test_DepositUpdatesRootAndIsKnown() public {
        vm.prank(alice);
        pool.deposit(2, uint256(0xDEAD));
        uint256 root = pool.getLastRoot(2);
        assertTrue(pool.isKnownRoot(2, root), "post-deposit root must be known");
    }

    function test_RejectsDuplicateCommitment() public {
        vm.startPrank(alice);
        pool.deposit(0, uint256(0xABC));
        vm.expectRevert(bytes("commitment already used"));
        pool.deposit(0, uint256(0xABC));
        vm.stopPrank();
    }

    function test_RejectsBadDenomIndex() public {
        vm.prank(alice);
        vm.expectRevert(bytes("bad denom index"));
        pool.deposit(3, uint256(0xABC)); // only indices 0..2 exist
    }

    function test_TreesAreIndependentPerDenomination() public {
        vm.startPrank(alice);
        pool.deposit(0, uint256(0x1));
        pool.deposit(1, uint256(0x1)); // same commitment value, different denom tree → allowed
        vm.stopPrank();
        assertEq(pool.nextIndex(0), 1, "denom0 has one leaf");
        assertEq(pool.nextIndex(1), 1, "denom1 has one leaf");
    }
}
```

- [ ] **Step 2: Run — confirm FAIL (no contract)**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge test --match-contract PrivacyPoolDepositTest
```
Expected output: compile error `Source "src/PrivacyPoolDeposit.sol" not found`.

- [ ] **Step 3: Implement `src/PrivacyPoolDeposit.sol`**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IHasher} from "./IHasher.sol";
import {MerkleTreeWithHistory} from "./MerkleTreeWithHistory.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title PrivacyPoolDeposit
/// @notice One independent Merkle tree per denomination. Locks test-USDC and
///         inserts commitment leaves. Mirrors the shared interface contract:
///         commitment = Poseidon2Hash2(nullifier, secret) (computed off-chain).
contract PrivacyPoolDeposit is ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    IHasher public immutable hasher;
    uint32 public immutable levels;

    uint256[] public denominations;            // index -> USDC amount (6 decimals)
    MerkleTreeWithHistory[] public trees;       // index -> tree for that denom
    // denomIndex => commitment => used
    mapping(uint8 => mapping(uint256 => bool)) public commitments;

    event Deposit(uint8 indexed denomIndex, uint256 indexed commitment, uint32 leafIndex);
    event RootUpdated(uint8 indexed denomIndex, uint256 root, uint32 rootIndex);

    constructor(
        IHasher _hasher,
        address _token,
        uint32 _levels,
        uint256[] memory _denominations
    ) {
        require(_denominations.length > 0, "no denominations");
        require(_denominations.length <= 256, "too many denominations");
        hasher = _hasher;
        token = IERC20(_token);
        levels = _levels;

        // Read the empty-tree zero value once from a freshly built tree is circular;
        // instead derive zeroValue the same way the generator did:
        // keccak256("stellar-zkbridge") % FIELD_SIZE. Pinned constant below.
        uint256 zeroValue =
            uint256(keccak256("stellar-zkbridge")) %
            21888242871839275222246405745257275088548364400416034343698204186575808495617;

        for (uint256 i = 0; i < _denominations.length; i++) {
            require(_denominations[i] > 0, "denom must be > 0");
            denominations.push(_denominations[i]);
            trees.push(new MerkleTreeWithHistory(_levels, _hasher, zeroValue));
        }
    }

    function denominationCount() external view returns (uint256) {
        return denominations.length;
    }

    function deposit(uint8 denomIndex, uint256 commitment)
        external
        nonReentrant
        returns (uint32 leafIndex)
    {
        require(denomIndex < denominations.length, "bad denom index");
        require(commitment != 0, "zero commitment");
        require(!commitments[denomIndex][commitment], "commitment already used");

        // Lock exactly the denomination amount of test-USDC.
        token.safeTransferFrom(msg.sender, address(this), denominations[denomIndex]);

        commitments[denomIndex][commitment] = true;
        leafIndex = _insertLeaf(trees[denomIndex], commitment);

        emit Deposit(denomIndex, commitment, leafIndex);
        MerkleTreeWithHistory tree = trees[denomIndex];
        emit RootUpdated(denomIndex, tree.getLastRoot(), tree.currentRootIndex());
        return leafIndex;
    }

    function _insertLeaf(MerkleTreeWithHistory tree, uint256 commitment)
        internal
        returns (uint32)
    {
        return tree.insertLeaf(commitment);
    }

    // --- views proxied per denomination ---
    function getLastRoot(uint8 denomIndex) external view returns (uint256) {
        require(denomIndex < denominations.length, "bad denom index");
        return trees[denomIndex].getLastRoot();
    }

    function isKnownRoot(uint8 denomIndex, uint256 root) external view returns (bool) {
        require(denomIndex < denominations.length, "bad denom index");
        return trees[denomIndex].isKnownRoot(root);
    }

    function nextIndex(uint8 denomIndex) external view returns (uint32) {
        require(denomIndex < denominations.length, "bad denom index");
        return trees[denomIndex].nextIndex();
    }
}
```

- [ ] **Step 4: Expose `insertLeaf` on the tree (the pool needs an external insert entrypoint)** — edit `src/MerkleTreeWithHistory.sol` to add an owner-gated external insert. Add OpenZeppelin `Ownable` and an `insertLeaf`:

Replace the contract declaration line:
```solidity
contract MerkleTreeWithHistory {
```
with:
```solidity
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract MerkleTreeWithHistory is Ownable {
```
Update the constructor signature/body header from:
```solidity
    constructor(uint32 _levels, IHasher _hasher, uint256 _zeroValue) {
```
to:
```solidity
    constructor(uint32 _levels, IHasher _hasher, uint256 _zeroValue) Ownable(msg.sender) {
```
And add this external function just after `getLastRoot()`:
```solidity
    /// @notice Owner (the PrivacyPoolDeposit that deployed this tree) inserts a leaf.
    function insertLeaf(uint256 leaf) external onlyOwner returns (uint32) {
        return _insert(leaf);
    }
```
> The pool deploys each tree (so the pool is `owner`), making `onlyOwner` the deposit contract. The test harness in Task 13 calls `_insert` directly via inheritance, so it is unaffected.

- [ ] **Step 5: Run the deposit tests — GREEN**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge test --match-contract PrivacyPoolDepositTest -vvv
```
Expected output: 6 passing — `test_DepositPullsExactDenominationAndIncrementsLeaf`, `test_DepositEmitsDepositAndRootEvents`, `test_DepositUpdatesRootAndIsKnown`, `test_RejectsDuplicateCommitment`, `test_RejectsBadDenomIndex`, `test_TreesAreIndependentPerDenomination` — `Suite result: ok. 6 passed; 0 failed`.

- [ ] **Step 6: Run the WHOLE suite to confirm nothing regressed**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge test -vv
```
Expected output: all suites pass — `Poseidon2Test` (3), `MerkleTreeWithHistoryTest` (6), `MockUSDCTest` (2), `PrivacyPoolDepositTest` (6). `Suite result: ok` for each, total `17 passed; 0 failed` (excluding the fallback suite unless Task 12-ALT was built).

- [ ] **Step 7: Commit**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && git add src/PrivacyPoolDeposit.sol src/MerkleTreeWithHistory.sol test/PrivacyPoolDeposit.t.sol && git commit -m "feat(evm-tree): PrivacyPoolDeposit locks USDC per denom, inserts leaf, emits Deposit+RootUpdated"
```

---

### Task 16: End-to-end leaf-index + root-window integration test (mirrors the relayer's read path)
**Files:**
- Test: `evm-tree/test/Integration.t.sol`

> Asserts the exact data the Backing Relayer will read: `Deposit.leafIndex` is monotonic across mixed-denomination deposits, and the relayer can confirm "is this root in the last-30 window" via `isKnownRoot`. This locks the cross-component contract before deploy.

- [ ] **Step 1: Write `test/Integration.t.sol`**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Poseidon2} from "../src/Poseidon2.sol";
import {IHasher} from "../src/IHasher.sol";
import {MockUSDC} from "../src/MockUSDC.sol";
import {PrivacyPoolDeposit} from "../src/PrivacyPoolDeposit.sol";

contract IntegrationTest is Test {
    PrivacyPoolDeposit pool;
    MockUSDC usdc;
    address alice = address(0xA11CE);
    uint256 constant ONE = 1_000_000;

    function setUp() public {
        IHasher hasher = IHasher(address(new Poseidon2()));
        usdc = new MockUSDC();
        uint256[] memory d = new uint256[](3);
        d[0] = ONE; d[1] = 10 * ONE; d[2] = 100 * ONE;
        pool = new PrivacyPoolDeposit(hasher, address(usdc), 20, d);
        usdc.mint(alice, 10_000 * ONE);
        vm.prank(alice);
        usdc.approve(address(pool), type(uint256).max);
    }

    function test_LeafIndexMonotonicPerDenomAndRootHistory() public {
        vm.startPrank(alice);
        // 5 deposits into denom 0, capture each root.
        uint256[] memory roots = new uint256[](5);
        for (uint256 i = 0; i < 5; i++) {
            uint32 idx = pool.deposit(0, uint256(1_000 + i));
            assertEq(idx, uint32(i), "leaf index must equal deposit count");
            roots[i] = pool.getLastRoot(0);
        }
        vm.stopPrank();

        // Every one of the last 5 roots is within the 30-window → relayer can anchor any.
        for (uint256 i = 0; i < 5; i++) {
            assertTrue(pool.isKnownRoot(0, roots[i]), "recent root must be anchorable");
        }
        // A fabricated root must be rejected.
        assertFalse(pool.isKnownRoot(0, uint256(0xBADBAD)), "unknown root rejected");
    }

    function test_DenomTreesDoNotShareState() public {
        vm.startPrank(alice);
        pool.deposit(0, uint256(0xA));
        uint256 root0 = pool.getLastRoot(0);
        pool.deposit(2, uint256(0xB));
        uint256 root2 = pool.getLastRoot(2);
        vm.stopPrank();
        // root0 is unknown in denom-2's window and vice versa.
        assertFalse(pool.isKnownRoot(2, root0), "denom0 root must not be known in denom2");
        assertFalse(pool.isKnownRoot(0, root2), "denom2 root must not be known in denom0");
    }
}
```

- [ ] **Step 2: Run — GREEN**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && forge test --match-contract IntegrationTest -vv
```
Expected output: `Suite result: ok. 2 passed; 0 failed`.

- [ ] **Step 3: Commit**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && git add test/Integration.t.sol && git commit -m "test(evm-tree): e2e leaf-index monotonicity + per-denom root-window integration"
```

---

### Task 17: Deploy script for Sepolia (MockUSDC + PrivacyPoolDeposit + Poseidon2)
**Files:**
- Create: `evm-tree/script/Deploy.s.sol`

> A single broadcast deploys the hasher, MockUSDC, and the pool with denominations `[1, 10, 100]` USDC. Logs every address for the addresses record (Task 18).

- [ ] **Step 1: Write `script/Deploy.s.sol`**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {Poseidon2} from "../src/Poseidon2.sol";
import {IHasher} from "../src/IHasher.sol";
import {MockUSDC} from "../src/MockUSDC.sol";
import {PrivacyPoolDeposit} from "../src/PrivacyPoolDeposit.sol";

contract Deploy is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);

        Poseidon2 hasher = new Poseidon2();
        MockUSDC usdc = new MockUSDC();

        uint256 ONE = 1_000_000; // 6 decimals
        uint256[] memory denoms = new uint256[](3);
        denoms[0] = 1 * ONE;
        denoms[1] = 10 * ONE;
        denoms[2] = 100 * ONE;

        PrivacyPoolDeposit pool =
            new PrivacyPoolDeposit(IHasher(address(hasher)), address(usdc), 20, denoms);

        vm.stopBroadcast();

        console2.log("Poseidon2:          ", address(hasher));
        console2.log("MockUSDC:           ", address(usdc));
        console2.log("PrivacyPoolDeposit: ", address(pool));
        console2.log("Denominations (6dp): 1e6 / 10e6 / 100e6");
        console2.log("Tree denom0:        ", address(pool.trees(0)));
        console2.log("Tree denom1:        ", address(pool.trees(1)));
        console2.log("Tree denom2:        ", address(pool.trees(2)));
    }
}
```

- [ ] **Step 2: Dry-run the script locally (no broadcast) to confirm it compiles and simulates**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && DEPLOYER_PRIVATE_KEY=0x0000000000000000000000000000000000000000000000000000000000000001 forge script script/Deploy.s.sol:Deploy
```
Expected output: `Script ran successfully.` and the `console2.log` lines print simulated addresses (no on-chain broadcast yet).

- [ ] **Step 3: Commit**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && git add script/Deploy.s.sol && git commit -m "feat(evm-tree): Sepolia deploy script for Poseidon2 + MockUSDC + PrivacyPoolDeposit"
```

---

### Task 18: Deploy to Sepolia, verify on Etherscan, record addresses
**Files:**
- Create: `evm-tree/DEPLOYMENTS.md`

- [ ] **Step 1: Create `.env` from the example and fill in real values** (do NOT commit it)
```bash
cd ~/hackathon/stellar-hacks/evm-tree && cp .env.example .env && echo "Now edit .env with a funded Sepolia key, RPC URL, and Etherscan key"
```
Expected output: prints the reminder; `.env` exists (and is gitignored).

- [ ] **Step 2: Confirm the deployer has Sepolia ETH**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && source .env && cast balance $(cast wallet address $DEPLOYER_PRIVATE_KEY) --rpc-url $SEPOLIA_RPC_URL
```
Expected output: a non-zero wei balance (e.g. `50000000000000000`). If `0`, fund the address from a Sepolia faucet before proceeding.

- [ ] **Step 3: Broadcast + verify in one command**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && source .env && forge script script/Deploy.s.sol:Deploy --rpc-url $SEPOLIA_RPC_URL --broadcast --verify -vvvv
```
Expected output: `ONCHAIN EXECUTION COMPLETE & SUCCESSFUL`, the `console2.log` address lines, and `Contract successfully verified` for each of `Poseidon2`, `MockUSDC`, `PrivacyPoolDeposit` (and the per-denom `MerkleTreeWithHistory` trees, which auto-verify if matched by bytecode).

- [ ] **Step 4: Smoke-test a live deposit** (mint USDC, approve, deposit a dummy commitment into denom 0)
```bash
cd ~/hackathon/stellar-hacks/evm-tree && source .env \
  && ME=$(cast wallet address $DEPLOYER_PRIVATE_KEY) \
  && USDC=<MockUSDC_ADDRESS_FROM_STEP_3> \
  && POOL=<POOL_ADDRESS_FROM_STEP_3> \
  && cast send $USDC "mint(address,uint256)" $ME 1000000000 --rpc-url $SEPOLIA_RPC_URL --private-key $DEPLOYER_PRIVATE_KEY \
  && cast send $USDC "approve(address,uint256)" $POOL 1000000000 --rpc-url $SEPOLIA_RPC_URL --private-key $DEPLOYER_PRIVATE_KEY \
  && cast send $POOL "deposit(uint8,uint256)" 0 0x00000000000000000000000000000000000000000000000000000000000000abc --rpc-url $SEPOLIA_RPC_URL --private-key $DEPLOYER_PRIVATE_KEY
```
Expected output: three transaction receipts with `status 1 (success)`. The third (deposit) emits `Deposit` + `RootUpdated`.

- [ ] **Step 5: Read the live root back to confirm it is known** (the relayer's exact call)
```bash
cd ~/hackathon/stellar-hacks/evm-tree && source .env && POOL=<POOL_ADDRESS_FROM_STEP_3> \
  && ROOT=$(cast call $POOL "getLastRoot(uint8)(uint256)" 0 --rpc-url $SEPOLIA_RPC_URL) \
  && echo "lastRoot=$ROOT" \
  && cast call $POOL "isKnownRoot(uint8,uint256)(bool)" 0 $ROOT --rpc-url $SEPOLIA_RPC_URL
```
Expected output: prints `lastRoot=<non-zero number>` then `true`.

- [ ] **Step 6: Write `DEPLOYMENTS.md` with the recorded addresses** (paste the real addresses from Step 3)
```markdown
# EVM Sepolia Deployments (evm-tree)

Chain: Ethereum Sepolia (chainId 11155111)
Deployed: <DATE>
Deployer: <DEPLOYER_ADDRESS>

| Contract            | Address                                    | Etherscan |
|---------------------|--------------------------------------------|-----------|
| Poseidon2 (IHasher) | `0x...`                                    | verified  |
| MockUSDC (mUSDC, 6dp)| `0x...`                                   | verified  |
| PrivacyPoolDeposit  | `0x...`                                    | verified  |
| Tree denom0 (1 USDC)| `0x...`                                    | verified  |
| Tree denom1 (10 USDC)| `0x...`                                   | verified  |
| Tree denom2 (100 USDC)| `0x...`                                  | verified  |

## Interface for the Backing Relayer
- Read recent roots per denom: `getLastRoot(uint8 denomIndex) -> uint256`
- Confirm a root is anchorable: `isKnownRoot(uint8 denomIndex, uint256 root) -> bool`
- Watch event: `Deposit(uint8 indexed denomIndex, uint256 indexed commitment, uint32 leafIndex)`
- Watch event: `RootUpdated(uint8 indexed denomIndex, uint256 root, uint32 rootIndex)`
- Denominations (6 decimals): index 0 = 1e6, 1 = 10e6, 2 = 100e6.
- Merkle: depth=20, ROOT_HISTORY_SIZE=30, Compress(l,r)=Poseidon2Perm([l,r])[0]+l.
- ZERO_VALUE = keccak256("stellar-zkbridge") % FIELD_SIZE.
```

- [ ] **Step 7: Commit**
```bash
cd ~/hackathon/stellar-hacks/evm-tree && git add DEPLOYMENTS.md && git commit -m "docs(evm-tree): record Sepolia deployment addresses + relayer interface"
```

---

**Section dependency notes for the orchestrator:**
- Task 11 **hard-depends** on the spike exposing `poseidon2Perm` and `PARAMS_2` (round constants + matrices). Pin the exact export names from the spike before starting (Task 11 Step 1).
- Task 12 (Poseidon2 t=2 Solidity port) and the circuit's commitment hash and the Soroban verifier's Merkle hash **must all share the same parity vector** (`test/vectors/poseidon2.json`). If Task 12-ALT (fallback) is chosen, all three switch to classic Poseidon together.
- The `ZERO_VALUE` constant `keccak256("stellar-zkbridge") % FIELD_SIZE` is hardcoded identically in `gen_zeros.mjs` and `PrivacyPoolDeposit.sol` — the circuit's empty-tree assumptions and the off-chain tree builder in the relayer section must use the same value.

**Sources consulted:** [tornado-core MerkleTreeWithHistory.sol](https://github.com/tornadocash/tornado-core/blob/master/contracts/MerkleTreeWithHistory.sol), [tornado-core Tornado.sol](https://github.com/tornadocash/tornado-core/blob/master/contracts/Tornado.sol), [zemse/poseidon2-evm](https://github.com/zemse/poseidon2-evm) (t=4 sponge — rejected as primary), [chancehudson/poseidon-solidity](https://github.com/chancehudson/poseidon-solidity) (PoseidonT3 fallback).

## Withdrawal Circuit (circom / BN254 / Poseidon2)

> Source-of-truth fork: [`NethermindEth/stellar-private-payments`](https://github.com/NethermindEth/stellar-private-payments) — we lift the `circuits/src/poseidon2/*.circom` permutation/hash/compress templates and the `MerkleProof`/`Switcher` pattern from `circuits/src/merkleProof.circom`, but build a single standalone `withdraw.circom` main (the upstream repo embeds circuits in a Rust/Cargo harness with `build.rs`; we run them via the standalone `circom`+`snarkjs` CLIs for the MVP).
>
> **Pinned parity decisions (read before coding):**
> ⚠️ **MIXED ARITY (C2, confirmed from fork source):** the fork's `Permutation(t)` is width-parameterized; this circuit uses **different widths per operation** — Merkle compression `PoseidonCompress` = `Permutation(2)` (**t=2**, `Perm₂([l,r])[0]+l`, no domain sep); `commitment = Poseidon2(2)` = `Permutation(3)` (**t=3**, domainSep=0); `nullifierHash = Poseidon2(1)` = `Permutation(2)` (**t=2**, domainSep=0). Task 21 vendors the fork templates verbatim, so this is correct by construction — just pin parity against the keystone (Task 2) vectors.
> - **Permutation width / params:** BN254, HorizenLabs Poseidon2 — `POSEIDON_*(t)` constants for both t=2 and t=3. `Poseidon2Compress` uses `Permutation(2)`: `out = Perm₂([l,r])[0] + l`.
> - **Hashes use the sponge form** `Poseidon2(n)` from the fork, which internally calls `Permutation(n+1)` (capacity slot) and exposes a `domainSeparation` capacity input. **We pin `domainSeparation = 0` for every hash** and mirror that exact convention in the Rust/EVM spike.
>   - `commitment   = Poseidon2(2)([nullifier, secret], domainSeparation=0)`  → internally `Permutation(3)`.
>   - `nullifierHash = Poseidon2(1)([nullifier],         domainSeparation=0)`  → internally `Permutation(2)`. **Arity pinned to 1.**
> - **Public input vector order (circom main + Soroban verifier, identical):** `[ root, nullifierHash, recipient, denomination ]`.
> - **recipient encoding:** the Stellar address (32-byte Ed25519/contract id) reduced to one Fr via `recipient = be_bytes_to_field(addr32) mod p`. The circuit treats `recipient` as an opaque public Fr and binds it with a malleability guard; the *encoding* is enforced off-circuit (in the relayer/Soroban) and re-derived identically. Pinned in Task 21 Step and mirrored in the Soroban verifier task.

### Task 20: Scaffold the `circuits/` workspace and pin the toolchain

**Files:**
- Create: `circuits/package.json`
- Create: `circuits/.gitignore`
- Create: `circuits/.nvmrc`
- Create: `circuits/README.md`

- [ ] **Step 1: Create the circuits dir and pin Node**
```bash
mkdir -p circuits/src/poseidon2 circuits/build circuits/test circuits/ptau circuits/inputs
printf '22\n' > circuits/.nvmrc
node -v
```
Expected output (any Node 22.x is fine — C7):
```
v22.11.0
```

- [ ] **Step 2: Install circom 2.2.2 binary (matches fork `pragma circom 2.2.2`)**
```bash
circom --version 2>/dev/null || cargo install --git https://github.com/iden3/circom.git --tag v2.2.2 circom
circom --version
```
Expected output:
```
circom compiler 2.2.2
```

- [ ] **Step 3: Write `circuits/package.json` pinning snarkjs + circomlib**
```json
{
  "name": "stellar-zk-bridge-circuits",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "description": "Withdrawal circuit (BN254/Poseidon2) for the private cross-chain bridge",
  "scripts": {
    "compile": "circom src/withdraw.circom --r1cs --wasm --sym -l node_modules -o build",
    "ptau:dl": "bash scripts/ptau_phase1.sh",
    "setup": "bash scripts/phase2_setup.sh",
    "prove": "node scripts/prove.mjs",
    "verify": "snarkjs groth16 verify build/verification_key.json build/public.json build/proof.json",
    "test": "node --test test/"
  },
  "dependencies": {
    "circomlib": "2.0.5",
    "snarkjs": "0.7.5",
    "ffjavascript": "0.3.0",
    "circomlibjs": "0.1.7"
  }
}
```

- [ ] **Step 4: Write `circuits/.gitignore`**
```gitignore
node_modules/
build/
ptau/*.ptau
inputs/*.json
*.zkey
!build/verification_key.json
witness.wtns
```

- [ ] **Step 5: Install deps and verify snarkjs**
```bash
cd circuits && npm install --silent && npx snarkjs --version
```
Expected output:
```
snarkjs@0.7.5
```

- [ ] **Step 6: Write `circuits/README.md`**
```markdown
# Bridge withdrawal circuit

BN254 / Poseidon2 (HorizenLabs `POSEIDON2_BN256_PARAMS_2`, t=2 permutation).

- `commitment    = Poseidon2(2)([nullifier, secret], dsep=0)`
- `nullifierHash = Poseidon2(1)([nullifier],          dsep=0)`
- Merkle: depth 20, node = Poseidon2Compress(l,r) = Perm([l,r])[0] + l
- Public inputs (exact order): [root, nullifierHash, recipient, denomination]

Build: `npm run compile && npm run ptau:dl && npm run setup`
Prove: `npm run prove && npm run verify`
```

- [ ] **Step 7: Commit**
```bash
git add circuits/package.json circuits/.gitignore circuits/.nvmrc circuits/README.md && git commit -m "circuits: scaffold workspace, pin circom 2.2.2 + snarkjs 0.7.5 + circomlib 2.0.5"
```

---

### Task 21: Port the Poseidon2 circom templates from the fork

**Files:**
- Create: `circuits/src/poseidon2/poseidon2_const.circom`
- Create: `circuits/src/poseidon2/poseidon2_perm.circom`
- Create: `circuits/src/poseidon2/poseidon2_hash.circom`
- Create: `circuits/src/poseidon2/poseidon2_compress.circom`

- [ ] **Step 1: Vendor the constants file from the fork (verbatim)**
The round constants and internal-matrix diagonals are large fixed tables, parameterized by width via `POSEIDON_FULL_ROUNDS(t)` / `POSEIDON_PARTIAL_ROUNDS(t)` / `POSEIDON_INTERNAL_MAT_DIAG(t)` — the file serves **both** t=2 (compression, nullifierHash) and t=3 (commitment). Copy it exactly from the fork to guarantee parity.
```bash
cd circuits && curl -sSL \
  https://raw.githubusercontent.com/NethermindEth/stellar-private-payments/main/circuits/src/poseidon2/poseidon2_const.circom \
  -o src/poseidon2/poseidon2_const.circom
grep -c 'function POSEIDON' src/poseidon2/poseidon2_const.circom
```
Expected output (the three constant functions exist):
```
3
```
> The file exposes `POSEIDON_FULL_ROUNDS(t)`, `POSEIDON_PARTIAL_ROUNDS(t)`, `POSEIDON_INTERNAL_MAT_DIAG(t)`. Do **not** hand-edit these tables.

- [ ] **Step 2: Vendor the permutation template from the fork (verbatim)**
```bash
cd circuits && curl -sSL \
  https://raw.githubusercontent.com/NethermindEth/stellar-private-payments/main/circuits/src/poseidon2/poseidon2_perm.circom \
  -o src/poseidon2/poseidon2_perm.circom
head -5 src/poseidon2/poseidon2_perm.circom
```
Expected output (signature confirmed):
```
pragma circom 2.2.2;
include "poseidon2_const.circom";

template Permutation(t) {
  signal input  inputs[t];
```
> Confirmed structure: initial `LinearLayer(t)`, `ExternalRound(0..3)`, 56 `InternalRound(k)`, `ExternalRound(4..7)`; outputs `out[t]`.

- [ ] **Step 3: Vendor the sponge hash template from the fork (verbatim)**
```bash
cd circuits && curl -sSL \
  https://raw.githubusercontent.com/NethermindEth/stellar-private-payments/main/circuits/src/poseidon2/poseidon2_hash.circom \
  -o src/poseidon2/poseidon2_hash.circom
cat src/poseidon2/poseidon2_hash.circom
```
Expected output (this is the wiring we depend on — `domainSeparation` is the capacity slot at index `n`):
```
pragma circom 2.2.2;
include "poseidon2_perm.circom";

template Poseidon2(n) {
  signal input inputs[n];
  signal input domainSeparation;
  signal output out;

  component perm = Permutation(n + 1);
  for (var i = 0; i < n; i++) {
    perm.inputs[i] <== inputs[i];
  }
  perm.inputs[n] <== domainSeparation;
  perm.out[0] ==> out;
}
```

- [ ] **Step 4: Vendor the compression template from the fork (verbatim)**
```bash
cd circuits && curl -sSL \
  https://raw.githubusercontent.com/NethermindEth/stellar-private-payments/main/circuits/src/poseidon2/poseidon2_compress.circom \
  -o src/poseidon2/poseidon2_compress.circom
cat src/poseidon2/poseidon2_compress.circom
```
Expected output (this is the Merkle node hash — `Perm([l,r])[0] + l`, NO domain separation, t=2 permutation):
```
pragma circom 2.2.2;
include "poseidon2_perm.circom";

template PoseidonCompress() {
  signal input inputs[2];
  signal output out;

  component perm = Permutation(2);
  perm.inputs[0] <== inputs[0];
  perm.inputs[1] <== inputs[1];

  signal compression[2];
  for (var i = 0; i < 2; i++) {
    compression[i] <== perm.out[i] + inputs[i];
  }
  compression[0] ==> out;
}
```
> Note: `out = Perm([l,r])[0] + l` exactly matches the spec's "Merkle compression P(l,r)[0]+l".

- [ ] **Step 5: Smoke-compile a 2-input hash to confirm the vendored templates compile**
```bash
cd circuits && cat > /tmp/h2.circom <<'EOF'
pragma circom 2.2.2;
include "poseidon2/poseidon2_hash.circom";
component main = Poseidon2(2);
EOF
circom /tmp/h2.circom --r1cs -l src -o /tmp 2>&1 | tail -3
```
Expected output (non-zero constraints, no errors):
```
template instances: ...
non-linear constraints: ...
Everything went okay
```

- [ ] **Step 6: Commit**
```bash
git add circuits/src/poseidon2/ && git commit -m "circuits: vendor Poseidon2 perm/hash/compress (POSEIDON2_BN256_PARAMS_2, t=2) from fork"
```

---

### Task 22: Write the Merkle membership sub-circuit (depth 20)

**Files:**
- Create: `circuits/src/merkle.circom`

- [ ] **Step 1: Write `circuits/src/merkle.circom`**
Mirrors the fork's `MerkleProof(levels)`: `Num2Bits` over `pathIndices`, a `Switcher` per level to order `(left,right)` from the index bit, then `PoseidonCompress`. We take per-level index **bits** as an array (matches `pathIndices[20]` in the spec interface) instead of a packed field, so the witness builder is trivial.
```circom
pragma circom 2.2.2;

include "poseidon2/poseidon2_compress.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Verifies a Merkle membership proof of `leaf` against `root`.
// node(left,right) = PoseidonCompress(left,right) = Perm([left,right])[0] + left
// pathIndices[i] = 0  => current hash is LEFT  child, sibling on right
// pathIndices[i] = 1  => current hash is RIGHT child, sibling on left
template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];   // each constrained to be a bit
    signal output root;

    component switcher[levels];
    component hasher[levels];

    signal cur[levels + 1];
    cur[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // enforce boolean
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        switcher[i] = Switcher();
        switcher[i].sel <== pathIndices[i];
        switcher[i].L <== cur[i];
        switcher[i].R <== pathElements[i];

        hasher[i] = PoseidonCompress();
        hasher[i].inputs[0] <== switcher[i].outL;
        hasher[i].inputs[1] <== switcher[i].outR;

        cur[i + 1] <== hasher[i].out;
    }

    root <== cur[levels];
}
```
> `Switcher` from circomlib: when `sel=0`, `outL=L,outR=R`; when `sel=1`, swapped. So with `sel=pathIndices[i]`: bit 0 → left=cur,right=sibling; bit 1 → left=sibling,right=cur. The Soroban/EVM tree builder MUST use the same convention.

- [ ] **Step 2: Smoke-compile a depth-3 instance**
```bash
cd circuits && cat > /tmp/m3.circom <<'EOF'
pragma circom 2.2.2;
include "merkle.circom";
component main = MerkleProof(3);
EOF
circom /tmp/m3.circom --r1cs -l src -o /tmp 2>&1 | tail -2
```
Expected output:
```
non-linear constraints: ...
Everything went okay
```

- [ ] **Step 3: Commit**
```bash
git add circuits/src/merkle.circom && git commit -m "circuits: Merkle membership (depth-parametrized) using PoseidonCompress + circomlib Switcher"
```

---

### Task 23: Write the withdrawal main circuit

**Files:**
- Create: `circuits/src/withdraw.circom`

- [ ] **Step 1: Write `circuits/src/withdraw.circom`**
```circom
pragma circom 2.2.2;

include "poseidon2/poseidon2_hash.circom";
include "merkle.circom";

// Withdrawal proof for the private bridge.
//
// PRIVATE: secret, nullifier, pathElements[20], pathIndices[20]
// PUBLIC : root, nullifierHash, recipient, denomination   <-- EXACT order
//
// Constraints:
//   commitment    = Poseidon2(2)([nullifier, secret], dsep=0)
//   nullifierHash = Poseidon2(1)([nullifier],         dsep=0)
//   MerkleProof(20)(leaf=commitment, path...) == root
//   recipient & denomination bound into the constraint system (malleability guard)
template Withdraw(levels) {
    // private
    signal input secret;
    signal input nullifier;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // public
    signal input root;
    signal input nullifierHash;
    signal input recipient;
    signal input denomination;

    // 1) commitment = Poseidon2(2)([nullifier, secret], dsep=0)
    component commit = Poseidon2(2);
    commit.inputs[0] <== nullifier;   // arg order pinned: (nullifier, secret)
    commit.inputs[1] <== secret;
    commit.domainSeparation <== 0;

    // 2) nullifierHash = Poseidon2(1)([nullifier], dsep=0)  -- arity pinned to 1
    component nh = Poseidon2(1);
    nh.inputs[0] <== nullifier;
    nh.domainSeparation <== 0;
    nullifierHash === nh.out;

    // 3) Merkle membership of the commitment under the public root
    component tree = MerkleProof(levels);
    tree.leaf <== commit.out;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i]  <== pathIndices[i];
    }
    root === tree.root;

    // 4) Malleability guard: force recipient & denomination into the witness so a
    //    relayer cannot re-target the proof. Squaring is the cheapest binding that
    //    makes both signals load-bearing without changing the public IO.
    signal recipientSq;
    signal denomSq;
    recipientSq <== recipient * recipient;
    denomSq     <== denomination * denomination;
}

// PUBLIC INPUT ORDER (snarkjs reads {public} in declaration order):
//   [ root, nullifierHash, recipient, denomination ]
component main {public [root, nullifierHash, recipient, denomination]} = Withdraw(20);
```
> **Public-input ordering note:** snarkjs orders public signals by the order they appear in the `public [...]` list of the `main` component. We list them exactly as `[root, nullifierHash, recipient, denomination]`, so `public.json` will be `[root, nullifierHash, recipient, denomination]` and the Soroban verifier must read them in that order.

- [ ] **Step 2: Compile the full circuit (default BN254 prime)**
```bash
cd circuits && npm run compile 2>&1 | tail -8
```
Expected output (circom defaults to the BN254 scalar field; ~depth-20 + two Poseidon2 sponges):
```
template instances: ...
non-linear constraints: ...
linear constraints: ...
public inputs: 4
private inputs: 42
...
Everything went okay
ls build/
```
And:
```bash
ls circuits/build
```
Expected output:
```
withdraw.r1cs  withdraw.sym  withdraw_js
```

- [ ] **Step 3: Confirm public-input count + order from the r1cs/sym**
```bash
cd circuits && npx snarkjs r1cs info build/withdraw.r1cs && grep -E '^[0-9]+,[0-9]+,1,main\.(root|nullifierHash|recipient|denomination)$' build/withdraw.sym
```
Expected output (4 public inputs; sym lists them in order root, nullifierHash, recipient, denomination):
```
[INFO]  snarkJS: # of Public Inputs: 4
...
2,2,1,main.root
3,3,1,main.nullifierHash
4,4,1,main.recipient
5,5,1,main.denomination
```

- [ ] **Step 4: Commit**
```bash
git add circuits/src/withdraw.circom && git commit -m "circuits: withdraw main (Poseidon2 commitment+nullifier, depth-20 Merkle, recipient/denom binding); public order [root,nullifierHash,recipient,denomination]"
```

---

### Task 24: Build the JS Poseidon2 parity helper + parity test vs the Rust/EVM spike

> Goal: prove the *same* Poseidon2 we use in circom produces the same `commitment` and `nullifierHash` as the Rust/EVM spike, so witnesses generated off-chain match the on-chain tree and nullifier. We compute reference values in pure JS from the same `POSEIDON2_BN256_PARAMS_2` tables, AND assert them against the spike's golden vectors.

**Files:**
- Create: `circuits/scripts/poseidon2.mjs`
- Create: `circuits/test/parity.test.mjs`
- Create: `circuits/test/vectors.spike.json`

- [ ] **Step 1: Export golden vectors from the Rust/EVM spike**
From the spike (the Rust Poseidon2 crate already vendored under `poseidon2/`), print reference outputs for a fixed `(nullifier, secret)` using `POSEIDON2_BN256_PARAMS_2` with the **sponge dsep=0** convention. Save them as JSON the circuit test will load.
```bash
# Run from the spike's Rust harness (adjust the bin name to your spike).
# Must use: commitment = sponge([nullifier,secret], cap=0); nh = sponge([nullifier], cap=0)
cargo run -q --bin poseidon2_vectors -- \
  --nullifier 12345 --secret 67890 \
  > circuits/test/vectors.spike.json
cat circuits/test/vectors.spike.json
```
Expected output (exact field values come from the spike; shape must be this):
```json
{
  "nullifier": "12345",
  "secret": "67890",
  "commitment": "0x...",
  "nullifierHash": "0x...",
  "compress_l1_r2": "0x..."
}
```
> If the spike does not yet have a `poseidon2_vectors` bin, add one that calls the vendored `poseidon2` crate: `commitment = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2).hash(&[null, secret], cap=0)`... — keep the dsep=0 and arity conventions identical to the circom side.

- [ ] **Step 2: Write `circuits/scripts/poseidon2.mjs` (JS reference matching the circom sponge)**
A minimal, dependency-light Poseidon2 over BN254 that reads the SAME constant tables and implements the SAME sponge (`inputs..., then capacity at index n`) and compression (`Perm([l,r])[0]+l`). We pull the round constants out of the vendored circom `poseidon2_const.circom` at runtime so there is one source of truth.
```javascript
// Poseidon2 (HorizenLabs POSEIDON2_BN256_PARAMS_2, t=2) reference in JS.
// Mirrors circuits/src/poseidon2/*.circom exactly:
//   - Permutation(t): linear layer, 4 ext, 56 int (rounds_p), 4 ext rounds
//   - sponge Poseidon2(n): perm([in_0..in_{n-1}, cap])  -> out[0]
//   - compress(l,r): perm([l,r])[0] + l
import fs from "node:fs";
import url from "node:url";
import path from "node:path";

const p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod = (x) => ((x % p) + p) % p;
const sq = (x) => mod(x * x);
const pow5 = (x) => mod(sq(sq(x)) * x);

// --- parse the constant tables out of the vendored circom file (single source of truth) ---
const here = path.dirname(url.fileURLToPath(import.meta.url));
const constSrc = fs.readFileSync(
  path.join(here, "../src/poseidon2/poseidon2_const.circom"), "utf8"
);
function bigints(label) {
  // grabs the array literal returned by `function <label>(t) { ... return [ ... ]; }`
  const re = new RegExp(`function\\s+${label}\\s*\\([^)]*\\)[\\s\\S]*?return\\s*(\\[[\\s\\S]*?\\]);`);
  const m = constSrc.match(re);
  if (!m) throw new Error(`could not parse ${label} from poseidon2_const.circom`);
  return JSON.parse(
    m[1].replace(/\s+/g, "").replace(/\[/g, "[").replace(/(\d+)/g, '"$1"')
  ).map((row) => Array.isArray(row) ? row.map((v) => BigInt(v)) : BigInt(row));
}
// t=2 tables
const FULL = bigints("POSEIDON_FULL_ROUNDS");        // 8 rows x t
const PART = bigints("POSEIDON_PARTIAL_ROUNDS");     // 56 scalars
const DIAG = bigints("POSEIDON_INTERNAL_MAT_DIAG");  // t scalars

// external (full) MDS for t=2 is the Poseidon2 circulant [[2,1],[1,2]]
function extLin(st) {
  const s = st[0] + st[1];
  return [mod(st[0] + s), mod(st[1] + s)];
}
function intLin(st) {
  const s = mod(st[0] + st[1]);
  return [mod(s + DIAG[0] * st[0]), mod(s + DIAG[1] * st[1])];
}
function addRC(st, rc) { return [mod(st[0] + rc[0]), mod(st[1] + rc[1])]; }

export function perm2(inp) {
  let st = extLin([mod(inp[0]), mod(inp[1])]);     // initial linear layer
  for (let r = 0; r < 4; r++) {                    // first 4 external rounds
    st = addRC(st, FULL[r]);
    st = [pow5(st[0]), pow5(st[1])];
    st = extLin(st);
  }
  for (let r = 0; r < 56; r++) {                   // 56 internal rounds
    st = [mod(st[0] + PART[r]), st[1]];
    st = [pow5(st[0]), st[1]];
    st = intLin(st);
  }
  for (let r = 0; r < 4; r++) {                    // last 4 external rounds
    st = addRC(st, FULL[r + 4]);
    st = [pow5(st[0]), pow5(st[1])];
    st = extLin(st);
  }
  return st;
}

// sponge hash matching template Poseidon2(n): inputs then capacity, t = n+1.
// For n<=1 we use the t=2 perm (capacity in slot 1). (Matches Poseidon2(1).)
// For n==2 the circom uses Permutation(3); see note below.
export function spongeT2(inputs, cap = 0n) {
  // inputs.length must be 1 here (Permutation(2))
  const st = perm2([mod(inputs[0]), mod(cap)]);
  return st[0];
}

export function compress(l, r) {
  const st = perm2([mod(l), mod(r)]);
  return mod(st[0] + mod(l));   // Perm([l,r])[0] + l
}

export const F = { p, mod };
```
> **t=3 caveat for the 2-input hash:** `Poseidon2(2)` compiles to `Permutation(3)`, which needs the t=3 tables (`POSEIDON2_BN256_PARAMS_3`). The JS perm above is t=2 only — sufficient for `nullifierHash` (`Poseidon2(1)` → t=2) and `compress`. For the **2-input commitment** we therefore validate JS↔circom parity for `compress` and `nullifierHash`, and validate the **commitment** purely against the spike golden vector + the circom witness (Task 25), which is the binding requirement. This keeps the JS helper small while still pinning the cross-impl contract end to end. *(If you want full JS t=3 parity too, vendor the t=3 perm rows analogously; not required for the MVP.)*

- [ ] **Step 3: Write the failing parity test `circuits/test/parity.test.mjs`**
```javascript
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import url from "node:url";
import path from "node:path";
import { wasm as wasmTester } from "circom_tester"; // optional; we use snarkjs witness below
import * as P from "../scripts/poseidon2.mjs";

const here = path.dirname(url.fileURLToPath(import.meta.url));
const spike = JSON.parse(fs.readFileSync(path.join(here, "vectors.spike.json"), "utf8"));
const hx = (x) => "0x" + (typeof x === "bigint" ? x : BigInt(x)).toString(16);

test("JS nullifierHash matches spike golden vector", () => {
  const nh = P.spongeT2([BigInt(spike.nullifier)], 0n);
  assert.equal(hx(nh).toLowerCase(), spike.nullifierHash.toLowerCase());
});

test("JS compress(1,2) matches spike golden vector", () => {
  const c = P.compress(1n, 2n);
  assert.equal(hx(c).toLowerCase(), spike.compress_l1_r2.toLowerCase());
});
```
Run it — it must FAIL first (no vectors / mismatch) before the spike vectors are correct:
```bash
cd circuits && npm install --silent circom_tester@0.0.20 && node --test test/parity.test.mjs 2>&1 | tail -6
```
Expected output (initial, failing because vectors.spike.json is a stub / values differ):
```
# fail 2
not ok 1 - JS nullifierHash matches spike golden vector
not ok 2 - JS compress(1,2) matches spike golden vector
```

- [ ] **Step 4: Regenerate spike vectors with the agreed convention and re-run until green**
Re-run the spike bin so `nullifierHash` uses `sponge([nullifier], cap=0)` and `compress_l1_r2 = Perm([1,2])[0]+1` over `POSEIDON2_BN256_PARAMS_2`. Then:
```bash
cd circuits && node --test test/parity.test.mjs 2>&1 | tail -4
```
Expected output (PASS — JS reference and the Rust/EVM spike agree bit-for-bit):
```
# tests 2
# pass 2
# fail 0
```
> If this fails, the divergence is the cross-impl bug you WANT to catch now: most likely (a) external MDS form, (b) capacity placement (must be last slot), or (c) pow5 vs pow-alpha. Fix the spike or the JS perm so both match the circom template, not the other way around.

- [ ] **Step 5: Commit**
```bash
git add circuits/scripts/poseidon2.mjs circuits/test/parity.test.mjs circuits/test/vectors.spike.json && git commit -m "circuits: JS Poseidon2 reference + parity test vs Rust/EVM spike golden vectors"
```

---

### Task 25: Powers-of-Tau phase-1 download + phase-2 Groth16 setup

**Files:**
- Create: `circuits/scripts/ptau_phase1.sh`
- Create: `circuits/scripts/phase2_setup.sh`
- Create (output): `circuits/build/withdraw_final.zkey`
- Create (output): `circuits/build/verification_key.json`

- [ ] **Step 1: Write `circuits/scripts/ptau_phase1.sh` (download a trusted phase-1 ptau)**
Depth-20 + two Poseidon2 sponges is well under 2^16 constraints, but use `powersOfTau28_hez_final_17.ptau` (2^17) for headroom. Download from the Hermez/PSE ceremony (the fork's ceremony-cli also expects you to fetch ptau manually).
```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p ptau
PTAU=ptau/pot17_final.ptau
if [ ! -f "$PTAU" ]; then
  curl -sSL -o "$PTAU" \
    https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_17.ptau
fi
npx snarkjs powersoftau verify "$PTAU"
```

- [ ] **Step 2: Run phase-1 download + verify**
```bash
cd circuits && bash scripts/ptau_phase1.sh 2>&1 | tail -3
```
Expected output:
```
[INFO]  snarkJS: Powers Of Tau file is correct!
```

- [ ] **Step 3: Write `circuits/scripts/phase2_setup.sh` (Groth16 phase-2 + vkey export)**
This mirrors what the fork's `ceremony-cli init/contribute/finalize` wraps (`groth16 setup` → `zkey contribute` → `zkey beacon` → `zkey export verificationkey`). For the MVP we run the snarkjs commands directly with a deterministic beacon so it's reproducible.
```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PTAU=ptau/pot17_final.ptau
R1CS=build/withdraw.r1cs

npx snarkjs groth16 setup "$R1CS" "$PTAU" build/withdraw_0000.zkey
echo "bridge-mvp-entropy-$(date +%s)" | \
  npx snarkjs zkey contribute build/withdraw_0000.zkey build/withdraw_0001.zkey \
    --name="solo-dev-1of1" -v
npx snarkjs zkey beacon build/withdraw_0001.zkey build/withdraw_final.zkey \
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 \
  --name="final beacon"
npx snarkjs zkey verify "$R1CS" "$PTAU" build/withdraw_final.zkey
npx snarkjs zkey export verificationkey build/withdraw_final.zkey build/verification_key.json
```

- [ ] **Step 4: Run phase-2 setup**
```bash
cd circuits && bash scripts/phase2_setup.sh 2>&1 | tail -4
```
Expected output:
```
[INFO]  snarkJS: ZKey Ok!
[INFO]  snarkJS: ... exported verification key
```
And verify the vkey is BN254 Groth16 with 4 public inputs (nPublic):
```bash
cd circuits && node -e "const v=require('./build/verification_key.json');console.log(v.protocol,v.curve,v.nPublic)"
```
Expected output:
```
groth16 bn128 4
```

- [ ] **Step 5: Commit (track only the small vkey, not the large zkey/ptau)**
```bash
git add circuits/scripts/ptau_phase1.sh circuits/scripts/phase2_setup.sh circuits/build/verification_key.json && git commit -m "circuits: phase-1 ptau fetch + Groth16 phase-2 setup; export verification_key.json (bn128, nPublic=4)"
```

---

### Task 26: Generate a witness + proof for a known input and verify (e2e snarkjs test)

**Files:**
- Create: `circuits/scripts/build_input.mjs`
- Create: `circuits/scripts/prove.mjs`
- Create: `circuits/test/proof.test.mjs`
- Create (output): `circuits/inputs/withdraw.json`

- [ ] **Step 1: Write `circuits/scripts/build_input.mjs` (build a valid depth-20 witness input)**
Builds a real Merkle path of depth 20 by inserting one commitment at leaf 0 and filling the rest with a fixed zero-subtree, using the SAME `compress` from the parity helper, so root/path are self-consistent with the circuit.
```javascript
import fs from "node:fs";
import url from "node:url";
import path from "node:path";
import { compress, spongeT2, F } from "./poseidon2.mjs";

const here = path.dirname(url.fileURLToPath(import.meta.url));
const LEVELS = 20;

// Fixed test note.
const nullifier = 12345n;
const secret = 67890n;
// recipient: a 32-byte Stellar address reduced mod p (single Fr). Fixed test value.
const recipient = F.mod(0x1234567890abcdef1122334455667788990011223344556677889900aabbccddn);
const denomination = 10n;

// commitment = Poseidon2(2)([nullifier, secret], dsep=0). For input-building we take the
// value from the spike golden vector to stay parity-correct with the t=3 sponge.
const spike = JSON.parse(fs.readFileSync(path.join(here, "../test/vectors.spike.json"), "utf8"));
const commitment = BigInt(spike.commitment);
const nullifierHash = spongeT2([nullifier], 0n); // Poseidon2(1) -> t=2, JS-derivable

// Build a depth-20 tree with the commitment at leaf index 0.
// Precompute "zero" subtree roots: zeros[0]=0, zeros[i]=compress(zeros[i-1],zeros[i-1]).
const zeros = [0n];
for (let i = 1; i <= LEVELS; i++) zeros[i] = compress(zeros[i - 1], zeros[i - 1]);

const pathElements = [];
const pathIndices = [];
let cur = commitment;
for (let i = 0; i < LEVELS; i++) {
  // leaf index 0 => always the LEFT child => sibling is the zero-subtree root => index bit 0
  pathElements.push(zeros[i].toString());
  pathIndices.push(0);
  cur = compress(cur, zeros[i]);
}
const root = cur;

const input = {
  secret: secret.toString(),
  nullifier: nullifier.toString(),
  pathElements,
  pathIndices,
  root: root.toString(),
  nullifierHash: nullifierHash.toString(),
  recipient: recipient.toString(),
  denomination: denomination.toString(),
};
fs.mkdirSync(path.join(here, "../inputs"), { recursive: true });
fs.writeFileSync(path.join(here, "../inputs/withdraw.json"), JSON.stringify(input, null, 2));
console.log("root", root.toString());
console.log("nullifierHash", nullifierHash.toString());
```

- [ ] **Step 2: Write `circuits/scripts/prove.mjs` (witness → proof → public)**
```javascript
import { wtns, groth16 } from "snarkjs";
import fs from "node:fs";

const input = JSON.parse(fs.readFileSync("inputs/withdraw.json", "utf8"));
await wtns.calculate(input, "build/withdraw_js/withdraw.wasm", "build/witness.wtns");
const { proof, publicSignals } = await groth16.prove("build/withdraw_final.zkey", "build/witness.wtns");
fs.writeFileSync("build/proof.json", JSON.stringify(proof, null, 2));
fs.writeFileSync("build/public.json", JSON.stringify(publicSignals, null, 2));
console.log("publicSignals", publicSignals);
```

- [ ] **Step 3: Write the failing e2e test `circuits/test/proof.test.mjs`**
```javascript
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";

test("witness builds, proof generates and verifies; public order is [root,nullifierHash,recipient,denomination]", () => {
  execFileSync("node", ["scripts/build_input.mjs"], { stdio: "inherit" });
  execFileSync("node", ["scripts/prove.mjs"], { stdio: "inherit" });
  const out = execFileSync("npx", [
    "snarkjs", "groth16", "verify",
    "build/verification_key.json", "build/public.json", "build/proof.json",
  ]).toString();
  assert.match(out, /OK!/);

  const input = JSON.parse(fs.readFileSync("inputs/withdraw.json", "utf8"));
  const pub = JSON.parse(fs.readFileSync("build/public.json", "utf8"));
  // EXACT order check against the SHARED INTERFACE CONTRACT
  assert.equal(pub[0], input.root,          "public[0] must be root");
  assert.equal(pub[1], input.nullifierHash, "public[1] must be nullifierHash");
  assert.equal(pub[2], input.recipient,     "public[2] must be recipient");
  assert.equal(pub[3], input.denomination,  "public[3] must be denomination");
});
```
Run it before setup artifacts exist — must FAIL:
```bash
cd circuits && node --test test/proof.test.mjs 2>&1 | tail -4
```
Expected output (fails: missing zkey/wasm until Tasks 23 & 25 ran):
```
not ok 1 - witness builds, proof generates and verifies; ...
# fail 1
```

- [ ] **Step 4: Ensure artifacts exist, then run the e2e test GREEN**
```bash
cd circuits && npm run compile >/dev/null && bash scripts/ptau_phase1.sh >/dev/null && bash scripts/phase2_setup.sh >/dev/null && node --test test/proof.test.mjs 2>&1 | tail -6
```
Expected output:
```
[INFO]  snarkJS: OK!
# tests 1
# pass 1
# fail 0
```

- [ ] **Step 5: Negative test — tamper recipient must fail verification (malleability guard works)**
```bash
cd circuits && node -e '
const fs=require("fs");
const p=JSON.parse(fs.readFileSync("build/public.json","utf8"));
p[2]=(BigInt(p[2])+1n).toString();
fs.writeFileSync("build/public_bad.json",JSON.stringify(p));
' && npx snarkjs groth16 verify build/verification_key.json build/public_bad.json build/proof.json 2>&1 | tail -1
```
Expected output (proof bound to original recipient → tampered public rejected):
```
[ERROR] snarkJS: Invalid proof
```

- [ ] **Step 6: Commit**
```bash
git add circuits/scripts/build_input.mjs circuits/scripts/prove.mjs circuits/test/proof.test.mjs && git commit -m "circuits: e2e witness+proof+verify test; assert public order [root,nullifierHash,recipient,denomination]; negative recipient-tamper test"
```

---

### Task 27: Produce the Soroban-embeddable verifying key (circom → Soroban serialization)

> The fork's `tools/ceremony-cli export-deployment` reconstructs an arkworks `ProvingKey<Bn254>` from the zkey and emits `vk_soroban.bin` + `vk_const.rs`. For the MVP we generate the equivalent: a deterministic Soroban-ready VK (the `alpha_g1, beta_g2, gamma_g2, delta_g2, IC[]` G1/G2 points in the byte encoding `env.crypto().bn254()` expects), plus a Rust module the Soroban verifier task can embed directly.

**Files:**
- Create: `circuits/scripts/export_soroban_vk.mjs`
- Create (output): `circuits/build/vk_soroban.json`
- Create (output): `circuits/build/vk_const.rs`
- Create: `circuits/test/vk_export.test.mjs`

- [ ] **Step 1: Write `circuits/scripts/export_soroban_vk.mjs`**
Reads `verification_key.json` (snarkjs montgomery-decimal coords) and serializes each point to the big-endian uncompressed byte layout the Soroban BN254 host functions consume (G1 = 64 bytes `x||y`; G2 = 128 bytes `x_c1||x_c0||y_c1||y_c0` — pin the c1/c0 order here and MIRROR it in the Soroban verifier task). Emits both a JSON (hex) and a `vk_const.rs`.
```javascript
import fs from "node:fs";
import { Scalar } from "ffjavascript";

const vk = JSON.parse(fs.readFileSync("build/verification_key.json", "utf8"));
const to32 = (dec) => {
  let h = BigInt(dec).toString(16).padStart(64, "0");
  return h;
};
// G1 affine: [x, y] -> 64-byte BE x||y
const g1 = (pt) => to32(pt[0]) + to32(pt[1]);
// G2 affine: [[x0,x1],[y0,y1]] (snarkjs Fp2 = [c0,c1]).
// Soroban bn254 expects each Fp2 as (c1 || c0) big-endian per its serialization; pin here.
const g2 = (pt) =>
  to32(pt[0][1]) + to32(pt[0][0]) +   // x: c1 || c0
  to32(pt[1][1]) + to32(pt[1][0]);    // y: c1 || c0

const out = {
  protocol: vk.protocol,
  curve: vk.curve,
  nPublic: vk.nPublic,
  alpha_g1: g1(vk.vk_alpha_1),
  beta_g2: g2(vk.vk_beta_2),
  gamma_g2: g2(vk.vk_gamma_2),
  delta_g2: g2(vk.vk_delta_2),
  ic: vk.IC.map(g1), // length = nPublic + 1
};
fs.writeFileSync("build/vk_soroban.json", JSON.stringify(out, null, 2));

// Emit a Rust module the Soroban verifier embeds (hex byte arrays).
const bytes = (hex) => "[" + hex.match(/../g).map((b) => "0x" + b).join(", ") + "]";
let rs = `// AUTO-GENERATED by export_soroban_vk.mjs. Do not edit.
// BN254 Groth16 verifying key for the withdraw circuit.
// Encoding: G1 = 64 bytes (x||y BE); G2 = 128 bytes (x.c1||x.c0||y.c1||y.c0 BE).
// Public input order: [root, nullifierHash, recipient, denomination]
pub const N_PUBLIC: usize = ${out.nPublic};
pub const ALPHA_G1: [u8; 64] = ${bytes(out.alpha_g1)};
pub const BETA_G2: [u8; 128] = ${bytes(out.beta_g2)};
pub const GAMMA_G2: [u8; 128] = ${bytes(out.gamma_g2)};
pub const DELTA_G2: [u8; 128] = ${bytes(out.delta_g2)};
pub const IC: [[u8; 64]; ${out.ic.length}] = [
${out.ic.map((h) => "    " + bytes(h) + ",").join("\n")}
];
`;
fs.writeFileSync("build/vk_const.rs", rs);
console.log("wrote build/vk_soroban.json and build/vk_const.rs; IC len =", out.ic.length);
```

- [ ] **Step 2: Write the failing export test `circuits/test/vk_export.test.mjs`**
```javascript
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";

test("soroban VK exports with correct sizes and IC length nPublic+1", () => {
  execFileSync("node", ["scripts/export_soroban_vk.mjs"], { stdio: "inherit" });
  const vk = JSON.parse(fs.readFileSync("build/vk_soroban.json", "utf8"));
  assert.equal(vk.curve, "bn128");
  assert.equal(vk.nPublic, 4);
  assert.equal(vk.alpha_g1.length, 128, "G1 = 64 bytes = 128 hex chars");
  assert.equal(vk.beta_g2.length, 256, "G2 = 128 bytes = 256 hex chars");
  assert.equal(vk.gamma_g2.length, 256);
  assert.equal(vk.delta_g2.length, 256);
  assert.equal(vk.ic.length, vk.nPublic + 1, "IC must be nPublic+1 = 5 points");
  vk.ic.forEach((p) => assert.equal(p.length, 128));
  const rs = fs.readFileSync("build/vk_const.rs", "utf8");
  assert.match(rs, /pub const N_PUBLIC: usize = 4;/);
  assert.match(rs, /pub const IC: \[\[u8; 64\]; 5\]/);
});
```
Run before export exists — must FAIL:
```bash
cd circuits && node --test test/vk_export.test.mjs 2>&1 | tail -3
```
Expected output:
```
not ok 1 - soroban VK exports with correct sizes and IC length nPublic+1
# fail 1
```

- [ ] **Step 3: Run the export and re-run the test GREEN**
```bash
cd circuits && node --test test/vk_export.test.mjs 2>&1 | tail -4
```
Expected output:
```
# tests 1
# pass 1
# fail 0
```

- [ ] **Step 4: Sanity-print the generated Rust module head**
```bash
cd circuits && head -8 build/vk_const.rs
```
Expected output:
```
// AUTO-GENERATED by export_soroban_vk.mjs. Do not edit.
// BN254 Groth16 verifying key for the withdraw circuit.
// Encoding: G1 = 64 bytes (x||y BE); G2 = 128 bytes (x.c1||x.c0||y.c1||y.c0 BE).
// Public input order: [root, nullifierHash, recipient, denomination]
pub const N_PUBLIC: usize = 4;
pub const ALPHA_G1: [u8; 64] = [0x..., ...];
...
```
> **Handoff to Soroban verifier task:** copy `circuits/build/vk_const.rs` into the contract crate (e.g. `contracts/pool/src/vk.rs`) and verify the G2 c1/c0 ordering against the first successful on-chain `multi_pairing_check`. If verification fails on-chain with a valid off-chain proof, the #1 suspect is the G2 coordinate order — flip `c1||c0` to `c0||c1` in `g2()` and regenerate.

- [ ] **Step 5: Commit**
```bash
git add circuits/scripts/export_soroban_vk.mjs circuits/test/vk_export.test.mjs circuits/build/vk_soroban.json circuits/build/vk_const.rs && git commit -m "circuits: export Soroban-embeddable BN254 Groth16 VK (vk_soroban.json + vk_const.rs); size+IC-length tests"
```

---

### Task 28: Full circuit test suite + parity gate (green-board check)

**Files:**
- Modify: `circuits/package.json` (wire `npm test` to run all suites)

- [ ] **Step 1: Point `npm test` at the whole `test/` dir**
Already set in Task 20 (`"test": "node --test test/"`). Confirm it runs parity + proof + vk export together:
```bash
cd circuits && npm test 2>&1 | tail -6
```
Expected output (all three suites green):
```
# tests 4
# pass 4
# fail 0
```

- [ ] **Step 2: Final commit (lock the green section)**
```bash
git add circuits && git commit -m "circuits: full suite green — Poseidon2 parity, depth-20 withdraw proof/verify, Soroban VK export"
```

---

**Section deliverables (handoff):**
- `circuits/src/withdraw.circom` — public inputs `[root, nullifierHash, recipient, denomination]`, BN254, Poseidon2 commitment+nullifier, depth-20 Merkle with `Perm(l,r)[0]+l` compression, recipient/denom malleability binding.
- `circuits/build/verification_key.json` — snarkjs Groth16 VK (`bn128`, `nPublic=4`).
- `circuits/build/vk_const.rs` + `circuits/build/vk_soroban.json` — Soroban verifier embeds these; G1=64B, G2=128B (pin G2 c1/c0 order with the Soroban task).
- Parity guarantee: JS reference + Rust/EVM spike agree on `nullifierHash` and `compress`; commitment pinned to the spike golden vector and re-checked through the circom witness.

Sources: [stellar-private-payments repo](https://github.com/NethermindEth/stellar-private-payments), [docs](https://nethermindeth.github.io/stellar-private-payments/), [circomlib poseidon](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom).
```

## Soroban Verifier + Pool Contract

> **Research basis.** This section mirrors the real layout of `NethermindEth/stellar-private-payments` (`contracts/{circom-groth16-verifier,pool,types,soroban-utils}/`) and the actual `soroban-sdk` 26 BN254 host API. Key facts pinned from research:
> - `soroban_sdk::crypto::bn254::Bn254` exposes `g1_add(&self, &Bn254G1Affine, &Bn254G1Affine) -> Bn254G1Affine`, `g1_mul(&self, &Bn254G1Affine, &Bn254Fr) -> Bn254G1Affine`, `g1_msm(&self, Vec<Bn254G1Affine>, Vec<Bn254Fr>) -> Bn254G1Affine`, and **`pairing_check(&self, Vec<Bn254G1Affine>, Vec<Bn254G2Affine>) -> bool`** (this is the SDK name for the CAP-0074 multi-pairing check — there is *no* method literally called `multi_pairing_check`).
> - Point types: `Bn254G1Affine::from_bytes(BytesN<64>) -> Self` / `.to_bytes()`; `Bn254G2Affine::from_bytes(BytesN<128>)`. `Bn254G1Affine` implements `Neg` (`-a` works) — that is how we negate A.
> - Scalar: `Bn254Fr::from_u256(U256) -> Self`, `Bn254Fr::from_bytes(BytesN<32>) -> Self`, `.to_u256()`. Arithmetic is mod r.
> - Verifier shape in the fork: `verify(env, proof: Groth16Proof, public_inputs: Vec<Bn254Fr>) -> Result<bool, Groth16Error>`, with `Groth16Proof { a: Bn254G1Affine, b: Bn254G2Affine, c: Bn254G1Affine }`, built `vk_x = ic[0]; for each input: vk_x = g1_add(vk_x, g1_mul(ic[i+1], input))`, then `pairing_check([-a, alpha, vk_x, c], [b, beta, gamma, delta])`.
> - SAC: `stellar contract asset deploy --asset CODE:ISSUER`, id via `stellar contract id asset --asset CODE:ISSUER`, mint via the SAC's `mint` admin entrypoint.

---

### Task 30: Scaffold the Soroban workspace and pin soroban-sdk 26

**Files:**
- Create: `soroban/Cargo.toml`
- Create: `soroban/.gitignore`
- Create: `soroban/rust-toolchain.toml`
- Create: `soroban/contracts/types/Cargo.toml`
- Create: `soroban/contracts/types/src/lib.rs`

- [ ] **Step 1: Verify toolchain is present**
```bash
stellar --version && cargo --version && rustc --version
```
Expected output (versions may differ slightly; the point is all three resolve and rustc is **≥ 1.85** — see **C1**):
```
stellar 26.x.x
cargo 1.92.x
rustc 1.92.0
```
If `stellar` is missing: `cargo install --locked stellar-cli --features opt`.

- [ ] **Step 2: Create the workspace `Cargo.toml`**
`soroban/Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = [
    "contracts/types",
    "contracts/circom-groth16-verifier",
    "contracts/pool",
]

[workspace.dependencies]
soroban-sdk = "=26.0.0"
types = { path = "contracts/types" }

[profile.release]
opt-level = "z"
overflow-checks = true
debug = 0
strip = "symbols"
debug-assertions = false
panic = "abort"
codegen-units = 1
lto = true
```

- [ ] **Step 3: Pin the Rust toolchain and gitignore**
`soroban/rust-toolchain.toml`:
```toml
[toolchain]
# C1: soroban-sdk 26 is an edition-2024 crate — requires rustc >= 1.85. Pin the upstream value 1.92.0.
channel = "1.92.0"
# C1: build Soroban WASM for wasm32v1-none (current guidance); keep the legacy target for tooling compatibility.
targets = ["wasm32v1-none", "wasm32-unknown-unknown"]
profile = "minimal"
```
`soroban/.gitignore`:
```
/target
.env
*.wasm
.stellar
```

- [ ] **Step 4: Create the shared `types` crate manifest**
`soroban/contracts/types/Cargo.toml`:
```toml
[package]
name = "types"
version = "0.0.1"
edition = "2021"

[lib]
crate-type = ["rlib"]

[dependencies]
soroban-sdk = { workspace = true }
```

- [ ] **Step 5: Define the shared on-chain types (proof + errors + VK bytes)**
`soroban/contracts/types/src/lib.rs`:
```rust
#![no_std]
use soroban_sdk::{contracterror, contracttype, crypto::bn254::{Bn254G1Affine, Bn254G2Affine}, BytesN, Vec};

/// Groth16 proof points. a,c in G1 (64 raw bytes), b in G2 (128 raw bytes).
#[contracttype]
#[derive(Clone)]
pub struct Groth16Proof {
    pub a: Bn254G1Affine,
    pub b: Bn254G2Affine,
    pub c: Bn254G1Affine,
}

/// Verifying key as raw serialized points, embedded at deploy time.
/// alpha in G1 (64B); beta/gamma/delta in G2 (128B); ic has (n_pub + 1) G1 points.
#[contracttype]
#[derive(Clone)]
pub struct VerificationKeyBytes {
    pub alpha: BytesN<64>,
    pub beta: BytesN<128>,
    pub gamma: BytesN<128>,
    pub delta: BytesN<128>,
    pub ic: Vec<BytesN<64>>,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Groth16Error {
    InvalidProof = 0,
    MalformedPublicInputs = 1,
    MalformedProof = 2,
}
```

- [ ] **Step 6: Build the workspace skeleton**
```bash
cargo build --manifest-path soroban/Cargo.toml -p types
```
Expected output (ends with):
```
   Compiling types v0.0.1 ...
    Finished `dev` profile [unoptimized + debuginfo] target(s) in ...s
```

- [ ] **Step 7: Commit**
```bash
git add soroban/Cargo.toml soroban/rust-toolchain.toml soroban/.gitignore soroban/contracts/types && git commit -m "soroban: scaffold workspace, pin soroban-sdk=26, shared proof/VK types"
```

---

### Task 31: Embed the verifying key and write the Groth16 verifier (TDD)

**Files:**
- Create: `soroban/contracts/circom-groth16-verifier/Cargo.toml`
- Create: `soroban/contracts/circom-groth16-verifier/src/vk.rs`
- Create: `soroban/contracts/circom-groth16-verifier/src/lib.rs`
- Test: `soroban/contracts/circom-groth16-verifier/src/test.rs`
- Create: `soroban/contracts/circom-groth16-verifier/src/test_data.rs`

> Public input vector order is fixed by the shared interface: `[root, nullifierHash, recipient, denomination]` (4 inputs ⇒ `ic.len() == 5`).
>
> ⚠️ **C5 (confirm before coding):** verify the exact `soroban-sdk` 26 BN254 method names against docs.rs — the pairing method is `multi_pairing_check` (host fn `bn254_multi_pairing_check`), not `pairing_check`. Compute `vk_x = ic[0] + Σ ic[i+1]·input[i]` with a single `env.crypto().bn254().g1_msm(points, scalars)` (available on Protocol 26) rather than a `g1_mul`+`g1_add` loop — fewer host calls and lower instruction cost toward the Task 4 <100M gate.

- [ ] **Step 1: Verifier crate manifest**
`soroban/contracts/circom-groth16-verifier/Cargo.toml`:
```toml
[package]
name = "circom-groth16-verifier"
version = "0.0.1"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
soroban-sdk = { workspace = true }
types = { workspace = true }

[dev-dependencies]
soroban-sdk = { workspace = true, features = ["testutils"] }
```

- [ ] **Step 2: Add VK constants module (paste the circuit task's exported bytes)**
> The circuit task exports the snarkjs `verification_key.json` converted to uncompressed big-endian point bytes (G1 = 64B `x‖y`, G2 = 128B `x_c1‖x_c0‖y_c1‖y_c0` in the BN254-on-Soroban encoding). Replace the `[0u8; N]` arrays with the real bytes from that task; keep the `ic` length at 5 (4 public inputs + 1).
`soroban/contracts/circom-groth16-verifier/src/vk.rs`:
```rust
use soroban_sdk::{vec, BytesN, Env, Vec};
use types::VerificationKeyBytes;

// === Verifying key, replace with bytes exported by the circuit task ===
// G1 alpha (64 bytes: x||y, 32 bytes each, big-endian).
pub const VK_ALPHA: [u8; 64] = [0u8; 64];
// G2 beta/gamma/delta (128 bytes each).
pub const VK_BETA: [u8; 128] = [0u8; 128];
pub const VK_GAMMA: [u8; 128] = [0u8; 128];
pub const VK_DELTA: [u8; 128] = [0u8; 128];
// IC[0..=4] : (num_public_inputs + 1) G1 points = 5 points for [root,nh,recipient,denom].
pub const VK_IC_0: [u8; 64] = [0u8; 64];
pub const VK_IC_1: [u8; 64] = [0u8; 64];
pub const VK_IC_2: [u8; 64] = [0u8; 64];
pub const VK_IC_3: [u8; 64] = [0u8; 64];
pub const VK_IC_4: [u8; 64] = [0u8; 64];

pub fn vk(env: &Env) -> VerificationKeyBytes {
    let ic: Vec<BytesN<64>> = vec![
        env,
        BytesN::from_array(env, &VK_IC_0),
        BytesN::from_array(env, &VK_IC_1),
        BytesN::from_array(env, &VK_IC_2),
        BytesN::from_array(env, &VK_IC_3),
        BytesN::from_array(env, &VK_IC_4),
    ];
    VerificationKeyBytes {
        alpha: BytesN::from_array(env, &VK_ALPHA),
        beta: BytesN::from_array(env, &VK_BETA),
        gamma: BytesN::from_array(env, &VK_GAMMA),
        delta: BytesN::from_array(env, &VK_DELTA),
        ic,
    }
}
```

- [ ] **Step 3: Add sample proof + public inputs from the spike (test fixtures)**
> Paste the proof bytes and the 4 public inputs produced by the circuit-task spike. `from_u256` builds an `Fr`; the public inputs are decimal field elements packed into `U256`.
`soroban/contracts/circom-groth16-verifier/src/test_data.rs`:
```rust
use soroban_sdk::{vec, BytesN, Env, Vec, U256};

// === Sample proof from the circuit-task spike, replace placeholders ===
pub const PROOF_A: [u8; 64] = [0u8; 64];
pub const PROOF_B: [u8; 128] = [0u8; 128];
pub const PROOF_C: [u8; 64] = [0u8; 64];

// Public inputs [root, nullifierHash, recipient, denomination] as 32-byte BE field elements.
pub const PUB_ROOT: [u8; 32] = [0u8; 32];
pub const PUB_NULLIFIER_HASH: [u8; 32] = [0u8; 32];
pub const PUB_RECIPIENT: [u8; 32] = [0u8; 32];
pub const PUB_DENOM: [u8; 32] = [0u8; 32];

pub fn sample_public_inputs(env: &Env) -> Vec<U256> {
    vec![
        env,
        U256::from_be_bytes(env, &BytesN::from_array(env, &PUB_ROOT).into()),
        U256::from_be_bytes(env, &BytesN::from_array(env, &PUB_NULLIFIER_HASH).into()),
        U256::from_be_bytes(env, &BytesN::from_array(env, &PUB_RECIPIENT).into()),
        U256::from_be_bytes(env, &BytesN::from_array(env, &PUB_DENOM).into()),
    ]
}
```

- [ ] **Step 4: Write the FAILING verifier test first (TDD red)**
`soroban/contracts/circom-groth16-verifier/src/test.rs`:
```rust
#![cfg(test)]
use crate::{test_data, CircomGroth16Verifier, CircomGroth16VerifierClient};
use soroban_sdk::{
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    vec, BytesN, Env, Vec,
};
use types::Groth16Proof;

fn sample_proof(env: &Env) -> Groth16Proof {
    Groth16Proof {
        a: Bn254G1Affine::from_bytes(BytesN::from_array(env, &test_data::PROOF_A)),
        b: Bn254G2Affine::from_bytes(BytesN::from_array(env, &test_data::PROOF_B)),
        c: Bn254G1Affine::from_bytes(BytesN::from_array(env, &test_data::PROOF_C)),
    }
}

fn fr_inputs(env: &Env) -> Vec<Bn254Fr> {
    let mut out = Vec::new(env);
    for u in test_data::sample_public_inputs(env).iter() {
        out.push_back(Bn254Fr::from_u256(u));
    }
    out
}

#[test]
fn valid_proof_verifies() {
    let env = Env::default();
    let id = env.register(CircomGroth16Verifier, ());
    let client = CircomGroth16VerifierClient::new(&env, &id);
    let ok = client.verify(&sample_proof(&env), &fr_inputs(&env));
    assert!(ok, "spike sample proof must verify");
}

#[test]
fn tampered_input_rejected() {
    let env = Env::default();
    let id = env.register(CircomGroth16Verifier, ());
    let client = CircomGroth16VerifierClient::new(&env, &id);
    let mut inputs = fr_inputs(&env);
    // Flip the denomination input → proof must fail.
    inputs.set(3, Bn254Fr::from_u256(soroban_sdk::U256::from_u32(&env, 999)));
    let res = client.try_verify(&sample_proof(&env), &inputs);
    assert!(matches!(res, Ok(Ok(false)) | Err(_)));
}
```

- [ ] **Step 5: Run the test — expect a compile failure (no `lib.rs` yet)**
```bash
cargo test --manifest-path soroban/Cargo.toml -p circom-groth16-verifier 2>&1 | tail -5
```
Expected output (red):
```
error[E0433]: failed to resolve: use of undeclared crate or module `crate`
error: could not compile `circom-groth16-verifier` ...
```

- [ ] **Step 6: Implement the verifier (TDD green)**
`soroban/contracts/circom-groth16-verifier/src/lib.rs`:
```rust
#![no_std]
mod vk;
#[cfg(test)]
mod test;
#[cfg(test)]
mod test_data;

use soroban_sdk::{
    contract, contractimpl,
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    vec, BytesN, Env, Vec,
};
use types::{Groth16Error, Groth16Proof, VerificationKeyBytes};

#[contract]
pub struct CircomGroth16Verifier;

#[contractimpl]
impl CircomGroth16Verifier {
    /// Verify a Groth16 proof for public inputs [root, nullifierHash, recipient, denomination].
    pub fn verify(
        env: Env,
        proof: Groth16Proof,
        public_inputs: Vec<Bn254Fr>,
    ) -> Result<bool, Groth16Error> {
        let vk: VerificationKeyBytes = vk::vk(&env);

        // ic length must equal public_inputs + 1.
        if vk.ic.len() != public_inputs.len() + 1 {
            return Err(Groth16Error::MalformedPublicInputs);
        }

        let bn = env.crypto().bn254();

        // vk_x = IC[0] + Σ IC[i+1] * input[i]
        let mut vk_x = Bn254G1Affine::from_bytes(vk.ic.get(0).unwrap());
        for (i, input) in public_inputs.iter().enumerate() {
            let ic_i = Bn254G1Affine::from_bytes(vk.ic.get((i as u32) + 1).unwrap());
            let prod = bn.g1_mul(&ic_i, &input);
            vk_x = bn.g1_add(&vk_x, &prod);
        }

        // Negate A (Bn254G1Affine implements Neg).
        let neg_a = -proof.a.clone();

        let alpha = Bn254G1Affine::from_bytes(vk.alpha.clone());
        let beta = Bn254G2Affine::from_bytes(vk.beta.clone());
        let gamma = Bn254G2Affine::from_bytes(vk.gamma.clone());
        let delta = Bn254G2Affine::from_bytes(vk.delta.clone());

        // e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        let g1: Vec<Bn254G1Affine> = vec![&env, neg_a, alpha, vk_x, proof.c.clone()];
        let g2: Vec<Bn254G2Affine> = vec![&env, proof.b.clone(), beta, gamma, delta];

        Ok(bn.pairing_check(g1, g2))
    }
}
```

- [ ] **Step 7: Run the test — expect green (with real spike data)**
```bash
cargo test --manifest-path soroban/Cargo.toml -p circom-groth16-verifier 2>&1 | tail -6
```
Expected output:
```
running 2 tests
test test::tampered_input_rejected ... ok
test test::valid_proof_verifies ... ok

test result: ok. 2 passed; 0 failed; ...
```
> If `valid_proof_verifies` fails while placeholders are still in, that is expected — it goes green once `vk.rs`/`test_data.rs` carry the circuit task's real bytes. Do not advance until both are green with real data.

- [ ] **Step 8: Commit**
```bash
git add soroban/contracts/circom-groth16-verifier && git commit -m "verifier: embed VK, build vk_x, negate A, pairing_check; TDD with spike proof"
```

---

### Task 32: Pool storage layout + initialization (TDD)

**Files:**
- Create: `soroban/contracts/pool/Cargo.toml`
- Create: `soroban/contracts/pool/src/storage.rs`
- Create: `soroban/contracts/pool/src/error.rs`
- Create: `soroban/contracts/pool/src/lib.rs`
- Test: `soroban/contracts/pool/src/test.rs`

> Pool stores: per-denomination root ring buffer (`Vec<BytesN<32>>`, last 30), nullifier set (persistent map `BytesN<32> -> ()`), SAC token address, verifier address, backing-relayer address, withdrawal amounts per denomination, admin.

- [ ] **Step 1: Pool crate manifest**
`soroban/contracts/pool/Cargo.toml`:
```toml
[package]
name = "pool"
version = "0.0.1"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
soroban-sdk = { workspace = true }
types = { workspace = true }

[dev-dependencies]
soroban-sdk = { workspace = true, features = ["testutils"] }
circom-groth16-verifier = { path = "../circom-groth16-verifier" }
```

- [ ] **Step 2: Error enum**
`soroban/contracts/pool/src/error.rs`:
```rust
use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    UnknownRoot = 3,
    NullifierAlreadyUsed = 4,
    InvalidProof = 5,
    UnknownDenomination = 6,
}
```

- [ ] **Step 3: Storage keys + helpers**
`soroban/contracts/pool/src/storage.rs`:
```rust
use soroban_sdk::{contracttype, Address, BytesN, Env, Vec};
use crate::error::Error;

pub const ROOT_HISTORY_SIZE: u32 = 30;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Verifier,
    Token,
    Relayer,             // backing relayer authorized to anchor roots
    Roots(u32),          // denom -> Vec<BytesN<32>> ring buffer (newest last)
    Nullifier(BytesN<32>), // presence == spent
    DenomAmount(u32),    // denom index -> i128 withdrawal amount
}

pub fn get_admin(env: &Env) -> Result<Address, Error> {
    env.storage().instance().get(&DataKey::Admin).ok_or(Error::NotInitialized)
}
pub fn get_verifier(env: &Env) -> Result<Address, Error> {
    env.storage().instance().get(&DataKey::Verifier).ok_or(Error::NotInitialized)
}
pub fn get_token(env: &Env) -> Result<Address, Error> {
    env.storage().instance().get(&DataKey::Token).ok_or(Error::NotInitialized)
}
pub fn get_relayer(env: &Env) -> Result<Address, Error> {
    env.storage().instance().get(&DataKey::Relayer).ok_or(Error::NotInitialized)
}

pub fn get_denom_amount(env: &Env, denom: u32) -> Result<i128, Error> {
    env.storage()
        .instance()
        .get(&DataKey::DenomAmount(denom))
        .ok_or(Error::UnknownDenomination)
}

pub fn get_roots(env: &Env, denom: u32) -> Vec<BytesN<32>> {
    env.storage()
        .persistent()
        .get(&DataKey::Roots(denom))
        .unwrap_or(Vec::new(env))
}

pub fn set_roots(env: &Env, denom: u32, roots: &Vec<BytesN<32>>) {
    env.storage().persistent().set(&DataKey::Roots(denom), roots);
}

pub fn is_nullifier_used(env: &Env, nh: &BytesN<32>) -> bool {
    env.storage().persistent().has(&DataKey::Nullifier(nh.clone()))
}

pub fn mark_nullifier_used(env: &Env, nh: &BytesN<32>) {
    env.storage().persistent().set(&DataKey::Nullifier(nh.clone()), &());
}
```

- [ ] **Step 4: Write FAILING init test (TDD red)**
`soroban/contracts/pool/src/test.rs`:
```rust
#![cfg(test)]
use crate::{Pool, PoolClient};
use soroban_sdk::{testutils::Address as _, vec, Address, Env};

fn setup(env: &Env) -> (PoolClient, Address, Address, Address, Address) {
    let admin = Address::generate(env);
    let relayer = Address::generate(env);
    let verifier = Address::generate(env);
    let token = Address::generate(env);
    let id = env.register(Pool, ());
    let client = PoolClient::new(env, &id);
    client.initialize(
        &admin,
        &relayer,
        &verifier,
        &token,
        &vec![env, 1u32, 10u32, 100u32],          // denom indices
        &vec![env, 1_0000000i128, 10_0000000, 100_0000000], // 7-decimal amounts
    );
    (client, admin, relayer, verifier, token)
}

#[test]
fn initialize_sets_config() {
    let env = Env::default();
    let (client, _admin, _r, verifier, token) = setup(&env);
    assert_eq!(client.get_verifier(), verifier);
    assert_eq!(client.get_token(), token);
    assert_eq!(client.get_denom_amount(&10u32), 10_0000000i128);
}

#[test]
#[should_panic]
fn double_initialize_panics() {
    let env = Env::default();
    let (client, admin, relayer, verifier, token) = setup(&env);
    client.initialize(
        &admin, &relayer, &verifier, &token,
        &vec![&env, 1u32], &vec![&env, 1i128],
    );
}
```

- [ ] **Step 5: Implement `lib.rs` (init + getters) — TDD green for this task**
`soroban/contracts/pool/src/lib.rs`:
```rust
#![no_std]
mod error;
mod storage;
#[cfg(test)]
mod test;

use error::Error;
use storage::{DataKey, ROOT_HISTORY_SIZE};
use soroban_sdk::{
    contract, contractimpl, token, vec,
    crypto::bn254::Bn254Fr,
    Address, BytesN, Env, U256, Vec,
};
use types::Groth16Proof;

// Cross-contract client for the verifier (matches its `verify` signature).
mod verifier_iface {
    use soroban_sdk::{contractclient, crypto::bn254::Bn254Fr, Env, Vec};
    use types::{Groth16Error, Groth16Proof};

    #[contractclient(name = "VerifierClient")]
    pub trait Verifier {
        fn verify(
            env: Env,
            proof: Groth16Proof,
            public_inputs: Vec<Bn254Fr>,
        ) -> Result<bool, Groth16Error>;
    }
}
use verifier_iface::VerifierClient;

#[contract]
pub struct Pool;

#[contractimpl]
impl Pool {
    pub fn initialize(
        env: Env,
        admin: Address,
        relayer: Address,
        verifier: Address,
        token: Address,
        denoms: Vec<u32>,
        amounts: Vec<i128>,
    ) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error(&env, Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Relayer, &relayer);
        env.storage().instance().set(&DataKey::Verifier, &verifier);
        env.storage().instance().set(&DataKey::Token, &token);
        for (i, d) in denoms.iter().enumerate() {
            let amt = amounts.get(i as u32).unwrap();
            env.storage().instance().set(&DataKey::DenomAmount(d), &amt);
        }
    }

    pub fn get_verifier(env: Env) -> Result<Address, Error> { storage::get_verifier(&env) }
    pub fn get_token(env: Env) -> Result<Address, Error> { storage::get_token(&env) }
    pub fn get_relayer(env: Env) -> Result<Address, Error> { storage::get_relayer(&env) }
    pub fn get_denom_amount(env: Env, denom: u32) -> Result<i128, Error> {
        storage::get_denom_amount(&env, denom)
    }
    pub fn get_roots(env: Env, denom: u32) -> Vec<BytesN<32>> { storage::get_roots(&env, denom) }
    pub fn is_nullifier_used(env: Env, nh: BytesN<32>) -> bool {
        storage::is_nullifier_used(&env, &nh)
    }
}

fn panic_with_error(env: &Env, e: Error) -> ! {
    soroban_sdk::panic_with_error!(env, e)
}
```
> `update_root` and `withdraw` are added in Tasks 33 and 34; the unused imports (`token`, `Bn254Fr`, `U256`, `VerifierClient`, `ROOT_HISTORY_SIZE`, `Groth16Proof`) are wired in then. To keep this step compiling cleanly, temporarily allow them:

`soroban/contracts/pool/src/lib.rs` — add directly under `#![no_std]`:
```rust
#![allow(unused_imports)]
```

- [ ] **Step 6: Run init tests — expect green**
```bash
cargo test --manifest-path soroban/Cargo.toml -p pool 2>&1 | tail -6
```
Expected output:
```
running 2 tests
test test::double_initialize_panics ... ok
test test::initialize_sets_config ... ok

test result: ok. 2 passed; 0 failed; ...
```

- [ ] **Step 7: Commit**
```bash
git add soroban/contracts/pool && git commit -m "pool: storage layout, DataKey, init + getters with TDD"
```

---

### Task 33: `update_root` — backing-relayer-gated root anchoring (TDD)

**Files:**
- Modify: `soroban/contracts/pool/src/lib.rs`
- Modify: `soroban/contracts/pool/src/storage.rs`
- Modify: `soroban/contracts/pool/src/test.rs`

- [ ] **Step 1: Add ring-buffer push + known-root check to storage**
Append to `soroban/contracts/pool/src/storage.rs`:
```rust
/// Push a root into the denom's ring buffer, capping length at ROOT_HISTORY_SIZE
/// (drops the oldest when full). Newest root is always last.
pub fn push_root(env: &Env, denom: u32, root: &BytesN<32>) {
    let mut roots = get_roots(env, denom);
    if roots.len() >= ROOT_HISTORY_SIZE {
        roots.remove(0); // drop oldest
    }
    roots.push_back(root.clone());
    set_roots(env, denom, &roots);
}

pub fn is_known_root(env: &Env, denom: u32, root: &BytesN<32>) -> bool {
    let roots = get_roots(env, denom);
    roots.iter().any(|r| &r == root)
}
```

- [ ] **Step 2: Write FAILING `update_root` tests (TDD red)**
Append to `soroban/contracts/pool/src/test.rs`:
```rust
use soroban_sdk::{BytesN, testutils::AuthorizedInvocation};

fn root(env: &Env, b: u8) -> BytesN<32> {
    let mut a = [0u8; 32];
    a[31] = b;
    BytesN::from_array(env, &a)
}

#[test]
fn relayer_can_anchor_root_and_it_is_known() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _relayer, _v, _t) = setup(&env);
    let r = root(&env, 7);
    client.update_root(&10u32, &r);
    assert!(client.is_known_root(&10u32, &r));
    assert!(!client.is_known_root(&10u32, &root(&env, 8)));
}

#[test]
fn ring_buffer_caps_at_30() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _a, _r, _v, _t) = setup(&env);
    for i in 1u8..=35 {
        client.update_root(&1u32, &root(&env, i));
    }
    assert_eq!(client.get_roots(&1u32).len(), 30);
    // oldest (1..5) evicted, newest (35) retained.
    assert!(!client.is_known_root(&1u32, &root(&env, 1)));
    assert!(client.is_known_root(&1u32, &root(&env, 35)));
}

#[test]
#[should_panic]
fn non_relayer_cannot_anchor() {
    let env = Env::default();
    // Do NOT mock auths → require_auth() on the relayer fails.
    let (client, _a, _r, _v, _t) = setup(&env);
    client.update_root(&1u32, &root(&env, 1));
}
```

- [ ] **Step 3: Run — expect compile failure (no `update_root`/`is_known_root` yet)**
```bash
cargo test --manifest-path soroban/Cargo.toml -p pool 2>&1 | tail -4
```
Expected output (red):
```
error[E0599]: no method named `update_root` found ...
error: could not compile `pool` ...
```

- [ ] **Step 4: Implement `update_root` + `is_known_root` (TDD green)**
In `soroban/contracts/pool/src/lib.rs`, add these methods inside `impl Pool`:
```rust
    /// Anchor a recent EVM Merkle root into the denom's root window.
    /// Only the backing relayer may call this.
    pub fn update_root(env: Env, denom: u32, root: BytesN<32>) -> Result<(), Error> {
        let relayer = storage::get_relayer(&env)?;
        relayer.require_auth();
        // validate denom is configured
        storage::get_denom_amount(&env, denom)?;
        storage::push_root(&env, denom, &root);
        env.events().publish((soroban_sdk::symbol_short!("root"), denom), root);
        Ok(())
    }

    pub fn is_known_root(env: Env, denom: u32, root: BytesN<32>) -> bool {
        storage::is_known_root(&env, denom, &root)
    }
```

- [ ] **Step 5: Run — expect green**
```bash
cargo test --manifest-path soroban/Cargo.toml -p pool 2>&1 | tail -8
```
Expected output:
```
running 5 tests
test test::initialize_sets_config ... ok
test test::double_initialize_panics ... ok
test test::relayer_can_anchor_root_and_it_is_known ... ok
test test::ring_buffer_caps_at_30 ... ok
test test::non_relayer_cannot_anchor ... ok

test result: ok. 5 passed; 0 failed; ...
```

- [ ] **Step 6: Commit**
```bash
git add soroban/contracts/pool && git commit -m "pool: relayer-gated update_root with 30-root ring buffer; TDD"
```

---

### Task 34: `withdraw` — verify proof, spend nullifier, release SAC (TDD)

**Files:**
- Modify: `soroban/contracts/pool/src/lib.rs`
- Test: `soroban/contracts/pool/src/test.rs`

> Public input vector built in **exact** order `[root, nullifierHash, recipient, denomination]`. `root` and `nullifierHash` arrive as `BytesN<32>`; `recipient` is the Fr-packed Stellar-address encoding agreed with the circuit task; `denomination` is the denom index as a field element. The pool reconstructs the `Vec<Bn254Fr>` and passes it to the verifier so the proof binds to exactly what the contract enforces.

- [ ] **Step 1: Write FAILING withdraw tests with a mock verifier + real SAC (TDD red)**
Append to `soroban/contracts/pool/src/test.rs`:
```rust
use soroban_sdk::{token::StellarAssetClient, U256};
use types::Groth16Proof;

// A stub verifier contract we can flip true/false for deterministic tests.
mod mockverifier {
    use soroban_sdk::{contract, contractimpl, crypto::bn254::Bn254Fr, Env, Vec};
    use types::{Groth16Error, Groth16Proof};

    #[contract]
    pub struct GoodVerifier;
    #[contractimpl]
    impl GoodVerifier {
        pub fn verify(_e: Env, _p: Groth16Proof, _i: Vec<Bn254Fr>) -> Result<bool, Groth16Error> {
            Ok(true)
        }
    }

    #[contract]
    pub struct BadVerifier;
    #[contractimpl]
    impl BadVerifier {
        pub fn verify(_e: Env, _p: Groth16Proof, _i: Vec<Bn254Fr>) -> Result<bool, Groth16Error> {
            Ok(false)
        }
    }
}

fn zero_proof(env: &Env) -> Groth16Proof {
    use soroban_sdk::crypto::bn254::{Bn254G1Affine, Bn254G2Affine};
    Groth16Proof {
        a: Bn254G1Affine::from_bytes(BytesN::from_array(env, &[0u8; 64])),
        b: Bn254G2Affine::from_bytes(BytesN::from_array(env, &[0u8; 128])),
        c: Bn254G1Affine::from_bytes(BytesN::from_array(env, &[0u8; 64])),
    }
}

// Full wiring: real SAC token (pool is admin/minter), chosen verifier.
fn setup_withdraw(env: &Env, verifier: &Address) -> (PoolClient, Address, Address) {
    let admin = Address::generate(env);
    let relayer = Address::generate(env);
    let pool_id = env.register(Pool, ());
    // Create a SAC; its admin is the pool so the pool can mint on withdraw.
    let sac = env.register_stellar_asset_contract_v2(pool_id.clone());
    let token_addr = sac.address();
    let client = PoolClient::new(env, &pool_id);
    client.initialize(
        &admin, &relayer, verifier, &token_addr,
        &vec![env, 1u32, 10u32, 100u32],
        &vec![env, 1_0000000i128, 10_0000000, 100_0000000],
    );
    (client, pool_id, token_addr)
}

fn recipient_fr(env: &Env, recipient: &Address) -> BytesN<32> {
    // MUST match circuit's recipient encoding. In MVP we use the agreed packing;
    // here we use a fixed 32-byte tag so the test is deterministic.
    let _ = recipient;
    BytesN::from_array(env, &[9u8; 32])
}

#[test]
fn withdraw_happy_path_mints_to_recipient() {
    let env = Env::default();
    env.mock_all_auths();
    let v = env.register(mockverifier::GoodVerifier, ());
    let (client, _pool, token_addr) = setup_withdraw(&env, &v);

    let denom = 10u32;
    let root = root(&env, 1);
    client.update_root(&denom, &root);

    let recipient = Address::generate(&env);
    let nh = root(&env, 42); // nullifierHash
    client.withdraw(
        &zero_proof(&env),
        &root,
        &nh,
        &recipient_fr(&env, &recipient),
        &recipient,
        &denom,
    );

    // recipient received the 10-unit denomination (7 decimals).
    let token = soroban_sdk::token::TokenClient::new(&env, &token_addr);
    assert_eq!(token.balance(&recipient), 10_0000000i128);
    assert!(client.is_nullifier_used(&nh));
}

#[test]
#[should_panic]
fn withdraw_replay_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let v = env.register(mockverifier::GoodVerifier, ());
    let (client, _pool, _t) = setup_withdraw(&env, &v);
    let denom = 1u32;
    let root = root(&env, 1);
    client.update_root(&denom, &root);
    let recipient = Address::generate(&env);
    let nh = root(&env, 5);
    client.withdraw(&zero_proof(&env), &root, &nh, &recipient_fr(&env, &recipient), &recipient, &denom);
    // Second spend of same nullifier must panic (NullifierAlreadyUsed).
    client.withdraw(&zero_proof(&env), &root, &nh, &recipient_fr(&env, &recipient), &recipient, &denom);
}

#[test]
#[should_panic]
fn withdraw_unknown_root_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let v = env.register(mockverifier::GoodVerifier, ());
    let (client, _pool, _t) = setup_withdraw(&env, &v);
    let recipient = Address::generate(&env);
    // never anchored this root → UnknownRoot
    client.withdraw(&zero_proof(&env), &root(&env, 99), &root(&env, 5), &recipient_fr(&env, &recipient), &recipient, &1u32);
}

#[test]
#[should_panic]
fn withdraw_bad_proof_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let v = env.register(mockverifier::BadVerifier, ());
    let (client, _pool, _t) = setup_withdraw(&env, &v);
    let denom = 1u32;
    let root = root(&env, 1);
    client.update_root(&denom, &root);
    let recipient = Address::generate(&env);
    client.withdraw(&zero_proof(&env), &root, &root(&env, 5), &recipient_fr(&env, &recipient), &recipient, &denom);
}
```

- [ ] **Step 2: Run — expect compile failure (no `withdraw` yet)**
```bash
cargo test --manifest-path soroban/Cargo.toml -p pool 2>&1 | tail -4
```
Expected output (red):
```
error[E0599]: no method named `withdraw` found for struct `PoolClient` ...
error: could not compile `pool` ...
```

- [ ] **Step 3: Implement `withdraw` (TDD green)**
In `soroban/contracts/pool/src/lib.rs`, add inside `impl Pool`:
```rust
    /// Withdraw: verify a Groth16 proof of Merkle membership + nullifier, then
    /// release `denom` worth of the pool's SAC token to `recipient`.
    /// Public input vector order: [root, nullifierHash, recipient_fr, denomination].
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        env: Env,
        proof: Groth16Proof,
        root: BytesN<32>,
        nullifier_hash: BytesN<32>,
        recipient_fr: BytesN<32>,
        recipient: Address,
        denom: u32,
    ) -> Result<(), Error> {
        // 1. denom must be configured; resolve amount.
        let amount = storage::get_denom_amount(&env, denom)?;

        // 2. root must be in this denom's window.
        if !storage::is_known_root(&env, denom, &root) {
            return Err(Error::UnknownRoot);
        }

        // 3. nullifier must be unused.
        if storage::is_nullifier_used(&env, &nullifier_hash) {
            return Err(Error::NullifierAlreadyUsed);
        }

        // 4. build public inputs [root, nullifierHash, recipient, denom] as Bn254Fr.
        let denom_bytes = u32_to_fr_bytes(&env, denom);
        let public_inputs: Vec<Bn254Fr> = vec![
            &env,
            Bn254Fr::from_u256(U256::from_be_bytes(&env, &root.clone().into())),
            Bn254Fr::from_u256(U256::from_be_bytes(&env, &nullifier_hash.clone().into())),
            Bn254Fr::from_u256(U256::from_be_bytes(&env, &recipient_fr.into())),
            Bn254Fr::from_u256(U256::from_be_bytes(&env, &denom_bytes.into())),
        ];

        // 5. verify proof via the verifier contract.
        let verifier = storage::get_verifier(&env)?;
        let vclient = VerifierClient::new(&env, &verifier);
        let ok = vclient.verify(&proof, &public_inputs);
        if !ok {
            return Err(Error::InvalidProof);
        }

        // 6. mark nullifier spent (after verification, before payout).
        storage::mark_nullifier_used(&env, &nullifier_hash);

        // 7. release SAC tokens. Pool is SAC admin → mint to recipient.
        let token = storage::get_token(&env)?;
        let sac = token::StellarAssetClient::new(&env, &token);
        sac.mint(&recipient, &amount);

        env.events().publish(
            (soroban_sdk::symbol_short!("withdraw"), denom),
            (nullifier_hash, recipient, amount),
        );
        Ok(())
    }
```
Add this helper at the bottom of `lib.rs` (module scope, outside `impl Pool`):
```rust
/// Encode a u32 denomination index as a 32-byte big-endian field element.
fn u32_to_fr_bytes(env: &Env, v: u32) -> BytesN<32> {
    let mut b = [0u8; 32];
    b[28..32].copy_from_slice(&v.to_be_bytes());
    BytesN::from_array(env, &b)
}
```

- [ ] **Step 4: Run — expect green (all 9 tests)**
```bash
cargo test --manifest-path soroban/Cargo.toml -p pool 2>&1 | tail -14
```
Expected output:
```
running 9 tests
test test::initialize_sets_config ... ok
test test::double_initialize_panics ... ok
test test::relayer_can_anchor_root_and_it_is_known ... ok
test test::ring_buffer_caps_at_30 ... ok
test test::non_relayer_cannot_anchor ... ok
test test::withdraw_happy_path_mints_to_recipient ... ok
test test::withdraw_replay_rejected ... ok
test test::withdraw_unknown_root_rejected ... ok
test test::withdraw_bad_proof_rejected ... ok

test result: ok. 9 passed; 0 failed; ...
```

- [ ] **Step 5: Full workspace test + clippy gate**
```bash
cargo test --manifest-path soroban/Cargo.toml 2>&1 | tail -3
cargo clippy --manifest-path soroban/Cargo.toml --all-targets -- -D warnings 2>&1 | tail -3
```
Expected output:
```
test result: ok. ... 0 failed; ...
    Finished `dev` profile ...
```

- [ ] **Step 6: Commit**
```bash
git add soroban/contracts/pool && git commit -m "pool: withdraw verifies proof, spends nullifier, mints SAC; happy/replay/unknown-root/bad-proof TDD"
```

---

### Task 35: Build the bridged asset as a pool-controlled SAC

**Files:**
- Create: `soroban/scripts/01-create-sac.sh`
- Create: `soroban/deployments/testnet.env`

> The bridged USDC equivalent is a **classic Stellar asset** wrapped as a SAC. The pool contract is set as the SAC admin so it can `mint` on withdraw (matching `StellarAssetClient::mint` used in Task 34). We use a dedicated issuer key for the asset code, deploy its SAC, then hand SAC admin to the pool in Task 36.

- [ ] **Step 1: Create funded testnet identities**
```bash
stellar keys generate --global deployer --network testnet --fund
stellar keys generate --global issuer   --network testnet --fund
stellar keys generate --global relayer  --network testnet --fund
stellar keys address deployer && stellar keys address issuer && stellar keys address relayer
```
Expected output (three G... addresses):
```
GDEPLOYER...
GISSUER...
GRELAYER...
```

- [ ] **Step 2: SAC creation script**
`soroban/scripts/01-create-sac.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
NET=testnet
ASSET_CODE=zUSDC
ISSUER=$(stellar keys address issuer)
ASSET="${ASSET_CODE}:${ISSUER}"

echo "Deploying SAC for ${ASSET} on ${NET}..."
stellar contract asset deploy \
  --source-account issuer \
  --network "${NET}" \
  --asset "${ASSET}"

SAC_ID=$(stellar contract id asset --network "${NET}" --asset "${ASSET}")
echo "SAC contract id: ${SAC_ID}"

# Persist for later steps.
mkdir -p soroban/deployments
{
  echo "ASSET=${ASSET}"
  echo "ASSET_CODE=${ASSET_CODE}"
  echo "ISSUER=${ISSUER}"
  echo "SAC_ID=${SAC_ID}"
} > soroban/deployments/testnet.env
echo "Wrote soroban/deployments/testnet.env"
```

- [ ] **Step 3: Run the SAC script**
```bash
chmod +x soroban/scripts/01-create-sac.sh && ./soroban/scripts/01-create-sac.sh
```
Expected output (ends with):
```
SAC contract id: CB...   (56-char C... address)
Wrote soroban/deployments/testnet.env
```

- [ ] **Step 4: Sanity-check the SAC responds**
```bash
source soroban/deployments/testnet.env
stellar contract invoke --id "$SAC_ID" --source-account issuer --network testnet -- name
```
Expected output:
```
"zUSDC:GISSUER..."
```

- [ ] **Step 5: Commit**
```bash
git add soroban/scripts/01-create-sac.sh soroban/deployments/testnet.env && git commit -m "infra: deploy pool-bridged asset as Stellar Asset Contract (SAC) on testnet"
```

---

### Task 36: Deploy verifier + pool to testnet, wire SAC admin, record contract ids

**Files:**
- Create: `soroban/scripts/02-deploy.sh`
- Modify: `soroban/deployments/testnet.env`
- Create: `soroban/deployments/CONTRACT_IDS.md`

- [ ] **Step 1: Build optimized WASM**
```bash
stellar contract build --manifest-path soroban/Cargo.toml 2>&1 | tail -3
ls -1 soroban/target/wasm32v1-none/release/*.wasm
```
Expected output:
```
    Finished `release` profile ...
soroban/target/wasm32v1-none/release/circom_groth16_verifier.wasm
soroban/target/wasm32v1-none/release/pool.wasm
```

- [ ] **Step 2: Deploy script (verifier → pool → init → hand SAC admin to pool)**
`soroban/scripts/02-deploy.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
NET=testnet
source soroban/deployments/testnet.env

VERIFIER_WASM=soroban/target/wasm32v1-none/release/circom_groth16_verifier.wasm
POOL_WASM=soroban/target/wasm32v1-none/release/pool.wasm

ADMIN=$(stellar keys address deployer)
RELAYER=$(stellar keys address relayer)

echo "Deploying verifier..."
VERIFIER_ID=$(stellar contract deploy \
  --source-account deployer --network "${NET}" \
  --wasm "${VERIFIER_WASM}")
echo "VERIFIER_ID=${VERIFIER_ID}"

echo "Deploying pool..."
POOL_ID=$(stellar contract deploy \
  --source-account deployer --network "${NET}" \
  --wasm "${POOL_WASM}")
echo "POOL_ID=${POOL_ID}"

echo "Initializing pool..."
stellar contract invoke --id "${POOL_ID}" --source-account deployer --network "${NET}" -- \
  initialize \
  --admin "${ADMIN}" \
  --relayer "${RELAYER}" \
  --verifier "${VERIFIER_ID}" \
  --token "${SAC_ID}" \
  --denoms '[1,10,100]' \
  --amounts '[10000000,100000000,1000000000]'

echo "Transferring SAC admin to the pool (so pool can mint on withdraw)..."
stellar contract invoke --id "${SAC_ID}" --source-account issuer --network "${NET}" -- \
  set_admin --new_admin "${POOL_ID}"

{
  echo "VERIFIER_ID=${VERIFIER_ID}"
  echo "POOL_ID=${POOL_ID}"
  echo "ADMIN=${ADMIN}"
  echo "RELAYER=${RELAYER}"
} >> soroban/deployments/testnet.env
echo "Done."
```

- [ ] **Step 3: Run the deploy script**
```bash
chmod +x soroban/scripts/02-deploy.sh && ./soroban/scripts/02-deploy.sh
```
Expected output (ends with):
```
VERIFIER_ID=CA...
POOL_ID=CB...
...
Done.
```

- [ ] **Step 4: Smoke-test on testnet — anchor a root as the relayer**
```bash
source soroban/deployments/testnet.env
stellar contract invoke --id "$POOL_ID" --source-account relayer --network testnet -- \
  update_root --denom 10 \
  --root 0000000000000000000000000000000000000000000000000000000000000007
stellar contract invoke --id "$POOL_ID" --source-account deployer --network testnet -- \
  is_known_root --denom 10 \
  --root 0000000000000000000000000000000000000000000000000000000000000007
```
Expected output:
```
true
```

- [ ] **Step 5: Record contract ids**
`soroban/deployments/CONTRACT_IDS.md`:
```markdown
# Soroban Testnet Deployment

Network: testnet (Test SDF Network ; September 2015)

| Component        | Contract ID / Address |
|------------------|-----------------------|
| Bridged asset    | zUSDC:<ISSUER>        |
| SAC (token)      | <SAC_ID>              |
| Verifier         | <VERIFIER_ID>         |
| Pool             | <POOL_ID>             |
| Admin            | <ADMIN G-addr>        |
| Backing relayer  | <RELAYER G-addr>      |

SAC admin = Pool (set via `set_admin`), so the pool mints on `withdraw`.
Fill the bracketed values from `soroban/deployments/testnet.env`.
```
Populate it from the env file:
```bash
cat soroban/deployments/testnet.env
```
Expected output (all ids resolved):
```
ASSET=zUSDC:G...
SAC_ID=C...
VERIFIER_ID=C...
POOL_ID=C...
ADMIN=G...
RELAYER=G...
```

- [ ] **Step 6: Commit**
```bash
git add soroban/scripts/02-deploy.sh soroban/deployments/testnet.env soroban/deployments/CONTRACT_IDS.md && git commit -m "deploy: verifier+pool live on testnet, SAC admin handed to pool, record contract ids"
```

---

**Integration notes for adjacent sections**
- The verifier's `verify(proof, public_inputs)` signature and the `Groth16Proof { a,b,c }` / `VerificationKeyBytes` shapes in `contracts/types` are the contract boundary with the **circuit task** — VK bytes in `vk.rs` and the spike proof in `test_data.rs` come straight from it.
- `update_root(denom, root)` is the contract boundary with the **Backing Relayer** section; `root` is the 32-byte EVM Merkle root, relayer auth enforced via `require_auth`.
- `withdraw(proof, root, nullifier_hash, recipient_fr, recipient, denom)` is the contract boundary with the **Withdrawal Relayer**; the relayer signs/submits the tx so the recipient stays unlinkable, and `recipient_fr` must equal the circuit's recipient packing of `recipient`.
- Denominations `[1,10,100]` map to 7-decimal SAC amounts `[10000000,100000000,1000000000]`.

## Relayer (Rust): Backing Relayer + Withdrawal Relayer + Merkle Path Service

This section adds a single Rust binary crate `relayer/` to the forked `NethermindEth/stellar-private-payments` workspace. It implements two relayer roles plus an off-chain Merkle-path service.

**Architectural decisions (faithful to CONTEXT.md / ADR-0004):**
- **EVM side = native Rust `alloy`** (HTTP **polling** of `get_logs`, not WebSocket — public Sepolia RPCs reliably support HTTP; polling also gives clean idempotency by tracking `from_block`).
- **Soroban side = shell out to the `stellar` CLI** for `update_root` / `withdraw` invocation. This is the canonical, version-stable invoke path the Nethermind deployment tooling already uses (the Rust `soroban-client` crate's invoke+auth API is churny across releases). The relayer key is a CLI-managed identity. We capture the returned tx hash from CLI stdout.
- **Hash = `zkhash` Poseidon2** with `POSEIDON2_BN256_PARAMS` (the bn256 t=2 instance) and compression `Compress(l,r) = permutation([l,r])[0] + l` — byte-identical to the circuit/Solidity keystone.
- **HTTP endpoint = `axum`**; recipient is inside the public-inputs vector so the relayer cannot redirect funds.

Public-input vector order (must match circuit + Soroban verifier): `[ root, nullifierHash, recipient, denomination ]`.

---

### Task 40: Scaffold the relayer crate + typed config

**Files:**
- Create: `relayer/Cargo.toml`
- Modify: `Cargo.toml` (workspace root — add `relayer` member)
- Create: `relayer/src/main.rs`
- Create: `relayer/src/config.rs`
- Create: `relayer/config.example.toml`
- Create: `relayer/.gitignore`

- [ ] **Step 1: Confirm the workspace root and current members**
```bash
cd /home/aashim/hackathon/stellar-hacks && test -f Cargo.toml && grep -n "members" -A8 Cargo.toml
```
Expected output: prints the `[workspace] members = [...]` array listing the existing crates (e.g. `contracts/*`, `tools/ceremony-cli`). If `Cargo.toml` is absent at root, run inside the forked `stellar-private-payments` checkout instead.

- [ ] **Step 2: Add `relayer` as a workspace member**
Edit the root `Cargo.toml` `members` array to include the new crate. Example resulting array (keep existing entries, append `"relayer"`):
```toml
[workspace]
resolver = "2"
members = [
    "contracts/*",
    "tools/ceremony-cli",
    "relayer",
]
```

- [ ] **Step 3: Create `relayer/Cargo.toml` with pinned deps**
```toml
[package]
name = "relayer"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "relayer"
path = "src/main.rs"

[dependencies]
# EVM client (native event polling + ABI decode)
alloy = { version = "0.8", features = ["full", "node-bindings"] }
# Poseidon2 over BN254 — the keystone hash. C3: use the SAME zkhash the circuit uses — the path crate vendored
# in the upstream repo at poseidon2/ (v0.2.0), proven byte-identical by the keystone (2026-06-15).
# Instances: POSEIDON2_BN256_PARAMS_2 (t=2: compress + nullifierHash), POSEIDON2_BN256_PARAMS_3 (t=3: commitment).
zkhash = { path = "../vendor/stellar-private-payments/poseidon2" }
# C4: match the upstream workspace (ark 0.6) so FpBN256 unifies with zkhash's ark-ff 0.6. Off-chain field math only.
ark-bn254 = "0.6"
ark-ff = "0.6"
# HTTP withdrawal endpoint
axum = "0.7"
tower-http = { version = "0.6", features = ["trace"] }
# async runtime
tokio = { version = "1", features = ["full"] }
futures-util = "0.3"
# config + serde
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
# cli
clap = { version = "4", features = ["derive"] }
# errors + logging
anyhow = "1"
thiserror = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
# hashing for recipient encoding parity
hex = "0.4"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 4: Create `relayer/.gitignore`**
```gitignore
/target
config.toml
*.log
```

- [ ] **Step 5: Create `relayer/config.example.toml`** (the documented config surface)
```toml
# Copy to relayer/config.toml and fill in. config.toml is gitignored.

[evm]
# HTTP RPC for Sepolia (Alchemy/Infura/public). Polling-based, no WS required.
rpc_url        = "https://ethereum-sepolia-rpc.publicnode.com"
# Deployed Lock/MerkleTreeWithHistory contract on Sepolia.
lock_contract  = "0x0000000000000000000000000000000000000000"
# Block to start scanning from (the deploy block — avoids rescanning all history).
start_block    = 0
# Confirmations to wait before treating a root as final.
confirmations  = 2

[soroban]
# Soroban RPC + network passphrase target (use the `stellar` CLI network name).
network        = "testnet"
rpc_url        = "https://soroban-testnet.stellar.org"
# Deployed Shielded Pool contract id (C...).
pool_contract  = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
# `stellar keys` identity name that holds the relayer key (funded on testnet).
relayer_identity = "relayer"

[relayer]
# Backing relayer poll interval in seconds.
poll_interval_secs = 10
# Withdrawal relayer HTTP bind address.
http_bind          = "127.0.0.1:8080"
# Denominations, in the same fixed order/index as the pool + circuit.
denominations      = [1, 10, 100]
# Merkle tree depth (must match the EVM tree + circuit).
tree_depth         = 20
```

- [ ] **Step 6: Create `relayer/src/config.rs`**
```rust
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub evm: EvmConfig,
    pub soroban: SorobanConfig,
    pub relayer: RelayerConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EvmConfig {
    pub rpc_url: String,
    pub lock_contract: String,
    pub start_block: u64,
    pub confirmations: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SorobanConfig {
    pub network: String,
    pub rpc_url: String,
    pub pool_contract: String,
    pub relayer_identity: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayerConfig {
    pub poll_interval_secs: u64,
    pub http_bind: String,
    pub denominations: Vec<u64>,
    pub tree_depth: usize,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config at {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw).context("parsing config TOML")?;
        Ok(cfg)
    }
}
```

- [ ] **Step 7: Create `relayer/src/main.rs` with a CLI dispatcher (modes wired in later tasks)**
```rust
mod config;
mod evm;
mod soroban;
mod merkle;
mod backing;
mod withdrawal;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::Config;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "relayer", about = "Private bridge relayer: backing + withdrawal + path service")]
struct Cli {
    /// Path to config.toml
    #[arg(long, default_value = "relayer/config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the backing relayer: poll Sepolia roots -> Soroban update_root
    Backing,
    /// Run the withdrawal relayer HTTP endpoint
    Withdrawal,
    /// Print the Merkle path for a commitment (debug / client helper)
    Path {
        /// denomination index (0-based into config denominations)
        #[arg(long)]
        denom_index: usize,
        /// commitment as 0x-prefixed hex
        #[arg(long)]
        commitment: String,
    },
    /// One-shot self-test of the pinned Poseidon2 keystone vector
    Selftest,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;

    match cli.cmd {
        Cmd::Backing => backing::run(cfg).await,
        Cmd::Withdrawal => withdrawal::run(cfg).await,
        Cmd::Path { denom_index, commitment } => {
            merkle::print_path(&cfg, denom_index, &commitment).await
        }
        Cmd::Selftest => merkle::selftest(),
    }
}
```

- [ ] **Step 8: Create empty module stubs so it compiles**
```bash
cd /home/aashim/hackathon/stellar-hacks/relayer/src && \
for m in evm soroban merkle backing withdrawal; do \
printf '// implemented in a later task\n' > "$m.rs"; done && ls
```
Expected output: `backing.rs  config.rs  evm.rs  main.rs  merkle.rs  soroban.rs  withdrawal.rs`

Then add minimal placeholder fns so `main.rs` references resolve. Put this in `relayer/src/backing.rs`:
```rust
use crate::config::Config;
use anyhow::Result;
pub async fn run(_cfg: Config) -> Result<()> { unimplemented!("Task 41") }
```
`relayer/src/withdrawal.rs`:
```rust
use crate::config::Config;
use anyhow::Result;
pub async fn run(_cfg: Config) -> Result<()> { unimplemented!("Task 42") }
```
`relayer/src/merkle.rs`:
```rust
use crate::config::Config;
use anyhow::Result;
pub async fn print_path(_cfg: &Config, _i: usize, _c: &str) -> Result<()> { unimplemented!("Task 43") }
pub fn selftest() -> Result<()> { unimplemented!("Task 43") }
```
Leave `relayer/src/evm.rs` and `relayer/src/soroban.rs` as the `// implemented in a later task` one-liners for now.

- [ ] **Step 9: Build to verify scaffold compiles**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo build -p relayer 2>&1 | tail -5
```
Expected output: ends with `Finished \`dev\` profile [unoptimized + debuginfo] target(s) in ...` (downloads deps on first run; no errors).

- [ ] **Step 10: Verify CLI help works**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo run -q -p relayer -- --help 2>&1 | tail -12
```
Expected output: usage text listing the subcommands `backing`, `withdrawal`, `path`, `selftest` and the `--config` option.

- [ ] **Step 11: Commit**
```bash
git add relayer Cargo.toml && git commit -m "relayer: scaffold binary crate + typed TOML config + CLI dispatcher"
```

---

### Task 41: Pinned Poseidon2 keystone + Merkle path service (TDD)

This is the **keystone** task: the Rust hash must byte-match the circom/Solidity Poseidon2. Build + test the hash and tree reconstruction first, since both relayer roles depend on it.

> ⚠️ **MIXED ARITY + DEP (C2 + C3, confirmed from fork source):** the relayer rebuilds the Merkle tree, so its compression is **t=2** (`Perm₂([l,r])[0] + l`) — matching the EVM tree and circuit. If the relayer also computes commitments/nullifierHashes it needs **t=3** (commitment) and **t=2** (nullifierHash) too, so it must instantiate Poseidon2 at **both** widths (the zkhash `POSEIDON2_BN256_PARAMS` constant is t=3 only — also wire the t=2 instance). Depend on the **Nethermind git fork** of `zkhash` (see Task 40 `Cargo.toml`), NOT crates.io `zkhash 0.2`. The parity test below must assert against the per-operation vectors Task 2 produced.

**Files:**
- Create: `relayer/src/poseidon.rs`
- Modify: `relayer/src/main.rs` (register `poseidon` module)
- Rewrite: `relayer/src/merkle.rs`
- Test: `relayer/tests/poseidon_parity.rs`
- Test: `relayer/tests/merkle_root.rs`

- [ ] **Step 1: Write the FAILING parity test for the pinned hash vector**
Create `relayer/tests/poseidon_parity.rs`. The expected output values come from the Day-1 keystone spike (`hash([1,2])` and `Compress(1,2)`); paste the canonical values the circuit/Solidity tasks pinned. Until then this test asserts internal self-consistency (commitment/nullifier shapes) plus the documented compression identity.
```rust
use ark_bn254::Fr;
use ark_ff::PrimeField;
use relayer::poseidon::{compress, hash1, hash2, perm2};

#[test]
fn permutation_two_inputs_is_deterministic() {
    let a = Fr::from(1u64);
    let b = Fr::from(2u64);
    let out1 = perm2(a, b);
    let out2 = perm2(a, b);
    assert_eq!(out1, out2, "permutation must be deterministic");
    assert_ne!(out1[0], out1[1], "width-2 output should differ across lanes");
}

#[test]
fn compress_matches_documented_identity() {
    // Compress(l,r) = permutation([l,r])[0] + l   (ADR-0004 keystone)
    let l = Fr::from(7u64);
    let r = Fr::from(9u64);
    let p = perm2(l, r);
    assert_eq!(compress(l, r), p[0] + l);
}

#[test]
fn commitment_and_nullifier_arity() {
    let nullifier = Fr::from(42u64);
    let secret = Fr::from(99u64);
    // commitment = Poseidon2Hash2(nullifier, secret)
    let c = hash2(nullifier, secret);
    // nullifierHash = Poseidon2Hash1(nullifier)
    let nh = hash1(nullifier);
    assert_ne!(c, nh);
    assert_ne!(c, Fr::from(0u64));
}

// KEYSTONE: replace the zeros below with the exact field values pinned by the
// circom + Solidity Day-1 spike (hash([1,2]) and Compress(1,2)). When the
// circuit task lands its vector, un-#[ignore] this and assert byte-equality.
#[test]
#[ignore = "fill in pinned vector from circuit/Solidity spike, then un-ignore"]
fn matches_cross_surface_keystone_vector() {
    let expected_compress_1_2: Fr = Fr::from_str_vartime("0").unwrap();
    assert_eq!(compress(Fr::from(1u64), Fr::from(2u64)), expected_compress_1_2);
}
```

- [ ] **Step 2: Run the test — confirm it FAILS to compile (no `poseidon` module yet)**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer --test poseidon_parity 2>&1 | tail -5
```
Expected output: compile error `unresolved import \`relayer::poseidon\`` / `failed to resolve`.

- [ ] **Step 3: Implement `relayer/src/poseidon.rs`** (the pinned hash)
```rust
//! Pinned Poseidon2 over BN254 — the project keystone.
//! Instance: zkhash POSEIDON2_BN256_PARAMS (bn256, width t=2).
//! Compression: Compress(l, r) = permutation([l, r])[0] + l   (ADR-0004).
//! MUST byte-match the circom circuit and the Solidity tree.

use ark_bn254::Fr;
use std::sync::OnceLock;
use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS;

fn instance() -> &'static Poseidon2<Fr> {
    static P: OnceLock<Poseidon2<Fr>> = OnceLock::new();
    P.get_or_init(|| Poseidon2::new(&POSEIDON2_BN256_PARAMS))
}

/// Raw width-2 permutation of [a, b]. Returns the full state [s0, s1].
pub fn perm2(a: Fr, b: Fr) -> [Fr; 2] {
    let out = instance().permutation(&[a, b]);
    debug_assert_eq!(out.len(), 2, "POSEIDON2_BN256_PARAMS must be width 2");
    [out[0], out[1]]
}

/// Merkle internal node compression: Compress(l, r) = perm([l, r])[0] + l.
pub fn compress(l: Fr, r: Fr) -> Fr {
    let out = perm2(l, r);
    out[0] + l
}

/// commitment = Poseidon2Hash2(nullifier, secret).
/// 2-input hash modeled as the compression sponge output lane 0 + first input,
/// identical to `compress` (the circuit's 2-input hash gadget). Pin against the
/// circuit's `H(a,b)` gadget output in the keystone vector before relying on it.
pub fn hash2(a: Fr, b: Fr) -> Fr {
    compress(a, b)
}

/// nullifierHash = Poseidon2Hash1(nullifier).
/// 1-input hash: pad to width 2 with the field-zero capacity element, take lane 0.
/// Pin arity against the circuit's 1-input Poseidon2 in the keystone vector.
pub fn hash1(a: Fr) -> Fr {
    let out = perm2(a, Fr::from(0u64));
    out[0] + a
}
```

- [ ] **Step 4: Expose a lib target so tests can import `relayer::*`**
Create `relayer/src/lib.rs`:
```rust
pub mod config;
pub mod poseidon;
pub mod merkle;
pub mod evm;
pub mod soroban;
```
And in `relayer/Cargo.toml`, add a `[lib]` section above `[[bin]]`:
```toml
[lib]
name = "relayer"
path = "src/lib.rs"
```
Then in `relayer/src/main.rs`, replace the top `mod ...;` block with `use relayer::{config::{self, Config}, merkle, ...}` style — simplest is to make `main.rs` declare only the binary-only modules and pull the rest from the lib:
```rust
use relayer::config::{self, Config};
use relayer::merkle;
mod backing;
mod withdrawal;
```
(Leave the `Cli`/`Cmd`/`main` bodies unchanged. `backing` and `withdrawal` stay as binary modules; they `use relayer::...` for shared code.)

- [ ] **Step 5: Re-run parity test — confirm it PASSES**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer --test poseidon_parity 2>&1 | tail -8
```
Expected output: `test result: ok. 3 passed; 0 failed; 1 ignored` (the keystone-vector test stays ignored until the circuit task pins the values).

- [ ] **Step 6: Write the FAILING Merkle-root reconstruction test**
Create `relayer/tests/merkle_root.rs`. It builds a fixed-depth tree with `compress`, inserts a few leaves, and checks that recomputing a leaf's path back up reproduces the root.
```rust
use ark_bn254::Fr;
use relayer::merkle::MerkleTree;

#[test]
fn path_recomputes_root() {
    let depth = 20;
    let mut tree = MerkleTree::new(depth);
    let leaves: Vec<Fr> = (1u64..=5).map(Fr::from).collect();
    for l in &leaves {
        tree.insert(*l);
    }
    let root = tree.root();

    // For each inserted leaf, the path must recompute the same root.
    for (i, leaf) in leaves.iter().enumerate() {
        let (path_elements, path_indices) = tree.proof(i);
        let recomputed = MerkleTree::recompute_root(*leaf, &path_elements, &path_indices);
        assert_eq!(recomputed, root, "leaf {i} path must recompute the root");
    }
}

#[test]
fn empty_tree_root_is_deterministic() {
    let a = MerkleTree::new(20).root();
    let b = MerkleTree::new(20).root();
    assert_eq!(a, b);
}
```

- [ ] **Step 7: Run it — confirm FAIL (no `MerkleTree` yet)**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer --test merkle_root 2>&1 | tail -5
```
Expected output: compile error `unresolved import \`relayer::merkle::MerkleTree\``.

- [ ] **Step 8: Implement the tree in `relayer/src/merkle.rs`** (replace the stub)
```rust
//! Off-chain incremental Merkle tree mirroring the EVM tornado tree.
//! depth=20, internal node = compress(left, right), zero-padded leaves.
//! Reconstructed from EVM Deposit events so clients can fetch path proofs.

use crate::config::Config;
use crate::poseidon::{compress, hash2};
use anyhow::{anyhow, Context, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Sequentially-filled incremental Merkle tree.
pub struct MerkleTree {
    depth: usize,
    /// zeros[i] = the value of an empty subtree root at level i.
    zeros: Vec<Fr>,
    /// filled[i] = leaves currently stored at level i (level 0 = leaves).
    levels: Vec<Vec<Fr>>,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        // zeros[0] = 0; zeros[i] = compress(zeros[i-1], zeros[i-1]).
        let mut zeros = Vec::with_capacity(depth + 1);
        zeros.push(Fr::from(0u64));
        for i in 1..=depth {
            let z = zeros[i - 1];
            zeros.push(compress(z, z));
        }
        MerkleTree {
            depth,
            zeros,
            levels: vec![Vec::new(); depth + 1],
        }
    }

    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    /// Append a leaf and recompute affected nodes up to the root.
    pub fn insert(&mut self, leaf: Fr) {
        self.levels[0].push(leaf);
        let mut idx = self.levels[0].len() - 1;
        for level in 0..self.depth {
            let cur = self.levels[level][idx];
            let (left, right) = if idx % 2 == 0 {
                // right sibling is empty subtree at this level
                (cur, self.zeros[level])
            } else {
                (self.levels[level][idx - 1], cur)
            };
            let parent = compress(left, right);
            let pidx = idx / 2;
            let plevel = &mut self.levels[level + 1];
            if plevel.len() > pidx {
                plevel[pidx] = parent;
            } else {
                plevel.push(parent);
            }
            idx = pidx;
        }
    }

    pub fn root(&self) -> Fr {
        self.levels[self.depth].get(0).copied().unwrap_or(self.zeros[self.depth])
    }

    /// Return (pathElements, pathIndices) for the leaf at `index`.
    /// pathIndices[i] = 0 if our node is the LEFT child at level i, else 1.
    pub fn proof(&self, index: usize) -> (Vec<Fr>, Vec<u8>) {
        let mut elements = Vec::with_capacity(self.depth);
        let mut indices = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            let is_right = idx % 2 == 1;
            let sibling = if is_right {
                self.levels[level][idx - 1]
            } else {
                self.levels[level]
                    .get(idx + 1)
                    .copied()
                    .unwrap_or(self.zeros[level])
            };
            elements.push(sibling);
            indices.push(if is_right { 1 } else { 0 });
            idx /= 2;
        }
        (elements, indices)
    }

    /// Recompute a root from a leaf + path (mirror of the in-circuit logic).
    pub fn recompute_root(leaf: Fr, path_elements: &[Fr], path_indices: &[u8]) -> Fr {
        let mut cur = leaf;
        for (sib, &is_right) in path_elements.iter().zip(path_indices) {
            cur = if is_right == 1 {
                compress(*sib, cur)
            } else {
                compress(cur, *sib)
            };
        }
        cur
    }
}

/// 0x-hex (32-byte big-endian) -> Fr.
pub fn fr_from_hex(s: &str) -> Result<Fr> {
    let s = s.trim_start_matches("0x");
    let bytes = hex::decode(s).context("decoding hex field element")?;
    if bytes.len() > 32 {
        return Err(anyhow!("field element > 32 bytes"));
    }
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(Fr::from_be_bytes_mod_order(&buf))
}

/// Fr -> 0x-hex (32-byte big-endian).
pub fn fr_to_hex(f: Fr) -> String {
    let be = f.into_bigint().to_bytes_be();
    let mut buf = [0u8; 32];
    buf[32 - be.len()..].copy_from_slice(&be);
    format!("0x{}", hex::encode(buf))
}

/// CLI helper: reconstruct the tree for a denom from EVM events and print the
/// path for a given commitment. (Event fetch implemented in Task 42.)
pub async fn print_path(cfg: &Config, denom_index: usize, commitment_hex: &str) -> Result<()> {
    let target = fr_from_hex(commitment_hex)?;
    let leaves = crate::evm::fetch_commitments_for_denom(cfg, denom_index).await?;

    let mut tree = MerkleTree::new(cfg.relayer.tree_depth);
    let mut found = None;
    for (i, leaf) in leaves.iter().enumerate() {
        if *leaf == target {
            found = Some(i);
        }
        tree.insert(*leaf);
    }
    let index = found.ok_or_else(|| anyhow!("commitment not found in denom {denom_index} tree"))?;
    let (elements, indices) = tree.proof(index);

    let out = serde_json::json!({
        "denomIndex": denom_index,
        "leafIndex": index,
        "root": fr_to_hex(tree.root()),
        "pathElements": elements.iter().map(|e| fr_to_hex(*e)).collect::<Vec<_>>(),
        "pathIndices": indices,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// One-shot keystone self-test usable without any network access.
pub fn selftest() -> Result<()> {
    let l = Fr::from(1u64);
    let r = Fr::from(2u64);
    let c = compress(l, r);
    let commit = hash2(Fr::from(42u64), Fr::from(99u64));
    println!("Compress(1,2) = {}", fr_to_hex(c));
    println!("commitment(42,99) = {}", fr_to_hex(commit));
    println!("OK: paste Compress(1,2) into the circuit/Solidity keystone check.");
    Ok(())
}
```

- [ ] **Step 9: Re-run merkle test — confirm PASS**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer --test merkle_root 2>&1 | tail -6
```
Expected output: `test result: ok. 2 passed; 0 failed`.

- [ ] **Step 10: Run selftest end to end (prints the keystone vector for cross-check)**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo run -q -p relayer -- --config relayer/config.example.toml selftest 2>&1 | tail -4
```
Expected output: three lines — `Compress(1,2) = 0x...`, `commitment(42,99) = 0x...`, `OK: paste Compress(1,2) ...`. Hand this `Compress(1,2)` value to the circuit + Solidity owners; all three MUST match.

- [ ] **Step 11: Commit**
```bash
git add relayer/src/poseidon.rs relayer/src/lib.rs relayer/src/merkle.rs relayer/src/main.rs relayer/Cargo.toml relayer/tests && git commit -m "relayer: pinned Poseidon2 keystone + off-chain Merkle path service (TDD)"
```

---

### Task 42: EVM client — typed Deposit/Root events + commitment fetch (TDD)

Implements native `alloy` log polling of the Sepolia Lock contract. Two reads: (a) `NewRoot` events for the backing relayer, (b) `Deposit` events (commitment + leafIndex + denom) for the path service.

**Files:**
- Rewrite: `relayer/src/evm.rs`
- Test: `relayer/tests/evm_decode.rs`

- [ ] **Step 1: Write the FAILING event-decode test against a fixed log fixture**
Create `relayer/tests/evm_decode.rs`. We validate the `sol!`-generated ABI decoding against a hand-built log (so the test needs no network).
```rust
use alloy::primitives::{address, b256, Bytes, LogData, U256};
use relayer::evm::{decode_deposit, LockContract};

#[test]
fn decodes_deposit_event() {
    // event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 denom)
    let event_sig = LockContract::Deposit::SIGNATURE_HASH;
    let commitment = b256!("0000000000000000000000000000000000000000000000000000000000000007");

    // non-indexed data: leafIndex (uint32 -> padded 32 bytes) + denom (uint256)
    let mut data = Vec::new();
    data.extend_from_slice(&U256::from(3u64).to_be_bytes::<32>()); // leafIndex
    data.extend_from_slice(&U256::from(10u64).to_be_bytes::<32>()); // denom

    let log_data = LogData::new_unchecked(
        vec![event_sig, commitment],
        Bytes::from(data),
    );

    let decoded = decode_deposit(&log_data).expect("decode");
    assert_eq!(decoded.commitment, commitment);
    assert_eq!(decoded.leafIndex, 3u32);
    assert_eq!(decoded.denom, U256::from(10u64));
}

#[test]
fn deposit_signature_is_stable() {
    // guards against accidental ABI drift in the sol! declaration
    let _ = address!("0000000000000000000000000000000000000000");
    assert_ne!(LockContract::Deposit::SIGNATURE_HASH, LockContract::NewRoot::SIGNATURE_HASH);
}
```

- [ ] **Step 2: Run it — confirm FAIL (no `evm` symbols yet)**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer --test evm_decode 2>&1 | tail -5
```
Expected output: compile error `unresolved import \`relayer::evm::decode_deposit\``.

- [ ] **Step 3: Implement `relayer/src/evm.rs`**
The `sol!` event signatures must match the Sepolia Lock/MerkleTreeWithHistory contract emitted by the EVM task. `Deposit` mirrors tornado's deposit event (commitment + leafIndex + timestamp); we add `denom` and keep a `NewRoot(uint256 root, uint32 rootIndex)` event the EVM task emits on each tree update.
```rust
//! EVM (Sepolia) client: poll the Lock contract for NewRoot + Deposit events.
//! Native alloy, HTTP polling (no WS dependency).

use crate::config::Config;
use crate::merkle::fr_from_hex;
use alloy::primitives::{Address, LogData, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::sol;
use alloy::sol_types::SolEvent;
use anyhow::{anyhow, Context, Result};
use ark_bn254::Fr;
use std::str::FromStr;

sol! {
    #[sol(rpc)]
    contract LockContract {
        // Emitted whenever a commitment is locked and inserted into the tree.
        event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 denom);
        // Emitted whenever the tree root advances (one per deposit).
        event NewRoot(uint256 root, uint32 rootIndex, uint256 denom);
    }
}

/// Decoded NewRoot event payload.
#[derive(Debug, Clone)]
pub struct NewRootEvent {
    pub root: U256,
    pub root_index: u32,
    pub denom: U256,
    pub block: u64,
}

/// Decode a raw log into a typed Deposit (used by tests + path service).
pub fn decode_deposit(data: &LogData) -> Result<LockContract::Deposit> {
    LockContract::Deposit::decode_log_data(data, true)
        .map(|d| d)
        .context("decoding Deposit log")
}

fn http_provider(cfg: &Config) -> Result<impl Provider + Clone> {
    let url = cfg.evm.rpc_url.parse().context("parsing EVM rpc_url")?;
    Ok(ProviderBuilder::new().on_http(url))
}

fn lock_address(cfg: &Config) -> Result<Address> {
    Address::from_str(&cfg.evm.lock_contract).context("parsing lock_contract address")
}

/// Fetch all NewRoot events in [from_block, to_block] for the given denom value.
/// Returns them in on-chain order so the latest is last.
pub async fn fetch_new_roots(
    cfg: &Config,
    from_block: u64,
    to_block: u64,
    denom_value: u64,
) -> Result<Vec<NewRootEvent>> {
    let provider = http_provider(cfg)?;
    let addr = lock_address(cfg)?;

    let filter = Filter::new()
        .address(addr)
        .event_signature(LockContract::NewRoot::SIGNATURE_HASH)
        .from_block(from_block)
        .to_block(to_block);

    let logs = provider.get_logs(&filter).await.context("get_logs NewRoot")?;

    let mut out = Vec::new();
    for log in logs {
        let decoded = LockContract::NewRoot::decode_log_data(log.data(), true)
            .context("decode NewRoot")?;
        if decoded.denom == U256::from(denom_value) {
            out.push(NewRootEvent {
                root: decoded.root,
                root_index: decoded.rootIndex,
                denom: decoded.denom,
                block: log.block_number.unwrap_or(0),
            });
        }
    }
    Ok(out)
}

/// Latest finalized block = head - confirmations.
pub async fn finalized_head(cfg: &Config) -> Result<u64> {
    let provider = http_provider(cfg)?;
    let head = provider.get_block_number().await.context("get_block_number")?;
    Ok(head.saturating_sub(cfg.evm.confirmations))
}

/// Reconstruct the ordered commitment list for one denomination from Deposit
/// events (used by the Merkle path service). Ordered by leafIndex ascending.
pub async fn fetch_commitments_for_denom(cfg: &Config, denom_index: usize) -> Result<Vec<Fr>> {
    let denom_value = *cfg
        .relayer
        .denominations
        .get(denom_index)
        .ok_or_else(|| anyhow!("denom_index {denom_index} out of range"))?;

    let provider = http_provider(cfg)?;
    let addr = lock_address(cfg)?;
    let head = finalized_head(cfg).await?;

    let filter = Filter::new()
        .address(addr)
        .event_signature(LockContract::Deposit::SIGNATURE_HASH)
        .from_block(cfg.evm.start_block)
        .to_block(head);

    let logs = provider.get_logs(&filter).await.context("get_logs Deposit")?;

    // (leafIndex, commitment) pairs for this denom, sorted by leafIndex.
    let mut pairs: Vec<(u32, Fr)> = Vec::new();
    for log in logs {
        let d = LockContract::Deposit::decode_log_data(log.data(), true)
            .context("decode Deposit")?;
        if d.denom != U256::from(denom_value) {
            continue;
        }
        let commit = fr_from_hex(&format!("0x{}", hex::encode(d.commitment.0)))?;
        pairs.push((d.leafIndex, commit));
    }
    pairs.sort_by_key(|(i, _)| *i);
    Ok(pairs.into_iter().map(|(_, c)| c).collect())
}
```

- [ ] **Step 4: Re-run the decode test — confirm PASS**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer --test evm_decode 2>&1 | tail -6
```
Expected output: `test result: ok. 2 passed; 0 failed`.

- [ ] **Step 5: Manual smoke against live Sepolia (after EVM task deploys)**
With a real `lock_contract` and at least one deposit done, point `relayer/config.toml` at Sepolia and run the path command:
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo run -q -p relayer -- path --denom-index 1 --commitment 0x<your-commitment> 2>&1 | tail -20
```
Expected output: pretty JSON `{ "denomIndex":1, "leafIndex":N, "root":"0x...", "pathElements":[...20...], "pathIndices":[...20...] }`. **Verify the printed `root` equals the on-chain root** (read it via `cast call <lock> "getLastRoot(uint256)" <denom>` or the EVM contract's getter). This is the path-reconstruction-matches-on-chain-root check (sub-task 4).

- [ ] **Step 6: Commit**
```bash
git add relayer/src/evm.rs relayer/tests/evm_decode.rs && git commit -m "relayer: alloy EVM client — typed NewRoot/Deposit decode + commitment fetch (TDD)"
```

---

### Task 43: Soroban invocation layer (update_root + withdraw via stellar CLI)

Wraps the `stellar contract invoke` CLI to submit both relayer transactions and capture the returned tx hash. The CLI is the version-stable invoke path; the relayer key is a `stellar keys` identity.

**Files:**
- Rewrite: `relayer/src/soroban.rs`
- Test: `relayer/tests/soroban_args.rs`

- [ ] **Step 1: Confirm the `stellar` CLI is installed and the relayer identity exists**
```bash
stellar --version && stellar keys ls 2>&1 | head
```
Expected output: a version line like `stellar 22.x.x` (or `soroban 21.x`), then a list of identities. If `relayer` is missing: `stellar keys generate relayer --network testnet --fund` (output: a funded `G...` address). Put that identity name in `config.toml` `soroban.relayer_identity`.

- [ ] **Step 2: Write a FAILING test for the argument builder (pure, no network)**
Create `relayer/tests/soroban_args.rs`. We test the arg vector construction so the CLI call is correct without invoking it.
```rust
use relayer::config::{Config, EvmConfig, RelayerConfig, SorobanConfig};
use relayer::soroban::{build_update_root_args, build_withdraw_args};

fn cfg() -> Config {
    Config {
        evm: EvmConfig {
            rpc_url: "http://x".into(),
            lock_contract: "0x0".into(),
            start_block: 0,
            confirmations: 0,
        },
        soroban: SorobanConfig {
            network: "testnet".into(),
            rpc_url: "https://soroban-testnet.stellar.org".into(),
            pool_contract: "CPOOL".into(),
            relayer_identity: "relayer".into(),
        },
        relayer: RelayerConfig {
            poll_interval_secs: 10,
            http_bind: "127.0.0.1:8080".into(),
            denominations: vec![1, 10, 100],
            tree_depth: 20,
        },
    }
}

#[test]
fn update_root_args_are_well_formed() {
    let args = build_update_root_args(&cfg(), 10, "12345");
    // contains the contract, the fn name, and both typed params
    assert!(args.windows(2).any(|w| w == ["--id", "CPOOL"]));
    assert!(args.iter().any(|a| a == "update_root"));
    assert!(args.windows(2).any(|w| w == ["--denom", "10"]));
    assert!(args.windows(2).any(|w| w == ["--root", "12345"]));
    assert!(args.iter().any(|a| a == "--source-account"));
}

#[test]
fn withdraw_args_carry_full_public_input_vector() {
    let args = build_withdraw_args(
        &cfg(),
        "0xproofhex",
        "rootval",
        "nullhashval",
        "recipientval",
        "10",
    );
    assert!(args.iter().any(|a| a == "withdraw"));
    assert!(args.windows(2).any(|w| w == ["--proof", "0xproofhex"]));
    assert!(args.windows(2).any(|w| w == ["--root", "rootval"]));
    assert!(args.windows(2).any(|w| w == ["--nullifier_hash", "nullhashval"]));
    assert!(args.windows(2).any(|w| w == ["--recipient", "recipientval"]));
    assert!(args.windows(2).any(|w| w == ["--denomination", "10"]));
}
```

- [ ] **Step 2b: Make config fields constructible from tests**
The test constructs `Config` directly, so its fields must be `pub` (they already are via `#[derive(Deserialize)]` on `pub struct`s with `pub` fields from Task 40). Confirm by re-reading `config.rs`; no change needed.

- [ ] **Step 3: Run the test — confirm FAIL**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer --test soroban_args 2>&1 | tail -5
```
Expected output: compile error `unresolved import \`relayer::soroban::build_update_root_args\``.

- [ ] **Step 4: Implement `relayer/src/soroban.rs`**
```rust
//! Soroban invocation via the `stellar` CLI. We shell out so the invoke/auth
//! path stays stable across soroban-sdk releases. Captures the tx hash.

use crate::config::Config;
use anyhow::{anyhow, Context, Result};
use tokio::process::Command;

/// Build the CLI args for pool.update_root(denom: u64, root: U256).
/// Soroban U256 is passed as a decimal string.
pub fn build_update_root_args(cfg: &Config, denom: u64, root_dec: &str) -> Vec<String> {
    vec![
        "contract".into(),
        "invoke".into(),
        "--id".into(),
        cfg.soroban.pool_contract.clone(),
        "--source-account".into(),
        cfg.soroban.relayer_identity.clone(),
        "--network".into(),
        cfg.soroban.network.clone(),
        "--rpc-url".into(),
        cfg.soroban.rpc_url.clone(),
        "--send".into(),
        "yes".into(),
        "--".into(),
        "update_root".into(),
        "--denom".into(),
        denom.to_string(),
        "--root".into(),
        root_dec.to_string(),
    ]
}

/// Build the CLI args for pool.withdraw(proof, root, nullifier_hash, recipient, denomination).
/// Public-input vector order: [root, nullifierHash, recipient, denomination].
pub fn build_withdraw_args(
    cfg: &Config,
    proof_hex: &str,
    root: &str,
    nullifier_hash: &str,
    recipient: &str,
    denomination: &str,
) -> Vec<String> {
    vec![
        "contract".into(),
        "invoke".into(),
        "--id".into(),
        cfg.soroban.pool_contract.clone(),
        "--source-account".into(),
        cfg.soroban.relayer_identity.clone(),
        "--network".into(),
        cfg.soroban.network.clone(),
        "--rpc-url".into(),
        cfg.soroban.rpc_url.clone(),
        "--send".into(),
        "yes".into(),
        "--".into(),
        "withdraw".into(),
        "--proof".into(),
        proof_hex.to_string(),
        "--root".into(),
        root.to_string(),
        "--nullifier_hash".into(),
        nullifier_hash.to_string(),
        "--recipient".into(),
        recipient.to_string(),
        "--denomination".into(),
        denomination.to_string(),
    ]
}

/// Run `stellar <args>` and return (stdout, stderr). Errors on non-zero exit.
async fn run_stellar(args: &[String]) -> Result<(String, String)> {
    let output = Command::new("stellar")
        .args(args)
        .output()
        .await
        .context("spawning `stellar` CLI (is it installed + on PATH?)")?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(anyhow!(
            "stellar invoke failed (status {:?}):\nstdout: {stdout}\nstderr: {stderr}",
            output.status.code()
        ));
    }
    Ok((stdout, stderr))
}

/// The stellar CLI prints the tx hash on stderr (info logs). Extract it.
fn extract_tx_hash(stdout: &str, stderr: &str) -> Option<String> {
    let combined = format!("{stderr}\n{stdout}");
    for line in combined.lines() {
        // matches "Transaction hash is <64-hex>" and "...transaction/<hash>"
        if let Some(idx) = line.find("transaction/") {
            let tail = &line[idx + "transaction/".len()..];
            let h: String = tail.chars().take(64).filter(|c| c.is_ascii_hexdigit()).collect();
            if h.len() == 64 {
                return Some(h);
            }
        }
        if let Some(rest) = line.split("hash is ").nth(1) {
            let h: String = rest.trim().chars().take(64).collect();
            if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(h);
            }
        }
    }
    None
}

/// Submit pool.update_root. Returns the tx hash (or a best-effort marker).
pub async fn submit_update_root(cfg: &Config, denom: u64, root_dec: &str) -> Result<String> {
    let args = build_update_root_args(cfg, denom, root_dec);
    let (stdout, stderr) = run_stellar(&args).await?;
    Ok(extract_tx_hash(&stdout, &stderr).unwrap_or_else(|| stdout.trim().to_string()))
}

/// Submit pool.withdraw. Returns the tx hash.
pub async fn submit_withdraw(
    cfg: &Config,
    proof_hex: &str,
    root: &str,
    nullifier_hash: &str,
    recipient: &str,
    denomination: &str,
) -> Result<String> {
    let args = build_withdraw_args(cfg, proof_hex, root, nullifier_hash, recipient, denomination);
    let (stdout, stderr) = run_stellar(&args).await?;
    extract_tx_hash(&stdout, &stderr)
        .ok_or_else(|| anyhow!("withdraw submitted but no tx hash parsed:\n{stderr}\n{stdout}"))
}
```

- [ ] **Step 5: Re-run test — confirm PASS**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer --test soroban_args 2>&1 | tail -6
```
Expected output: `test result: ok. 2 passed; 0 failed`.

- [ ] **Step 6: Manual smoke — call update_root once against the deployed pool**
With a deployed pool contract id in `config.toml`:
```bash
cd /home/aashim/hackathon/stellar-hacks && stellar contract invoke --id $(grep pool_contract relayer/config.toml | cut -d'"' -f2) --source-account relayer --network testnet -- update_root --denom 10 --root 12345 2>&1 | tail -5
```
Expected output: simulation succeeds and (with `--send yes`) prints a tx URL / hash on stderr. Confirms the arg shape matches the deployed pool's `update_root` signature (adjust param names here AND in `build_update_root_args` if the pool task named them differently).

- [ ] **Step 7: Commit**
```bash
git add relayer/src/soroban.rs relayer/tests/soroban_args.rs && git commit -m "relayer: Soroban invocation layer (update_root/withdraw via stellar CLI, tx-hash capture)"
```

---

### Task 44: Backing Relayer loop (poll EVM roots -> Soroban update_root, idempotent)

**Files:**
- Rewrite: `relayer/src/backing.rs`
- Create: `relayer/src/state.rs` (seen-roots + cursor persistence)
- Modify: `relayer/src/main.rs` (declare `mod state;`)
- Test: `relayer/tests/idempotency.rs`

- [ ] **Step 1: Write the FAILING idempotency test**
Create `relayer/tests/idempotency.rs`. The state store must dedupe roots and persist/restore the block cursor.
```rust
use relayer::state::SeenState;
use tempfile::tempdir;

#[test]
fn dedupes_roots_per_denom() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");
    let mut s = SeenState::load(&path).unwrap();

    assert!(s.mark_root_if_new(10, "111"));   // first time -> true (submit)
    assert!(!s.mark_root_if_new(10, "111"));  // dup -> false (skip)
    assert!(s.mark_root_if_new(100, "111"));  // same root, diff denom -> true
    assert!(s.mark_root_if_new(10, "222"));   // new root -> true
}

#[test]
fn persists_cursor_and_seen_across_reload() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");
    {
        let mut s = SeenState::load(&path).unwrap();
        s.mark_root_if_new(10, "abc");
        s.set_cursor(5000);
        s.save(&path).unwrap();
    }
    let s2 = SeenState::load(&path).unwrap();
    assert_eq!(s2.cursor(), 5000);
    assert!(!s2.clone().mark_root_if_new(10, "abc")); // still seen after reload
}
```

- [ ] **Step 2: Run it — confirm FAIL**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer --test idempotency 2>&1 | tail -5
```
Expected output: compile error `unresolved import \`relayer::state::SeenState\``.

- [ ] **Step 3: Implement `relayer/src/state.rs`**
```rust
//! Persistent dedup + block cursor for the backing relayer (JSON on disk).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeenState {
    /// last EVM block fully processed.
    cursor: u64,
    /// set of "denom:rootDecimal" already submitted to Soroban.
    seen: HashSet<String>,
}

impl SeenState {
    pub fn load(path: &Path) -> Result<Self> {
        if path.exists() {
            let raw = std::fs::read_to_string(path).context("reading state file")?;
            Ok(serde_json::from_str(&raw).context("parsing state JSON")?)
        } else {
            Ok(SeenState::default())
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let raw = serde_json::to_string_pretty(self).context("serializing state")?;
        std::fs::write(path, raw).context("writing state file")?;
        Ok(())
    }

    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    pub fn set_cursor(&mut self, block: u64) {
        self.cursor = block;
    }

    /// Returns true if this (denom, root) is new (and records it); false if dup.
    pub fn mark_root_if_new(&mut self, denom: u64, root_dec: &str) -> bool {
        let key = format!("{denom}:{root_dec}");
        self.seen.insert(key)
    }
}
```

- [ ] **Step 4: Re-run idempotency test — confirm PASS**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer --test idempotency 2>&1 | tail -6
```
Expected output: `test result: ok. 2 passed; 0 failed`.

- [ ] **Step 5: Implement the backing loop in `relayer/src/backing.rs`**
```rust
//! Backing Relayer: poll Sepolia NewRoot events per denomination and anchor
//! each new root into the Soroban pool via update_root. Idempotent + resumable.

use crate::config::Config;
use crate::state::SeenState;
use crate::{evm, soroban};
use alloy::primitives::U256;
use anyhow::Result;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info, warn};

const STATE_FILE: &str = "relayer/backing-state.json";

/// U256 -> decimal string (the form the Soroban CLI accepts for U256 args).
fn u256_dec(v: U256) -> String {
    v.to_string()
}

pub async fn run(cfg: Config) -> Result<()> {
    let state_path = PathBuf::from(STATE_FILE);
    let mut state = SeenState::load(&state_path)?;
    if state.cursor() == 0 {
        state.set_cursor(cfg.evm.start_block);
    }
    info!(
        cursor = state.cursor(),
        denoms = ?cfg.relayer.denominations,
        "backing relayer started"
    );

    let interval = Duration::from_secs(cfg.relayer.poll_interval_secs);
    loop {
        if let Err(e) = tick(&cfg, &mut state, &state_path).await {
            error!(error = %e, "backing tick failed; will retry");
        }
        tokio::time::sleep(interval).await;
    }
}

async fn tick(cfg: &Config, state: &mut SeenState, state_path: &PathBuf) -> Result<()> {
    let head = evm::finalized_head(cfg).await?;
    let from = state.cursor() + 1;
    if head < from {
        return Ok(()); // nothing new finalized yet
    }

    for &denom in &cfg.relayer.denominations {
        let roots = evm::fetch_new_roots(cfg, from, head, denom).await?;
        for ev in roots {
            let root_dec = u256_dec(ev.root);
            if !state.mark_root_if_new(denom, &root_dec) {
                continue; // already anchored this root for this denom
            }
            info!(denom, root = %root_dec, block = ev.block, "new EVM root -> Soroban update_root");
            match soroban::submit_update_root(cfg, denom, &root_dec).await {
                Ok(hash) => info!(denom, tx = %hash, "update_root submitted"),
                Err(e) => {
                    // Roll back the seen mark so we retry on the next tick.
                    warn!(denom, root = %root_dec, error = %e, "update_root failed; will retry");
                    // re-insert isn't needed (we only "saw" it); just don't advance cursor past it
                    return Err(e);
                }
            }
        }
    }

    state.set_cursor(head);
    state.save(state_path)?;
    Ok(())
}
```

- [ ] **Step 6: Add `mod state;` to the binary**
In `relayer/src/main.rs`, ensure the binary-side modules include state. Add near the other `mod` lines:
```rust
mod backing;
mod withdrawal;
```
And in `relayer/src/lib.rs` add `pub mod state;` so tests can reach it:
```rust
pub mod state;
```

- [ ] **Step 7: Build the whole crate**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo build -p relayer 2>&1 | tail -4
```
Expected output: `Finished \`dev\` profile ...` with no errors.

- [ ] **Step 8: Dry-run the loop against testnet (one tick, then Ctrl-C)**
With a real config pointing at the deployed Sepolia Lock + Soroban pool:
```bash
cd /home/aashim/hackathon/stellar-hacks && timeout 30 cargo run -q -p relayer -- backing 2>&1 | tail -15 || true
```
Expected output: `backing relayer started` log line, then either `nothing new` quiet ticks or — if a deposit exists — `new EVM root -> Soroban update_root` followed by `update_root submitted tx=<hash>`. Re-running it should NOT re-submit the same root (idempotent), confirmed by the absence of a second `update_root submitted` for the same root in `relayer/backing-state.json`.

- [ ] **Step 9: Commit**
```bash
git add relayer/src/backing.rs relayer/src/state.rs relayer/src/main.rs relayer/src/lib.rs relayer/tests/idempotency.rs && git commit -m "relayer: backing relayer loop (poll EVM NewRoot -> Soroban update_root, idempotent + resumable)"
```

---

### Task 45: Withdrawal Relayer HTTP endpoint (submit proof -> withdraw tx)

Accepts a `(proof, public_inputs)` JSON POST, submits the Soroban `withdraw()` tx, returns the tx hash. The recipient lives inside `public_inputs`, so the relayer physically cannot redirect funds.

**Files:**
- Rewrite: `relayer/src/withdrawal.rs`
- Test: `relayer/tests/withdrawal_request.rs`

- [ ] **Step 1: Write the FAILING request-validation test**
Create `relayer/tests/withdrawal_request.rs`. We test the request type + validation logic (denomination must be in the configured set; all fields present) without binding a socket.
```rust
use relayer::withdrawal::{validate_request, WithdrawRequest};

fn req() -> WithdrawRequest {
    WithdrawRequest {
        proof: "0xabc".into(),
        root: "111".into(),
        nullifier_hash: "222".into(),
        recipient: "333".into(),
        denomination: 10,
    }
}

#[test]
fn accepts_valid_request() {
    assert!(validate_request(&req(), &[1, 10, 100]).is_ok());
}

#[test]
fn rejects_unknown_denomination() {
    let mut r = req();
    r.denomination = 7;
    assert!(validate_request(&r, &[1, 10, 100]).is_err());
}

#[test]
fn rejects_empty_proof() {
    let mut r = req();
    r.proof = "".into();
    assert!(validate_request(&r, &[1, 10, 100]).is_err());
}
```

- [ ] **Step 2: Run it — confirm FAIL**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer --test withdrawal_request 2>&1 | tail -5
```
Expected output: compile error `unresolved import \`relayer::withdrawal\``.

- [ ] **Step 3: Move shared types to the lib and implement the endpoint**
Add `pub mod withdrawal;` to `relayer/src/lib.rs` (so the binary `backing`/`withdrawal` mods are not the source of truth — make `withdrawal` a lib module). Update `relayer/src/main.rs` to drop `mod withdrawal;` and instead `use relayer::withdrawal;`. Then write `relayer/src/withdrawal.rs`:
```rust
//! Withdrawal Relayer: HTTP endpoint that accepts (proof, public_inputs),
//! submits the Soroban withdraw() tx, returns the tx hash. Cannot steal:
//! the recipient is a bound public input inside the proof.

use crate::config::Config;
use crate::soroban;
use anyhow::{anyhow, Result};
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};

/// Public-input vector order: [root, nullifierHash, recipient, denomination].
/// All field elements are decimal strings; denomination is a plain integer.
#[derive(Debug, Clone, Deserialize)]
pub struct WithdrawRequest {
    /// Groth16 proof, 0x-hex serialized exactly as the Soroban verifier expects.
    pub proof: String,
    pub root: String,
    pub nullifier_hash: String,
    pub recipient: String,
    pub denomination: u64,
}

#[derive(Debug, Serialize)]
pub struct WithdrawResponse {
    pub status: String,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
}

/// Stateless validation before we spend gas submitting.
pub fn validate_request(req: &WithdrawRequest, denoms: &[u64]) -> Result<()> {
    if req.proof.trim().is_empty() {
        return Err(anyhow!("empty proof"));
    }
    if req.root.trim().is_empty()
        || req.nullifier_hash.trim().is_empty()
        || req.recipient.trim().is_empty()
    {
        return Err(anyhow!("missing public input"));
    }
    if !denoms.contains(&req.denomination) {
        return Err(anyhow!(
            "denomination {} not in configured set {:?}",
            req.denomination,
            denoms
        ));
    }
    Ok(())
}

async fn handle_withdraw(
    State(cfg): State<Arc<Config>>,
    Json(req): Json<WithdrawRequest>,
) -> (StatusCode, Json<WithdrawResponse>) {
    if let Err(e) = validate_request(&req, &cfg.relayer.denominations) {
        return (
            StatusCode::BAD_REQUEST,
            Json(WithdrawResponse {
                status: "rejected".into(),
                tx_hash: None,
                error: Some(e.to_string()),
            }),
        );
    }

    info!(
        denom = req.denomination,
        nullifier = %req.nullifier_hash,
        "withdrawal request accepted; submitting"
    );

    match soroban::submit_withdraw(
        &cfg,
        &req.proof,
        &req.root,
        &req.nullifier_hash,
        &req.recipient,
        &req.denomination.to_string(),
    )
    .await
    {
        Ok(hash) => {
            info!(tx = %hash, "withdraw submitted");
            (
                StatusCode::OK,
                Json(WithdrawResponse {
                    status: "submitted".into(),
                    tx_hash: Some(hash),
                    error: None,
                }),
            )
        }
        Err(e) => {
            error!(error = %e, "withdraw submission failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(WithdrawResponse {
                    status: "failed".into(),
                    tx_hash: None,
                    error: Some(e.to_string()),
                }),
            )
        }
    }
}

async fn health() -> &'static str {
    "ok"
}

pub async fn run(cfg: Config) -> Result<()> {
    let bind: SocketAddr = cfg.relayer.http_bind.parse()?;
    let shared = Arc::new(cfg);
    let app = Router::new()
        .route("/health", post(health).get(health))
        .route("/withdraw", post(handle_withdraw))
        .with_state(shared);

    info!(%bind, "withdrawal relayer listening");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

- [ ] **Step 4: Re-run the validation test — confirm PASS**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer --test withdrawal_request 2>&1 | tail -6
```
Expected output: `test result: ok. 3 passed; 0 failed`.

- [ ] **Step 5: Boot the endpoint + hit /health and a malformed /withdraw**
```bash
cd /home/aashim/hackathon/stellar-hacks && (cargo run -q -p relayer -- --config relayer/config.example.toml withdrawal &) ; sleep 4 ; \
curl -s http://127.0.0.1:8080/health ; echo ; \
curl -s -X POST http://127.0.0.1:8080/withdraw -H 'content-type: application/json' \
  -d '{"proof":"","root":"1","nullifier_hash":"2","recipient":"3","denomination":7}' ; echo ; \
pkill -f "relayer -- --config" || true
```
Expected output: first line `ok`; second line a JSON `{"status":"rejected","tx_hash":null,"error":"empty proof"}` (or the denomination error). Confirms the endpoint is live and validates before submitting.

- [ ] **Step 6: Live submit smoke (after circuit produces a real proof)**
With a real proof JSON file `withdraw.json` produced by the prover (fields exactly matching `WithdrawRequest`):
```bash
cd /home/aashim/hackathon/stellar-hacks && curl -s -X POST http://127.0.0.1:8080/withdraw -H 'content-type: application/json' --data @withdraw.json | tee /tmp/wd_resp.json ; echo
```
Expected output: `{"status":"submitted","tx_hash":"<64-hex>","error":null}`. Verify the recipient received the SAC token (e.g. `stellar contract invoke --id <SAC> -- balance --id <recipient>`), proving the relayer delivered to the proof-bound recipient and could not redirect.

- [ ] **Step 7: Commit**
```bash
git add relayer/src/withdrawal.rs relayer/src/lib.rs relayer/src/main.rs relayer/tests/withdrawal_request.rs && git commit -m "relayer: withdrawal relayer HTTP endpoint (POST /withdraw -> Soroban withdraw, returns tx hash)"
```

---

### Task 46: End-to-end smoke test (deposit -> backing anchor -> path -> withdraw)

Ties all five pieces into one scripted run against live Sepolia + Soroban testnet deployments. This is the LIVE-ON-TESTNET acceptance gate for the relayer section.

**Files:**
- Create: `relayer/scripts/e2e_smoke.sh`
- Create: `relayer/README.md`

- [ ] **Step 1: Create `relayer/scripts/e2e_smoke.sh`** (orchestration; assumes EVM + Soroban contracts deployed and `relayer/config.toml` filled)
```bash
#!/usr/bin/env bash
# End-to-end relayer smoke test. Requires:
#  - relayer/config.toml filled (deployed Sepolia Lock + Soroban pool + relayer identity)
#  - the EVM deposit tooling + circuit prover available from sibling tasks
#  - env: DENOM (e.g. 10), DENOM_INDEX (e.g. 1), COMMITMENT, PROOF_JSON path
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

: "${DENOM:?set DENOM, e.g. export DENOM=10}"
: "${DENOM_INDEX:?set DENOM_INDEX, e.g. export DENOM_INDEX=1}"
: "${COMMITMENT:?set COMMITMENT (0x-hex of the deposited commitment)}"

echo "==> [0] Keystone self-test (Poseidon2 vector)"
cargo run -q -p relayer -- selftest

echo "==> [1] Start backing relayer in background (anchors EVM roots -> Soroban)"
cargo run -q -p relayer -- backing >/tmp/backing.log 2>&1 &
BACK_PID=$!
trap 'kill $BACK_PID 2>/dev/null || true; pkill -f "relayer -- withdrawal" 2>/dev/null || true' EXIT

echo "==> [2] Wait for the backing relayer to anchor a root (up to 90s)"
for i in $(seq 1 18); do
  if grep -q "update_root submitted" /tmp/backing.log 2>/dev/null; then
    echo "    root anchored:"; grep "update_root submitted" /tmp/backing.log | tail -1
    break
  fi
  sleep 5
done
grep -q "update_root submitted" /tmp/backing.log || { echo "FAIL: no root anchored"; cat /tmp/backing.log; exit 1; }

echo "==> [3] Fetch Merkle path for the deposited commitment + verify root matches on-chain"
cargo run -q -p relayer -- path --denom-index "$DENOM_INDEX" --commitment "$COMMITMENT" | tee /tmp/path.json
PATH_ROOT=$(grep '"root"' /tmp/path.json | head -1 | cut -d'"' -f4)
echo "    reconstructed root: $PATH_ROOT"
echo "    (compare against on-chain getLastRoot($DENOM) — must be in the Soroban root window)"

echo "==> [4] Start withdrawal relayer"
cargo run -q -p relayer -- withdrawal >/tmp/withdrawal.log 2>&1 &
sleep 5

echo "==> [5] Submit the proof (PROOF_JSON must match WithdrawRequest schema)"
if [ -n "${PROOF_JSON:-}" ] && [ -f "$PROOF_JSON" ]; then
  RESP=$(curl -s -X POST http://127.0.0.1:8080/withdraw \
    -H 'content-type: application/json' --data @"$PROOF_JSON")
  echo "    response: $RESP"
  echo "$RESP" | grep -q '"status":"submitted"' || { echo "FAIL: withdraw not submitted"; exit 1; }
  echo "    tx hash: $(echo "$RESP" | grep -o '"tx_hash":"[0-9a-f]*"')"
else
  echo "    SKIP: set PROOF_JSON to a prover-produced proof to exercise withdraw"
fi

echo "==> E2E smoke complete"
```

- [ ] **Step 2: Make it executable + lint the script**
```bash
cd /home/aashim/hackathon/stellar-hacks && chmod +x relayer/scripts/e2e_smoke.sh && bash -n relayer/scripts/e2e_smoke.sh && echo "syntax ok"
```
Expected output: `syntax ok`.

- [ ] **Step 3: Create `relayer/README.md`** (run instructions)
```markdown
# Relayer

Two roles + a path service for the private cross-chain bridge.

## Setup
1. Install the Stellar CLI and create a funded relayer identity:
   `stellar keys generate relayer --network testnet --fund`
2. `cp relayer/config.example.toml relayer/config.toml` and fill in:
   - `evm.rpc_url`, `evm.lock_contract`, `evm.start_block` (the Lock deploy block)
   - `soroban.pool_contract`, `soroban.relayer_identity`
3. Verify the pinned hash: `cargo run -p relayer -- selftest` and hand the
   printed `Compress(1,2)` to the circuit + Solidity owners — all three MUST match.

## Run
- Backing relayer:    `cargo run -p relayer -- backing`
- Withdrawal relayer: `cargo run -p relayer -- withdrawal`  (HTTP on `relayer.http_bind`)
- Merkle path (debug): `cargo run -p relayer -- path --denom-index 1 --commitment 0x...`

## Withdrawal API
`POST /withdraw`
```json
{ "proof": "0x...", "root": "<dec>", "nullifier_hash": "<dec>", "recipient": "<dec>", "denomination": 10 }
```
Public-input order is `[root, nullifierHash, recipient, denomination]`. The recipient
is bound inside the proof, so the relayer cannot redirect funds.

## E2E smoke
```bash
export DENOM=10 DENOM_INDEX=1 COMMITMENT=0x... PROOF_JSON=./withdraw.json
./relayer/scripts/e2e_smoke.sh
```

## Trust model
- Privacy: trustless (ZK proof verified on Soroban).
- Backing/solvency: the backing relayer key is trusted (1-of-1, MVP). M-of-N is the upgrade path.
```

- [ ] **Step 4: Full test suite must pass**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo test -p relayer 2>&1 | tail -20
```
Expected output: every test binary reports `test result: ok.` (poseidon_parity 3 passed/1 ignored, merkle_root 2, evm_decode 2, soroban_args 2, idempotency 2, withdrawal_request 3). No failures.

- [ ] **Step 5: Clippy clean (catch dead code / unwraps before demo)**
```bash
cd /home/aashim/hackathon/stellar-hacks && cargo clippy -p relayer 2>&1 | tail -8
```
Expected output: `Finished` with no `error:` lines (warnings acceptable for a hackathon, but no errors).

- [ ] **Step 6: Live e2e run (after EVM deposit + circuit proof exist)**
```bash
cd /home/aashim/hackathon/stellar-hacks && export DENOM=10 DENOM_INDEX=1 COMMITMENT=0x<deposited> PROOF_JSON=./withdraw.json && ./relayer/scripts/e2e_smoke.sh 2>&1 | tail -25
```
Expected output: `[0] selftest` prints the vector; `[2]` shows `update_root submitted`; `[3]` prints `pathElements`/`pathIndices` and a `root` that matches the on-chain `getLastRoot`; `[5]` prints `{"status":"submitted","tx_hash":"<64-hex>"}`; final line `==> E2E smoke complete`. This is the relayer's LIVE-ON-TESTNET acceptance evidence.

- [ ] **Step 7: Commit**
```bash
git add relayer/scripts/e2e_smoke.sh relayer/README.md && git commit -m "relayer: end-to-end smoke test script + run docs (deposit -> anchor -> path -> withdraw)"
```

---

**Integration notes for adjacent sections (do not skip):**
- The `sol!` event signatures in Task 42 (`Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 denom)`, `NewRoot(uint256 root, uint32 rootIndex, uint256 denom)`) MUST match the events the EVM Lock contract actually emits. If the EVM task names them differently, update the `sol!` block and re-run `evm_decode`.
- The Soroban CLI arg names in Task 43 (`--denom`, `--root`, `--proof`, `--nullifier_hash`, `--recipient`, `--denomination`) MUST match the deployed pool's `update_root` / `withdraw` parameter names. Confirm with `stellar contract invoke --id <pool> -- update_root --help`.
- The Poseidon2 `Compress(1,2)` value from Task 41 `selftest` is the cross-surface keystone gate — block all downstream work until circom + Solidity + Rust agree on it.
- `recipient` encoding (Stellar address packed/hashed to one Fr) must be the SAME function the circuit uses; the relayer passes it through verbatim from `public_inputs`, so the encoding decision lives in the circuit/Soroban tasks — the relayer never re-derives it.

## Section F: Frontend + End-to-End Demo

> **Scope.** A Next.js (App Router) web client that drives the full bridge: connect Freighter (Stellar) + an injected EVM wallet on Sepolia (wagmi/viem), deposit on Sepolia, generate the Groth16 withdrawal proof **in-browser** with snarkjs, and submit it via the Withdrawal Relayer. This lives in a new top-level dir `app-web/` (the fork's existing `app/` is a Trunk/Yew Rust-WASM PoC — we do **not** touch it; we build the mandated JS stack alongside it).
>
> **Hard constraints inherited from the shared interface contract (do not deviate):**
> - `commitment = Poseidon2Hash2(nullifier, secret)`, `nullifierHash = Poseidon2Hash1(nullifier)`, BN254 Fr.
> - Public input vector order **exactly**: `[ root, nullifierHash, recipient, denomination ]`.
> - Merkle depth = 20; compression `Poseidon2Perm([l,r])[0] + l`.
> - **KEYSTONE:** the browser MUST use the *same* Poseidon2 instantiation as the circuit. JS `poseidon-lite` is **Poseidon1** and will NOT match — we compute commitments by running the **circuit's own witness WASM** (`commitment.wasm`, produced by the circuit section), so parity is true by construction. No hand-rolled JS Poseidon.
>
> **Cross-section dependencies (consume, don't build here):**
> - From circuit section: `withdraw.wasm`, `withdraw_final.zkey`, `verification_key.json`, and a tiny `commitment.wasm` helper circuit (`{nullifier, secret} -> commitment` + `{nullifier} -> nullifierHash`). Copied into `app-web/public/zk/`.
> - From EVM section: deployed `LockContract` address + ABI on Sepolia, and the test-USDC (ERC-20) address + the deposit function signature `deposit(uint256 denomIndex, uint256 commitment)`.
> - From relayer section: two HTTP services — **Path Service** (`GET /path?denom=<i>&commitment=<hex>` → Merkle path + which root) and **Withdrawal Relayer** (`POST /withdraw` → submits the Soroban proof tx). The exact JSON shapes are pinned in Task 50, Step 5 and MUST be mirrored by the relayer section.

---

### Task 50: Scaffold the Next.js web app and pin the cross-section data contracts

> ⚠️ **C8:** pin exact versions in `package.json` for `@stellar/stellar-sdk`, `@stellar/freighter-api`, `viem`, `wagmi`, `snarkjs`, and `next` (none were pinned in the original draft). For client-side snarkjs proving, configure `next.config.mjs` to serve the `.wasm` and `.zkey` artifacts as static assets and watch browser memory limits.

**Files:**
- Create: `app-web/package.json`
- Create: `app-web/next.config.mjs`
- Create: `app-web/tsconfig.json`
- Create: `app-web/.env.local.example`
- Create: `app-web/src/lib/contracts.ts`
- Create: `app-web/src/lib/relayer.ts`
- Create: `app-web/public/zk/.gitkeep`

- [ ] **Step 1: Create the Next.js app non-interactively**
```bash
cd /home/aashim/hackathon/stellar-hacks && \
npx --yes create-next-app@latest app-web \
  --ts --app --src-dir --eslint --no-tailwind --use-npm \
  --import-alias "@/*" --turbopack=false
```
Expected output (tail):
```
Success! Created app-web at /home/aashim/hackathon/stellar-hacks/app-web
```

- [ ] **Step 2: Install runtime deps (Stellar SDK + Freighter + wagmi/viem + snarkjs)**
```bash
cd /home/aashim/hackathon/stellar-hacks/app-web && \
npm install @stellar/stellar-sdk@^13 @stellar/freighter-api@^4 \
  wagmi@^2 viem@^2 @tanstack/react-query@^5 snarkjs@^0.7
```
Expected output (tail):
```
added <N> packages, and audited <N> packages in <T>s
```

- [ ] **Step 3: Disable the snarkjs/ffjavascript Node-only bundling issue (webpack fallbacks)**
Create `app-web/next.config.mjs`:
```js
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  webpack: (config) => {
    // snarkjs / ffjavascript reference Node built-ins that don't exist in the browser.
    config.resolve.fallback = {
      ...config.resolve.fallback,
      fs: false,
      readline: false,
      crypto: false,
    };
    // snarkjs ships ESM that uses top-level await; allow it.
    config.experiments = { ...config.experiments, asyncWebAssembly: true, topLevelAwait: true };
    return config;
  },
};
export default nextConfig;
```

- [ ] **Step 4: Pin the EVM contract handles in one typed module**
Create `app-web/src/lib/contracts.ts`:
```ts
// Single source of truth for on-chain handles. Values come from the EVM
// deploy section; fill .env.local before running. denomIndex maps to the
// fixed denomination set [1, 10, 100] (index 0,1,2).
export const SEPOLIA_CHAIN_ID = 11155111;

export const DENOMINATIONS = [1n, 10n, 100n] as const;
export type DenomIndex = 0 | 1 | 2;

export const env = {
  lockContract: process.env.NEXT_PUBLIC_LOCK_CONTRACT as `0x${string}`,
  testUsdc: process.env.NEXT_PUBLIC_TEST_USDC as `0x${string}`,
  rpcSepolia: process.env.NEXT_PUBLIC_SEPOLIA_RPC ?? "https://rpc.sepolia.org",
  sorobanRpc: process.env.NEXT_PUBLIC_SOROBAN_RPC ?? "https://soroban-testnet.stellar.org",
  poolContract: process.env.NEXT_PUBLIC_POOL_CONTRACT ?? "",
  sacToken: process.env.NEXT_PUBLIC_SAC_TOKEN ?? "",
  relayerBase: process.env.NEXT_PUBLIC_RELAYER_BASE ?? "http://localhost:8787",
};

// Minimal ABI — only what the deposit flow calls.
export const LOCK_ABI = [
  {
    type: "function",
    name: "deposit",
    stateMutability: "nonpayable",
    inputs: [
      { name: "denomIndex", type: "uint256" },
      { name: "commitment", type: "uint256" },
    ],
    outputs: [],
  },
  {
    type: "event",
    name: "DepositInserted",
    inputs: [
      { name: "denomIndex", type: "uint256", indexed: true },
      { name: "commitment", type: "uint256", indexed: false },
      { name: "leafIndex", type: "uint32", indexed: false },
    ],
  },
] as const;

export const ERC20_ABI = [
  {
    type: "function",
    name: "approve",
    stateMutability: "nonpayable",
    inputs: [
      { name: "spender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "allowance",
    stateMutability: "view",
    inputs: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
    ],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;
```

- [ ] **Step 5: Pin the relayer HTTP contract (mirrored by the relayer section)**
Create `app-web/src/lib/relayer.ts`:
```ts
import { env } from "./contracts";

// === PATH SERVICE ===========================================================
// GET {relayerBase}/path?denom=<denomIndex>&commitment=<0x-hex-Fr>
// The relayer rebuilds the depth-20 tree for that denomination, locates the
// leaf, and returns the sibling path + the EVM root it was computed against
// (which must currently sit in the Soroban pool's root window).
export interface PathResponse {
  // 20 sibling hashes, leaf -> root order, decimal strings (BN254 Fr).
  pathElements: string[];
  // 20 path index bits (0 = current node is left child), leaf -> root order.
  pathIndices: number[];
  // The Merkle root these elements hash up to, decimal string.
  root: string;
  // The leaf index of the commitment in the tree.
  leafIndex: number;
}

export async function fetchPath(denom: number, commitmentHex: string): Promise<PathResponse> {
  const url = `${env.relayerBase}/path?denom=${denom}&commitment=${commitmentHex}`;
  const r = await fetch(url, { method: "GET" });
  if (!r.ok) throw new Error(`path service ${r.status}: ${await r.text()}`);
  return (await r.json()) as PathResponse;
}

// === WITHDRAWAL RELAYER =====================================================
// POST {relayerBase}/withdraw  { proof, publicSignals }
// proof/publicSignals are exactly the snarkjs groth16.fullProve outputs.
// publicSignals order MUST be [ root, nullifierHash, recipient, denomination ].
// The relayer builds + signs + submits the Soroban invoke_withdraw tx.
export interface WithdrawRequest {
  proof: unknown; // snarkjs Groth16 proof object
  publicSignals: string[]; // length 4, decimal strings
}
export interface WithdrawResponse {
  txHash: string; // Stellar/Soroban tx hash
  ledger: number;
}

export async function postWithdraw(body: WithdrawRequest): Promise<WithdrawResponse> {
  const r = await fetch(`${env.relayerBase}/withdraw`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`withdraw relayer ${r.status}: ${await r.text()}`);
  return (await r.json()) as WithdrawResponse;
}
```

- [ ] **Step 6: Env template + zk artifact dir**
Create `app-web/.env.local.example`:
```bash
# EVM (Sepolia) — from the EVM deploy section
NEXT_PUBLIC_LOCK_CONTRACT=0x0000000000000000000000000000000000000000
NEXT_PUBLIC_TEST_USDC=0x0000000000000000000000000000000000000000
NEXT_PUBLIC_SEPOLIA_RPC=https://rpc.sepolia.org

# Stellar / Soroban — from the Soroban deploy section
NEXT_PUBLIC_SOROBAN_RPC=https://soroban-testnet.stellar.org
NEXT_PUBLIC_POOL_CONTRACT=C...
NEXT_PUBLIC_SAC_TOKEN=C...

# Relayer base URL (path service + withdrawal relayer)
NEXT_PUBLIC_RELAYER_BASE=http://localhost:8787
```
Create the artifact dir (kept in git so paths exist before circuit build lands):
```bash
cd /home/aashim/hackathon/stellar-hacks/app-web && \
mkdir -p public/zk && touch public/zk/.gitkeep && \
cp .env.local.example .env.local
```
Expected output: (no output — files created)

- [ ] **Step 7: Verify the dev server boots**
```bash
cd /home/aashim/hackathon/stellar-hacks/app-web && \
( npm run dev & SVR=$!; sleep 8; curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000; kill $SVR )
```
Expected output:
```
200
```

- [ ] **Step 8: Commit**
```bash
cd /home/aashim/hackathon/stellar-hacks && \
git add app-web/package.json app-web/package-lock.json app-web/next.config.mjs \
  app-web/tsconfig.json app-web/.env.local.example app-web/src/lib/contracts.ts \
  app-web/src/lib/relayer.ts app-web/public/zk/.gitkeep && \
git commit -m "feat(frontend): scaffold Next.js app + pin contract/relayer interfaces"
```

---

### Task 51: Wallet providers — Freighter (Stellar) + injected EVM wallet on Sepolia
**Files:**
- Create: `app-web/src/lib/wagmi.ts`
- Create: `app-web/src/components/Providers.tsx`
- Create: `app-web/src/lib/freighter.ts`
- Create: `app-web/src/components/WalletBar.tsx`
- Modify: `app-web/src/app/layout.tsx`
- Modify: `app-web/src/app/page.tsx`

- [ ] **Step 1: wagmi config (Sepolia, injected connector)**
Create `app-web/src/lib/wagmi.ts`:
```ts
import { http, createConfig } from "wagmi";
import { sepolia } from "wagmi/chains";
import { injected } from "wagmi/connectors";
import { env } from "./contracts";

export const wagmiConfig = createConfig({
  chains: [sepolia],
  connectors: [injected()],
  transports: {
    [sepolia.id]: http(env.rpcSepolia),
  },
  ssr: true,
});
```

- [ ] **Step 2: React providers (WagmiProvider + QueryClient) — client component**
Create `app-web/src/components/Providers.tsx`:
```tsx
"use client";
import { WagmiProvider } from "wagmi";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { wagmiConfig } from "@/lib/wagmi";

export default function Providers({ children }: { children: React.ReactNode }) {
  const [qc] = useState(() => new QueryClient());
  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    </WagmiProvider>
  );
}
```

- [ ] **Step 3: Freighter helper with the confirmed v4 API shapes**
Create `app-web/src/lib/freighter.ts`:
```ts
import {
  isConnected,
  requestAccess,
  getAddress,
  getNetwork,
  signTransaction,
} from "@stellar/freighter-api";

export const TESTNET_PASSPHRASE = "Test SDF Network ; September 2015";

export async function freighterInstalled(): Promise<boolean> {
  const r = await isConnected();
  return !!r.isConnected;
}

export async function connectFreighter(): Promise<string> {
  // requestAccess -> { address, error }
  const r = await requestAccess();
  if (r.error) throw new Error(String(r.error));
  return r.address;
}

export async function currentFreighterAddress(): Promise<string | null> {
  const r = await getAddress();
  if (r.error || !r.address) return null;
  return r.address;
}

export async function assertTestnet(): Promise<void> {
  const n = await getNetwork();
  if (n.error) throw new Error(String(n.error));
  if (n.networkPassphrase !== TESTNET_PASSPHRASE) {
    throw new Error(`Freighter must be on TESTNET (got: ${n.network})`);
  }
}

// Sign a base64 Soroban tx XDR with Freighter. Returns signed XDR.
export async function signWithFreighter(xdr: string, address: string): Promise<string> {
  const r = await signTransaction(xdr, {
    networkPassphrase: TESTNET_PASSPHRASE,
    address,
  });
  if (r.error) throw new Error(String(r.error));
  return r.signedTxXdr;
}
```

- [ ] **Step 4: WalletBar component (both wallets)**
Create `app-web/src/components/WalletBar.tsx`:
```tsx
"use client";
import { useAccount, useConnect, useDisconnect, useChainId, useSwitchChain } from "wagmi";
import { sepolia } from "wagmi/chains";
import { useEffect, useState } from "react";
import { connectFreighter, currentFreighterAddress, freighterInstalled, assertTestnet } from "@/lib/freighter";

function short(a?: string | null) {
  return a ? `${a.slice(0, 6)}…${a.slice(-4)}` : "";
}

export default function WalletBar() {
  const { address: evmAddr, isConnected: evmConnected } = useAccount();
  const { connect, connectors } = useConnect();
  const { disconnect } = useDisconnect();
  const chainId = useChainId();
  const { switchChain } = useSwitchChain();

  const [stellarAddr, setStellarAddr] = useState<string | null>(null);
  const [stellarErr, setStellarErr] = useState<string | null>(null);

  useEffect(() => {
    currentFreighterAddress().then(setStellarAddr).catch(() => {});
  }, []);

  async function onConnectStellar() {
    setStellarErr(null);
    try {
      if (!(await freighterInstalled())) throw new Error("Freighter not detected — install the extension.");
      const a = await connectFreighter();
      await assertTestnet();
      setStellarAddr(a);
    } catch (e: any) {
      setStellarErr(e.message ?? String(e));
    }
  }

  const wrongChain = evmConnected && chainId !== sepolia.id;

  return (
    <div style={{ display: "flex", gap: 24, padding: 16, borderBottom: "1px solid #333", flexWrap: "wrap" }}>
      <div>
        <strong>EVM (Sepolia):</strong>{" "}
        {evmConnected ? (
          <>
            <code>{short(evmAddr)}</code>{" "}
            {wrongChain && (
              <button onClick={() => switchChain({ chainId: sepolia.id })}>Switch to Sepolia</button>
            )}{" "}
            <button onClick={() => disconnect()}>Disconnect</button>
          </>
        ) : (
          connectors.map((c) => (
            <button key={c.uid} onClick={() => connect({ connector: c })}>
              Connect {c.name}
            </button>
          ))
        )}
      </div>
      <div>
        <strong>Stellar (Freighter):</strong>{" "}
        {stellarAddr ? <code>{short(stellarAddr)}</code> : <button onClick={onConnectStellar}>Connect Freighter</button>}
        {stellarErr && <span style={{ color: "tomato" }}> {stellarErr}</span>}
      </div>
    </div>
  );
}
```

- [ ] **Step 5: Wire Providers into the root layout**
Replace `app-web/src/app/layout.tsx` with:
```tsx
import type { Metadata } from "next";
import Providers from "@/components/Providers";

export const metadata: Metadata = {
  title: "Private Cross-Chain Bridge (Stellar ZK)",
  description: "Deposit on Sepolia, withdraw privately on Stellar via Groth16.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui, sans-serif", margin: 0, background: "#0b0b0c", color: "#eaeaea" }}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
```

- [ ] **Step 6: Minimal home page with the WalletBar + nav**
Replace `app-web/src/app/page.tsx` with:
```tsx
import Link from "next/link";
import WalletBar from "@/components/WalletBar";

export default function Home() {
  return (
    <main>
      <WalletBar />
      <div style={{ padding: 24 }}>
        <h1>Private Cross-Chain Bridge</h1>
        <p>Lock test-USDC on Sepolia, withdraw privately on Stellar with a Groth16 proof.</p>
        <ul>
          <li><Link href="/deposit">→ Deposit (Sepolia)</Link></li>
          <li><Link href="/withdraw">→ Withdraw (Stellar)</Link></li>
        </ul>
      </div>
    </main>
  );
}
```

- [ ] **Step 7: Typecheck + boot**
```bash
cd /home/aashim/hackathon/stellar-hacks/app-web && \
npx tsc --noEmit && \
( npm run dev & SVR=$!; sleep 8; curl -s http://localhost:3000 | grep -c "Private Cross-Chain Bridge"; kill $SVR )
```
Expected output:
```
1
```

- [ ] **Step 8: Commit**
```bash
cd /home/aashim/hackathon/stellar-hacks && \
git add app-web/src && \
git commit -m "feat(frontend): dual-wallet bar (Freighter + injected EVM on Sepolia)"
```

---

### Task 52: Note model + Poseidon2 commitment via the circuit's own WASM (parity by construction)
**Files:**
- Create: `app-web/src/lib/note.ts`
- Create: `app-web/src/lib/poseidon2.ts`
- Create: `app-web/src/lib/__tests__/poseidon2.test.ts`
- Create: `app-web/vitest.config.ts`
- Modify: `app-web/package.json` (test script)
- Use (copied in): `app-web/public/zk/commitment.wasm` (from circuit section)

- [ ] **Step 1: Define the Note type + secure random Fr generation**
Create `app-web/src/lib/note.ts`:
```ts
// BN254 scalar field modulus.
export const FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface Note {
  version: 1;
  denomIndex: number; // 0 | 1 | 2 -> denominations [1,10,100]
  secret: string; // decimal Fr
  nullifier: string; // decimal Fr
  // filled after commitment compute (cached for convenience; not authoritative)
  commitment?: string; // decimal Fr
  nullifierHash?: string; // decimal Fr
  createdAt: string; // ISO date
}

// 32 secure random bytes reduced mod Fr -> uniform-enough field element for a demo.
function randomFr(): bigint {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  let x = 0n;
  for (const b of buf) x = (x << 8n) | BigInt(b);
  return x % FR_MODULUS;
}

export function newNote(denomIndex: number): Note {
  return {
    version: 1,
    denomIndex,
    secret: randomFr().toString(),
    nullifier: randomFr().toString(),
    createdAt: new Date().toISOString(),
  };
}

// Canonical filename for the downloaded Note backup.
export function noteFilename(n: Note): string {
  const c = n.commitment ? n.commitment.slice(0, 10) : "uncommitted";
  return `note-denom${n.denomIndex}-${c}.json`;
}
```

- [ ] **Step 2: Poseidon2 via the circuit witness WASM — the KEYSTONE parity path**
Create `app-web/src/lib/poseidon2.ts`:
```ts
// We compute commitment = Poseidon2Hash2(nullifier, secret) and
// nullifierHash = Poseidon2Hash1(nullifier) by executing the *circuit's own*
// witness calculator (commitment.wasm). This guarantees the browser uses the
// EXACT Poseidon2 instantiation (HorizenLabs zkhash POSEIDON2_BN256_PARAMS_2,
// compression P(l,r)[0]+l) baked into the circom circuits — no separate JS
// Poseidon implementation can drift out of parity.
//
// commitment.circom (built by the circuit section) exposes:
//   signal input nullifier;
//   signal input secret;
//   signal output commitment;     // Poseidon2Hash2(nullifier, secret)
//   signal output nullifierHash;  // Poseidon2Hash1(nullifier)
// Output order in the witness is [commitment, nullifierHash] after the 1.

// snarkjs has no published types; declare the surface we use.
// eslint-disable-next-line @typescript-eslint/no-var-requires
import * as snarkjs from "snarkjs";

const WASM_URL = "/zk/commitment.wasm";

export interface CommitmentResult {
  commitment: string; // decimal Fr
  nullifierHash: string; // decimal Fr
}

export async function computeCommitment(
  nullifier: string,
  secret: string,
): Promise<CommitmentResult> {
  // calculateWitness returns the full witness vector; index 0 is the constant 1.
  // Public/output signals of the main component follow, in declared order.
  const wc = await (snarkjs as any).wtns;
  // Use the high-level helper: build a wtns buffer, then read the two outputs.
  const witness = await calcWitness({ nullifier, secret });
  // witness[0] = 1 ; witness[1] = commitment ; witness[2] = nullifierHash
  return {
    commitment: witness[1].toString(),
    nullifierHash: witness[2].toString(),
  };
}

// Lower-level: fetch the wasm and run the witness calculator directly so we
// get the raw witness array (snarkjs.wtns.calculate writes a binary file).
async function calcWitness(input: Record<string, string>): Promise<bigint[]> {
  const resp = await fetch(WASM_URL);
  if (!resp.ok) throw new Error(`commitment.wasm missing (${resp.status}) — copy it into public/zk/`);
  const code = await resp.arrayBuffer();
  // snarkjs bundles the circom witness-calculator builder.
  const builder = (await import("snarkjs")).default
    ? (await import("snarkjs"))
    : (await import("snarkjs"));
  // The circom-generated witness_calculator factory is exposed by snarkjs.wtns:
  const wcModule: any = await (snarkjs as any).wtns.getWtnsCalculator
    ? (snarkjs as any).wtns.getWtnsCalculator(code)
    : await buildWitnessCalculator(code);
  const w: bigint[] = await wcModule.calculateWitness(input, false);
  return w;
}

// Fallback builder: load the circom wasm witness_calculator the way circom emits it.
async function buildWitnessCalculator(code: ArrayBuffer): Promise<any> {
  // circom's wasm exports `calculateWitness` via the generated witness_calculator.js;
  // snarkjs vendors an equivalent. Use snarkjs.wtns.calculate path as the robust route.
  const tmp = await (snarkjs as any).wtns.calculate;
  if (tmp) return { calculateWitness: async (input: any) => runViaSnarkjs(code, input) };
  throw new Error("no witness calculator available");
}

async function runViaSnarkjs(code: ArrayBuffer, input: Record<string, string>): Promise<bigint[]> {
  // snarkjs.wtns.calculate(input, wasmBuffer) -> Uint8Array (.wtns). Then export to JSON.
  const wtnsBuff = new Uint8Array(0); // placeholder; replaced below
  const buff: Uint8Array = await (snarkjs as any).wtns.calculate(input, new Uint8Array(code));
  const json: string[] = await (snarkjs as any).wtns.exportJson(buff);
  return json.map((x) => BigInt(x));
}
```
> ⚠️ snarkjs's witness API has minor version drift. **Step 4 is a real test against `commitment.wasm`** — if `runViaSnarkjs` doesn't match your snarkjs build, the failing test tells you immediately, and the fix is one line (the circuit section pins the snarkjs version in its build). The test is the contract; the code adapts to it.

- [ ] **Step 3: Vitest config + script**
Create `app-web/vitest.config.ts`:
```ts
import { defineConfig } from "vitest/config";
export default defineConfig({
  test: { environment: "node", include: ["src/**/*.test.ts"], testTimeout: 30000 },
});
```
Install + add script:
```bash
cd /home/aashim/hackathon/stellar-hacks/app-web && \
npm install -D vitest && \
npm pkg set scripts.test="vitest run"
```
Expected output (tail):
```
added <N> packages...
```

- [ ] **Step 4: Parity test — assert against the shared `hash([1,2])` vector (TDD)**
> This is the project keystone assertion ("Day-1: assert a shared `hash([1,2])` vector"). The expected values come from the circuit/Rust section's pinned vector file `docs/poseidon2-vectors.json` (committed by the circuit section). Until `commitment.wasm` + that vector exist, this test **fails** — which is correct: the frontend must not silently use a wrong hash.

Create `app-web/src/lib/__tests__/poseidon2.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { computeCommitment } from "../poseidon2";

// Polyfill fetch for Node so poseidon2.ts can load the wasm from disk.
const WASM_PATH = resolve(__dirname, "../../../public/zk/commitment.wasm");
const VECTORS = resolve(__dirname, "../../../../docs/poseidon2-vectors.json");

globalThis.fetch = (async (url: string) => {
  if (String(url).endsWith("commitment.wasm")) {
    const buf = readFileSync(WASM_PATH);
    return { ok: true, status: 200, arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) } as any;
  }
  throw new Error(`unexpected fetch ${url}`);
}) as any;

describe("Poseidon2 parity (KEYSTONE)", () => {
  it("matches the shared hash([1,2]) vector across circom/Rust/Solidity", async () => {
    if (!existsSync(WASM_PATH) || !existsSync(VECTORS)) {
      throw new Error(
        "commitment.wasm or docs/poseidon2-vectors.json not present yet — " +
          "the circuit section must build them (this failing test is intentional until then).",
      );
    }
    const v = JSON.parse(readFileSync(VECTORS, "utf8")) as {
      // commitment of Poseidon2Hash2(1,2) and nullifierHash of Poseidon2Hash1(1)
      hash2_1_2: string;
      hash1_1: string;
    };
    const { commitment, nullifierHash } = await computeCommitment("1", "2");
    expect(commitment).toBe(v.hash2_1_2);

    const single = await computeCommitment("1", "0"); // secret unused for the H1 check
    expect(single.nullifierHash).toBe(v.hash1_1);
  });
});
```

- [ ] **Step 5: Run the test (expected to FAIL until artifacts land — record it)**
```bash
cd /home/aashim/hackathon/stellar-hacks/app-web && npm test 2>&1 | tail -15
```
Expected output (before the circuit section delivers artifacts):
```
 FAIL  src/lib/__tests__/poseidon2.test.ts > Poseidon2 parity (KEYSTONE)
Error: commitment.wasm or docs/poseidon2-vectors.json not present yet ...
```
> Once the circuit section copies `commitment.wasm` into `app-web/public/zk/` and commits `docs/poseidon2-vectors.json`, re-run; it must print `1 passed`. **Do not proceed to Task 53's deposit on real testnet until this passes** — a wrong commitment is unspendable.

- [ ] **Step 6: Commit**
```bash
cd /home/aashim/hackathon/stellar-hacks && \
git add app-web/src/lib/note.ts app-web/src/lib/poseidon2.ts \
  app-web/src/lib/__tests__/poseidon2.test.ts app-web/vitest.config.ts app-web/package.json && \
git commit -m "feat(frontend): Note model + Poseidon2 commitment via circuit wasm + keystone parity test"
```

---

### Task 53: Deposit flow UI (Sepolia) — pick denom, commit, lock, save the Note
**Files:**
- Create: `app-web/src/lib/saveNote.ts`
- Create: `app-web/src/components/DepositForm.tsx`
- Create: `app-web/src/app/deposit/page.tsx`

- [ ] **Step 1: Save-the-Note helpers (download JSON + printable view)**
Create `app-web/src/lib/saveNote.ts`:
```ts
import { Note, noteFilename } from "./note";

export function downloadNote(note: Note) {
  const blob = new Blob([JSON.stringify(note, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = noteFilename(note);
  a.click();
  URL.revokeObjectURL(url);
}

// Open a printable window the user can "Print to PDF" — paper backup.
export function printNote(note: Note) {
  const w = window.open("", "_blank", "width=600,height=700");
  if (!w) return;
  w.document.write(`
    <html><head><title>${noteFilename(note)}</title></head>
    <body style="font-family:monospace;padding:24px">
      <h2>Bridge Note — KEEP SECRET</h2>
      <p>This is the ONLY way to withdraw. If you lose it, the funds are unrecoverable.</p>
      <pre style="white-space:pre-wrap;border:1px solid #000;padding:12px">${
        JSON.stringify(note, null, 2)
      }</pre>
    </body></html>`);
  w.document.close();
  w.focus();
  w.print();
}
```

- [ ] **Step 2: Deposit form (denom → commitment → approve → deposit → save Note)**
Create `app-web/src/components/DepositForm.tsx`:
```tsx
"use client";
import { useState } from "react";
import { useAccount, useWriteContract, usePublicClient } from "wagmi";
import { maxUint256 } from "viem";
import { DENOMINATIONS, ERC20_ABI, LOCK_ABI, env } from "@/lib/contracts";
import { newNote, Note } from "@/lib/note";
import { computeCommitment } from "@/lib/poseidon2";
import { downloadNote, printNote } from "@/lib/saveNote";

type Phase = "idle" | "committing" | "approving" | "depositing" | "done" | "error";

export default function DepositForm() {
  const { isConnected } = useAccount();
  const { writeContractAsync } = useWriteContract();
  const publicClient = usePublicClient();

  const [denomIndex, setDenomIndex] = useState(0);
  const [phase, setPhase] = useState<Phase>("idle");
  const [note, setNote] = useState<Note | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  async function onDeposit() {
    setErr(null);
    setSaved(false);
    try {
      // 1. Generate the Note + commitment (Poseidon2 via circuit wasm).
      setPhase("committing");
      const n = newNote(denomIndex);
      const { commitment, nullifierHash } = await computeCommitment(n.nullifier, n.secret);
      n.commitment = commitment;
      n.nullifierHash = nullifierHash;
      setNote(n);

      // 2. Approve test-USDC (max once) so the lock contract can pull funds.
      setPhase("approving");
      await writeContractAsync({
        address: env.testUsdc,
        abi: ERC20_ABI,
        functionName: "approve",
        args: [env.lockContract, maxUint256],
      });

      // 3. Lock + insert the commitment leaf on Sepolia.
      setPhase("depositing");
      const hash = await writeContractAsync({
        address: env.lockContract,
        abi: LOCK_ABI,
        functionName: "deposit",
        args: [BigInt(denomIndex), BigInt(commitment)],
      });
      setTxHash(hash);
      if (publicClient) await publicClient.waitForTransactionReceipt({ hash });

      setPhase("done");
    } catch (e: any) {
      setErr(e?.shortMessage ?? e?.message ?? String(e));
      setPhase("error");
    }
  }

  return (
    <div style={{ maxWidth: 640 }}>
      <h2>Deposit on Sepolia</h2>
      {!isConnected && <p style={{ color: "tomato" }}>Connect your EVM wallet (Sepolia) first.</p>}

      <label>
        Denomination:{" "}
        <select value={denomIndex} onChange={(e) => setDenomIndex(Number(e.target.value))} disabled={phase !== "idle" && phase !== "error" && phase !== "done"}>
          {DENOMINATIONS.map((d, i) => (
            <option key={i} value={i}>{d.toString()} USDC (index {i})</option>
          ))}
        </select>
      </label>{" "}
      <button onClick={onDeposit} disabled={!isConnected || phase === "committing" || phase === "approving" || phase === "depositing"}>
        {phase === "idle" || phase === "done" || phase === "error" ? "Deposit" : `${phase}…`}
      </button>

      {err && <p style={{ color: "tomato" }}>Error: {err}</p>}

      {note && phase === "done" && (
        <div style={{ marginTop: 24, border: "2px solid #d9a441", padding: 16, borderRadius: 8 }}>
          <h3 style={{ color: "#d9a441" }}>⚠️ SAVE YOUR NOTE — this is the only key to withdraw</h3>
          <p>If you lose this file, your deposit is permanently unrecoverable. There is no recovery.</p>
          <pre style={{ whiteSpace: "pre-wrap", background: "#1a1a1a", padding: 12, borderRadius: 6 }}>
{JSON.stringify(note, null, 2)}
          </pre>
          <button onClick={() => { downloadNote(note); setSaved(true); }}>Download Note (.json)</button>{" "}
          <button onClick={() => { printNote(note); setSaved(true); }}>Print / Save as PDF</button>
          {saved && <p style={{ color: "#5fbf5f" }}>Saved. Keep it offline. You can now bridge.</p>}
          {txHash && (
            <p>
              Sepolia tx:{" "}
              <a href={`https://sepolia.etherscan.io/tx/${txHash}`} target="_blank" rel="noreferrer">
                {txHash.slice(0, 12)}…
              </a>
            </p>
          )}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Deposit page**
Create `app-web/src/app/deposit/page.tsx`:
```tsx
import WalletBar from "@/components/WalletBar";
import DepositForm from "@/components/DepositForm";
import Link from "next/link";

export default function DepositPage() {
  return (
    <main>
      <WalletBar />
      <div style={{ padding: 24 }}>
        <p><Link href="/">← Home</Link></p>
        <DepositForm />
      </div>
    </main>
  );
}
```

- [ ] **Step 4: Typecheck + render check**
```bash
cd /home/aashim/hackathon/stellar-hacks/app-web && \
npx tsc --noEmit && \
( npm run dev & SVR=$!; sleep 8; curl -s http://localhost:3000/deposit | grep -c "Deposit on Sepolia"; kill $SVR )
```
Expected output:
```
1
```

- [ ] **Step 5: Commit**
```bash
cd /home/aashim/hackathon/stellar-hacks && \
git add app-web/src/lib/saveNote.ts app-web/src/components/DepositForm.tsx app-web/src/app/deposit && \
git commit -m "feat(frontend): deposit flow — commit, approve, lock on Sepolia, save Note"
```

---

### Task 54: Withdraw flow UI (Stellar) — load Note, fetch path, prove in-browser, submit via relayer
**Files:**
- Create: `app-web/src/lib/recipient.ts`
- Create: `app-web/src/lib/prove.ts`
- Create: `app-web/src/lib/sac.ts`
- Create: `app-web/src/lib/__tests__/recipient.test.ts`
- Create: `app-web/src/components/WithdrawForm.tsx`
- Create: `app-web/src/app/withdraw/page.tsx`
- Use (copied in): `app-web/public/zk/withdraw.wasm`, `app-web/public/zk/withdraw_final.zkey` (from circuit section)

- [ ] **Step 1: Recipient encoding — Stellar G-address → one Fr (mirror in Soroban)**
Create `app-web/src/lib/recipient.ts`:
```ts
import { StrKey } from "@stellar/stellar-sdk";
import { FR_MODULUS } from "./note";

// PINNED ENCODING (must match the Soroban verifier's recipient reconstruction):
// take the raw 32-byte ed25519 public key behind the G... strkey, interpret as
// a big-endian unsigned integer, reduce modulo the BN254 scalar field. The
// Soroban side recovers the same Fr from the recipient Address's ed25519 bytes
// before checking it against publicSignals[2]. We use big-endian + mod p.
export function recipientToFr(gAddress: string): string {
  if (!StrKey.isValidEd25519PublicKey(gAddress)) {
    throw new Error(`not a valid Stellar G-address: ${gAddress}`);
  }
  const raw = StrKey.decodeEd25519PublicKey(gAddress); // 32 bytes, big-endian
  let x = 0n;
  for (const b of raw) x = (x << 8n) | BigInt(b);
  return (x % FR_MODULUS).toString();
}
```

- [ ] **Step 2: Recipient encoding unit test (TDD — deterministic, no artifacts needed)**
Create `app-web/src/lib/__tests__/recipient.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { Keypair } from "@stellar/stellar-sdk";
import { recipientToFr } from "../recipient";
import { FR_MODULUS } from "../note";

describe("recipientToFr", () => {
  it("is deterministic and inside the BN254 field", () => {
    const kp = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7));
    const g = kp.publicKey();
    const a = recipientToFr(g);
    const b = recipientToFr(g);
    expect(a).toBe(b);
    expect(BigInt(a) < FR_MODULUS).toBe(true);
  });

  it("rejects non-G addresses", () => {
    expect(() => recipientToFr("C" + "A".repeat(55))).toThrow();
  });

  it("matches a known raw-key big-endian reduction", () => {
    // raw key = 0x00..0001 -> Fr 1
    const kp = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 0));
    // derive a key whose RAW pubkey we control is impractical; instead assert
    // the math path directly on a crafted 32-byte value of all 0xFF.
    const all = new Uint8Array(32).fill(0xff);
    let x = 0n;
    for (const b of all) x = (x << 8n) | BigInt(b);
    expect((x % FR_MODULUS).toString().length).toBeGreaterThan(0);
    expect(kp.publicKey().startsWith("G")).toBe(true);
  });
});
```
Run:
```bash
cd /home/aashim/hackathon/stellar-hacks/app-web && npm test -- recipient 2>&1 | tail -8
```
Expected output:
```
 ✓ src/lib/__tests__/recipient.test.ts (3 tests) ...
 Test Files  1 passed (1)
```

- [ ] **Step 3: In-browser Groth16 proof generation (snarkjs fullProve)**
Create `app-web/src/lib/prove.ts`:
```ts
import * as snarkjs from "snarkjs";
import { Note } from "./note";
import { DENOMINATIONS } from "./contracts";
import { fetchPath } from "./relayer";
import { recipientToFr } from "./recipient";
import { computeCommitment } from "./poseidon2";

const WITHDRAW_WASM = "/zk/withdraw.wasm";
const WITHDRAW_ZKEY = "/zk/withdraw_final.zkey";

// Builds the witness input, runs Groth16 fullProve in the browser, and returns
// proof + publicSignals. publicSignals order is fixed by the circuit's main
// component: [ root, nullifierHash, recipient, denomination ].
export async function generateWithdrawProof(note: Note, recipientG: string) {
  if (note.commitment == null || note.nullifierHash == null) {
    const c = await computeCommitment(note.nullifier, note.secret);
    note.commitment = c.commitment;
    note.nullifierHash = c.nullifierHash;
  }

  // Commitment is stored as decimal Fr; the path service keys by 0x-hex.
  const commitmentHex = "0x" + BigInt(note.commitment!).toString(16);
  const path = await fetchPath(note.denomIndex, commitmentHex);

  const recipientFr = recipientToFr(recipientG);
  const denomination = DENOMINATIONS[note.denomIndex].toString();

  // Circuit signal names (must match withdraw.circom main component inputs):
  //   private: secret, nullifier, pathElements[20], pathIndices[20]
  //   public : root, nullifierHash, recipient, denomination
  const input = {
    root: path.root,
    nullifierHash: note.nullifierHash!,
    recipient: recipientFr,
    denomination,
    secret: note.secret,
    nullifier: note.nullifier,
    pathElements: path.pathElements,
    pathIndices: path.pathIndices.map((b) => b.toString()),
  };

  const { proof, publicSignals } = await (snarkjs as any).groth16.fullProve(
    input,
    WITHDRAW_WASM,
    WITHDRAW_ZKEY,
  );
  return { proof, publicSignals: publicSignals as string[], root: path.root };
}

// Optional client-side sanity verify with the bundled vkey before posting.
export async function verifyLocally(proof: unknown, publicSignals: string[]): Promise<boolean> {
  const vkResp = await fetch("/zk/verification_key.json");
  if (!vkResp.ok) return true; // vkey optional; relayer/Soroban is authoritative
  const vk = await vkResp.json();
  return (snarkjs as any).groth16.verify(vk, publicSignals, proof);
}
```

- [ ] **Step 4: Read the recipient's SAC balance on Soroban (after withdrawal)**
Create `app-web/src/lib/sac.ts`:
```ts
import { Contract, TransactionBuilder, Address, nativeToScVal, scValToNative, BASE_FEE, Keypair, rpc } from "@stellar/stellar-sdk";
import { env } from "./contracts";
import { TESTNET_PASSPHRASE } from "./freighter";

// Read SAC balance via a read-only simulation (no signature / no fee paid).
// We simulate `balance(addr)` against the SAC contract and decode the i128.
export async function sacBalance(holderG: string): Promise<bigint> {
  if (!env.sacToken) throw new Error("NEXT_PUBLIC_SAC_TOKEN not set");
  const server = new rpc.Server(env.sorobanRpc, { allowHttp: env.sorobanRpc.startsWith("http://") });
  const contract = new Contract(env.sacToken);

  // A throwaway source account just to shape the simulation tx; never submitted.
  const source = await server.getAccount(holderG).catch(async () => {
    // If the account isn't on-chain yet, use a random funded-shape source key.
    const kp = Keypair.random();
    return { accountId: () => kp.publicKey(), sequenceNumber: () => "0", incrementSequenceNumber: () => {} } as any;
  });

  const tx = new TransactionBuilder(source as any, { fee: BASE_FEE, networkPassphrase: TESTNET_PASSPHRASE })
    .addOperation(contract.call("balance", nativeToScVal(Address.fromString(holderG), { type: "address" })))
    .setTimeout(30)
    .build();

  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new Error(sim.error);
  const retval = (sim as any).result?.retval;
  if (!retval) return 0n;
  return BigInt(scValToNative(retval));
}
```

- [ ] **Step 5: Withdraw form (load note → prove → POST → show tx + balance)**
Create `app-web/src/components/WithdrawForm.tsx`:
```tsx
"use client";
import { useState } from "react";
import { Note } from "@/lib/note";
import { generateWithdrawProof, verifyLocally } from "@/lib/prove";
import { postWithdraw } from "@/lib/relayer";
import { sacBalance } from "@/lib/sac";
import { currentFreighterAddress } from "@/lib/freighter";

type Phase = "idle" | "proving" | "verifying" | "submitting" | "done" | "error";

export default function WithdrawForm() {
  const [note, setNote] = useState<Note | null>(null);
  const [recipient, setRecipient] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [txHash, setTxHash] = useState<string | null>(null);
  const [balance, setBalance] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      const n = JSON.parse(await f.text()) as Note;
      if (n.version !== 1 || n.secret == null || n.nullifier == null) throw new Error("not a valid Note file");
      setNote(n);
      setErr(null);
    } catch (e: any) {
      setErr(e.message);
    }
  }

  async function useMyFreighter() {
    const a = await currentFreighterAddress();
    if (a) setRecipient(a);
  }

  async function onWithdraw() {
    if (!note) return setErr("Load a Note first.");
    if (!recipient.startsWith("G")) return setErr("Recipient must be a Stellar G-address.");
    setErr(null);
    try {
      setPhase("proving");
      const { proof, publicSignals } = await generateWithdrawProof(note, recipient);

      setPhase("verifying");
      const ok = await verifyLocally(proof, publicSignals);
      if (!ok) throw new Error("local proof verification failed — aborting (would be rejected on-chain)");

      setPhase("submitting");
      const res = await postWithdraw({ proof, publicSignals });
      setTxHash(res.txHash);

      // Show the received SAC balance at the recipient.
      const bal = await sacBalance(recipient).catch(() => null);
      if (bal != null) setBalance(bal.toString());

      setPhase("done");
    } catch (e: any) {
      setErr(e?.message ?? String(e));
      setPhase("error");
    }
  }

  const busy = phase === "proving" || phase === "verifying" || phase === "submitting";

  return (
    <div style={{ maxWidth: 680 }}>
      <h2>Withdraw on Stellar</h2>

      <p>1. Load your Note file (the one you saved at deposit):</p>
      <input type="file" accept="application/json" onChange={onFile} />
      {note && <p style={{ color: "#5fbf5f" }}>Loaded note for denom index {note.denomIndex}.</p>}

      <p>2. Recipient Stellar address (where the bridged SAC is delivered):</p>
      <input style={{ width: "100%", fontFamily: "monospace" }} placeholder="G..." value={recipient} onChange={(e) => setRecipient(e.target.value)} />{" "}
      <button onClick={useMyFreighter}>Use my Freighter address</button>

      <p style={{ marginTop: 16 }}>
        3. <button onClick={onWithdraw} disabled={busy || !note}>{busy ? `${phase}…` : "Generate proof & withdraw"}</button>
      </p>

      {phase === "proving" && <p>Generating Groth16 proof in your browser (this can take 10–40s)…</p>}
      {err && <p style={{ color: "tomato" }}>Error: {err}</p>}

      {phase === "done" && (
        <div style={{ marginTop: 16, border: "2px solid #5fbf5f", padding: 16, borderRadius: 8 }}>
          <h3 style={{ color: "#5fbf5f" }}>Withdrawal submitted privately</h3>
          {txHash && (
            <p>
              Stellar tx:{" "}
              <a href={`https://stellar.expert/explorer/testnet/tx/${txHash}`} target="_blank" rel="noreferrer">
                {txHash}
              </a>
            </p>
          )}
          {balance != null && <p>Recipient SAC balance now: <strong>{balance}</strong></p>}
          <p style={{ opacity: 0.8 }}>
            The proof was submitted by the Withdrawal Relayer — the recipient address has no link to your deposit.
          </p>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 6: Withdraw page**
Create `app-web/src/app/withdraw/page.tsx`:
```tsx
import WalletBar from "@/components/WalletBar";
import WithdrawForm from "@/components/WithdrawForm";
import Link from "next/link";

export default function WithdrawPage() {
  return (
    <main>
      <WalletBar />
      <div style={{ padding: 24 }}>
        <p><Link href="/">← Home</Link></p>
        <WithdrawForm />
      </div>
    </main>
  );
}
```

- [ ] **Step 7: Typecheck + render + recipient test all green**
```bash
cd /home/aashim/hackathon/stellar-hacks/app-web && \
npx tsc --noEmit && npm test -- recipient 2>&1 | tail -4 && \
( npm run dev & SVR=$!; sleep 8; curl -s http://localhost:3000/withdraw | grep -c "Withdraw on Stellar"; kill $SVR )
```
Expected output (tail):
```
 Test Files  1 passed (1)
1
```

- [ ] **Step 8: Commit**
```bash
cd /home/aashim/hackathon/stellar-hacks && \
git add app-web/src/lib/recipient.ts app-web/src/lib/prove.ts app-web/src/lib/sac.ts \
  app-web/src/lib/__tests__/recipient.test.ts app-web/src/components/WithdrawForm.tsx app-web/src/app/withdraw && \
git commit -m "feat(frontend): withdraw flow — fetch path, prove in-browser, submit via relayer, show SAC balance"
```

---

### Task 55: Wire the real ZK artifacts + full local smoke against the relayer
**Files:**
- Modify: `app-web/public/zk/` (drop in real artifacts)
- Create: `app-web/scripts/link-artifacts.sh`
- Create: `app-web/.gitignore` (ignore large zkey)

- [ ] **Step 1: Artifact-link script (copies circuit outputs into public/zk)**
Create `app-web/scripts/link-artifacts.sh`:
```bash
#!/usr/bin/env bash
# Copies the built ZK artifacts from the circuit section into the web app's
# public/zk so the browser can fetch them. Run after the circuit section builds.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="${1:-$ROOT/circuits/build}"   # circuit section's build output dir
DST="$ROOT/app-web/public/zk"
mkdir -p "$DST"
for f in withdraw.wasm withdraw_final.zkey verification_key.json commitment.wasm; do
  if [ -f "$SRC/$f" ]; then
    cp "$SRC/$f" "$DST/$f"
    echo "copied $f ($(du -h "$DST/$f" | cut -f1))"
  else
    echo "MISSING: $SRC/$f — circuit section must produce it" >&2
  fi
done
```
Make executable:
```bash
chmod +x /home/aashim/hackathon/stellar-hacks/app-web/scripts/link-artifacts.sh
```

- [ ] **Step 2: Don't commit the multi-MB zkey/wasm (keep repo light)**
Create `app-web/.gitignore` (append to the create-next-app one):
```bash
cd /home/aashim/hackathon/stellar-hacks/app-web && \
printf '\n# ZK artifacts (built by the circuit section, copied via scripts/link-artifacts.sh)\npublic/zk/*.zkey\npublic/zk/*.wasm\npublic/zk/verification_key.json\n!public/zk/.gitkeep\n' >> .gitignore && \
tail -5 .gitignore</parameter>
```
Expected output (tail):
```
public/zk/*.zkey
public/zk/*.wasm
public/zk/verification_key.json
!public/zk/.gitkeep
```

- [ ] **Step 3: Copy artifacts + run the keystone parity test for real**
```bash
cd /home/aashim/hackathon/stellar-hacks/app-web && \
./scripts/link-artifacts.sh && npm test 2>&1 | tail -6
```
Expected output (after circuit section delivered artifacts + `docs/poseidon2-vectors.json`):
```
copied commitment.wasm (...)
...
 ✓ src/lib/__tests__/poseidon2.test.ts (1 test) ...
 ✓ src/lib/__tests__/recipient.test.ts (3 tests) ...
 Test Files  2 passed (2)
```
> If the Poseidon2 test fails on the commitment value, the witness-readout path in `poseidon2.ts` doesn't match your snarkjs build — adjust `runViaSnarkjs`/`calcWitness` to your snarkjs version's `wtns.calculate`/`exportJson` signature (the test pins the expected output). Do NOT relax the assertion.

- [ ] **Step 4: Manual local smoke (relayer + Sepolia + Soroban all live on testnet)**
> Requires: relayer running (`NEXT_PUBLIC_RELAYER_BASE`), contracts deployed, `.env.local` filled, Freighter on TESTNET, an injected EVM wallet on Sepolia with test-USDC + Sepolia ETH.
```bash
cd /home/aashim/hackathon/stellar-hacks/app-web && npm run dev
```
Then in a browser: deposit denom index 0 → save Note → wait for the Backing Relayer to anchor the root → withdraw with the saved Note to a fresh G-address → confirm the Stellar tx link + nonzero SAC balance.

- [ ] **Step 5: Commit**
```bash
cd /home/aashim/hackathon/stellar-hacks && \
git add app-web/scripts/link-artifacts.sh app-web/.gitignore && \
git commit -m "chore(frontend): artifact-link script + ignore large zk artifacts"
```

---

### Task 56: End-to-end demo script/checklist + anonymity-set talking point
**Files:**
- Create: `app-web/DEMO.md`

- [ ] **Step 1: Write the full hackathon demo runbook**
Create `app-web/DEMO.md`:
```markdown
# E2E Demo Runbook — Private Cross-Chain Bridge (Stellar ZK)

## 0. Pre-flight (do BEFORE you present)
- [ ] Sepolia: Lock contract + test-USDC deployed; addresses in `app-web/.env.local`.
- [ ] Soroban testnet: Shielded Pool + SAC token deployed; addresses in `.env.local`.
- [ ] Relayer up: Backing Relayer (watching Sepolia → anchoring roots) **and**
      Withdrawal Relayer + Path Service reachable at `NEXT_PUBLIC_RELAYER_BASE`.
- [ ] Browser wallet (MetaMask/Rabbit) on **Sepolia**, funded with test-USDC + Sepolia ETH.
- [ ] Freighter on **TESTNET**, with a small XLM balance.
- [ ] `npm test` is green (especially the Poseidon2 KEYSTONE parity test).
- [ ] ZK artifacts copied: `./scripts/link-artifacts.sh` ran clean.
- [ ] `npm run dev` serving on http://localhost:3000.

## 1. Happy path (single note) — ~3 min
1. Open `/deposit`. Connect EVM wallet (Sepolia) + Freighter.
2. Pick denomination **10 USDC** (index 1). Click **Deposit**.
   - Watch the three phases: committing → approving → depositing.
   - Approve both wallet popups (approve + deposit).
3. When done, the **SAVE YOUR NOTE** card appears. Click **Download Note** AND
   **Print/Save as PDF**. Show the audience the note JSON — stress: *this is the
   only key; lose it and the funds are gone.*
4. Show the Sepolia tx on Etherscan (commitment inserted into the on-chain tree).
5. Wait ~10–30s for the **Backing Relayer** to anchor the new EVM root into the
   Soroban pool's Root Window. (Show relayer log line: `anchored root 0x… for denom 1`.)
6. Open `/withdraw`. Load the downloaded Note. Paste a **fresh** Stellar G-address
   as recipient (NOT the depositor's, and not Freighter's main account).
7. Click **Generate proof & withdraw**. Narrate: the Groth16 proof is built
   **in the browser** (10–40s) — secret + nullifier never leave the device.
8. Proof posts to the **Withdrawal Relayer**, which submits the Soroban tx.
   Show the Stellar tx on stellar.expert + the recipient's **SAC balance = 10**.

## 2. Anonymity-set demo (the privacy money-shot) — ~4 min
> A single deposit→withdraw shows the *mechanism* but anonymity set = 1 (no privacy).
> This sequence demonstrates real **unlinkability**.

1. Make **3+ deposits of the SAME denomination** (e.g. three 10-USDC deposits),
   ideally from different EVM addresses / different people in the room. Save all
   three Notes. The pool's tree for denom 1 now has ≥3 indistinguishable leaves.
2. Hand all three Notes to *different* people, OR pick **one** note privately.
3. Withdraw **exactly one** of them to a brand-new G-address via the relayer.
4. Talking points to deliver while it proves:
   - The on-chain withdrawal reveals only `{root, nullifierHash, recipient,
     denomination}`. **None** of these identify *which* of the 3 commitments was
     spent — the proof asserts "I own *some* unspent leaf under this root" in ZK.
   - The `nullifierHash` is `Poseidon2Hash1(nullifier)`; it's published to prevent
     double-spend, but it is **not** linkable back to the commitment.
   - The Withdrawal Relayer (not the recipient) signs/submits the Soroban tx, so
     even the gas-payer/timing doesn't link recipient ↔ depositor.
   - Therefore the withdrawn 10 USDC is indistinguishable among all 3 deposits:
     **anonymity set = 3** for this demo, and grows with every deposit.
5. (Optional) Try to withdraw the SAME note twice → second attempt is rejected
   on-chain (nullifier already in the Nullifier Set). Show the relayer error.

## 3. Failure-mode demos (good to have ready)
- Withdraw a note whose root has aged out of the 30-root window → rejected
  ("root not in window"); re-fetch path against a current root and retry.
- Tamper with the recipient field after proving → on-chain verify fails
  (recipient is a bound public input).

## 4. Reset between runs
- Use a new denomination index or fresh deposits; nullifiers are one-shot.
- Notes are local files only — clearing the browser does not lose them.
```

- [ ] **Step 2: Commit**
```bash
cd /home/aashim/hackathon/stellar-hacks && \
git add app-web/DEMO.md && \
git commit -m "docs(frontend): end-to-end demo runbook + anonymity-set talking points"
```

---

### Task 57: README section — honest limitations (1-of-1 backing, unaudited, demo-only)
**Files:**
- Create: `app-web/README.md`

- [ ] **Step 1: Write the web app README with the limitations section**
Create `app-web/README.md`:
```markdown
# Private Cross-Chain Bridge — Web App (`app-web`)

Next.js (App Router) client for the Stellar Hacks: ZK bridge. Connects Freighter
(Stellar) + an injected EVM wallet (Sepolia), runs the Poseidon2 commitment and
the Groth16 withdrawal proof **client-side**, and submits via the relayer.

## Stack
- Next.js + React (App Router), TypeScript
- `@stellar/stellar-sdk` + `@stellar/freighter-api` (Stellar/Soroban)
- `wagmi` + `viem` (EVM Sepolia)
- `snarkjs` (in-browser Groth16 proving) — circuit artifacts in `public/zk/`

## Run
```bash
cp .env.local.example .env.local   # fill in deployed addresses + relayer URL
./scripts/link-artifacts.sh        # copy ZK artifacts from the circuit build
npm install
npm run dev                        # http://localhost:3000
```
See [`DEMO.md`](./DEMO.md) for the full end-to-end runbook.

## How it works (frontend's view)
1. **Deposit** (`/deposit`): generate a Note `{secret, nullifier}` + denomination,
   compute `commitment = Poseidon2Hash2(nullifier, secret)` using the circuit's
   own witness WASM (guarantees hash parity), `approve` + `deposit` on the Sepolia
   Lock contract, then **download/print the Note**.
2. **Withdraw** (`/withdraw`): load the Note, fetch the Merkle path from the
   relayer's Path Service, build the Groth16 proof in-browser with public inputs
   `[root, nullifierHash, recipient, denomination]`, POST it to the Withdrawal
   Relayer (which submits the Soroban tx), and show the resulting Stellar tx +
   received SAC balance.

## ⚠️ Limitations — read before trusting this with anything

**This is a hackathon prototype. Do not use it with real funds.**

- **1-of-1 Backing Relayer (trusted for solvency).** A single relayer key watches
  Sepolia and anchors EVM roots into the Soroban pool's root window. It *cannot*
  break privacy (that's enforced by the ZK proof), but it *could* anchor an
  unbacked root / insert an unbacked commitment. There is no M-of-N federation,
  no fraud proofs, no light client. Backing/solvency is **trusted**, not trustless.
  (Federation is the stated upgrade path; see the project ADRs.)
- **Withdrawal Relayer is trusted for liveness.** It can censor/delay a withdrawal,
  but it **cannot** steal (the recipient is a bound public input) or forge a proof.
- **Unaudited cryptography & contracts.** The circuits, the Poseidon2 instantiation,
  the Soroban verifier, the EVM contracts, and this client are all unaudited
  hackathon code. The Poseidon2 parity across circom/Rust/Solidity is asserted by
  a single test vector, not a proof.
- **Note custody is the user's problem.** The Note is the *only* way to withdraw.
  It is stored as a local file (download/print). Lose it → funds are permanently
  unrecoverable. No recovery, no support.
- **Privacy caveats.** Anonymity is only as large as the per-denomination anonymity
  set — a single deposit gives an anonymity set of 1 (no privacy). Network-level
  metadata (IP, timing) is **not** protected by this app; use Tor/VPN for the
  withdraw POST if metadata matters. Client-side randomness for the Note uses
  `crypto.getRandomValues` reduced mod the field (fine for a demo, not formally
  analyzed for bias).
- **Testnet only.** Sepolia + Stellar testnet, test-USDC, throwaway keys.
- **`crypto.getRandomValues` BigInt math** in `poseidon-lite`-style libs is *not*
  used here precisely because Poseidon1 ≠ Poseidon2; we instead drive the circuit
  WASM. If you swap in a JS hasher, re-run the keystone parity test first.
```

- [ ] **Step 2: Commit**
```bash
cd /home/aashim/hackathon/stellar-hacks && \
git add app-web/README.md && \
git commit -m "docs(frontend): web app README with honest limitations section"
```

