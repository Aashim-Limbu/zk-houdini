# ProofReceipt M2 — x402 Async Audit Service (Design Spec)

**Date:** 2026-06-25
**Status:** Approved (design), pending implementation plan
**Builds on:** M1 (proof-gated escrow contract) and M0 (RISC Zero prove→verify on testnet)
**Branch:** off `feat/proofreceipt-m1` (M1 PR not yet merged)

## Goal

Put ProofReceipt on the **x402 agent-payment rail**: an AI-agent buyer pays a seller's
audit API over real x402, the audit runs asynchronously, and the buyer receives a
**ZK proof receipt** it can verify on-chain ("the agreed audit program ran on my exact
input"). Demonstrates the agent-payment story end-to-end.

## Settlement model (the defining decision)

**Option B — real x402, proof-as-receipt.** Payment settles **to the seller up front**
via the OpenZeppelin Channels facilitator (canonical x402); the ZK proof comes back as a
**verifiable receipt**, NOT a payment gate. This deliberately trades away M1's "pay only
if proof valid" property in exchange for true x402-rail compatibility and the strongest
agent-payment narrative. The M1 escrow contract is **unused** in this path.

(Rejected alternatives: 402-gated escrow — keeps proof-gating but isn't literal x402;
hybrid fee+escrow — most surface area.)

## Architecture

```
Buyer (TS agent, @x402/fetch)     Seller audit server (Rust/axum)   OZ Facilitator   Stellar
  POST /audit (artifact) ─────────▶
  ◀── 402 + PAYMENT-REQUIRED hdr ──
  (x402 fetch builds+signs a USDC transfer tx, base64 in PAYMENT-SIGNATURE)
  POST /audit + PAYMENT-SIGNATURE ▶
                                    /verify then /settle ─────────▶  USDC → seller ▶
  ◀── 202 {job_id} + PAYMENT-RESPONSE  (synchronous, ~5s)
                                    [spawn m0-host on artifact — async, minutes]
  GET /audit/{job_id} (poll) ─────▶
  ◀── 200 {seal,image_id,journal,journal_digest,verdict}  ← proof receipt
  simulate verify(seal,image_id,journal_digest) on deployed verifier ──────────────▶ ✓
```

### Pinned x402 facts (v2 — verified from `@x402/*@2.16.0` source + live OZ facilitator probes)

The original draft of this spec described the **v1** flow (`X-PAYMENT`, body-delivered
402). Stellar only exists in **x402 v2**, which is header-based. The binding facts:
- Packages `@x402/core` + `@x402/stellar` + `@x402/fetch` all at **`2.16.0`**; wire
  `x402Version: 2`; scheme literal **`"exact"`**; `@stellar/stellar-sdk@^14.6.1`.
- **Headers (base64 of JSON, case-insensitive):** 402 → `PAYMENT-REQUIRED`; request →
  `PAYMENT-SIGNATURE` (NOT `X-PAYMENT`, which is v1-only); settle success →
  `PAYMENT-RESPONSE`.
- **402 body (`PaymentRequired`):** `{x402Version:2, resource:{url,...}, accepts:[{scheme:"exact",
  network:"stellar:testnet", asset:<USDC SAC>, amount:<atomic 7-dec string>, payTo:<G...>,
  maxTimeoutSeconds:60, extra:{areFeesSponsored:true}}]}`. `extra.areFeesSponsored:true`
  is REQUIRED or the buyer client throws.
- **Payment payload (decoded `PAYMENT-SIGNATURE`):** `{x402Version:2, accepted:{...}, payload:{transaction:"<base64 Stellar tx XDR>"}}` — forward `payload` opaque; do not parse the XDR.
- **Facilitator:** base `https://channels.openzeppelin.com/x402/testnet`; `POST /verify`
  + `POST /settle` body `{x402Version:2, paymentPayload, paymentRequirements}`; `/verify`
  → `{isValid, invalidReason?, payer?}` (200 even when invalid); `/settle` →
  `{success, transaction, network, payer, errorReason?}`. **Auth required** on every call:
  `Authorization: Bearer <key>`; a free testnet key comes from `GET https://channels.openzeppelin.com/testnet/gen` → `{apiKey}`.
- **USDC testnet SAC:** `CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA`
  (issuer `GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5`, 7 decimals). This is
  NOT the repo's bridged zUSDC SAC — do not reuse `SOROBAN_SAC_ID`.

### Components
- **Buyer agent** — a small TS script using `@x402/fetch` + `@x402/stellar` (the real
  client; emits a valid `PAYMENT-SIGNATURE`). Submits the artifact, polls for the receipt,
  then verifies it **on-chain** (read-only `simulateTransaction`) against the deployed verifier.
- **Audit server** — a NEW isolated Rust/axum crate `proofreceipt-server/` (NOT wedged
  into the bridge relayer). Borrows the relayer's `soroban.rs` invoke + TOML-config
  patterns. Modules:
  - `x402` — build the 402 challenge JSON; call the facilitator `/verify` then `/settle`
    (Bearer-auth HTTP) by hand.
  - `audit` — `POST /audit` and `GET /audit/{job_id}` handlers, an in-memory job store,
    and spawning the prover.
- **Prover** — shells out to the existing `m0-host` with the buyer's artifact bytes;
  produces `(seal, image_id, journal, journal_digest)`.
- **Verifier** — the already-deployed RISC Zero leaf verifier on testnet
  (`CCR6QRJJBEFKUDE4YXQ2L6VII6M6C57ENXXJ5A4HQWOO6PYKRP4KS4IU`), used read-only by the
  buyer to check the receipt.

## Flow & binding

1. Buyer `POST /audit` with `{artifact: base64(bytes)}` (the thing to audit). No payment yet.
2. Server → `402` with the `PAYMENT-REQUIRED` header (base64 of the §Pinned-facts 402 body).
   The challenge `extra` also **advertises the agreed `image_id`** (the audit program).
3. Buyer's x402 fetch builds + signs a USDC transfer tx, retries the SAME `POST /audit`
   (method + body preserved) with the `PAYMENT-SIGNATURE` header.
4. Server base64-decodes `PAYMENT-SIGNATURE` → `paymentPayload`; calls facilitator
   `/verify` (Bearer key); if `isValid`, calls `/settle` → USDC moves to the seller (~5s).
   **Synchronous, BEFORE returning 202 and BEFORE proving** (the signed auth entries expire
   in ~`maxTimeoutSeconds`, ~60s; the audit takes minutes).
5. Server stores the raw artifact bytes, returns `202 {job_id}` with the `PAYMENT-RESPONSE`
   header, and spawns `m0-host --input <artifact> --out <proof.json>` in the background
   (`spawn_blocking`).
6. Background: `m0-host` runs the guest on the artifact bytes → `seal`, `image_id`,
   `journal` (`input_hash ‖ verdict`, raw 36 bytes), `journal_digest`. Stored against `job_id`.
7. Buyer `GET /audit/{job_id}`: `202 {status:"pending"}` until done, then
   `200 {status:"done", seal, image_id, journal, journal_digest, verdict}`; on prover
   failure `200 {status:"error", error}`.
8. Buyer verifies, three checks: (a) `receipt.image_id == agreed image_id`; (b) from the
   returned **raw `journal`**: assert `journal[0..32] == sha256(my_artifact)` and
   `sha256(journal) == journal_digest` (do NOT trust a server-claimed verdict); (c) read-only
   simulate `verify(seal, image_id, journal_digest)` on the deployed verifier — a non-trap
   pass proves the agreed program ran on the buyer's exact bytes.

**The trust check is three things:** program binding (`image_id` matches the agreed one),
input binding (raw journal ties to the buyer's own artifact bytes), and proof validity
(on-chain `verify` simulation does not trap).

**Load-bearing invariant + positive test:** the bytes the prover hashes MUST equal the
buyer's raw artifact bytes (chain: buyer `base64(raw)` → server `base64-decode` → write raw
to file → `m0-host` reads raw → guest `sha256`). Any re-encode breaks it. A positive
binding test asserts the buyer-computed `journal_digest` equals the receipt's for a known
artifact (the M0 negative control already covers rejection).

## State & data

- **Job store:** in-memory map `job_id -> { status: Queued|Proving|Done|Failed, input_hash,
  receipt? }`. No persistence (demo scope).
- **Journal layout:** unchanged from M1 — `input_hash (32) ‖ verdict (4 LE u32)` = 36
  bytes, committed raw by the guest via `commit_slice`; `journal_digest = sha256(journal)`.
- **Config (TOML + env):** `OZ_API_KEY`, `FACILITATOR_URL`
  (default `https://channels.openzeppelin.com/x402/testnet`), `STELLAR_RECIPIENT`
  (seller `G...`, needs USDC trustline), `STELLAR_NETWORK` (`stellar:testnet`), price,
  the agreed `image_id`, `http_bind`, path to the `m0-host` binary.

## Scope (YAGNI)

- **In:** the x402 payment plumbing (by hand, Rust), the async job + poll, the prover
  spawn, the TS buyer agent, on-chain receipt verification.
- **Out / deferred:** real bounded audit logic (guest stays the stub
  `verdict = nonempty ? 1 : 0`) → M3. No escrow / dispute / refund (Option B settles up
  front). No persistent job store. No webhook callback (poll only).

## Testing

- **Unit (Rust server):** 402-challenge JSON matches the x402 `exact` spec; facilitator
  `/verify`+`/settle` request construction against a **mock facilitator** HTTP server (no
  live dependency); job-store transitions (Queued→Proving→Done); poll endpoint returns
  202-pending then 200-with-receipt; prover output parses into a receipt.
- **Binding test:** a foreign `image_id` or a `journal_digest` reconstructed from
  different bytes fails on-chain `verify()` (reuses M0 negative-control behavior).
- **Live e2e (testnet, manual):** real TS buyer pays via the real facilitator → server
  settles → `m0-host` proves → buyer polls → buyer verifies the receipt on-chain. Needs
  `OZ_API_KEY` + payer USDC + trustlines.

## Key risks / open items for the plan

1. **x402 wire formats — now PINNED** to `@x402/*@2.16.0` v2 (see §Pinned facts), verified
   from package source + live facilitator probes. Residual: a populated `/settle` SUCCESS
   body was schema-verified but not observed end-to-end. De-risking: a capture task runs a
   reference TS buyer→server→facilitator round-trip and saves the real bytes as fixtures the
   Rust serde structs must round-trip (locks the `PAYMENT-SIGNATURE` header + payload shape +
   settle body). Forward `paymentPayload` to the facilitator as opaque `serde_json::Value`.
2. **External live deps** for the e2e: facilitator availability + API key, payer USDC,
   trustlines. The mock-facilitator unit tests keep dev/CI independent of these.
3. **`m0-host` tweak:** accept arbitrary artifact input + a per-job output path
   (currently takes a string arg and writes a fixed `proof.json`). Minor.

## Placement & isolation

- New crate `proofreceipt-server/` (Rust/axum), sibling to `proofreceipt-m0/` and
  `proofreceipt-contract/`. Buyer agent is a separate TS package at sibling
  `proofreceipt-buyer/`. Bridge (`relayer/`, `soroban/`, `frontend/`, `vendor/`)
  untouched. M2 branches off `feat/proofreceipt-m1`.
