#!/usr/bin/env node
/**
 * capture.mjs — capture real x402 v2 wire bytes for Rust serde round-trip tests.
 *
 * Writes 3 fixtures to proofreceipt-server/tests/fixtures/:
 *   payment_payload.json  — real PAYMENT-SIGNATURE payload built by @x402/stellar
 *   supported.json        — live /supported response from OZ Channels facilitator
 *   verify_invalid.json   — live /verify response for an invalid (bad XDR) payload
 *
 * Required env vars:
 *   OZ_API_KEY          — OZ Channels testnet Bearer key
 *   CLIENT_PRIVATE_KEY  — Stellar S... secret for the e2e-buyer account
 *   PAY_TO              — seller G... address
 *
 * Asset used: native XLM SAC (CDLZFC3S...) — buyer holds ~9999 XLM.
 * This avoids needing testnet USDC (which the buyer doesn't hold).
 * The wire format produced by @x402/stellar is identical regardless of which
 * SAC is used — the Rust tests validate the JSON shape, not on-chain settlement.
 */
import { x402Client } from "@x402/fetch";
import { createEd25519Signer } from "@x402/stellar";
import { ExactStellarScheme } from "@x402/stellar/exact/client";
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const OZ_API_KEY = process.env.OZ_API_KEY;
const PRIVATE_KEY = process.env.CLIENT_PRIVATE_KEY;
const PAY_TO = process.env.PAY_TO;

if (!OZ_API_KEY) throw new Error("OZ_API_KEY env var required");
if (!PRIVATE_KEY) throw new Error("CLIENT_PRIVATE_KEY env var required");
if (!PAY_TO) throw new Error("PAY_TO env var required");

const FACILITATOR = "https://channels.openzeppelin.com/x402/testnet";

// Native XLM SAC on Stellar testnet — all accounts hold XLM, so simulation succeeds.
// Computed with: stellar contract id asset --asset native --network testnet ...
const XLM_SAC = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

// Transfer amount in SAC base units (7 decimals for XLM):  1_000_000 = 0.1 XLM
const AMOUNT = "1000000";

const FIXTURES_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../proofreceipt-server/tests/fixtures",
);
mkdirSync(FIXTURES_DIR, { recursive: true });

// ── 1. /supported ──────────────────────────────────────────────────────────────
console.log("[capture] 1/3 fetching /supported …");
const supRes = await fetch(`${FACILITATOR}/supported`, {
  headers: { Authorization: `Bearer ${OZ_API_KEY}` },
});
if (!supRes.ok) throw new Error(`/supported HTTP ${supRes.status}: ${await supRes.text()}`);
const supported = await supRes.json();
writeFileSync(join(FIXTURES_DIR, "supported.json"), JSON.stringify(supported, null, 2));
console.log("[capture] ✓ supported.json written");

// ── 2. /verify (invalid XDR) → verify_invalid.json ────────────────────────────
console.log("[capture] 2/3 fetching /verify with intentionally invalid XDR …");
const badPayload = {
  x402Version: 2,
  accepted: {
    scheme: "exact",
    network: "stellar:testnet",
    asset: XLM_SAC,
    amount: AMOUNT,
    payTo: PAY_TO,
    maxTimeoutSeconds: 60,
    extra: { areFeesSponsored: true },
  },
  payload: { transaction: "AAAAAAAAAAAAAAAA" },  // deliberately invalid XDR
  resource: { url: "http://127.0.0.1:9999/audit" },
};
const verRes = await fetch(`${FACILITATOR}/verify`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Authorization: `Bearer ${OZ_API_KEY}`,
  },
  body: JSON.stringify({
    x402Version: 2,
    paymentPayload: badPayload,
    paymentRequirements: badPayload.accepted,
  }),
});
const verifyText = await verRes.text();
let verifyInvalid;
try {
  verifyInvalid = JSON.parse(verifyText);
} catch {
  throw new Error(`/verify response not JSON (HTTP ${verRes.status}): ${verifyText}`);
}
writeFileSync(join(FIXTURES_DIR, "verify_invalid.json"), JSON.stringify(verifyInvalid, null, 2));
console.log(`[capture] ✓ verify_invalid.json written  (isValid=${verifyInvalid.isValid})`);

// ── 3. Build real PAYMENT-SIGNATURE payload ────────────────────────────────────
console.log("[capture] 3/3 building payment payload (queries Soroban RPC for latest ledger) …");
const signer = createEd25519Signer(PRIVATE_KEY, "stellar:testnet");
const client = new x402Client().register("stellar:*", new ExactStellarScheme(signer));

const paymentRequired = {
  x402Version: 2,
  resource: { url: "http://127.0.0.1:9999/audit" },
  accepts: [
    {
      scheme: "exact",
      network: "stellar:testnet",
      asset: XLM_SAC,
      amount: AMOUNT,
      payTo: PAY_TO,
      maxTimeoutSeconds: 60,
      extra: { areFeesSponsored: true },
    },
  ],
};

const paymentPayload = await client.createPaymentPayload(paymentRequired);
writeFileSync(
  join(FIXTURES_DIR, "payment_payload.json"),
  JSON.stringify(paymentPayload, null, 2),
);
console.log("[capture] ✓ payment_payload.json written");
console.log("[capture] all 3 fixtures written to", FIXTURES_DIR);
