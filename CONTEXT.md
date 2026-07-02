# ProofReceipt — domain context & ubiquitous language

The vocabulary the team agrees to use precisely. Domain terms only — not implementation
detail. (The earlier zk-bridge context lives in `legacy/CONTEXT.md`.)

## Core idea

When one party pays another for work it cannot observe or re-run, settlement needs
trust or an arbiter. ProofReceipt replaces both with a proof: the buyer escrows USDC
pinned to an exact input and an agreed program (`image_id`); the seller is paid **only**
by a Groth16 proof, verified on Stellar/Soroban, that *the agreed program ran on that
exact input*. No matching proof → the buyer reclaims. **Verification is settlement.**

Motto: **"Pay for provable work — or get your money back."**

Scope rule: ProofReceipt applies when re-execution is not an option — the seller's
model/data is private, or the verifier is a contract that cannot execute the work.
If you can cheaply re-run the work yourself, you don't need ProofReceipt.

The x402 rail is a secondary adapter: the same proof rides existing agent-payment
tooling as a verifiable receipt instead of a payment gate. The escrow is the product.

## Glossary

- **Attestation** (a.k.a. **capability-policy attestation**) — the unit ProofReceipt sells:
  a proof + verdict, cryptographically bound to a specific contract's exact bytes. It states
  *which capabilities a contract's code carries under an agreed policy* — **not** that the
  contract is "safe", "secure", or "audited". Never use "audit"/"safe"/"secure" for a verdict.

- **Verdict** — the result of the attestation, a `u32` findings bitmask committed in the
  proof's journal. `0` = clean (no policy violations found); a non-zero bit = a specific
  finding (allowlist violation / denylist hit / storage-write-without-auth-import). A verdict
  attests *what was found by a specific decidable analysis*, scoped by the `image_id`.

- **image_id** — the program commitment of the guest. Because the policy is baked into the
  guest, the `image_id` **is** the agreed policy. A different policy ⇒ a different `image_id`.
  Bit semantics are append-only; policy changes ship as a *new* `image_id`, never by mutating
  an existing one.

- **Buyer** — the party paying for work it cannot observe or re-run; the party the escrow
  protects. Often a contract or an autonomous agent, not a human web user. A **buyer agent**
  (holds a wallet, pays via x402) is one instance, used in the demo.

- **Verdict gate** — the rule that ties the verdict to an outcome. It can live in two places:
  - **off-chain (agent-enforced):** the buyer agent reads the verdict and decides
    (proceed / abort / escalate). Trust rests on the agent's own code.
  - **on-chain (contract-enforced)** — *chosen design:* a Soroban contract enforces the
    gate so no off-chain code can bypass it. See **verdict-pinned escrow**.

- **verdict-pinned escrow** (the contract-enforced gate, extends settle-core) — the buyer
  escrows USDC for a *specific* verdict: `open_job` pins `expected_verdict` (e.g. `0` = clean).
  `submit_proof` rebuilds the journal from the **pinned** `(input_hash, expected_verdict)`, so
  the seller can only claim if the real proof matches it. Clean contract → seller claims
  (paid for a clean attestation); dirty contract → no matching proof exists → seller can't
  claim → **buyer_reclaim** returns the funds after a deadline. Net: *"pay for a provably
  clean attestation, or get your money back."* The seller runs the cheap import scan first and
  only pays for the expensive Groth16 prove when it will be claimable.

- **buyer_reclaim** — the buyer's on-chain exit: withdraw the escrowed USDC after a deadline if
  the job is still `Open` (no clean proof landed). Without it, a dirty contract locks funds.

- **Intended action** — what the buyer agent was about to do with the contract that the gate
  guards (e.g. deposit funds, invoke a function, add to a trusted set). Gated on the verdict.

- **Seller** — the party running the attestation service, paid per attestation.

- **Settlement rails** — two ways payment relates to the proof:
  - **settle-core (escrow):** a Soroban contract escrows the buyer's USDC and releases it
    only when a valid proof lands — *verification is settlement*.
  - **x402 rail:** the buyer pays up front over x402; the proof is a verifiable *receipt*,
    not a payment gate.

- **Journal binding** — the proof's journal commits `sha256(input) ‖ verdict`, so a valid
  on-chain verification proves the agreed program ran on the buyer's exact input. This binding
  is what makes the verdict unforgeable and non-replayable.

## What the attestation does NOT claim (honest boundaries)

- Verdict `0` ≠ "safe" — it is **import/capability-level**, not a proof of absence of bugs.
- The proof gives **integrity** (this program ran on these bytes), **not privacy** — the
  artifact and the verdict are public.
