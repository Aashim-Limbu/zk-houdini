"use client";

/* ─────────────────────────────────────────────────────────────────────────
 * HERO ENTRANCE STORYBOARD  (absolute ms from mount; shell never blank)
 *
 *    0ms   nav + page visible — first paint, interactive
 *   80ms   eyebrow fades in, live dot begins pulsing
 *  200ms   headline line 1 clips up — "Prove the work."
 *  340ms   headline line 2 clips up — "Not the data."
 *  520ms   lead paragraph fades up
 *  660ms   CTAs fade up
 *  780ms   proof artifact springs in from the right
 * ~1150ms  artifact runs verify() beat once → VERIFIED ON-CHAIN
 *
 * BELOW THE FOLD: each section reveals on scroll-into-view (once); repeated
 * children (steps, rails, verdicts, limits) stagger in. The 0.82 score counts
 * up when its section enters view. All of it degrades to static under
 * prefers-reduced-motion.
 * ───────────────────────────────────────────────────────────────────────── */

import { motion, useReducedMotion, useInView } from "motion/react";
import { useEffect, useRef, useState } from "react";

const REPO = "https://github.com/Aashim-Limbu/zk-houdini";
const EXPERT = "https://stellar.expert/explorer/testnet/contract";

const VERIFIER = "CCR6QRJJBEFKUDE4YXQ2L6VII6M6C57ENXXJ5A4HQWOO6PYKRP4KS4IU";
const SETTLE = "CCE46SRV3UVFTFJAMB4XSHCCCSZ4WRKDAM2SYSIB253AQ4WIGXLJD62U";
const USDC = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const short = (id: string) => `${id.slice(0, 6)}…${id.slice(-4)}`;

// ── timing / motion constants ───────────────────────────────────────────────
const TIMING = {
  eyebrow: 80,
  line1: 200,
  line2: 340,
  lead: 520,
  ctas: 660,
  artifact: 780,
} as const;

const SPRING_STIFF = { type: "spring" as const, stiffness: 350, damping: 28 };
const SPRING_SMOOTH = { type: "spring" as const, stiffness: 300, damping: 30 };
const LINE_REVEAL = { type: "spring" as const, stiffness: 320, damping: 30 };

const GROUP_V = {
  hidden: {},
  show: { transition: { staggerChildren: 0.07, delayChildren: 0.04 } },
};
const ITEM_V = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0, transition: SPRING_STIFF },
};

// ── content ─────────────────────────────────────────────────────────────────
const STEPS = [
  {
    t: "Pin the input",
    b: "The buyer pins exactly what it's paying for — the hash of its input and the agreed program (image_id).",
    c: "input_hash = sha256(input) · image_id = program",
  },
  {
    t: "Run in the zkVM",
    b: "The seller runs the agreed program inside a RISC Zero zkVM — over inputs you may never see. Malformed input fails closed.",
    c: "journal = sha256(input)‖result → 36 bytes",
  },
  {
    t: "Verify on Soroban",
    b: "The contract rebuilds the journal from the pinned hash + result, then checks the Groth16 seal on-chain via Stellar's BN254 host functions. A bad proof traps.",
    c: "verify(seal, image_id, journal) → trustless",
  },
  {
    t: "Settlement",
    b: "A passing verification is unforgeable evidence the agreed program ran on the exact input — and it is what releases the escrow. No proof, no payment: the buyer reclaims.",
    c: "valid seal ⇒ paid · no seal ⇒ refunded",
  },
];

const LIMITS = [
  {
    b: "Testnet only, unaudited.",
    r: "A hackathon prototype on unaudited reference code, including an unaudited RISC Zero Soroban verifier. Never framed as moving real funds.",
  },
  {
    b: "Integrity, not confidentiality.",
    r: "The proof shows this exact program ran on this exact input — but the artifact and result are public. Input privacy is a design goal, not a claim of this build.",
  },
  {
    b: "The demo is import-level, not runtime.",
    r: "The live audit attests which host functions a contract imports, not which code paths execute. Verdict 0 ≠ “safe”.",
  },
  {
    b: "Scoped by image_id.",
    r: "A result attests what one agreed, decidable analysis found — not that a contract is “secure” or “audited”. A new policy ships as a new image_id.",
  },
];

// ── reveal primitives ───────────────────────────────────────────────────────
function Reveal({
  children,
  className,
  y = 22,
}: {
  children: React.ReactNode;
  className?: string;
  y?: number;
}) {
  const reduce = useReducedMotion();
  if (reduce) return <div className={className}>{children}</div>;
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }}
      transition={SPRING_STIFF}
    >
      {children}
    </motion.div>
  );
}

function StaggerGroup({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  const reduce = useReducedMotion();
  if (reduce) return <div className={className}>{children}</div>;
  return (
    <motion.div
      className={className}
      variants={GROUP_V}
      initial="hidden"
      whileInView="show"
      viewport={{ once: true, margin: "-60px" }}
    >
      {children}
    </motion.div>
  );
}

function Item({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  const reduce = useReducedMotion();
  if (reduce) return <div className={className}>{children}</div>;
  return (
    <motion.div className={className} variants={ITEM_V}>
      {children}
    </motion.div>
  );
}

// ── the 0.82 score, counting up when it scrolls into view ────────────────────
function ScoreCount() {
  const reduce = useReducedMotion();
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, margin: "-40px" });
  const [v, setV] = useState(reduce ? 0.82 : 0);
  const started = useRef(false);

  useEffect(() => {
    if (reduce || started.current || !inView) return;
    started.current = true;
    const dur = 900;
    const t0 = performance.now();
    let raf = 0;
    const tick = (t: number) => {
      const p = Math.min(1, (t - t0) / dur);
      const eased = 1 - Math.pow(1 - p, 3); // easeOutCubic
      setV(0.82 * eased);
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, reduce]);

  return (
    <b>
      score of <span ref={ref} className="pr-score">{v.toFixed(2)}</span>
    </b>
  );
}

// ── the proof artifact: verifying… → VERIFIED (once, on mount) ───────────────
function ProofArtifact() {
  const reduce = useReducedMotion();
  const [pending, setPending] = useState(false);

  useEffect(() => {
    if (reduce) return;
    // Default render is the resolved VERIFIED state (legible with no JS); once
    // mounted, replay the verifying… → VERIFIED beat. rAF keeps setState out of
    // the effect body (no cascading render) — the pre-paint frame is invisible.
    const raf = requestAnimationFrame(() => setPending(true));
    const t = setTimeout(() => setPending(false), 1500);
    return () => {
      cancelAnimationFrame(raf);
      clearTimeout(t);
    };
  }, [reduce]);

  return (
    <div className="pr-artifact" aria-label="A proof verified on-chain">
      <div className="pr-artifact__head">
        <span>attestation</span>
        <span>on-chain record</span>
      </div>
      <div className="pr-artifact__row">
        <span className="pr-artifact__k">image_id</span>
        <span className="pr-artifact__v">ff…a91d · the agreed program</span>
      </div>
      <div className="pr-artifact__row">
        <span className="pr-artifact__k">result</span>
        <span className="pr-artifact__v">0 · <span className="pr-cl">CLEAN</span></span>
      </div>
      <div className="pr-artifact__row">
        <span className="pr-artifact__k">journal</span>
        <span className="pr-artifact__v">36 bytes · sha256(input)‖result</span>
      </div>
      <div className="pr-artifact__row">
        <span className="pr-artifact__k">seal</span>
        <span className="pr-artifact__v">Groth16 · BN254</span>
      </div>
      <div
        className={`pr-artifact__verify ${pending ? "is-pending" : "is-done"}`}
        aria-live="polite"
      >
        <span className="pr-artifact__arrow">verify() →</span>
        {pending ? (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <span className="pr-spin" aria-hidden="true" />
            verifying…
          </span>
        ) : (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <Check />
            VERIFIED ON-CHAIN
          </span>
        )}
      </div>
    </div>
  );
}

function Check() {
  return (
    <svg className="pr-check" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <path
        d="M4 10.5l4 4 8-9"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// ── hero (stage-driven entrance) ─────────────────────────────────────────────
function Hero() {
  const reduce = useReducedMotion();
  const [stage, setStage] = useState(reduce ? 6 : 0);

  useEffect(() => {
    if (reduce) return;
    const timers = [
      setTimeout(() => setStage(1), TIMING.eyebrow),
      setTimeout(() => setStage(2), TIMING.line1),
      setTimeout(() => setStage(3), TIMING.line2),
      setTimeout(() => setStage(4), TIMING.lead),
      setTimeout(() => setStage(5), TIMING.ctas),
      setTimeout(() => setStage(6), TIMING.artifact),
    ];
    return () => timers.forEach(clearTimeout);
  }, [reduce]);

  return (
    <header className="pr-hero pr-wrap" id="top">
      <motion.div
        className="pr-eyebrow"
        initial={{ opacity: 0, y: -6 }}
        animate={{ opacity: stage >= 1 ? 1 : 0, y: stage >= 1 ? 0 : -6 }}
        transition={SPRING_STIFF}
      >
        <span className="pr-dot" aria-hidden="true" />
        Live on Stellar testnet
      </motion.div>

      <h1 className="pr-h1">
        <span className="pr-h1__line">
          <motion.span
            style={{ display: "block" }}
            initial={{ y: "110%" }}
            animate={{ y: stage >= 2 ? "0%" : "110%" }}
            transition={LINE_REVEAL}
          >
            Pay for provable work.
          </motion.span>
        </span>
        <span className="pr-h1__line">
          <motion.span
            style={{ display: "block" }}
            initial={{ y: "110%" }}
            animate={{ y: stage >= 3 ? "0%" : "110%" }}
            transition={LINE_REVEAL}
          >
            Or your <span className="pr-rule">money back</span>.
          </motion.span>
        </span>
      </h1>

      <div className="pr-hero-grid">
        <div>
          <motion.p
            className="pr-lead"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: stage >= 4 ? 1 : 0, y: stage >= 4 ? 0 : 14 }}
            transition={SPRING_STIFF}
          >
            ProofReceipt is escrow with no arbiter. A buyer locks USDC on Stellar
            against an exact input and an agreed program; the seller is paid only by
            a zero-knowledge proof, verified on-chain, that the program ran on that
            input. No valid proof — the buyer takes the money back.{" "}
            <b>Verification is settlement.</b>
          </motion.p>
          <motion.div
            className="pr-ctas"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: stage >= 5 ? 1 : 0, y: stage >= 5 ? 0 : 14 }}
            transition={SPRING_STIFF}
          >
            <a className="pr-btn pr-btn--primary" href="#live">
              See a verified receipt
            </a>
            <a
              className="pr-btn pr-btn--secondary"
              href={REPO}
              target="_blank"
              rel="noreferrer"
            >
              Read the source ↗
            </a>
          </motion.div>
        </div>

        <motion.div
          initial={{ opacity: 0, x: 24 }}
          animate={{ opacity: stage >= 6 ? 1 : 0, x: stage >= 6 ? 0 : 24 }}
          transition={SPRING_SMOOTH}
        >
          <ProofArtifact />
        </motion.div>
      </div>
    </header>
  );
}

// ── page ─────────────────────────────────────────────────────────────────────
export default function Page() {
  return (
    <>
      <nav className="pr-nav">
        <div className="pr-nav__in">
          <a className="pr-brand" href="#top">
            <span className="pr-dot" aria-hidden="true" />
            ProofReceipt
          </a>
          <div className="pr-navlinks">
            <a href="#how">How it works</a>
            <a href="#live">Live</a>
            <a className="pr-src" href={REPO} target="_blank" rel="noreferrer">
              Source ↗
            </a>
          </div>
        </div>
      </nav>

      <main>
        <Hero />

        {/* ── why pay: the private-compute value ─────────────────────────── */}
        <section className="pr-section">
          <div className="pr-wrap">
            <Reveal className="pr-sec-grid">
              <div className="pr-tag">when you can’t just re-run it</div>
              <div>
                <h2 className="pr-sec-h">Some answers you can&apos;t get any other way.</h2>
                <p className="pr-sec-body">
                  A lender wants a fraud score before it lends. The scoring model is
                  private — the lender can&apos;t see it or reproduce the result, and
                  the provider won&apos;t hand it over. ProofReceipt proves the agreed
                  model ran on wallet X and returned a <ScoreCount />, revealing only
                  the result, gated on-chain. The answer becomes impossible to fake and
                  impossible to withhold — and the escrow pays only when that proof lands.
                  If you can cheaply re-run the work yourself, you don’t need ProofReceipt;
                  this is for when you can’t.
                </p>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── how it works ──────────────────────────────────────────────── */}
        <section className="pr-section" id="how">
          <div className="pr-wrap">
            <Reveal className="pr-sec-grid">
              <div className="pr-tag">how the proof becomes the receipt</div>
              <div>
                <h2 className="pr-sec-h">Four steps, one core.</h2>
                <p className="pr-sec-body">
                  The seller can submit, but can never fake the work — the contract
                  rebuilds the journal from what the buyer pinned.
                </p>
                <StaggerGroup className="pr-steps">
                  {STEPS.map((s, i) => (
                    <Item className="pr-step" key={s.t}>
                      <div className="pr-step__no">0{i + 1}</div>
                      <h3 className="pr-step__t">{s.t}</h3>
                      <p className="pr-step__b">{s.b}</p>
                      <code className="pr-step__code">{s.c}</code>
                    </Item>
                  ))}
                </StaggerGroup>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── the journal byte-map ──────────────────────────────────────── */}
        <section className="pr-section" id="journal">
          <div className="pr-wrap">
            <Reveal className="pr-sec-grid">
              <div className="pr-tag">the binding</div>
              <div>
                <h2 className="pr-sec-h">One binding makes the result unforgeable.</h2>
                <p className="pr-sec-body">
                  The zkVM commits a 36-byte journal: the hash of your input
                  concatenated with the result. Because the contract reconstructs it
                  from <em>your</em> pinned hash, a valid seal can never be replayed
                  against a different input — and the result can never be detached from
                  the input it describes.
                </p>
                <div className="pr-bytemap">
                  <div className="pr-byteseg">
                    <div className="pr-byteseg__n">bytes 0–31 · 32 bytes</div>
                    <div className="pr-byteseg__t">sha256(input) — your exact input</div>
                  </div>
                  <div className="pr-byteseg pr-byteseg--result">
                    <div className="pr-byteseg__n">32–35 · 4B</div>
                    <div className="pr-byteseg__t">result</div>
                  </div>
                </div>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── two rails ─────────────────────────────────────────────────── */}
        <section className="pr-section" id="rails">
          <div className="pr-wrap">
            <Reveal className="pr-sec-grid">
              <div className="pr-tag">settlement</div>
              <div>
                <h2 className="pr-sec-h">Escrow is the product. x402 is the adapter.</h2>
                <StaggerGroup className="pr-rails">
                  <Item className="pr-card">
                    <span className="pr-card__tag">The product · verification is settlement</span>
                    <h3 className="pr-h3">Settle-core</h3>
                    <p className="pr-card__b">
                      A Soroban contract escrows the buyer&apos;s USDC and releases it{" "}
                      <b>only</b> when a valid proof lands. Clean result → seller
                      claims; no clean proof → buyer reclaims after the deadline.
                    </p>
                    <div className="pr-flow">
                      <span className="pr-flow__node">open_job</span>
                      <span className="pr-flow__arr">→</span>
                      <span className="pr-flow__node">submit_proof</span>
                      <span className="pr-flow__arr">→</span>
                      <span className="pr-flow__node">claim</span>
                    </div>
                  </Item>
                  <Item className="pr-card">
                    <span className="pr-card__tag">The adapter · proof-as-receipt</span>
                    <h3 className="pr-h3">x402 rail</h3>
                    <p className="pr-card__b">
                      Settles over real x402 so it drops into existing agent-payment
                      tooling. The buyer pays up front; the proof is a receipt it
                      re-checks on-chain with a read-only call — no signing, no second
                      payment.
                    </p>
                    <div className="pr-flow">
                      <span className="pr-flow__node">402</span>
                      <span className="pr-flow__arr">→</span>
                      <span className="pr-flow__node">pay + settle</span>
                      <span className="pr-flow__arr">→</span>
                      <span className="pr-flow__node">receipt</span>
                    </div>
                  </Item>
                </StaggerGroup>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── live on testnet (the demo) ────────────────────────────────── */}
        <section className="pr-section" id="live">
          <div className="pr-wrap">
            <Reveal className="pr-sec-grid">
              <div className="pr-tag">live on testnet</div>
              <div>
                <h2 className="pr-sec-h">Working today, end to end.</h2>
                <p className="pr-sec-body">
                  The live demo runs a bounded WASM capability audit as its workload —
                  proving the whole pipeline on Stellar testnet with real USDC: a
                  provably-clean artifact pays the seller, a dirty one refunds the
                  buyer.
                </p>

                <StaggerGroup className="pr-verdicts">
                  <Item className="pr-vcard">
                    <div className="pr-vcard__head">
                      <h3 className="pr-h3">clean.wasm</h3>
                      <span className="pr-chip pr-chip--pass"><b>0</b> · CLEAN</span>
                    </div>
                    <div className="pr-vrow">
                      <span className="pr-vrow__k">job</span>
                      <span className="pr-vrow__v">efb330a5…</span>
                    </div>
                    <div className="pr-vrow">
                      <span className="pr-vrow__k">proof tx</span>
                      <span className="pr-vrow__v">4cebe3ac…</span>
                    </div>
                    <div className="pr-vrow">
                      <span className="pr-vrow__k">outcome</span>
                      <span className="pr-vrow__v pr-vrow__v--pass">PAID → SELLER</span>
                    </div>
                  </Item>
                  <Item className="pr-vcard">
                    <div className="pr-vcard__head">
                      <h3 className="pr-h3">denylisted.wasm</h3>
                      <span className="pr-chip pr-chip--fail"><b>2</b> · DENYLIST HIT</span>
                    </div>
                    <div className="pr-vrow">
                      <span className="pr-vrow__k">job</span>
                      <span className="pr-vrow__v">ec6dceb9…</span>
                    </div>
                    <div className="pr-vrow">
                      <span className="pr-vrow__k">reclaim tx</span>
                      <span className="pr-vrow__v">7506ae82…</span>
                    </div>
                    <div className="pr-vrow">
                      <span className="pr-vrow__k">outcome</span>
                      <span className="pr-vrow__v">REFUNDED → BUYER</span>
                    </div>
                  </Item>
                </StaggerGroup>

                <table className="pr-table">
                  <thead>
                    <tr>
                      <th>Contract</th>
                      <th>Testnet ID</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>RISC Zero verifier (Groth16, NethermindEth)</td>
                      <td>
                        <a href={`${EXPERT}/${VERIFIER}`} target="_blank" rel="noreferrer">
                          {short(VERIFIER)} ↗
                        </a>
                      </td>
                    </tr>
                    <tr>
                      <td>ProofReceipt settle-core (verdict-pinned escrow)</td>
                      <td>
                        <a href={`${EXPERT}/${SETTLE}`} target="_blank" rel="noreferrer">
                          {short(SETTLE)} ↗
                        </a>
                      </td>
                    </tr>
                    <tr>
                      <td>USDC (SEP-41 SAC, 7 decimals)</td>
                      <td>
                        <a href={`${EXPERT}/${USDC}`} target="_blank" rel="noreferrer">
                          {short(USDC)} ↗
                        </a>
                      </td>
                    </tr>
                  </tbody>
                </table>

                <p className="pr-footnote">
                  The audit is a demo workload, not the product. Verdict 0 means clean
                  against one agreed policy — not “safe”. Testnet only, unaudited.
                </p>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── honest limits ─────────────────────────────────────────────── */}
        <section className="pr-section">
          <div className="pr-wrap">
            <Reveal className="pr-sec-grid">
              <div className="pr-tag">honest limits</div>
              <div>
                <h2 className="pr-sec-h">What the proof does, and doesn&apos;t, claim.</h2>
                <StaggerGroup className="pr-limits">
                  {LIMITS.map((l, i) => (
                    <Item className="pr-limit" key={l.b}>
                      <span className="pr-limit__m">0{i + 1}</span>
                      <span>
                        <b>{l.b}</b> {l.r}
                      </span>
                    </Item>
                  ))}
                </StaggerGroup>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── closing ───────────────────────────────────────────────────── */}
        <section className="pr-section">
          <div className="pr-wrap">
            <Reveal>
              <div className="pr-closing">
                <h2>
                  Verify it <span className="pr-rule">yourself</span>.
                </h2>
                <p>
                  The whole stack runs on Stellar testnet — on-chain Groth16
                  verification, escrow settlement, real-USDC x402, and a real WASM
                  capability-policy audit as the live demo.
                </p>
                <div className="pr-ctas">
                  <a className="pr-btn pr-btn--primary" href={REPO} target="_blank" rel="noreferrer">
                    Clone the repo ↗
                  </a>
                  <a className="pr-btn pr-btn--secondary" href="#top">
                    Back to top ↑
                  </a>
                </div>
              </div>
            </Reveal>
          </div>
        </section>
      </main>

      <footer className="pr-footer">
        <div className="pr-footer__in">
          <span>ProofReceipt · Stellar Hacks: ZK</span>
          <span>
            Stellar · Soroban · RISC Zero · x402 —{" "}
            <a href={REPO} target="_blank" rel="noreferrer">
              source ↗
            </a>
          </span>
        </div>
      </footer>
    </>
  );
}
