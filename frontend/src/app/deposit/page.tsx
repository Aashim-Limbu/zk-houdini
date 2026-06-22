"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  Key,
  PlusCircle,
  ShieldCheck,
  TriangleAlert,
  Wallet,
} from "lucide-react";
import { TopBar } from "@/components/site/top-bar";
import { GlowOrb } from "@/components/site/glow-orb";
import { CtaButton } from "@/components/site/cta-button";
import { ActRail } from "@/components/site/deposit/act-rail";
import { StageStep } from "@/components/site/deposit/stage-step";
import { DenomPicker } from "@/components/site/deposit/denom-picker";
import { SummaryPanel } from "@/components/site/deposit/summary-panel";
import { StatusList } from "@/components/site/deposit/status-list";
import { VanishStage } from "@/components/site/deposit/vanish-stage";
import { SecretNoteCard } from "@/components/site/deposit/secret-note-card";
import { EVM, etherscan, truncate } from "@/lib/site";

// Mock EVM sender — display only, no real wallet.
const MOCK_SENDER = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";

type Step =
  | "idle"
  | "connecting"
  | "connected"
  | "locking"
  | "vanishing"
  | "noted"
  | "sealed";

const RAIL = [
  { label: "Choose" },
  { label: "Connect" },
  { label: "Lock" },
  { label: "Vanish" },
  { label: "Your note" },
];

// rail index per step
const RAIL_INDEX: Record<Step, number> = {
  idle: 0,
  connecting: 1,
  connected: 1,
  locking: 2,
  vanishing: 3,
  noted: 4,
  sealed: 4,
};

const LOCK_LINES = [
  { label: "Signing the deposit" },
  { label: "Broadcasting to Sepolia" },
  { label: "Confirmed on-chain" },
];

/** Build a format-only mock note (no real crypto). */
function makeMockNote(amount: number): string {
  const hex = (n: number) =>
    Array.from({ length: n }, () =>
      Math.floor(Math.random() * 16).toString(16),
    ).join("");
  return `zkh-note-v1:${amount}:${hex(24)}:${hex(40)}`;
}

export default function DepositPage() {
  const [step, setStep] = useState<Step>("idle");
  const [amount, setAmount] = useState<number | null>(null);
  const [note, setNote] = useState("");
  const [lockDone, setLockDone] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  const after = useCallback((ms: number, fn: () => void) => {
    const t = setTimeout(fn, ms);
    timers.current.push(t);
  }, []);

  useEffect(
    () => () => {
      timers.current.forEach(clearTimeout);
    },
    [],
  );

  const amountLabel = amount !== null ? `${amount} USDC` : "";

  function connect() {
    setError(null);
    setStep("connecting");
    after(700, () => setStep("connected"));
  }

  function lock() {
    setError(null);
    setStep("locking");
    setLockDone(0);
    after(450, () => setLockDone(1));
    after(950, () => setLockDone(2));
    after(1400, () => {
      setLockDone(3);
      after(350, () => setStep("vanishing"));
    });
  }

  const onVanished = useCallback(() => {
    setNote((prev) => prev || makeMockNote(amount ?? 0));
    setStep("noted");
  }, [amount]);

  function reset() {
    timers.current.forEach(clearTimeout);
    timers.current = [];
    setAmount(null);
    setNote("");
    setLockDone(0);
    setError(null);
    setStep("idle");
  }

  return (
    <>
      <TopBar />
      <main
        id="main"
        className="relative mx-auto flex min-h-screen max-w-xl flex-col px-6 pb-24 pt-28"
      >
        {/* dimmed orb behind the stage */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-x-0 top-24 -z-10 flex justify-center"
        >
          <GlowOrb size="lg" intensity={0.18} />
        </div>

        {/* act rail — persistent legible status (aria-live in StageStep) */}
        <div className="mb-10">
          <ActRail steps={RAIL} current={RAIL_INDEX[step]} />
        </div>

        {error && (
          <div
            role="alert"
            className="mb-6 flex items-start gap-3 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-ink"
          >
            <TriangleAlert className="mt-0.5 size-5 shrink-0 text-destructive" aria-hidden />
            <span>{error}</span>
          </div>
        )}

        <StageStep stepKey={step}>
          {/* ───────────────────────── idle ───────────────────────── */}
          {step === "idle" && (
            <section className="flex flex-col gap-6 text-center">
              <header className="flex flex-col gap-2">
                <p className="font-mono text-xs text-faint">Act I · The Vanish</p>
                <h1 className="text-display-section text-ink">
                  Choose what to make disappear.
                </h1>
              </header>

              <DenomPicker value={amount} onChange={setAmount} />

              <p className="text-sm text-muted-ink">
                Locking on {EVM.name} · pool{" "}
                <a
                  href={etherscan.address(EVM.pool)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-cyan underline-offset-4 hover:underline"
                >
                  {truncate(EVM.pool)}
                </a>
              </p>

              <div className="flex flex-col items-center gap-2">
                <CtaButton
                  onClick={connect}
                  disabled={amount === null}
                  size="lg"
                  className="w-full sm:w-auto"
                >
                  Continue
                  <ArrowRight className="size-4" aria-hidden />
                </CtaButton>
                {amount === null && (
                  <p className="text-xs text-faint">Pick an amount first.</p>
                )}
              </div>
            </section>
          )}

          {/* ─────────────────── connecting / connected ─────────────────── */}
          {(step === "connecting" || step === "connected") && (
            <section className="flex flex-col gap-6">
              <header className="flex flex-col gap-2 text-center">
                <h1 className="text-display-section text-ink">
                  {step === "connecting" ? "Connecting your wallet…" : "Ready to lock."}
                </h1>
                <p className="text-muted-ink">
                  {step === "connecting"
                    ? "Confirm the connection in your wallet."
                    : "Review the deposit before it vanishes."}
                </p>
              </header>

              {step === "connecting" ? (
                <div className="flex justify-center">
                  <StatusList
                    lines={[{ label: "Requesting MetaMask connection" }]}
                    done={0}
                  />
                </div>
              ) : (
                <>
                  <SummaryPanel
                    rows={[
                      { label: "Amount", value: amountLabel },
                      {
                        label: "From",
                        value: (
                          <>
                            {EVM.short} · {truncate(MOCK_SENDER)}
                          </>
                        ),
                      },
                      { label: "Into pool", value: truncate(EVM.pool) },
                    ]}
                  />

                  <div className="flex items-start gap-3 rounded-xl border border-gold/30 bg-bg-2/50 p-4 text-sm">
                    <Key className="mt-0.5 size-4 shrink-0 text-gold" aria-hidden />
                    <p className="text-muted-ink">
                      After locking you&rsquo;ll get a savable secret note — keep
                      it. Nothing is private yet; privacy comes from the proof later.
                    </p>
                  </div>

                  <div className="flex justify-center">
                    <CtaButton onClick={lock} size="lg" className="w-full sm:w-auto">
                      Lock {amountLabel} on {EVM.short}
                    </CtaButton>
                  </div>
                </>
              )}
            </section>
          )}

          {/* ───────────────────────── locking ───────────────────────── */}
          {step === "locking" && (
            <section className="flex flex-col items-center gap-6 text-center">
              <header className="flex flex-col gap-2">
                <h1 className="text-display-section text-ink">Locking on {EVM.short}…</h1>
                <p className="text-muted-ink">
                  Your {amountLabel} is being committed to the pool.
                </p>
              </header>
              <StatusList lines={LOCK_LINES} done={lockDone} />
            </section>
          )}

          {/* ──────────────────────── vanishing ──────────────────────── */}
          {step === "vanishing" && (
            <VanishStage figure={amountLabel} onDone={onVanished} />
          )}

          {/* ───────────────────── noted (the lifeline) ───────────────────── */}
          {step === "noted" && (
            <SecretNoteCard
              secret={note}
              amountLabel={amountLabel}
              onDone={() => setStep("sealed")}
            />
          )}

          {/* ───────────────────────── sealed ───────────────────────── */}
          {step === "sealed" && (
            <section className="flex flex-col gap-7 text-center">
              <header className="flex flex-col items-center gap-3">
                <span className="flex size-12 items-center justify-center rounded-full border border-success/40 bg-success/15">
                  <ShieldCheck className="size-6 text-success" aria-hidden />
                </span>
                <h1 className="text-display-section text-ink">Sealed.</h1>
                <p className="text-muted-ink">
                  Your {amountLabel} is in the pool. Only your note can bring it back.
                </p>
              </header>

              <div className="flex flex-col gap-3">
                <CtaButton href="/withdraw" size="lg">
                  Withdraw with this note
                  <ArrowRight className="size-4" aria-hidden />
                </CtaButton>
                <CtaButton onClick={reset} variant="glass">
                  <PlusCircle className="size-4" aria-hidden />
                  Make another deposit
                </CtaButton>
                <CtaButton href="/" variant="ghost">
                  Return to the stage
                </CtaButton>
              </div>

              <div className="flex items-center justify-center gap-2 rounded-xl border border-gold/30 bg-bg-2/50 px-4 py-3 text-sm text-muted-ink">
                <Key className="size-4 shrink-0 text-gold" aria-hidden />
                Keep your note safe — it&rsquo;s the only way back.
              </div>
            </section>
          )}
        </StageStep>

        {/* persistent honest footer marker */}
        {step !== "noted" && step !== "vanishing" && (
          <p className="mt-10 flex items-center justify-center gap-2 text-center text-xs text-faint">
            <Wallet className="size-3.5" aria-hidden />
            Mock flow · no real wallet or funds ·{" "}
            <Link href="/" className="underline-offset-4 hover:underline">
              back to stage
            </Link>
          </p>
        )}
      </main>
    </>
  );
}
