"use client";

import { useState } from "react";
import { Check } from "lucide-react";
import { cn } from "@/lib/utils";
import { truncate } from "@/lib/site";

type Status = "idle" | "connecting" | "connected";

function EthGlyph({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden className={cn("h-3.5 w-3.5", className)}>
      <path d="M12 2 6 12l6 3.5L18 12 12 2Z" fill="currentColor" opacity="0.85" />
      <path d="M6 13.3 12 22l6-8.7-6 3.5-6-3.5Z" fill="currentColor" opacity="0.55" />
    </svg>
  );
}

function StellarGlyph({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden className={cn("h-3.5 w-3.5", className)}>
      <circle cx="12" cy="12" r="8" stroke="currentColor" strokeWidth="1.4" fill="none" />
      <circle cx="12" cy="4" r="1.7" fill="currentColor" />
    </svg>
  );
}

function WalletChip({
  label,
  address,
  glyph,
}: {
  label: string;
  address: string;
  glyph: React.ReactNode;
}) {
  const [status, setStatus] = useState<Status>("idle");

  function toggle() {
    if (status === "connected") return setStatus("idle");
    if (status === "connecting") return;
    setStatus("connecting");
    window.setTimeout(() => setStatus("connected"), 700);
  }

  const connected = status === "connected";

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={
        connected
          ? `${label} connected: ${address}. Click to disconnect.`
          : `Connect ${label} wallet`
      }
      title={connected ? address : `Connect ${label}`}
      className="group/chip flex items-center gap-2 px-3 py-2 text-left transition-colors hover:bg-surface-2 focus-visible:bg-surface-2 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-focus"
    >
      <span
        className={cn(
          "transition-colors",
          connected ? "text-success" : "text-faint group-hover/chip:text-muted-ink",
        )}
      >
        {glyph}
      </span>
      <span className="flex flex-col leading-tight">
        <span className="text-[0.625rem] tracking-[0.02em] text-faint">{label}</span>
        {status === "connecting" ? (
          // skeleton, not a spinner (DESIGN.md). Carries no meaning by color alone.
          <span className="mt-0.5 flex items-center gap-1.5 font-mono text-xs text-muted-ink">
            <span
              className="h-3 w-16 animate-pulse rounded bg-surface-2 motion-reduce:animate-none"
              aria-hidden
            />
            <span className="sr-only">Summoning…</span>
          </span>
        ) : connected ? (
          <span className="flex items-center gap-1.5 font-mono text-xs text-ink">
            <Check className="size-3 text-success" aria-hidden />
            {truncate(address)}
          </span>
        ) : (
          <span className="font-mono text-xs text-muted-ink group-hover/chip:text-ink">
            Connect
          </span>
        )}
      </span>
    </button>
  );
}

/** Stubbed dual-wallet status for the shell. Wires to wagmi + Stellar Wallets Kit later. */
export function WalletStatus({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "inline-flex items-stretch divide-x divide-hairline overflow-hidden rounded-lg border border-hairline bg-surface",
        className,
      )}
    >
      <WalletChip
        label="Sepolia"
        address="0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
        glyph={<EthGlyph />}
      />
      <WalletChip
        label="Stellar"
        address="GDUNATWENXVS3JZQHQ7WTBWUEZG6RT3TBQ3T7XK7CV2YK7V2QH7N6QH"
        glyph={<StellarGlyph />}
      />
    </div>
  );
}
