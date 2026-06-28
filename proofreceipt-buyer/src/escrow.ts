import { createHash, randomBytes } from "node:crypto";

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** A fresh 32-byte job id as 64 hex chars (the contract's BytesN<32>). */
export function randomJobIdHex(): string {
  return randomBytes(32).toString("hex");
}

// A `Base` selects the network either by CLI alias (`network`) or by explicit
// RPC url + passphrase. The explicit form wins when present — it sidesteps a
// `stellar` quirk where the `--network testnet` alias can mis-resolve URLs.
type Base = {
  contractId: string;
  source: string;
  network?: string;
  rpcUrl?: string;
  networkPassphrase?: string;
};
type OpenJob = Base & {
  jobIdHex: string; buyer: string; seller: string; token: string; amount: string;
  inputHashHex: string; imageIdHex: string; expectedVerdict: number;
  reclaimSecs: number; challengeSecs: number;
};

function networkArgs(b: Base): string[] {
  return b.rpcUrl
    ? ["--rpc-url", b.rpcUrl, "--network-passphrase", b.networkPassphrase ?? ""]
    : ["--network", b.network ?? "testnet"];
}

function invokeBase(b: Base): string[] {
  return ["contract", "invoke", "--id", b.contractId, "--source", b.source, ...networkArgs(b), "--"];
}

export function openJobArgs(p: OpenJob): string[] {
  return [...invokeBase(p), "open_job",
    "--job_id", p.jobIdHex, "--buyer", p.buyer, "--seller", p.seller,
    "--token_addr", p.token, "--amount", p.amount,
    "--expected_input_hash", p.inputHashHex, "--expected_image_id", p.imageIdHex,
    "--expected_verdict", String(p.expectedVerdict),
    "--reclaim_secs", String(p.reclaimSecs), "--challenge_secs", String(p.challengeSecs)];
}

export function reclaimArgs(b: Base & { jobIdHex: string }): string[] {
  return [...invokeBase(b), "buyer_reclaim", "--job_id", b.jobIdHex];
}

/** `claim` is signed by the seller — pays out a Proven job after its challenge window. */
export function claimArgs(b: Base & { jobIdHex: string }): string[] {
  return [...invokeBase(b), "claim", "--job_id", b.jobIdHex];
}

/** `get_job` is a read — used to poll the job's status. */
export function getJobArgs(b: Base & { jobIdHex: string }): string[] {
  return [...invokeBase(b), "get_job", "--job_id", b.jobIdHex];
}
