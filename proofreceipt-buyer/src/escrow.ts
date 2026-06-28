import { createHash } from "node:crypto";

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

type Base = { contractId: string; source: string; network: string };
type OpenJob = Base & {
  jobIdHex: string; buyer: string; seller: string; token: string; amount: string;
  inputHashHex: string; imageIdHex: string; expectedVerdict: number;
  reclaimSecs: number; challengeSecs: number;
};

function invokeBase(b: Base): string[] {
  return ["contract", "invoke", "--id", b.contractId, "--source", b.source, "--network", b.network, "--"];
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
