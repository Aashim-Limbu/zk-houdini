import assert from "node:assert/strict";
import { openJobArgs, reclaimArgs, claimArgs, getJobArgs, randomJobIdHex } from "./escrow.js";

const base = { contractId: "CID", source: "buyer", network: "testnet" };
const a = openJobArgs({ ...base, jobIdHex: "ab", buyer: "GB", seller: "GS", token: "CT",
  amount: "100000", inputHashHex: "11", imageIdHex: "ff", expectedVerdict: 0, reclaimSecs: 3600, challengeSecs: 60 });
assert.ok(a.includes("open_job"));
assert.ok(a.join(" ").includes("--network testnet"));
assert.ok(a.join(" ").includes("--expected_verdict 0"));
assert.ok(a.join(" ").includes("--reclaim_secs 3600"));
assert.ok(a.join(" ").includes("--challenge_secs 60"));

const r = reclaimArgs({ ...base, jobIdHex: "ab" });
assert.ok(r.includes("buyer_reclaim") && r.join(" ").includes("--job_id ab"));

const c = claimArgs({ ...base, jobIdHex: "ab" });
assert.ok(c.includes("claim") && c.join(" ").includes("--job_id ab"));

const g = getJobArgs({ ...base, jobIdHex: "ab" });
assert.ok(g.includes("get_job") && g.join(" ").includes("--job_id ab"));

// Explicit RPC form (used by the runner) overrides the alias.
const explicit = reclaimArgs({ contractId: "CID", source: "buyer",
  rpcUrl: "https://soroban-testnet.stellar.org", networkPassphrase: "Test SDF Network ; September 2015",
  jobIdHex: "ab" });
assert.ok(explicit.join(" ").includes("--rpc-url https://soroban-testnet.stellar.org"));
assert.ok(explicit.join(" ").includes('--network-passphrase Test SDF Network ; September 2015'));
assert.ok(!explicit.includes("--network"));

const id = randomJobIdHex();
assert.equal(id.length, 64);
assert.ok(/^[0-9a-f]{64}$/.test(id));
assert.notEqual(randomJobIdHex(), randomJobIdHex());

console.log("escrow args: all assertions passed");
