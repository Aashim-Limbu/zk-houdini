import assert from "node:assert/strict";
import { openJobArgs, reclaimArgs } from "./escrow.js";

const base = { contractId: "CID", source: "buyer", network: "testnet" };
const a = openJobArgs({ ...base, jobIdHex: "ab", buyer: "GB", seller: "GS", token: "CT",
  amount: "100000", inputHashHex: "11", imageIdHex: "ff", expectedVerdict: 0, reclaimSecs: 3600, challengeSecs: 60 });
assert.ok(a.includes("open_job"));
assert.ok(a.join(" ").includes("--expected_verdict 0"));
assert.ok(a.join(" ").includes("--reclaim_secs 3600"));
const r = reclaimArgs({ ...base, jobIdHex: "ab" });
assert.ok(r.includes("buyer_reclaim") && r.join(" ").includes("--job_id ab"));
console.log("escrow args: all assertions passed");
