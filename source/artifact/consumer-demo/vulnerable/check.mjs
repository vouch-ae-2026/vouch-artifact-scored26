import assert from "node:assert/strict";

import { reduceCheckerReport, renderBooleanResult } from "./index.mjs";

const b01 = Object.freeze({
  bridge_verify_report: "vouch.bridge-verify-report/v0",
  status: "checked-external",
  primary_error: null,
});
assert.deepEqual(reduceCheckerReport(b01), { ok: true });
assert.equal(renderBooleanResult(reduceCheckerReport(b01)), "Verified");
console.log("intentional vulnerable consumer displays Verified for B01");
