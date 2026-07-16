import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const result = spawnSync(
  process.execPath,
  ["../../node_modules/typescript/bin/tsc", "-p", "test/type-negative-tsconfig.json"],
  { cwd: new URL("..", import.meta.url), encoding: "utf8" },
);
assert.notEqual(result.status, 0, "negative TypeScript fixture unexpectedly compiled");
const output = `${result.stdout}${result.stderr}`;
assert.match(output, /TS2345/g);
assert.equal((output.match(/TS2345/g) ?? []).length, 2);
console.log("vouch-consumer type-negative fixtures passed");
