import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const artifactDir = path.resolve(scriptDir, "..");
const expected = (
  await readFile(path.join(artifactDir, "contract", "SHA256"), "utf8")
).trim();
const contract = await readFile(
  path.join(artifactDir, "contract", "NATIVE-IMPLEMENTATION-CONDITIONS-v8.6.0.md"),
);
const actual = createHash("sha256").update(contract).digest("hex");
if (actual !== expected) {
  throw new Error(`contract SHA-256 mismatch: expected ${expected}, got ${actual}`);
}
console.log(`contract SHA-256 verified: ${actual}`);
