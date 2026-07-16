import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { writeArtifactJson } from "./artifact-json.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(scriptDir, "..", "tests", "cross-writer-goldens.json");
const fixture = JSON.parse(await readFile(fixturePath, "utf8"));

if (process.argv.includes("--write")) {
  for (const vector of fixture.vectors) {
    vector.expected_base64 = writeArtifactJson(vector.value).toString("base64");
  }
  await writeFile(fixturePath, writeArtifactJson(fixture));
}

if (fixture.cross_writer_goldens !== "csk.artifact-json-cross-writer/v0") {
  throw new Error("wrong cross-writer fixture version");
}
if (fixture.fixture_id !== "S1-CROSS-WRITER-01") {
  throw new Error("wrong cross-writer fixture id");
}
if (!Array.isArray(fixture.vectors) || fixture.vectors.length === 0) {
  throw new Error("cross-writer fixture has no vectors");
}

const ids = new Set();
const classes = new Set();
for (const vector of fixture.vectors) {
  if (ids.has(vector.id)) {
    throw new Error(`duplicate cross-writer vector id ${vector.id}`);
  }
  ids.add(vector.id);
  classes.add(vector.artifact_class);
  const actual = writeArtifactJson(vector.value);
  const expected = Buffer.from(vector.expected_base64, "base64");
  if (actual.toString("base64") !== vector.expected_base64 || !actual.equals(expected)) {
    throw new Error(`JavaScript canonical writer mismatch for ${vector.id}`);
  }
}

const requiredClasses = new Set(fixture.required_artifact_classes);
for (const artifactClass of requiredClasses) {
  if (!classes.has(artifactClass)) {
    throw new Error(`missing artifact class ${artifactClass}`);
  }
}
if (classes.size !== requiredClasses.size) {
  throw new Error("cross-writer fixture contains an undeclared artifact class");
}

for (const invalid of [1.5, -0, Number.POSITIVE_INFINITY, 9_007_199_254_740_992]) {
  try {
    writeArtifactJson(invalid);
    throw new Error(`writer accepted invalid number ${String(invalid)}`);
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
  }
}
try {
  writeArtifactJson("\ud800");
  throw new Error("writer accepted a lone surrogate");
} catch (error) {
  if (!(error instanceof TypeError)) throw error;
}

console.log(`cross-writer goldens valid: ${fixture.vectors.length} vectors, ${classes.size} artifact classes`);
