import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { writeArtifactJson } from './artifact-json.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const preExecution = process.argv.includes('--pre-execution');
const CLASSES = ['boundary', 'interior', 'invalid'];
const EXPECTED = {
  candidates: { boundary: 864, interior: 336, invalid: 336, total: 1536 },
  selected: { boundary: 144, interior: 48, invalid: 48, total: 240 },
  development: { boundary: 116, interior: 37, invalid: 39, total: 192 },
  held_out: { boundary: 28, interior: 11, invalid: 9, total: 48 },
};

function fail(message) {
  throw new Error(message);
}

function readCanonical(path) {
  const bytes = readFileSync(join(repoRoot, path));
  let value;
  try {
    value = JSON.parse(bytes);
  } catch (error) {
    fail(`${path}: invalid JSON: ${error.message}`);
  }
  if (!writeArtifactJson(value).equals(bytes))
    fail(`${path}: noncanonical artifact JSON`);
  return { bytes, value };
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest();
}

function digestId(bytes) {
  return `sha256:${digest(bytes).toString('hex')}`;
}

function parseDigest(value, subject) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value))
    fail(`${subject}: malformed digest`);
  return Buffer.from(value.slice(7), 'hex');
}

function selectionDigest(record) {
  return createHash('sha256')
    .update('vouch/workload-selection/v0', 'utf8')
    .update(Buffer.from([0]))
    .update(record.stratum_id, 'utf8')
    .update(Buffer.from([0]))
    .update(record.candidate_class, 'utf8')
    .update(Buffer.from([0]))
    .update(writeArtifactJson(record.input))
    .digest();
}

function splitDigest(record) {
  return createHash('sha256')
    .update('vouch/workload-split/v0', 'utf8')
    .update(Buffer.from([0]))
    .update(parseDigest(record.selection_sha256, record.candidate_id))
    .update(record.stratum_id, 'utf8')
    .update(Buffer.from([0]))
    .update(writeArtifactJson(record.input))
    .digest();
}

function count(records) {
  return {
    boundary: records.filter((record) => record.candidate_class === 'boundary')
      .length,
    interior: records.filter((record) => record.candidate_class === 'interior')
      .length,
    invalid: records.filter((record) => record.candidate_class === 'invalid')
      .length,
    total: records.length,
  };
}

function sameCounts(actual, expected, subject) {
  for (const key of Object.keys(expected)) {
    if (actual[key] !== expected[key]) {
      fail(
        `${subject}: expected ${JSON.stringify(expected)}, observed ${JSON.stringify(actual)}`
      );
    }
  }
}

function sameRecord(left, right) {
  return writeArtifactJson(left).equals(writeArtifactJson(right));
}

const space = readCanonical('artifact/workload/workload-space.json');
const candidates = readCanonical('artifact/workload/workload-candidates.json');
const selection = readCanonical('artifact/workload/workload-selection.json');
const split = readCanonical('artifact/workload/workload-split.json');
const holdout = readCanonical('artifact/workload/holdout-plan.json');

if (space.value.strata?.length !== 48)
  fail('workload space must contain S01-S48');
space.value.strata.forEach((stratum, index) => {
  const expected = `S${String(index + 1).padStart(2, '0')}`;
  if (stratum.stratum_id !== expected || stratum.thresholds?.length !== 6) {
    fail(`${expected}: stratum order or threshold count mismatch`);
  }
  const values = stratum.thresholds.map((record) => record.value);
  if (
    values[0] < 2 ||
    values.at(-1) > 999_998 ||
    values.some(
      (value, position) => position > 0 && value - values[position - 1] < 4
    )
  ) {
    fail(`${expected}: threshold spacing mismatch`);
  }
  for (const threshold of stratum.thresholds) {
    if (
      !Array.isArray(threshold.sources) ||
      threshold.sources.length !== 2 ||
      threshold.sources.some((source) => source.value !== threshold.value)
    ) {
      fail(`${expected}: threshold provenance mismatch`);
    }
  }
});

if (candidates.value.workload_space_sha256 !== digestId(space.bytes)) {
  fail('candidate manifest does not bind exact workload-space bytes');
}
sameCounts(
  count(candidates.value.candidates),
  EXPECTED.candidates,
  'candidate quantities'
);
const candidateById = new Map();
candidates.value.candidates.forEach((record, index) => {
  const expectedId = `C${String(index + 1).padStart(4, '0')}`;
  if (
    record.candidate_id !== expectedId ||
    candidateById.has(record.candidate_id)
  ) {
    fail(`${expectedId}: candidate identifier order/uniqueness mismatch`);
  }
  if (!CLASSES.includes(record.candidate_class))
    fail(`${expectedId}: candidate class mismatch`);
  const inputBytes = writeArtifactJson(record.input);
  if (record.canonical_input_sha256 !== digestId(inputBytes)) {
    fail(`${expectedId}: canonical input hash mismatch`);
  }
  const expectedSelection = selectionDigest(record);
  if (
    !parseDigest(record.selection_sha256, expectedId).equals(expectedSelection)
  ) {
    fail(`${expectedId}: selection hash mismatch`);
  }
  candidateById.set(record.candidate_id, record);
});

if (selection.value.workload_candidates_sha256 !== digestId(candidates.bytes)) {
  fail('selection does not bind exact candidate-manifest bytes');
}
sameCounts(
  count(selection.value.selected),
  EXPECTED.selected,
  'selection quantities'
);
const expectedSelected = [];
for (const stratum of space.value.strata) {
  const members = candidates.value.candidates.filter(
    (record) => record.stratum_id === stratum.stratum_id
  );
  for (const [candidateClass, quantity] of [
    ['boundary', 3],
    ['interior', 1],
    ['invalid', 1],
  ]) {
    expectedSelected.push(
      ...members
        .filter((record) => record.candidate_class === candidateClass)
        .sort((left, right) =>
          Buffer.compare(
            parseDigest(left.selection_sha256, left.candidate_id),
            parseDigest(right.selection_sha256, right.candidate_id)
          )
        )
        .slice(0, quantity)
    );
  }
}
selection.value.selected.forEach((record, index) => {
  if (!sameRecord(record, expectedSelected[index])) {
    fail(`selected index ${index}: manual/rank replacement detected`);
  }
});

if (split.value.workload_selection_sha256 !== digestId(selection.bytes)) {
  fail('split does not bind exact selection bytes');
}
const ranked = selection.value.selected.map((record) => ({
  record,
  digest: splitDigest(record),
}));
const heldIds = new Set();
for (const stratum of space.value.strata) {
  const first = ranked
    .filter(({ record }) => record.stratum_id === stratum.stratum_id)
    .sort((left, right) => Buffer.compare(left.digest, right.digest))[0];
  heldIds.add(first.record.candidate_id);
}
const expectedDevelopment = ranked
  .filter(({ record }) => !heldIds.has(record.candidate_id))
  .sort((left, right) => Buffer.compare(left.digest, right.digest));
const expectedHeldOut = ranked
  .filter(({ record }) => heldIds.has(record.candidate_id))
  .sort((left, right) => Buffer.compare(left.digest, right.digest));
sameCounts(
  count(expectedDevelopment.map(({ record }) => record)),
  EXPECTED.development,
  'development split'
);
sameCounts(
  count(expectedHeldOut.map(({ record }) => record)),
  EXPECTED.held_out,
  'held-out split'
);

const expectedCases = [
  ...expectedDevelopment.map(({ record, digest: value }, index) => ({
    ...record,
    case_id: `D${String(index + 1).padStart(3, '0')}`,
    partition: 'development',
    split_sha256: `sha256:${value.toString('hex')}`,
  })),
  ...expectedHeldOut.map(({ record, digest: value }, index) => ({
    ...record,
    case_id: `H${String(index + 1).padStart(3, '0')}`,
    partition: 'held-out',
    split_sha256: `sha256:${value.toString('hex')}`,
  })),
].sort((left, right) =>
  Buffer.compare(Buffer.from(left.case_id), Buffer.from(right.case_id))
);
if (split.value.cases.length !== expectedCases.length)
  fail('split case count mismatch');
split.value.cases.forEach((record, index) => {
  if (!sameRecord(record, expectedCases[index])) {
    fail(`${record.case_id ?? index}: split rank/stable-ID mismatch`);
  }
});

if (holdout.value.workload_split_sha256 !== digestId(split.bytes)) {
  fail('holdout plan does not bind exact split bytes');
}
const expectedHeldIds = expectedCases
  .filter((record) => record.partition === 'held-out')
  .map((record) => record.case_id);
if (
  JSON.stringify(holdout.value.held_out_case_ids) !==
  JSON.stringify(expectedHeldIds)
) {
  fail('holdout plan case identifiers differ from frozen split');
}
if (holdout.value.predicted_affected_strata?.length !== 48) {
  fail('holdout prediction protocol did not freeze all changed strata');
}

// Negative controls exercise this checker's independent comparisons.
const tampered = structuredClone(candidates.value.candidates[0]);
tampered.selection_sha256 = `sha256:${'0'.repeat(64)}`;
if (
  parseDigest(tampered.selection_sha256, 'negative').equals(
    selectionDigest(tampered)
  )
) {
  fail('selection-hash negative control failed to diverge');
}
const invalidSpacing = [2, 5, 9, 13, 17, 21];
if (
  !invalidSpacing.some(
    (value, index) => index > 0 && value - invalidSpacing[index - 1] < 4
  )
) {
  fail('empty-interior negative control failed to trigger');
}

if (preExecution) {
  for (const path of [
    'artifact/workload/workload-results.json',
    'artifact/workload/workload-metrics.csv',
    'generated/workload-results.tex',
  ]) {
    if (existsSync(join(repoRoot, path)))
      fail(`${path}: held-out result exists before freeze`);
  }
}

console.log(
  `SCORED26 workload freeze check passed (${EXPECTED.candidates.total}/${EXPECTED.selected.total}/` +
    `${EXPECTED.development.total}/${EXPECTED.held_out.total}${preExecution ? ', pre-execution clean' : ''})`
);
