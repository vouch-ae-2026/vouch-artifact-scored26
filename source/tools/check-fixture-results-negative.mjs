import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { writeArtifactJson } from '../artifact/scripts/artifact-json.mjs';
import { assertFixtureResultsBytes } from './fixture-results-lib.mjs';
import { projectionRoot } from './source-projection-lib.mjs';

const root = projectionRoot(import.meta.url);
const manifest = readFileSync(join(root, 'artifact/fixtures/fixture-manifest.json'));
const base = JSON.parse(
  readFileSync(join(root, 'artifact/results/fixture-results.json'), 'utf8')
);
let rejected = 0;

expectRejected('missing-row', (value) => value.results.pop());
expectRejected('duplicate-id', (value) => {
  value.results[1].fixture_id = value.results[0].fixture_id;
});
expectRejected('changed-outcome', (value) => {
  value.results[0].matched = false;
});
expectRejected('changed-accounting', (value) => {
  value.fixture_results.built.matched -= 1;
});
expectRejected('extra-field', (value) => {
  value.results[0].unexpected = true;
});
try {
  const valid = writeArtifactJson(base);
  assertFixtureResultsBytes(Buffer.concat([valid, Buffer.from(' ')]), manifest);
  throw new Error('negative control was accepted: noncanonical-bytes');
} catch (error) {
  if (error.message === 'negative control was accepted: noncanonical-bytes') throw error;
  rejected += 1;
}

console.log(`fixture result negative controls passed (${rejected}/6 rejected)`);

function expectRejected(label, mutate) {
  const value = structuredClone(base);
  mutate(value);
  try {
    assertFixtureResultsBytes(writeArtifactJson(value), manifest);
    throw new Error(`negative control was accepted: ${label}`);
  } catch (error) {
    if (error.message === `negative control was accepted: ${label}`) throw error;
    rejected += 1;
  }
}
