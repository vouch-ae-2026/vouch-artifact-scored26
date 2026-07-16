import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { assertFixtureResultsBytes } from './fixture-results-lib.mjs';
import { projectionRoot } from './source-projection-lib.mjs';

const root = projectionRoot(import.meta.url);
const validated = assertFixtureResultsBytes(
  readFileSync(join(root, 'artifact/results/fixture-results.json')),
  readFileSync(join(root, 'artifact/fixtures/fixture-manifest.json'))
);
console.log(
  `fixture result report passed (${validated.built}/${validated.built} built matched, canonical IDs and accounting)`
);
