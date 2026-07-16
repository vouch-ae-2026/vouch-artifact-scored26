import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { writeArtifactJson } from './artifact-json.mjs';
import {
  loadInputs,
  manifestPath,
  validateManifest,
} from './fixture-manifest-lib.mjs';

const { registry } = await loadInputs();
const bytes = await readFile(manifestPath);
const manifest = JSON.parse(bytes.toString('utf8'));
assert.deepEqual(
  writeArtifactJson(manifest),
  bytes,
  'manifest is not canonical artifact JSON'
);
assert.deepEqual(validateManifest(manifest, registry), []);

const duplicate = structuredClone(manifest);
duplicate.fixtures.push(structuredClone(duplicate.fixtures[0]));
assert(
  validateManifest(duplicate, registry).some((error) =>
    error.startsWith('fixture-duplicate-')
  )
);

const missing = structuredClone(manifest);
const removed = missing.fixtures.pop();
assert(
  validateManifest(missing, registry).includes(
    `fixture-missing-${removed.fixture_id}`
  )
);

const unknown = structuredClone(manifest);
unknown.fixtures[0].fixture_id = 'UNKNOWN-FIXTURE';
assert(
  validateManifest(unknown, registry).includes(
    'fixture-unknown-UNKNOWN-FIXTURE'
  )
);

const malformed = structuredClone(manifest);
malformed.fixtures[0].unexpected = true;
assert(validateManifest(malformed, registry).includes('fixture-row-0-fields'));

console.log(
  `fixture manifest check passed (${manifest.fixtures.length} rows; negative duplicate/missing/unknown/shape controls)`
);
