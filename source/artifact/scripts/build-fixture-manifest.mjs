import { readFile, writeFile } from 'node:fs/promises';

import { writeArtifactJson } from './artifact-json.mjs';
import {
  buildManifest,
  loadInputs,
  manifestPath,
  validateManifest,
} from './fixture-manifest-lib.mjs';

const { registry, contractText } = await loadInputs();
const manifest = buildManifest(registry, contractText);
const errors = validateManifest(manifest, registry);
if (errors.length > 0) throw new Error(errors.join('\n'));
const expected = writeArtifactJson(manifest);

if (process.argv.includes('--write')) {
  await writeFile(manifestPath, expected);
  console.log(
    `wrote ${manifest.fixtures.length} rows to artifact/fixtures/fixture-manifest.json`
  );
} else {
  const actual = await readFile(manifestPath).catch(() => null);
  if (!actual || !actual.equals(expected)) {
    throw new Error(
      'fixture manifest is stale; run npm run gen:scored26-fixture-manifest'
    );
  }
  console.log(
    `fixture manifest current (${manifest.fixtures.length} generated rows)`
  );
}
