import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  buildManifest,
  canonicalJson,
  projectionRoot,
  scanProjection,
} from './source-projection-lib.mjs';
import { verifySyntheticHistoryBundle } from './synthetic-checkout-lib.mjs';

const root = projectionRoot(import.meta.url);
const expected = canonicalJson(buildManifest(root));
const actual = readFileSync(join(root, 'SOURCE-MANIFEST.json'));
if (!actual.equals(expected)) {
  throw new Error(
    'SOURCE-MANIFEST.json is stale; run node tools/build-source-manifest.mjs --write'
  );
}
const issues = scanProjection(root);
if (issues.length > 0) throw new Error(issues.join('\n'));
const manifest = JSON.parse(actual);
const history = verifySyntheticHistoryBundle(root);
const rows = new Map(manifest.files.map((row) => [row.path, row]));
for (const path of history.paths) {
  if (rows.get(path)?.origin !== 'source-snapshot-byte-exact') {
    throw new Error(`${path}: C0 path is not classified byte-exact`);
  }
}
for (const row of manifest.files) {
  if (
    row.origin === 'source-snapshot-byte-exact' &&
    !history.paths.has(row.path)
  ) {
    throw new Error(`${row.path}: byte-exact classification is absent from C0`);
  }
}
console.log(
  `source projection passed (${history.paths.size} byte-exact C0 files, ${manifest.summary.file_count} total review files, exact F/B/C0 bundle, TypeScript ${manifest.review_toolchain.version} local toolchain, no .git metadata or anonymity findings)`
);
