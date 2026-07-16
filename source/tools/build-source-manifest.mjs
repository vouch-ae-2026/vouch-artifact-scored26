import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  buildManifest,
  canonicalJson,
  projectionRoot,
} from './source-projection-lib.mjs';

if (process.argv.length !== 3 || process.argv[2] !== '--write') {
  throw new Error('usage: node tools/build-source-manifest.mjs --write');
}

const root = projectionRoot(import.meta.url);
const bytes = canonicalJson(buildManifest(root));
writeFileSync(join(root, 'SOURCE-MANIFEST.json'), bytes);
console.log(`wrote SOURCE-MANIFEST.json (${bytes.length} bytes)`);

