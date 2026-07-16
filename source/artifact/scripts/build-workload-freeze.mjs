import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { generateFreezeArtifacts } from './workload-lib.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const write = process.argv.includes('--write');

function fail(message) {
  console.error(
    `SCORED26 workload freeze ${write ? 'generation' : 'check'} failed: ${message}`
  );
  process.exit(1);
}

let generated;
try {
  generated = await generateFreezeArtifacts(repoRoot);
} catch (error) {
  fail(error.stack ?? error.message);
}

for (const [relative, bytes] of generated.files) {
  const path = join(repoRoot, relative);
  if (write) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, bytes);
    continue;
  }
  if (!existsSync(path)) fail(`${relative} is missing`);
  const actual = readFileSync(path);
  if (!actual.equals(bytes))
    fail(`${relative} differs from deterministic regeneration`);
}

const split = generated.values.split;
console.log(
  `SCORED26 workload freeze ${write ? 'generated' : 'check passed'} ` +
    `(${generated.values.candidates.counts.total} candidates, ` +
    `${generated.values.selection.counts.total} selected, ` +
    `${split.counts.development.total} development, ${split.counts.held_out.total} held out)`
);
