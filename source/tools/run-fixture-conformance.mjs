import {
  existsSync,
  readFileSync,
  statSync,
  symlinkSync,
} from 'node:fs';
import { join } from 'node:path';

import { assertFixtureResultsBytes } from './fixture-results-lib.mjs';
import { projectionRoot } from './source-projection-lib.mjs';
import {
  assertSyntheticCheckoutClean,
  createSyntheticCheckout,
  ignoreSyntheticTopLevelPath,
  removeSyntheticCheckout,
  runInCheckout,
} from './synthetic-checkout-lib.mjs';

const root = projectionRoot(import.meta.url);
const nodeModules = join(root, 'node_modules');
if (!existsSync(nodeModules) || !statSync(nodeModules).isDirectory()) {
  throw new Error('node_modules is required; run npm ci --ignore-scripts first');
}

const synthetic = createSyntheticCheckout(root);
const outputRoot = join(synthetic.container, 'conformance-output');
try {
  symlinkSync(nodeModules, join(synthetic.checkout, 'node_modules'), 'dir');
  ignoreSyntheticTopLevelPath(synthetic.checkout, 'node_modules');
  assertSyntheticCheckoutClean(synthetic.checkout);

  // Strict-union sorts before the consumer operation in the canonical runner.
  // Build only its ignored generated output as setup; the canonical runner
  // remains byte-exact and still executes the consumer operation itself.
  runInCheckout(synthetic.checkout, 'npm', [
    '--prefix',
    'packages/vouch-consumer',
    'run',
    'build',
  ]);
  assertSyntheticCheckoutClean(synthetic.checkout);

  for (const [command, args] of [
    ['cargo', ['fmt', '--all', '--', '--check']],
    [
      'cargo',
      [
        'clippy',
        '--workspace',
        '--all-targets',
        '--all-features',
        '--frozen',
        '--offline',
        '--',
        '-D',
        'warnings',
      ],
    ],
    ['cargo', ['test', '--frozen', '--offline', '-p', 'vouch']],
    [
      'cargo',
      ['test', '--frozen', '--offline', '-p', 'scored26-release-anchor'],
    ],
  ]) {
    runInCheckout(synthetic.checkout, command, args);
  }

  runInCheckout(
    synthetic.checkout,
    process.execPath,
    ['artifact/scripts/run-core-conformance.mjs'],
    { env: { SCORED26_OUTPUT_ROOT: outputRoot } }
  );

  const manifest = readFileSync(
    join(root, 'artifact/fixtures/fixture-manifest.json')
  );
  const committed = readFileSync(
    join(root, 'artifact/results/fixture-results.json')
  );
  const generated = readFileSync(
    join(outputRoot, 'artifact/results/fixture-results.json')
  );
  const validation = assertFixtureResultsBytes(generated, manifest);
  assertFixtureResultsBytes(committed, manifest);
  if (!generated.equals(committed)) {
    throw new Error(
      'regenerated fixture-results.json differs from the committed report'
    );
  }
  assertSyntheticCheckoutClean(synthetic.checkout);
  console.log(
    `fixture conformance regeneration passed (${validation.built}/${validation.built}, exact committed bytes)`
  );
} finally {
  removeSyntheticCheckout(synthetic);
}
