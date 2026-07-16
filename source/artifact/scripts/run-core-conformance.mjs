import { spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { writeArtifactJson } from './artifact-json.mjs';
import {
  artifactDir,
  buildManifest,
  loadInputs,
  manifestPath,
  validateManifest,
} from './fixture-manifest-lib.mjs';

const repoRoot = path.resolve(artifactDir, '..');
const outputRoot = process.env.SCORED26_OUTPUT_ROOT
  ? path.resolve(process.env.SCORED26_OUTPUT_ROOT)
  : repoRoot;
const resultsPath = path.join(
  outputRoot,
  'artifact',
  'results',
  'fixture-results.json'
);
const operations = new Map([
  [
    'rust-public-contract-lane',
    [
      'cargo',
      [
        'test',
        '--manifest-path',
        'interp/Cargo.toml',
        '--features',
        'scored-native-contract',
        '--locked',
      ],
    ],
  ],
  [
    'vouch-consumer-public-api',
    ['npm', ['--prefix', 'packages/vouch-consumer', 'run', 'check']],
  ],
  [
    'strict-union-baseline',
    ['node', ['artifact/scripts/check-strict-union.mjs']],
  ],
  [
    'cross-writer-goldens',
    ['node', ['artifact/scripts/check-cross-writer-goldens.mjs']],
  ],
  [
    'fixture-manifest-negative',
    ['node', ['artifact/scripts/check-fixture-manifest.mjs']],
  ],
  [
    'scored26-workload-freeze',
    ['npm', ['run', 'check:scored26-workload-freeze']],
  ],
  [
    'scored26-workload-results',
    ['npm', ['run', 'check:scored26-workload-results']],
  ],
  [
    'scored26-condition-ledger',
    ['npm', ['run', 'check:scored26-condition-ledger']],
  ],
  [
    'scored26-mutation-mechanism',
    ['npm', ['run', 'check:scored26-mutation-mechanism']],
  ],
  [
    'scored26-mutation-results',
    ['npm', ['run', 'check:scored26-mutation-results']],
  ],
  [
    'scored26-release-schema',
    ['npm', ['run', 'check:scored26-release-schema']],
  ],
  [
    'scored26-release-finalizer',
    ['npm', ['run', 'check:scored26-release-finalizer']],
  ],
  [
    'scored26-release-publication',
    ['npm', ['run', 'check:scored26-release-publication']],
  ],
  [
    'scored26-release-supply',
    ['npm', ['run', 'check:scored26-release-supply']],
  ],
  ['scored26-clean-room', ['npm', ['run', 'check:scored26-clean-room']]],
  [
    'replay-manifest-public-api',
    ['npm', ['run', 'check:scored26-replay-manifest']],
  ],
]);

const { registry, contractText } = await loadInputs();
const manifestBytes = await readFile(manifestPath);
const manifest = JSON.parse(manifestBytes.toString('utf8'));
const expectedManifest = writeArtifactJson(
  buildManifest(registry, contractText)
);
if (!manifestBytes.equals(expectedManifest)) {
  throw new Error('fixture manifest is stale or noncanonical');
}
const manifestErrors = validateManifest(manifest, registry);
if (manifestErrors.length > 0) throw new Error(manifestErrors.join('\n'));

const requiredOperations = [
  ...new Set(
    manifest.fixtures
      .filter((row) => row.scope === 'built')
      .map((row) => row.command_or_api_operation)
  ),
].sort();
const outcomes = new Map();
for (const operation of requiredOperations) {
  const command = operations.get(operation);
  if (!command) {
    outcomes.set(operation, {
      matched: false,
      diagnostic: 'unknown-operation',
    });
    continue;
  }
  const [program, args] = command;
  console.log(`fixture operation: ${operation}`);
  const result = spawnSync(program, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { ...process.env, CARGO_TERM_COLOR: 'never', NO_COLOR: '1' },
  });
  const matched = result.status === 0;
  outcomes.set(operation, {
    matched,
    diagnostic: matched
      ? null
      : `${program} exited ${result.status}\n${result.stdout}\n${result.stderr}`,
  });
}

const details = manifest.fixtures.map((row) => {
  if (row.scope === 'design-target') {
    return {
      fixture_id: row.fixture_id,
      scope: row.scope,
      implemented: false,
      matched: false,
      operation: row.command_or_api_operation,
    };
  }
  const outcome = outcomes.get(row.command_or_api_operation);
  return {
    fixture_id: row.fixture_id,
    scope: row.scope,
    implemented: true,
    matched: outcome?.matched === true,
    operation: row.command_or_api_operation,
  };
});
const built = details.filter((row) => row.scope === 'built');
const designTarget = details.filter((row) => row.scope === 'design-target');
const matched = built.filter((row) => row.matched).length;
const report = {
  fixture_report: 'vouch.scored26-fixture/v0',
  fixture_results: {
    built: {
      expected: built.length,
      matched,
      mismatched: built.length - matched,
      skipped: 0,
    },
    design_target: {
      listed: designTarget.length,
      implemented: designTarget.filter((row) => row.implemented).length,
      matched: designTarget.filter((row) => row.matched).length,
      not_implemented: designTarget.filter((row) => !row.implemented).length,
    },
  },
  results: details,
};
await mkdir(path.dirname(resultsPath), { recursive: true });
await writeFile(resultsPath, writeArtifactJson(report));

const failures = [...outcomes.entries()].filter(
  ([, outcome]) => !outcome.matched
);
if (failures.length > 0) {
  for (const [operation, outcome] of failures) {
    console.error(`${operation}: ${outcome.diagnostic}`);
  }
  throw new Error(`${failures.length} built fixture operation(s) failed`);
}
if (matched !== built.length)
  throw new Error('built fixture accounting mismatch');
console.log(
  `SCORED26 core conformance passed (${built.length}/${built.length} built matched, 0 skipped; ${designTarget.length} design targets listed)`
);
