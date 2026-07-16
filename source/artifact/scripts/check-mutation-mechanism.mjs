import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { writeArtifactJson } from './artifact-json.mjs';
import {
  MUTANT_IDS,
  MUTATION_REGISTRY,
  mutationInternalsForTest,
} from './mutation-results-lib.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const buildNegatives = process.argv.slice(2).includes('--build-negatives');
const unknown = process.argv
  .slice(2)
  .filter((value) => value !== '--build-negatives');
if (unknown.length !== 0) fail(`unknown argument ${unknown[0]}`);

function fail(message) {
  console.error(`SCORED26 mutation mechanism check failed: ${message}`);
  process.exit(1);
}

function source(path) {
  return readFileSync(join(repoRoot, path), 'utf8');
}

function failedCargo(envPatch) {
  const env = { ...process.env, CARGO_TERM_COLOR: 'never', ...envPatch };
  for (const key of ['SCORED_MUTANT', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS']) {
    if (!(key in envPatch)) delete env[key];
  }
  const result = spawnSync(
    'cargo',
    [
      'check',
      '--locked',
      '--manifest-path',
      'interp/Cargo.toml',
      '--features',
      'scored-native-contract',
      '--lib',
    ],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      env,
      maxBuffer: 32 * 1024 * 1024,
      timeout: 10 * 60 * 1000,
    }
  );
  return result.status !== 0;
}

try {
  const suitePath = join(repoRoot, 'artifact/mutation/activation-suite.json');
  const suiteBytes = readFileSync(suitePath);
  const suite = JSON.parse(suiteBytes);
  if (!writeArtifactJson(suite).equals(suiteBytes)) {
    throw new Error('activation suite is not canonical csk.artifact-json/v0');
  }
  mutationInternalsForTest.validateActivationSuite(suite);

  const allRust = [
    ...new Set(MUTATION_REGISTRY.map((entry) => entry.sourceFile)),
  ]
    .map(source)
    .join('\n');
  for (const id of MUTANT_IDS) {
    const marker = `SCORED-MUTATION-SITE ${id}`;
    const markerCount = allRust.split(marker).length - 1;
    const cfgCount = allRust.split(`scored_mutant = "${id}"`).length - 1;
    if (markerCount !== 1 || cfgCount < 1) {
      throw new Error(
        `${id}: expected one semantic-site marker with compile-time selection`
      );
    }
  }

  const guard = source('interp/src/scored_mutation_guard.rs');
  const interpBuild = source('interp/build.rs');
  const vouchBuild = source('vouch/build.rs');
  for (const id of MUTANT_IDS) {
    if (
      !guard.includes(`cfg!(scored_mutant = "${id}")`) ||
      !interpBuild.includes(`"${id}"`) ||
      !vouchBuild.includes(`"${id}"`)
    ) {
      throw new Error(
        `${id}: missing from build validation or compile-time guard`
      );
    }
  }
  for (const build of [interpBuild, vouchBuild]) {
    if (
      !build.includes('cargo:rerun-if-env-changed=SCORED_MUTANT') ||
      !build.includes('CSK_SCORED_MUTANT') ||
      !build.includes('M01 through M12')
    ) {
      throw new Error(
        'one participating build script lacks closed mutant validation'
      );
    }
  }
  if (
    !guard.includes('#[cfg(scored_mutant_injected)]') ||
    !guard.includes('ACTIVE_SCORED_MUTANTS == 0') ||
    (guard.match(/ACTIVE_SCORED_MUTANTS == 1/g) ?? []).length !== 12
  ) {
    throw new Error('compile-time mutant integrity guard is incomplete');
  }

  const mutationRunner = source('interp/src/vouch_native/mutation.rs').split(
    '#[cfg(test)]'
  )[0];
  for (const forbidden of [
    'issue_native(',
    'LoadedReleaseKey',
    'KeyProvider',
    'ed25519',
    'sign_dsse',
    'payloadType',
    'signatures',
  ]) {
    if (mutationRunner.includes(forbidden)) {
      throw new Error(
        `keyless runner contains forbidden release path token ${forbidden}`
      );
    }
  }
  const cli = source('interp/src/bin/scored26-mutation-runner.rs');
  if (
    cli.includes('issue-native') ||
    cli.includes('LoadedReleaseKey') ||
    cli.includes('KeyProvider') ||
    !cli.includes('key_handle_and_mutant_selector_are_not_cli_arguments')
  ) {
    throw new Error(
      'mutation experiment CLI crosses the release issuer/key boundary'
    );
  }

  const m10 = suite.cases.find((row) => row.mutant_id === 'M10');
  if (!m10.source.includes('\n') || m10.source.includes('\\n')) {
    throw new Error('M10 witness must carry an actual U+000A scalar');
  }

  if (buildNegatives) {
    if (!failedCargo({ SCORED_MUTANT: 'M13' })) {
      throw new Error(
        'unknown SCORED_MUTANT negative build unexpectedly passed'
      );
    }
    if (!failedCargo({ RUSTFLAGS: '--cfg scored_mutant' })) {
      throw new Error(
        'injected scored_mutant cfg negative build unexpectedly passed'
      );
    }
    if (
      !failedCargo({
        RUSTFLAGS: '--cfg scored_mutant="M01" --cfg scored_mutant="M02"',
      })
    ) {
      throw new Error(
        'multiple scored_mutant cfg negative build unexpectedly passed'
      );
    }
  }

  console.log(
    `SCORED26 mutation mechanism check passed (12 single-site selectors${
      buildNegatives ? ', build negatives' : ''
    })`
  );
} catch (error) {
  fail(error.message);
}
