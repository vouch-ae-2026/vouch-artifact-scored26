import { generateKeyPairSync } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  buildReplayManifest,
  signReplayManifest,
} from './replay-manifest-lib.mjs';
import {
  buildWorkloadResultArtifacts,
  RESULT_PATHS,
} from './workload-results-lib.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const outputRoot = process.env.SCORED26_OUTPUT_ROOT
  ? join(process.env.SCORED26_OUTPUT_ROOT)
  : repoRoot;
const artifactFreezeCommit = 'c90f97ddd6b1d662791a76fe4663b90e79c443ec';
const frozenPaths = [
  'artifact/workload/parameters/baseline.json',
  'artifact/workload/parameters/changed.json',
  'artifact/workload/rules/baseline.lspx',
  'artifact/workload/rules/changed.lspx',
  'artifact/workload/workload-space.json',
  'artifact/workload/workload-candidates.json',
  'artifact/workload/workload-selection.json',
  'artifact/workload/workload-split.json',
  'artifact/workload/holdout-plan.json',
];
const write = process.argv.slice(2).includes('--write');
const unknown = process.argv.slice(2).filter((value) => value !== '--write');
if (unknown.length !== 0) fail(`unknown argument ${unknown[0]}`);

function fail(message) {
  console.error(
    `SCORED26 workload result ${write ? 'generation' : 'reproduction'} failed: ${message}`
  );
  process.exit(1);
}

function command(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: options.cwd ?? repoRoot,
    encoding: options.encoding ?? 'utf8',
    env: options.env ?? process.env,
    maxBuffer: 64 * 1024 * 1024,
    timeout: options.timeout ?? 15 * 60 * 1000,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${program} ${args.join(' ')} failed (status ${result.status})\n` +
        `${result.stdout ?? ''}${result.stderr ?? ''}${result.error?.message ?? ''}`
    );
  }
  return result;
}

function gitBytes(args, cwd = repoRoot) {
  return command('git', args, { cwd, encoding: 'buffer' }).stdout;
}

function assertCleanSource() {
  const status = command(
    'git',
    ['status', '--porcelain=v1', '--untracked-files=all'],
    { cwd: repoRoot }
  ).stdout;
  if (status !== '') {
    throw new Error('source worktree and index must be clean');
  }
  command('git', ['merge-base', '--is-ancestor', artifactFreezeCommit, 'HEAD']);
  for (const path of frozenPaths) {
    const frozen = gitBytes(['show', `${artifactFreezeCommit}:${path}`]);
    const current = readFileSync(join(repoRoot, path));
    if (!current.equals(frozen)) {
      throw new Error(`${path}: differs from ArtifactFreezeCommit`);
    }
  }
  for (const path of Object.values(RESULT_PATHS)) {
    const lookup = spawnSync(
      'git',
      ['cat-file', '-e', `${artifactFreezeCommit}:${path}`],
      { cwd: repoRoot, encoding: 'utf8' }
    );
    if (lookup.status === 0) {
      throw new Error(
        `${path}: result unexpectedly existed at ArtifactFreezeCommit`
      );
    }
  }
}

function cleanBuildEnvironment(targetDir) {
  const env = { ...process.env, CARGO_TARGET_DIR: targetDir };
  for (const name of [
    'RUSTFLAGS',
    'CARGO_ENCODED_RUSTFLAGS',
    'SCORED_MUTANT',
    'LISPEX_BUILD_COMMIT_HEX',
    'LISPEX_BUILD_COMMIT_DIRTY',
    'GITHUB_SHA',
  ]) {
    delete env[name];
  }
  env.CARGO_TERM_COLOR = 'never';
  return env;
}

let temporaryRoot;
let detachedRoot;
try {
  assertCleanSource();
  const head = command('git', ['rev-parse', '--verify', 'HEAD']).stdout.trim();
  if (!/^[0-9a-f]{40}$/.test(head)) throw new Error('HEAD is not full 40-hex');

  temporaryRoot = mkdtempSync(join(tmpdir(), 'lispex-stage8-results-'));
  detachedRoot = join(temporaryRoot, 'source');
  command('git', ['worktree', 'add', '--detach', detachedRoot, head]);
  const detachedHead = command('git', ['rev-parse', '--verify', 'HEAD'], {
    cwd: detachedRoot,
  }).stdout.trim();
  const symbolic = spawnSync('git', ['symbolic-ref', '-q', 'HEAD'], {
    cwd: detachedRoot,
    encoding: 'utf8',
  });
  const detachedStatus = command(
    'git',
    ['status', '--porcelain=v1', '--untracked-files=all'],
    { cwd: detachedRoot }
  ).stdout;
  if (detachedHead !== head || symbolic.status === 0 || detachedStatus !== '') {
    throw new Error('ephemeral release source is not the clean detached HEAD');
  }

  const generated = buildReplayManifest(detachedRoot);
  const keyPair = generateKeyPairSync('ed25519');
  const privateKeyDer = keyPair.privateKey.export({
    format: 'der',
    type: 'pkcs8',
  });
  const signed = signReplayManifest(generated.payloadBytes, privateKeyDer);
  const inputRoot = join(temporaryRoot, 'inputs');
  mkdirSync(inputRoot);
  const paths = {
    envelope: join(inputRoot, 'replay-manifest.dsse.json'),
    policy: join(inputRoot, 'trust-policy.json'),
    corpus: join(inputRoot, 'corpus.json'),
    key: join(inputRoot, 'release-key.pk8'),
    receipts: join(temporaryRoot, 'receipts'),
    execution: join(temporaryRoot, 'workload-execution.json'),
    target: join(temporaryRoot, 'target'),
  };
  writeFileSync(paths.envelope, signed.envelopeBytes);
  writeFileSync(paths.policy, signed.policyBytes);
  writeFileSync(paths.corpus, generated.corpusBytes);
  writeFileSync(paths.key, privateKeyDer, { mode: 0o600 });

  const env = cleanBuildEnvironment(paths.target);
  command(
    'cargo',
    [
      'build',
      '--release',
      '--locked',
      '--manifest-path',
      'interp/Cargo.toml',
      '--features',
      'scored-native-contract',
      '--bin',
      'scored26-workload-runner',
    ],
    { cwd: detachedRoot, env }
  );
  const runner = join(paths.target, 'release', 'scored26-workload-runner');
  const run = command(
    runner,
    [
      '--envelope',
      paths.envelope,
      '--trust-policy',
      paths.policy,
      '--baseline-rule',
      join(detachedRoot, 'artifact/workload/rules/baseline.lspx'),
      '--changed-rule',
      join(detachedRoot, 'artifact/workload/rules/changed.lspx'),
      '--workload-space',
      join(detachedRoot, 'artifact/workload/workload-space.json'),
      '--workload-selection',
      join(detachedRoot, 'artifact/workload/workload-selection.json'),
      '--workload-split',
      join(detachedRoot, 'artifact/workload/workload-split.json'),
      '--holdout-plan',
      join(detachedRoot, 'artifact/workload/holdout-plan.json'),
      '--corpus',
      paths.corpus,
      '--key-handle',
      `pkcs8-file://${paths.key}`,
      '--receipt-root',
      paths.receipts,
      '--execution-report',
      paths.execution,
    ],
    { cwd: detachedRoot, env }
  );
  const artifacts = buildWorkloadResultArtifacts(
    detachedRoot,
    readFileSync(paths.execution)
  );
  for (const [path, expected] of artifacts.files) {
    const destination = join(outputRoot, path);
    if (write) {
      mkdirSync(dirname(destination), { recursive: true });
      writeFileSync(destination, expected);
    } else {
      let actual;
      try {
        actual = readFileSync(destination);
      } catch (error) {
        throw new Error(`${path}: ${error.message}`);
      }
      if (!actual.equals(expected)) {
        throw new Error(`${path}: differs from authenticated reproduction`);
      }
    }
  }
  process.stdout.write(run.stdout);
  console.log(
    `SCORED26 workload result ${write ? 'generation' : 'reproduction'} passed ` +
      `(clean detached ${head.slice(0, 12)}, 240 cases/480 receipts)`
  );
} catch (error) {
  console.error(
    `SCORED26 workload result ${write ? 'generation' : 'reproduction'} failed: ${error.message}`
  );
  process.exitCode = 1;
} finally {
  if (detachedRoot) {
    spawnSync('git', ['worktree', 'remove', '--force', detachedRoot], {
      cwd: repoRoot,
      encoding: 'utf8',
    });
  }
  if (temporaryRoot) rmSync(temporaryRoot, { recursive: true, force: true });
}
