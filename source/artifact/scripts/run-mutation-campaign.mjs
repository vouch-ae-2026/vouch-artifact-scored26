import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { writeArtifactJson } from './artifact-json.mjs';
import {
  buildReplayManifest,
  signReplayManifest,
} from './replay-manifest-lib.mjs';
import { buildMutationArtifacts, MUTANT_IDS } from './mutation-results-lib.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const outputRoot = process.env.SCORED26_OUTPUT_ROOT
  ? join(process.env.SCORED26_OUTPUT_ROOT)
  : repoRoot;
const releaseRun = process.env.SCORED26_RELEASE_RUN === '1';
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
    `SCORED26 mutation campaign ${write ? 'generation' : 'reproduction'} failed: ${message}`
  );
  process.exit(1);
}

function command(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: options.cwd ?? repoRoot,
    encoding: options.encoding ?? 'utf8',
    env: options.env ?? process.env,
    maxBuffer: 128 * 1024 * 1024,
    timeout: options.timeout ?? 30 * 60 * 1000,
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
  if (status !== '') throw new Error('source worktree and index must be clean');
  command('git', ['merge-base', '--is-ancestor', artifactFreezeCommit, 'HEAD']);
  for (const path of frozenPaths) {
    const frozen = gitBytes(['show', `${artifactFreezeCommit}:${path}`]);
    if (!readFileSync(join(repoRoot, path)).equals(frozen)) {
      throw new Error(`${path}: differs from ArtifactFreezeCommit`);
    }
  }
}

function cleanBuildEnvironment(targetDir, mutantId) {
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
  if (mutantId !== 'baseline') env.SCORED_MUTANT = mutantId;
  env.CARGO_TERM_COLOR = 'never';
  return env;
}

function digestId(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

let temporaryRoot;
let detachedRoot;
try {
  assertCleanSource();
  const head = command('git', ['rev-parse', '--verify', 'HEAD']).stdout.trim();
  if (!/^[0-9a-f]{40}$/.test(head)) throw new Error('HEAD is not full 40-hex');
  const committedManifest = join(
    repoRoot,
    'artifact/mutation/mutation-manifest.json'
  );
  let mutationSourceCommit = head;
  if (!releaseRun && existsSync(committedManifest)) {
    const manifestBytes = readFileSync(committedManifest);
    const manifest = JSON.parse(manifestBytes);
    if (!writeArtifactJson(manifest).equals(manifestBytes)) {
      throw new Error('committed mutation manifest is not canonical');
    }
    if (!/^[0-9a-f]{40}$/.test(manifest.mutation_source_commit)) {
      throw new Error('committed mutation manifest has no valid source commit');
    }
    mutationSourceCommit = manifest.mutation_source_commit;
    command('git', ['merge-base', '--is-ancestor', mutationSourceCommit, head]);
  }
  command('git', [
    'merge-base',
    '--is-ancestor',
    artifactFreezeCommit,
    mutationSourceCommit,
  ]);

  const deterministicRoot = join(
    tmpdir(),
    `lispex-stage9-campaign-${mutationSourceCommit}`
  );
  mkdirSync(deterministicRoot, { mode: 0o700 });
  temporaryRoot = deterministicRoot;
  detachedRoot = join(temporaryRoot, 'source');
  command('git', [
    'worktree',
    'add',
    '--detach',
    detachedRoot,
    mutationSourceCommit,
  ]);
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
  if (
    detachedHead !== mutationSourceCommit ||
    symbolic.status === 0 ||
    detachedStatus !== ''
  ) {
    throw new Error('ephemeral mutation source is not the clean detached HEAD');
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
  const inputs = {
    corpus: join(inputRoot, 'corpus.json'),
    envelope: join(inputRoot, 'replay-manifest.dsse.json'),
    policy: join(inputRoot, 'trust-policy.json'),
  };
  writeFileSync(inputs.corpus, generated.corpusBytes);
  writeFileSync(inputs.envelope, signed.envelopeBytes);
  writeFileSync(inputs.policy, signed.policyBytes);
  // The private replay key is intentionally never written or passed to the runner.

  const targetDir = join(temporaryRoot, 'target');
  const binaryRoot = join(temporaryRoot, 'binaries');
  mkdirSync(binaryRoot);
  const executions = new Map();
  const observedBinaryDigests = new Set();
  for (const id of ['baseline', ...MUTANT_IDS]) {
    const env = cleanBuildEnvironment(targetDir, id);
    command(
      'cargo',
      [
        'build',
        '--release',
        ...(releaseRun ? ['--frozen', '--offline'] : []),
        '--locked',
        '--manifest-path',
        'interp/Cargo.toml',
        '--features',
        'scored-native-contract',
        '--bin',
        'scored26-mutation-runner',
      ],
      { cwd: detachedRoot, env }
    );
    const built = join(targetDir, 'release', 'scored26-mutation-runner');
    const binary = join(binaryRoot, `scored26-mutation-runner-${id}`);
    copyFileSync(built, binary);
    chmodSync(binary, 0o755);
    const binaryDigest = digestId(readFileSync(binary));
    if (observedBinaryDigests.has(binaryDigest)) {
      throw new Error(`${id}: binary digest duplicates a prior build`);
    }
    observedBinaryDigests.add(binaryDigest);

    const payloadRoot = join(temporaryRoot, 'payloads', id);
    const reportPath = join(temporaryRoot, 'reports', `${id}.json`);
    const run = command(
      binary,
      [
        '--envelope',
        inputs.envelope,
        '--trust-policy',
        inputs.policy,
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
        inputs.corpus,
        '--activation-suite',
        join(detachedRoot, 'artifact/mutation/activation-suite.json'),
        '--payload-root',
        payloadRoot,
        '--execution-report',
        reportPath,
      ],
      { cwd: detachedRoot, env }
    );
    const reportBytes = readFileSync(reportPath);
    const report = JSON.parse(reportBytes);
    if (report.binary_sha256 !== binaryDigest) {
      throw new Error(
        `${id}: runner binary identity differs from copied executable`
      );
    }
    process.stdout.write(run.stdout);
    executions.set(id, { payloadRoot, reportBytes });
  }

  const artifacts = buildMutationArtifacts(
    detachedRoot,
    executions,
    mutationSourceCommit,
    { includePresentation: process.env.SCORED26_PHASE1 !== '1' }
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
        throw new Error(
          `${path}: differs from clean detached mutation reproduction`
        );
      }
    }
  }
  console.log(
    `SCORED26 mutation campaign ${write ? 'generation' : 'reproduction'} passed ` +
      `(clean detached ${mutationSourceCommit.slice(0, 12)}, 13 binaries/12 mutants/240 workload cases)`
  );
} catch (error) {
  console.error(
    `SCORED26 mutation campaign ${write ? 'generation' : 'reproduction'} failed: ${error.message}`
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
