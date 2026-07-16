import { generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { writeArtifactJson } from './artifact-json.mjs';
import { consumeEnvironmentBuffer } from './cleanroom-driver-lib.mjs';
import {
  BUILD_IMAGE_RECORD_PATH,
  RELEASE_AUDIT_TIMEOUT_MS,
  RELEASE_COMMIT_PATH,
  RELEASE_EXECUTABLE_PATH,
  RELEASE_MANIFEST_PATH,
  buildReleaseDescriptor,
  dependencyManifestDigests,
  executionObservationHasReceipt,
  parseBuildImageRecord,
  verifyBuildImagePins,
  verifyReleaseManifestAfterPhaseOneCheckout,
} from './release-layer-lib.mjs';
import {
  authenticateDescriptor,
  parseCanonical,
  sha256Id,
} from './release-schema.mjs';
import { buildReplayManifest } from './replay-manifest-lib.mjs';
import {
  RESULT_PATHS,
  buildWorkloadResultArtifacts,
} from './workload-results-lib.mjs';

if (process.argv.length !== 2) {
  throw new Error('scored26:reproduce accepts no command-line arguments');
}

const sourceRoot = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const releaseRoot = requiredExternalDirectory('SCORED26_RELEASE_ROOT');
const outputRoot = requiredOutputDirectory('SCORED26_OUTPUT_ROOT');
const descriptorBytes = consumeEnvironmentBuffer(
  process.env,
  'SCORED26_DESCRIPTOR_B64'
);
const descriptorEnvelopeBytes = consumeEnvironmentBuffer(
  process.env,
  'SCORED26_DESCRIPTOR_ENVELOPE_B64'
);
const policyBytes = consumeEnvironmentBuffer(
  process.env,
  'SCORED26_TRUST_POLICY_B64'
);
const npm = resolve(requiredEnvironment('SCORED26_NPM'));
const timeExecutable = resolve(requiredEnvironment('SCORED26_TIME'));
const authenticated = authenticateDescriptor({
  policyBytes,
  descriptorBytes,
  envelopeBytes: descriptorEnvelopeBytes,
});
const descriptor = authenticated.descriptor;
const scratch = join(outputRoot, '.phase1-private');
const ephemeralKeyPath = join(scratch, 'ephemeral-issuance-key.pk8');
const ephemeralKeyHandle = `pkcs8-file://${ephemeralKeyPath}`;

try {
  verifySourceIdentity();
  verifyBuildIdentity();
  verifyInternalRelease();
  buildImplementations();

  mkdirSync(scratch, { recursive: true, mode: 0o700 });
  const ephemeralPrivateKey = generateKeyPairSync('ed25519').privateKey.export({
    format: 'der',
    type: 'pkcs8',
  });
  writeFileSync(ephemeralKeyPath, ephemeralPrivateKey, { mode: 0o600 });

  const generatedReplay = buildReplayManifest(sourceRoot);
  const storedReplay = readFileSync(
    join(releaseRoot, 'release/replay-manifest.json')
  );
  if (!generatedReplay.payloadBytes.equals(storedReplay)) {
    throw new Error('replay-manifest payload reproduction mismatch');
  }
  writeOutput('release/replay-manifest.json', generatedReplay.payloadBytes);

  verifySignedReplayManifest();
  const executionPath = join(scratch, 'workload-execution.json');
  const ephemeralReceipts = join(scratch, 'ephemeral-receipts');
  command(
    join(sourceRoot, 'target/release/scored26-workload-runner'),
    workloadArguments({
      keyHandle: ephemeralKeyHandle,
      receiptRoot: ephemeralReceipts,
      executionReport: executionPath,
    }),
    { cwd: sourceRoot, env: cleanEnvironment(), timeout: 15 * 60 * 1000 }
  );
  const executionBytes = readFileSync(executionPath);
  await reproduceAndVerifyReceipts({
    executionBytes,
    ephemeralReceipts,
  });

  const workloadArtifacts = buildWorkloadResultArtifacts(
    sourceRoot,
    executionBytes,
    { includePresentation: false }
  );
  for (const [path, bytes] of workloadArtifacts.files) {
    if (path !== RESULT_PATHS.tex) writeOutput(path, bytes);
  }

  runPhaseOneExperiments();
  reproduceDescriptor();
  rmSync(scratch, { recursive: true, force: true });
  runReleaseScans();
  requireCleanWorktree();
  requirePhaseOneBoundary();
  console.log(
    `SCORED26 phase-1 inner reproduction passed (${descriptor.artifact_commit.slice(0, 12)}, ${descriptor.exact_reproduction_results.length} exact results)`
  );
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

function verifySourceIdentity() {
  const head = command('git', ['rev-parse', '--verify', 'HEAD'], {
    cwd: sourceRoot,
  }).stdout.trim();
  if (head !== descriptor.artifact_commit) {
    throw new Error('checkout does not match authenticated artifact commit');
  }
  if (
    command('git', ['symbolic-ref', '-q', 'HEAD'], {
      cwd: sourceRoot,
      allowFailure: true,
    }).status === 0
  ) {
    throw new Error('phase-1 checkout must have detached HEAD');
  }
  command(
    'git',
    [
      'merge-base',
      '--is-ancestor',
      descriptor.artifact_freeze_commit,
      descriptor.artifact_commit,
    ],
    { cwd: sourceRoot }
  );
  const commitFile = readFileSync(
    join(releaseRoot, ...RELEASE_COMMIT_PATH.split('/')),
    'utf8'
  );
  if (commitFile !== `${descriptor.artifact_commit}\n`) {
    throw new Error('internal release COMMIT differs from descriptor');
  }
  const expectedPath = descriptor.build_parameters.build_path_policy.match(
    /^checkout=([^;]+);target=work\/target$/
  )?.[1];
  if (!expectedPath || sourceRoot !== expectedPath) {
    throw new Error('checkout path differs from deterministic build-path pin');
  }
  requireCleanWorktree();
}

function verifyBuildIdentity() {
  const runtimeBytes = readFileSync(
    join(sourceRoot, 'artifact/runtime-versions.json')
  );
  const runtime = parseCanonical(runtimeBytes, 'runtime-versions');
  const buildImageRecord = parseBuildImageRecord(
    readFileSync(join(sourceRoot, ...BUILD_IMAGE_RECORD_PATH.split('/')))
  );
  verifyBuildImagePins(
    buildImageRecord,
    descriptor.build_image_sha256,
    descriptor.build_parameters.os_image_reference
  );
  command(process.execPath, ['artifact/scripts/build-runtime-versions.mjs'], {
    cwd: sourceRoot,
  });
  command(process.execPath, ['artifact/scripts/build-vendor-manifest.mjs'], {
    cwd: sourceRoot,
    timeout: 10 * 60 * 1000,
  });
  const observed = {
    cargo: command('cargo', ['--version'], { cwd: sourceRoot }).stdout.trim(),
    glibc: command('getconf', ['GNU_LIBC_VERSION'], {
      cwd: sourceRoot,
    }).stdout.trim(),
    node: command(process.execPath, ['--version'], {
      cwd: sourceRoot,
    }).stdout.trim(),
    npm: command(npm, ['--version'], { cwd: sourceRoot }).stdout.trim(),
    rustc: command('rustc', ['--version'], { cwd: sourceRoot }).stdout.trim(),
    typescript: command(
      process.execPath,
      [join(sourceRoot, 'node_modules/typescript/bin/tsc'), '--version'],
      { cwd: sourceRoot }
    )
      .stdout.trim()
      .replace(/^Version /, ''),
  };
  for (const [name, value] of Object.entries(observed)) {
    if (
      value !== runtime.toolchains[name] ||
      value !== descriptor.toolchains[name]
    ) {
      throw new Error(`${name}: runtime observation differs from descriptor`);
    }
  }
  if (
    runtime.target_triple !== descriptor.target_triple ||
    command('rustc', ['-vV'], { cwd: sourceRoot }).stdout.match(
      /^host: (.+)$/m
    )?.[1] !== descriptor.target_triple
  ) {
    throw new Error('Rust host target differs from descriptor');
  }
  if (
    nonempty(process.env.RUSTFLAGS) ||
    nonempty(process.env.CARGO_ENCODED_RUSTFLAGS) ||
    descriptor.build_environment.rustflags !== '' ||
    descriptor.build_environment.cargo_encoded_rustflags !== ''
  ) {
    throw new Error('release Rust flags are not empty');
  }
  if (
    requiredEnvironment('SCORED26_BUILD_IMAGE_SHA256') !==
      descriptor.build_image_sha256 ||
    requiredEnvironment('SCORED26_OS_IMAGE_REFERENCE') !==
      descriptor.build_parameters.os_image_reference ||
    requiredEnvironment('SCORED26_LINKER') !==
      descriptor.build_parameters.linker
  ) {
    throw new Error('container or linker identity differs from descriptor');
  }
  if (
    descriptor.build_parameters.locale !== 'C.UTF-8' ||
    descriptor.build_parameters.source_date_epoch !== 0 ||
    descriptor.build_parameters.build_id_policy !==
      'rustc-default-deterministic'
  ) {
    throw new Error(
      'deterministic build parameters differ from release policy'
    );
  }
  comparePathDigests(
    dependencyManifestDigests(sourceRoot),
    descriptor.toolchains.dependency_version_manifest_digests,
    'dependency manifest'
  );
}

function verifyInternalRelease() {
  const releasePolicy = readFileSync(
    join(releaseRoot, 'release/trust-policy.json')
  );
  if (!releasePolicy.equals(policyBytes)) {
    throw new Error('internal trust policy differs from entry snapshot');
  }
  const executable = readFileSync(
    join(releaseRoot, ...RELEASE_EXECUTABLE_PATH.split('/'))
  );
  if (sha256Id(executable) !== descriptor.engine_sha256) {
    throw new Error('stored release executable digest mismatch');
  }
  const manifestBytes = readFileSync(
    join(releaseRoot, ...RELEASE_MANIFEST_PATH.split('/'))
  );
  verifyReleaseManifestAfterPhaseOneCheckout(
    releaseRoot,
    manifestBytes,
    descriptor.engine_sha256,
    sourceRoot
  );
  const expectedPaths = new Set(
    descriptor.exact_reproduction_results.map((row) => row.path)
  );
  for (const row of descriptor.exact_reproduction_results) {
    const bytes = readFileSync(join(releaseRoot, ...row.path.split('/')));
    if (sha256Id(bytes) !== row.sha256) {
      throw new Error(`${row.path}: stored exact-result digest mismatch`);
    }
  }
  if (
    !expectedPaths.has(RELEASE_EXECUTABLE_PATH) ||
    !expectedPaths.has('release/replay-manifest.json')
  ) {
    throw new Error('descriptor exact-result set omits release anchors');
  }
}

function buildImplementations() {
  const env = cleanEnvironment();
  command('cargo', ['build', '--frozen', '--offline', '--release'], {
    cwd: sourceRoot,
    env,
    timeout: 30 * 60 * 1000,
  });
  command(npm, ['--prefix', 'packages/vouch-consumer', 'run', 'build'], {
    cwd: sourceRoot,
    env,
  });
  const built = readFileSync(
    join(sourceRoot, 'target/release/scored26-workload-runner')
  );
  if (sha256Id(built) !== descriptor.engine_sha256) {
    throw new Error('rebuilt release executable is not byte-identical');
  }
  writeOutput(RELEASE_EXECUTABLE_PATH, built, 0o755);
  requireCleanWorktree();
}

function verifySignedReplayManifest() {
  command(
    join(sourceRoot, 'target/release/scored26-replay-verify'),
    [
      '--envelope',
      join(releaseRoot, 'release/replay-manifest.dsse.json'),
      '--trust-policy',
      join(releaseRoot, 'release/trust-policy.json'),
      '--baseline-rule',
      join(sourceRoot, 'artifact/workload/rules/baseline.lspx'),
      '--changed-rule',
      join(sourceRoot, 'artifact/workload/rules/changed.lspx'),
      '--workload-space',
      join(sourceRoot, 'artifact/workload/workload-space.json'),
      '--workload-selection',
      join(sourceRoot, 'artifact/workload/workload-selection.json'),
      '--workload-split',
      join(sourceRoot, 'artifact/workload/workload-split.json'),
      '--holdout-plan',
      join(sourceRoot, 'artifact/workload/holdout-plan.json'),
      '--corpus',
      join(releaseRoot, 'release/replay-corpus.json'),
    ],
    { cwd: sourceRoot, env: cleanEnvironment() }
  );
}

async function reproduceAndVerifyReceipts({
  executionBytes,
  ephemeralReceipts,
}) {
  const execution = parseCanonical(executionBytes, 'workload-execution');
  const split = parseCanonical(
    readFileSync(join(sourceRoot, 'artifact/workload/workload-split.json')),
    'workload-split'
  );
  const inputs = new Map(split.cases.map((row) => [row.case_id, row.input]));
  const sources = {
    baseline: readFileSync(
      join(sourceRoot, 'artifact/workload/rules/baseline.lspx')
    ),
    changed: readFileSync(
      join(sourceRoot, 'artifact/workload/rules/changed.lspx')
    ),
  };
  const { verifyNativeEvidence } = await import(
    pathToFileURL(join(sourceRoot, 'packages/vouch-consumer/dist/index.js'))
      .href
  );
  let count = 0;
  for (const row of execution.cases) {
    const input = writeArtifactJson(inputs.get(row.case_id));
    for (const side of ['baseline', 'changed']) {
      const relativeRoot = `release/receipts/${row.case_id}/${side}`;
      const regeneratedRoot = join(ephemeralReceipts, row.case_id, side);
      const storedRoot = join(releaseRoot, relativeRoot);
      const observation = row[side];
      if (!executionObservationHasReceipt(observation)) {
        if (existsSync(regeneratedRoot) || existsSync(storedRoot)) {
          throw new Error(
            `${row.case_id}/${side}: exceptional side has receipt`
          );
        }
        continue;
      }
      const regeneratedPayload = readFileSync(
        join(regeneratedRoot, 'payload.json')
      );
      const ephemeralEnvelope = readFileSync(
        join(regeneratedRoot, 'envelope.dsse.json')
      );
      const storedPayload = readFileSync(join(storedRoot, 'payload.json'));
      const storedEnvelope = readFileSync(
        join(storedRoot, 'envelope.dsse.json')
      );
      if (!regeneratedPayload.equals(storedPayload)) {
        throw new Error(`${row.case_id}/${side}: payload byte mismatch`);
      }
      if (sha256Id(regeneratedPayload) !== observation.receipt_payload_sha256) {
        throw new Error(`${row.case_id}/${side}: execution digest mismatch`);
      }
      const expected = {
        profile: 'csk.checked-profile/v1',
        source: sources[side],
        input,
      };
      const stored = verifyNativeEvidence(
        storedEnvelope,
        policyBytes,
        expected
      );
      if (!stored.ok) {
        throw new Error(
          `${row.case_id}/${side}: stored release signature rejected (${stored.error.code})`
        );
      }
      const ephemeral = verifyNativeEvidence(
        ephemeralEnvelope,
        policyBytes,
        expected
      );
      if (ephemeral.ok || ephemeral.error.code !== 'untrusted-native-key') {
        throw new Error(
          `${row.case_id}/${side}: ephemeral envelope crossed release policy`
        );
      }
      writeOutput(`${relativeRoot}/payload.json`, regeneratedPayload);
      count += 1;
    }
  }
  if (count !== execution.receipt_count) {
    throw new Error('regenerated receipt count mismatch');
  }
}

function runPhaseOneExperiments() {
  const env = {
    ...cleanEnvironment(),
    SCORED26_OUTPUT_ROOT: outputRoot,
    SCORED26_PHASE1: '1',
    SCORED26_RELEASE_RUN: '1',
  };
  command(npm, ['run', 'scored26:core-conformance'], {
    cwd: sourceRoot,
    env,
    timeout: 60 * 60 * 1000,
  });
  command(process.execPath, ['artifact/scripts/check-strict-union.mjs'], {
    cwd: sourceRoot,
    env,
  });
  command(process.execPath, ['artifact/consumer-demo/vulnerable/check.mjs'], {
    cwd: sourceRoot,
    env,
  });
  command(
    process.execPath,
    ['artifact/scripts/run-mutation-campaign.mjs', '--write'],
    { cwd: sourceRoot, env, timeout: 2 * 60 * 60 * 1000 }
  );
  command(
    process.execPath,
    [
      'artifact/scripts/run-release-performance.mjs',
      '--source-root',
      sourceRoot,
      '--release-root',
      releaseRoot,
      '--output-root',
      outputRoot,
      '--executable',
      join(sourceRoot, 'target/release/scored26-workload-runner'),
      '--ephemeral-key-handle',
      ephemeralKeyHandle,
      '--time',
      timeExecutable,
    ],
    { cwd: sourceRoot, env, timeout: 2 * 60 * 60 * 1000 }
  );
  for (const path of [
    'artifact/results/fixture-results.json',
    'artifact/workload/workload-results.json',
    'artifact/mutation/mutation-results.json',
    'artifact/performance/performance-results.json',
  ]) {
    if (!existsSync(join(outputRoot, ...path.split('/')))) {
      throw new Error(`${path}: phase-1 owner report missing`);
    }
  }
}

function reproduceDescriptor() {
  const exact = descriptor.exact_reproduction_results.map((row) => {
    const bytes = readFileSync(join(outputRoot, ...row.path.split('/')));
    return { path: row.path, sha256: sha256Id(bytes) };
  });
  const runtime = parseCanonical(
    readFileSync(join(sourceRoot, 'artifact/runtime-versions.json')),
    'runtime-versions'
  );
  const regenerated = buildReleaseDescriptor({
    archiveSha256: descriptor.archive_sha256,
    artifactCommit: descriptor.artifact_commit,
    artifactFreezeCommit: descriptor.artifact_freeze_commit,
    buildImageSha256: descriptor.build_image_sha256,
    buildParameters: descriptor.build_parameters,
    dependencyManifestDigests: dependencyManifestDigests(sourceRoot),
    engineSha256: sha256Id(
      readFileSync(join(outputRoot, ...RELEASE_EXECUTABLE_PATH.split('/')))
    ),
    exactReproductionResults: exact,
    keyId: descriptor.key_id,
    runtimeVersions: runtime,
  });
  if (!regenerated.bytes.equals(descriptorBytes)) {
    throw new Error('release descriptor byte reproduction mismatch');
  }
}

function runReleaseScans() {
  command(
    join(sourceRoot, 'artifact/scripts/scan-public-data'),
    [
      '--root',
      releaseRoot,
      '--bundle',
      join(releaseRoot, 'release/vouch-scored26.bundle'),
      '--phase1-checkout',
      sourceRoot,
    ],
    { timeout: RELEASE_AUDIT_TIMEOUT_MS }
  );
  for (const [name, value] of Object.entries(process.env)) {
    if (/release.*(?:private|secret).*key/i.test(name) && nonempty(value)) {
      throw new Error('release private-key environment variable is present');
    }
  }
  for (const root of [releaseRoot, outputRoot]) {
    const args = [
      join(sourceRoot, 'artifact/scripts/scan-private-key-markers.mjs'),
      '--root',
      root,
    ];
    if (root === releaseRoot) {
      args.push('--phase1-checkout', sourceRoot);
    }
    command(process.execPath, args);
  }
}

function requirePhaseOneBoundary() {
  for (const path of [
    'exact-reproduction-comparisons.json',
    'clean-run-report.json',
    'reproduction-observation.json',
    'reproduction-observation.dsse.json',
    'release-publication.json',
    'publication-report.json',
    'paper.pdf',
  ]) {
    if (existsSync(join(outputRoot, path))) {
      throw new Error(`${path}: forbidden phase-1 output`);
    }
  }
  if (existsSync(join(outputRoot, 'generated/workload-results.tex'))) {
    throw new Error('phase 1 regenerated workload LaTeX');
  }
  if (existsSync(join(outputRoot, 'generated/mutation-results.tex'))) {
    throw new Error('phase 1 regenerated mutation LaTeX');
  }
}

function workloadArguments({ keyHandle, receiptRoot, executionReport }) {
  return [
    '--envelope',
    join(releaseRoot, 'release/replay-manifest.dsse.json'),
    '--trust-policy',
    join(releaseRoot, 'release/trust-policy.json'),
    '--baseline-rule',
    join(sourceRoot, 'artifact/workload/rules/baseline.lspx'),
    '--changed-rule',
    join(sourceRoot, 'artifact/workload/rules/changed.lspx'),
    '--workload-space',
    join(sourceRoot, 'artifact/workload/workload-space.json'),
    '--workload-selection',
    join(sourceRoot, 'artifact/workload/workload-selection.json'),
    '--workload-split',
    join(sourceRoot, 'artifact/workload/workload-split.json'),
    '--holdout-plan',
    join(sourceRoot, 'artifact/workload/holdout-plan.json'),
    '--corpus',
    join(releaseRoot, 'release/replay-corpus.json'),
    '--key-handle',
    keyHandle,
    '--receipt-root',
    receiptRoot,
    '--execution-report',
    executionReport,
  ];
}

function cleanEnvironment() {
  const env = {
    ...process.env,
    CARGO_TERM_COLOR: 'never',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    SOURCE_DATE_EPOCH: '0',
  };
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
  return env;
}

function writeOutput(path, bytes, mode = 0o644) {
  const destination = join(outputRoot, ...path.split('/'));
  mkdirSync(dirname(destination), { recursive: true, mode: 0o755 });
  writeFileSync(destination, bytes, { mode });
  if (mode === 0o755) chmodSync(destination, mode);
}

function requireCleanWorktree() {
  const status = command(
    'git',
    ['status', '--porcelain=v1', '--untracked-files=all'],
    { cwd: sourceRoot }
  ).stdout;
  if (status !== '') throw new Error(`phase-1 worktree changed:\n${status}`);
}

function requiredExternalDirectory(name) {
  const path = resolve(requiredEnvironment(name));
  if (!existsSync(path)) throw new Error(`${name}: directory does not exist`);
  if (inside(sourceRoot, path)) {
    throw new Error(`${name}: path must remain outside the checkout`);
  }
  return path;
}

function requiredOutputDirectory(name) {
  const path = resolve(requiredEnvironment(name));
  if (inside(sourceRoot, path)) {
    throw new Error(`${name}: path must remain outside the checkout`);
  }
  if (existsSync(path)) {
    throw new Error(`${name}: output directory already exists`);
  }
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}

function inside(root, path) {
  const rel = relative(root, path);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..');
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (!nonempty(value)) throw new Error(`${name} is required`);
  return value;
}

function nonempty(value) {
  return typeof value === 'string' && value.length > 0;
}

function comparePathDigests(left, right, label) {
  const normalize = (rows) =>
    rows.map((row) => `${row.path}\0${row.sha256}`).join('\n');
  if (normalize(left) !== normalize(right)) {
    throw new Error(`${label} digests differ from descriptor`);
  }
}

function command(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: options.cwd ?? sourceRoot,
    encoding: options.encoding ?? 'utf8',
    env: options.env ?? process.env,
    maxBuffer: options.maxBuffer ?? 512 * 1024 * 1024,
    timeout: options.timeout ?? 10 * 60 * 1000,
  });
  if (result.error || (!options.allowFailure && result.status !== 0)) {
    throw new Error(
      `${program} failed (status ${result.status})\n` +
        `${result.stdout ?? ''}${result.stderr ?? ''}${result.error?.message ?? ''}`
    );
  }
  return result;
}
