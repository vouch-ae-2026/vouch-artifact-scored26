import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  closeSync,
  copyFileSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { writeArtifactJson } from './artifact-json.mjs';
import { buildReplayManifest } from './replay-manifest-lib.mjs';
import {
  keyHandlePath,
  keyHandleSyntaxValid,
} from './release-finalizer-lib.mjs';
import {
  BUILD_IMAGE_RECORD_PATH,
  RELEASE_AUDIT_TIMEOUT_MS,
  RELEASE_COMMIT_PATH,
  RELEASE_EXECUTABLE_PATH,
  RELEASE_MANIFEST_PATH,
  buildReleaseDescriptor,
  buildReleaseManifest,
  buildReleaseTrustPolicy,
  dependencyManifestDigests,
  exactReleaseResults,
  executionObservationHasReceipt,
  parseBuildImageRecord,
  parsePublicKeyRecord,
  verifyBuildImagePins,
  verifyReleaseManifest,
} from './release-layer-lib.mjs';
import {
  REPLAY_MANIFEST_PAYLOAD_TYPE,
  nativeKeyId,
  parseCanonical,
  parseTrustPolicy,
  rawPublicKeyFromPrivate,
  sha256Id,
  signEnvelope,
} from './release-schema.mjs';

const options = parseArgs(process.argv.slice(2));
const sourceRoot = resolve(options.get('--source-root'));
const cleanRoomRoot = resolve(options.get('--clean-room-root'));
const keyHandle = options.get('--key-handle');
const npm = resolve(options.get('--npm'));
const archiveRoot = dirname(sourceRoot);
const archiveName = 'vouch-scored26-artifact.tar.zst';
const archivePath = join(cleanRoomRoot, archiveName);
const archiveTemporary = `${archivePath}.staging`;
const sourceAfterAssembly = join(cleanRoomRoot, '.source-work');

if (
  basename(sourceRoot) !== 'work' ||
  basename(archiveRoot) !== 'vouch-scored26-artifact' ||
  dirname(archiveRoot) !== cleanRoomRoot
) {
  throw new Error(
    '--source-root must be <clean-room-root>/vouch-scored26-artifact/work'
  );
}
if (!keyHandleSyntaxValid(keyHandle)) throw new Error('invalid key handle');
for (const path of [archivePath, archiveTemporary, sourceAfterAssembly]) {
  if (existsSync(path)) throw new Error(`${path}: output already exists`);
}

const initialArchiveEntries = readdirSync(archiveRoot).sort();
if (initialArchiveEntries.length !== 1 || initialArchiveEntries[0] !== 'work') {
  throw new Error('archive root must initially contain only the work checkout');
}

const artifactCommit = command('git', ['rev-parse', '--verify', 'HEAD'], {
  cwd: sourceRoot,
}).stdout.trim();
if (!/^[0-9a-f]{40}$/.test(artifactCommit)) {
  throw new Error('source HEAD is not a full commit identifier');
}
if (
  command('git', ['symbolic-ref', '-q', 'HEAD'], {
    cwd: sourceRoot,
    allowFailure: true,
  }).status === 0
) {
  throw new Error('release source must be a detached HEAD');
}
requireClean(sourceRoot);

const runtimeBytes = readFileSync(
  join(sourceRoot, 'artifact/runtime-versions.json')
);
const runtimeVersions = parseCanonical(runtimeBytes, 'runtime-versions');
verifyRuntimePins(sourceRoot, runtimeVersions, npm);
const buildImageRecord = parseBuildImageRecord(
  readFileSync(join(sourceRoot, ...BUILD_IMAGE_RECORD_PATH.split('/')))
);
verifyBuildImagePins(
  buildImageRecord,
  options.get('--build-image-sha256'),
  options.get('--os-image-reference')
);
const publicKeyRecord = parsePublicKeyRecord(
  readFileSync(
    join(sourceRoot, 'artifact/trust/native-release-public-key.json')
  )
);
const artifactFreezeCommit = parseFreezeCommit(
  readFileSync(join(sourceRoot, 'generated/artifact-identity.tex'), 'utf8')
);
command(
  'git',
  ['merge-base', '--is-ancestor', artifactFreezeCommit, artifactCommit],
  { cwd: sourceRoot }
);

// All deterministic source, pin, build-environment, and public-key checks run
// before the release key path is resolved or opened.
const buildEnvironment = cleanBuildEnvironment();
command('cargo', ['build', '--frozen', '--offline', '--release'], {
  cwd: sourceRoot,
  env: buildEnvironment,
  timeout: 30 * 60 * 1000,
});
requireClean(sourceRoot);
command(npm, ['--prefix', 'packages/vouch-consumer', 'run', 'build'], {
  cwd: sourceRoot,
  env: buildEnvironment,
});

const builtExecutable = join(
  sourceRoot,
  'target/release/scored26-workload-runner'
);
const replayVerifier = join(
  sourceRoot,
  'target/release/scored26-replay-verify'
);
for (const path of [builtExecutable, replayVerifier]) {
  if (!existsSync(path))
    throw new Error(`${path}: release build omitted binary`);
}
const engineSha256 = sha256Id(readFileSync(builtExecutable));
const generatedReplay = buildReplayManifest(sourceRoot);

const releaseRoot = join(archiveRoot, 'release');
const npmCache = join(archiveRoot, 'vendor/npm-cache');
mkdirSync(releaseRoot, { recursive: true, mode: 0o755 });
mkdirSync(dirname(npmCache), { recursive: true, mode: 0o755 });
command(
  process.execPath,
  [
    join(sourceRoot, 'artifact/scripts/populate-npm-cache.mjs'),
    '--package-lock',
    join(sourceRoot, 'package-lock.json'),
    '--cache',
    npmCache,
    '--npm',
    npm,
    '--jobs',
    '8',
  ],
  { cwd: sourceRoot, timeout: 30 * 60 * 1000 }
);
removeNpmCacheNoise(npmCache);

const bundlePath = join(archiveRoot, 'release/vouch-scored26.bundle');
command(
  'git',
  ['-c', 'pack.threads=1', 'bundle', 'create', bundlePath, 'HEAD'],
  { cwd: sourceRoot, timeout: 10 * 60 * 1000 }
);
writeFileSync(
  join(archiveRoot, ...RELEASE_COMMIT_PATH.split('/')),
  `${artifactCommit}\n`,
  { mode: 0o644 }
);
copyFileSync(
  builtExecutable,
  join(archiveRoot, ...RELEASE_EXECUTABLE_PATH.split('/'))
);
chmodSync(join(archiveRoot, ...RELEASE_EXECUTABLE_PATH.split('/')), 0o755);

// C-KEY-03 preconditions are now complete. Resolve the opaque handle exactly
// once and require the actual private key to match the committed public record.
const privateKeyBytes = readFileSync(keyHandlePath(keyHandle));
const privateIdentity = rawPublicKeyFromPrivate(privateKeyBytes);
if (
  !privateIdentity.rawPublicKey.equals(publicKeyRecord.rawPublicKey) ||
  publicKeyRecord.key_id !== nativeKeyId(privateIdentity.rawPublicKey)
) {
  throw new Error('release private key does not match the public-key record');
}
const replaySignature = signEnvelope(
  REPLAY_MANIFEST_PAYLOAD_TYPE,
  generatedReplay.payloadBytes,
  privateKeyBytes
);
const trustPolicy = buildReleaseTrustPolicy(publicKeyRecord, engineSha256);
const trustPolicyBytes = writeArtifactJson(trustPolicy);
parseTrustPolicy(trustPolicyBytes);
writeFileSync(
  join(releaseRoot, 'replay-manifest.json'),
  generatedReplay.payloadBytes
);
writeFileSync(
  join(releaseRoot, 'replay-manifest.dsse.json'),
  replaySignature.envelopeBytes
);
writeFileSync(
  join(releaseRoot, 'replay-corpus.json'),
  generatedReplay.corpusBytes
);
writeFileSync(join(releaseRoot, 'trust-policy.json'), trustPolicyBytes);

command(
  replayVerifier,
  [
    '--envelope',
    join(releaseRoot, 'replay-manifest.dsse.json'),
    '--trust-policy',
    join(releaseRoot, 'trust-policy.json'),
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
    join(releaseRoot, 'replay-corpus.json'),
  ],
  { cwd: sourceRoot, env: buildEnvironment }
);

const receipts = join(releaseRoot, 'receipts');
const executionReport = join(releaseRoot, 'workload-execution.json');
command(
  builtExecutable,
  workloadArguments({
    sourceRoot,
    releaseRoot,
    keyHandle,
    receipts,
    executionReport,
  }),
  { cwd: sourceRoot, env: buildEnvironment, timeout: 15 * 60 * 1000 }
);
await verifyStoredReceipts({
  sourceRoot,
  releaseRoot,
  trustPolicyBytes,
  engineSha256,
  artifactCommit,
  executionReport,
});

const exactResults = exactReleaseResults(archiveRoot);
const dependencyDigests = dependencyManifestDigests(sourceRoot);
renameSync(sourceRoot, sourceAfterAssembly);

const manifestDirectory = dirname(
  join(archiveRoot, ...RELEASE_MANIFEST_PATH.split('/'))
);
mkdirSync(manifestDirectory, { recursive: true, mode: 0o755 });
const manifestBytes = buildReleaseManifest(archiveRoot, engineSha256);
writeFileSync(
  join(archiveRoot, ...RELEASE_MANIFEST_PATH.split('/')),
  manifestBytes
);
verifyReleaseManifest(archiveRoot, manifestBytes, engineSha256);

command(
  join(sourceAfterAssembly, 'artifact/scripts/scan-release-secrets'),
  [
    '--root',
    archiveRoot,
    '--bundle',
    bundlePath,
    '--private-key-handle',
    keyHandle,
  ],
  { cwd: sourceAfterAssembly, timeout: RELEASE_AUDIT_TIMEOUT_MS }
);
command(
  join(sourceAfterAssembly, 'artifact/scripts/scan-public-data'),
  ['--root', archiveRoot, '--bundle', bundlePath],
  { cwd: sourceAfterAssembly, timeout: RELEASE_AUDIT_TIMEOUT_MS }
);

command(
  'tar',
  [
    '--sort=name',
    '--format=gnu',
    '--mtime=@0',
    '--owner=0',
    '--group=0',
    '--numeric-owner',
    '--mode=u+rwX,go+rX,go-w',
    '--zstd',
    '-cf',
    archiveTemporary,
    '-C',
    cleanRoomRoot,
    'vouch-scored26-artifact',
  ],
  {
    cwd: cleanRoomRoot,
    env: { ...process.env, ZSTD_CLEVEL: '19', ZSTD_NBTHREADS: '1' },
    timeout: 30 * 60 * 1000,
  }
);
syncFile(archiveTemporary);
renameSync(archiveTemporary, archivePath);
syncDirectory(cleanRoomRoot);
const archiveBytes = readFileSync(archivePath);
const archiveSha256 = sha256Id(archiveBytes);

const descriptor = buildReleaseDescriptor({
  archiveSha256,
  artifactCommit,
  artifactFreezeCommit,
  buildImageSha256: options.get('--build-image-sha256'),
  buildParameters: {
    build_id_policy: 'rustc-default-deterministic',
    build_path_policy:
      'checkout=/opt/vouch-scored26/clean-room/vouch-scored26-artifact/work;target=work/target',
    linker: options.get('--linker'),
    locale: 'C.UTF-8',
    os_image_reference: options.get('--os-image-reference'),
    source_date_epoch: 0,
  },
  dependencyManifestDigests: dependencyDigests,
  engineSha256,
  exactReproductionResults: exactResults,
  keyId: publicKeyRecord.key_id,
  runtimeVersions,
});
const descriptorSignature = signEnvelope(
  'application/vnd.csk.release-descriptor.v0+json',
  descriptor.bytes,
  privateKeyBytes
);
if (descriptorSignature.keyId !== publicKeyRecord.key_id) {
  throw new Error('descriptor signer key changed after release assembly');
}

publishExternal('release-descriptor.json', descriptor.bytes);
publishExternal(
  'release-descriptor.dsse.json',
  descriptorSignature.envelopeBytes
);
publishExternal('trust-policy.json', trustPolicyBytes);
publishExternal(
  `${archiveName}.sha256`,
  Buffer.from(`${archiveSha256}  ${archiveName}\n`, 'utf8')
);
console.log(
  `SCORED26 release assembled (${artifactCommit.slice(0, 12)}, ${exactResults.length} exact results, ${archiveBytes.length} archive bytes)`
);

function parseArgs(raw) {
  const required = new Set([
    '--source-root',
    '--clean-room-root',
    '--key-handle',
    '--build-image-sha256',
    '--os-image-reference',
    '--linker',
    '--npm',
  ]);
  if (raw.length % 2 !== 0) throw new Error('every option requires a value');
  const values = new Map();
  for (let index = 0; index < raw.length; index += 2) {
    const name = raw[index];
    const value = raw[index + 1];
    if (!required.has(name) || values.has(name) || !value) {
      throw new Error(`invalid option ${name}`);
    }
    values.set(name, value);
  }
  for (const name of required) {
    if (!values.has(name)) throw new Error(`${name} is required`);
  }
  for (const name of ['--build-image-sha256']) {
    if (!/^sha256:[0-9a-f]{64}$/.test(values.get(name))) {
      throw new Error(`${name} must be a sha256 identifier`);
    }
  }
  return values;
}

function cleanBuildEnvironment() {
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

function verifyRuntimePins(root, runtime, npmPath) {
  const expected = runtime.toolchains;
  const observations = {
    cargo: command('cargo', ['--version'], { cwd: root }).stdout.trim(),
    glibc: command('getconf', ['GNU_LIBC_VERSION'], {
      cwd: root,
    }).stdout.trim(),
    node: command(process.execPath, ['--version'], { cwd: root }).stdout.trim(),
    npm: command(npmPath, ['--version'], { cwd: root }).stdout.trim(),
    rustc: command('rustc', ['--version'], { cwd: root }).stdout.trim(),
    typescript: command(
      process.execPath,
      [join(root, 'node_modules/typescript/bin/tsc'), '--version'],
      { cwd: root }
    )
      .stdout.trim()
      .replace(/^Version /, ''),
  };
  for (const [name, value] of Object.entries(observations)) {
    if (value !== expected[name]) {
      throw new Error(`${name}: expected ${expected[name]}, observed ${value}`);
    }
  }
  if (runtime.target_triple !== 'x86_64-unknown-linux-gnu') {
    throw new Error('runtime target triple is not pinned x86_64 Linux');
  }
}

function parseFreezeCommit(text) {
  const match =
    /^\\newcommand\{\\ArtifactFreezeCommit\}\{([0-9a-f]{40})\}\n$/.exec(text);
  if (!match)
    throw new Error('generated artifact freeze identity is malformed');
  return match[1];
}

function requireClean(root) {
  const status = command(
    'git',
    ['status', '--porcelain=v1', '--untracked-files=all'],
    { cwd: root }
  ).stdout;
  if (status !== '') throw new Error(`source worktree is dirty:\n${status}`);
}

function workloadArguments({
  sourceRoot: root,
  releaseRoot: release,
  keyHandle: handle,
  receipts,
  executionReport: report,
}) {
  return [
    '--envelope',
    join(release, 'replay-manifest.dsse.json'),
    '--trust-policy',
    join(release, 'trust-policy.json'),
    '--baseline-rule',
    join(root, 'artifact/workload/rules/baseline.lspx'),
    '--changed-rule',
    join(root, 'artifact/workload/rules/changed.lspx'),
    '--workload-space',
    join(root, 'artifact/workload/workload-space.json'),
    '--workload-selection',
    join(root, 'artifact/workload/workload-selection.json'),
    '--workload-split',
    join(root, 'artifact/workload/workload-split.json'),
    '--holdout-plan',
    join(root, 'artifact/workload/holdout-plan.json'),
    '--corpus',
    join(release, 'replay-corpus.json'),
    '--key-handle',
    handle,
    '--receipt-root',
    receipts,
    '--execution-report',
    report,
  ];
}

async function verifyStoredReceipts({
  sourceRoot: root,
  releaseRoot: release,
  trustPolicyBytes: policy,
  engineSha256: engine,
  artifactCommit: commit,
  executionReport: reportPath,
}) {
  const consumerPath = join(root, 'packages/vouch-consumer/dist/index.js');
  const { verifyNativeEvidence } = await import(pathToFileURL(consumerPath));
  const report = parseCanonical(readFileSync(reportPath), 'workload-execution');
  const split = parseCanonical(
    readFileSync(join(root, 'artifact/workload/workload-split.json')),
    'workload-split'
  );
  const cases = new Map(split.cases.map((row) => [row.case_id, row]));
  const sources = {
    baseline: readFileSync(join(root, 'artifact/workload/rules/baseline.lspx')),
    changed: readFileSync(join(root, 'artifact/workload/rules/changed.lspx')),
  };
  let receiptCount = 0;
  for (const row of report.cases) {
    const input = writeArtifactJson(cases.get(row.case_id).input);
    for (const side of ['baseline', 'changed']) {
      const observation = row[side];
      const receiptRoot = join(release, 'receipts', row.case_id, side);
      if (!executionObservationHasReceipt(observation)) {
        if (existsSync(receiptRoot)) {
          throw new Error(
            `${row.case_id}/${side}: exceptional side issued receipt`
          );
        }
        continue;
      }
      const payload = readFileSync(join(receiptRoot, 'payload.json'));
      const envelope = readFileSync(join(receiptRoot, 'envelope.dsse.json'));
      const parsedEnvelope = parseCanonical(envelope, 'native-envelope');
      if (!Buffer.from(parsedEnvelope.payload, 'base64').equals(payload)) {
        throw new Error(`${row.case_id}/${side}: payload/envelope mismatch`);
      }
      if (sha256Id(payload) !== observation.receipt_payload_sha256) {
        throw new Error(
          `${row.case_id}/${side}: execution payload digest mismatch`
        );
      }
      const parsedPayload = parseCanonical(payload, 'native-payload');
      if (
        parsedPayload.engine?.executable_sha256 !== engine ||
        parsedPayload.execution?.executable_sha256 !== engine ||
        parsedPayload.execution?.build_commit !== commit
      ) {
        throw new Error(`${row.case_id}/${side}: release identity mismatch`);
      }
      const verified = verifyNativeEvidence(envelope, policy, {
        profile: 'csk.checked-profile/v1',
        source: sources[side],
        input,
      });
      if (!verified.ok) {
        throw new Error(
          `${row.case_id}/${side}: stored receipt rejected ${verified.error.code}`
        );
      }
      receiptCount += 1;
    }
  }
  if (receiptCount !== report.receipt_count) {
    throw new Error('stored receipt inventory count mismatch');
  }
}

function removeNpmCacheNoise(cache) {
  for (const name of [
    '_logs',
    '_update-notifier-last-checked',
    '_timing.json',
  ]) {
    rmSync(join(cache, name), { recursive: true, force: true });
  }
}

function publishExternal(name, bytes) {
  const path = join(cleanRoomRoot, name);
  const staging = `${path}.staging`;
  if (existsSync(path) || existsSync(staging)) {
    throw new Error(`${path}: external output already exists`);
  }
  writeFileSync(staging, bytes, { mode: 0o644 });
  syncFile(staging);
  renameSync(staging, path);
  syncDirectory(cleanRoomRoot);
}

function syncFile(path) {
  const descriptor = openSync(path, 'r');
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function syncDirectory(path) {
  const descriptor = openSync(path, 'r');
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function command(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: options.cwd,
    encoding: options.encoding ?? 'utf8',
    env: options.env ?? process.env,
    maxBuffer: options.maxBuffer ?? 256 * 1024 * 1024,
    timeout: options.timeout ?? 5 * 60 * 1000,
  });
  if (result.error || (!options.allowFailure && result.status !== 0)) {
    throw new Error(
      `${program} ${args.join(' ')} failed (status ${result.status})\n` +
        `${result.stdout ?? ''}${result.stderr ?? ''}${result.error?.message ?? ''}`
    );
  }
  return result;
}
