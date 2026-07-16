import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

import { canonicalArtifactJson, writeArtifactJson } from './artifact-json.mjs';
import {
  NATIVE_PAYLOAD_TYPE,
  RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
  REPLAY_MANIFEST_PAYLOAD_TYPE,
  REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
  nativeKeyId,
  parseReleaseDescriptor,
  sha256Id,
} from './release-schema.mjs';

export const RELEASE_MANIFEST_TAG = 'vouch.scored26-release-manifest/v0';
export const PUBLIC_KEY_TAG = 'csk.native-public-key/v0';
export const RELEASE_EXECUTABLE_PATH = 'release/scored26-workload-runner';
export const RELEASE_COMMIT_PATH = 'release/COMMIT';
export const RELEASE_MANIFEST_PATH = 'artifact/release-manifest.json';
export const BUILD_IMAGE_RECORD_PATH = 'artifact/release/build-image.json';
export const RELEASE_AUDIT_TIMEOUT_MS = 30 * 60 * 1000;

const PUBLIC_KEY_FIELDS = Object.freeze([
  'algorithm',
  'key_id',
  'native_public_key',
  'public_key',
]);
const FILE_FIELDS = Object.freeze([
  'artifact_class',
  'byte_length',
  'expected_result',
  'generating_command',
  'path',
  'sha256',
]);
const BUILD_IMAGE_FIELDS = Object.freeze([
  'build_image',
  'build_image_sha256',
  'dockerfile_path',
  'node_base_image',
  'os_base_image',
  'platform',
  'rust_base_image',
]);

export function parsePublicKeyRecord(bytes) {
  const value = canonicalArtifactJson(bytes);
  exactKeys(value, PUBLIC_KEY_FIELDS, 'public-key-record');
  if (
    value.native_public_key !== PUBLIC_KEY_TAG ||
    value.algorithm !== 'ed25519' ||
    typeof value.public_key !== 'string' ||
    typeof value.key_id !== 'string'
  ) {
    throw new Error('public-key-record schema mismatch');
  }
  const raw = Buffer.from(value.public_key, 'base64');
  if (
    raw.length !== 32 ||
    raw.toString('base64') !== value.public_key ||
    nativeKeyId(raw) !== value.key_id
  ) {
    throw new Error('public-key-record identity mismatch');
  }
  return Object.freeze({ ...value, rawPublicKey: raw });
}

export function parseBuildImageRecord(bytes) {
  const value = canonicalArtifactJson(bytes);
  exactKeys(value, BUILD_IMAGE_FIELDS, 'build-image-record');
  if (
    value.build_image !== 'vouch.scored26-build-image/v0' ||
    value.dockerfile_path !== 'artifact/release/Dockerfile.scored26' ||
    value.platform !== 'linux/amd64' ||
    !/^sha256:[0-9a-f]{64}$/.test(value.build_image_sha256) ||
    !/^node@sha256:[0-9a-f]{64}$/.test(value.node_base_image) ||
    !/^rust@sha256:[0-9a-f]{64}$/.test(value.rust_base_image) ||
    !/^ubuntu@sha256:[0-9a-f]{64}$/.test(value.os_base_image)
  ) {
    throw new Error('build-image-record schema mismatch');
  }
  return Object.freeze({ ...value });
}

export function verifyBuildImagePins(
  buildImageRecord,
  buildImageSha256,
  osImageReference
) {
  if (
    buildImageRecord.build_image_sha256 !== buildImageSha256 ||
    buildImageRecord.os_base_image !== osImageReference
  ) {
    throw new Error(
      'release image options differ from committed build-image record'
    );
  }
}

export function executionObservationHasReceipt(observation) {
  const kind = observation?.outcome?.kind;
  const digest = observation?.receipt_payload_sha256;
  if (
    ![
      'decision',
      'profile-escape',
      'not-comparable',
      'pipeline-failure',
    ].includes(kind)
  ) {
    throw new Error('workload execution observation is malformed');
  }
  const hasReceipt = kind === 'decision';
  if (
    (hasReceipt && !/^sha256:[0-9a-f]{64}$/.test(digest)) ||
    (!hasReceipt && digest !== null)
  ) {
    throw new Error('workload execution receipt accounting mismatch');
  }
  return hasReceipt;
}

export function releasePerformanceReceiptPopulation(execution) {
  if (!Array.isArray(execution?.cases)) {
    throw new Error('workload execution cases are malformed');
  }
  const coordinates = [];
  const excluded = [];
  for (const row of execution.cases) {
    if (typeof row?.case_id !== 'string') {
      throw new Error('workload execution case identity is malformed');
    }
    for (const side of ['baseline', 'changed']) {
      if (executionObservationHasReceipt(row[side])) {
        coordinates.push({ caseId: row.case_id, side });
      } else {
        excluded.push({ case: row.case_id, side });
      }
    }
  }
  excluded.sort((left, right) =>
    Buffer.from(`${left.case}\0${left.side}`).compare(
      Buffer.from(`${right.case}\0${right.side}`)
    )
  );
  if (
    coordinates.length !== execution.receipt_count ||
    coordinates.length === 0
  ) {
    throw new Error('performance receipt population mismatch');
  }
  return Object.freeze({
    coordinates: Object.freeze(coordinates.map((row) => Object.freeze(row))),
    excluded: Object.freeze(excluded.map((row) => Object.freeze(row))),
  });
}

export function buildReleaseTrustPolicy(publicKeyRecord, engineSha256) {
  return {
    keys: [
      {
        algorithm: 'ed25519',
        allowed_engine_sha256: [engineSha256],
        allowed_payload_types: [
          NATIVE_PAYLOAD_TYPE,
          RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
          REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
          REPLAY_MANIFEST_PAYLOAD_TYPE,
        ],
        allowed_profiles: ['csk.checked-profile/v1'],
        key_id: publicKeyRecord.key_id,
        public_key: publicKeyRecord.public_key,
      },
    ],
    minimum_versions: {
      native_receipt: 0,
      release_descriptor: 0,
      replay_corpus_manifest: 0,
      reproduction_observation: 0,
    },
    trust_policy: 'csk.native-trust-policy/v0',
  };
}

export function buildReleaseDescriptor({
  archiveSha256,
  artifactCommit,
  artifactFreezeCommit,
  buildImageSha256,
  buildParameters,
  dependencyManifestDigests,
  engineSha256,
  exactReproductionResults,
  keyId,
  runtimeVersions,
}) {
  const descriptor = {
    archive_sha256: archiveSha256,
    artifact_commit: artifactCommit,
    artifact_freeze_commit: artifactFreezeCommit,
    build_environment: {
      cargo_encoded_rustflags: '',
      rustflags: '',
    },
    build_image_sha256: buildImageSha256,
    build_parameters: buildParameters,
    engine_sha256: engineSha256,
    exact_reproduction_results: sortPathDigests(exactReproductionResults),
    key_id: keyId,
    release_descriptor: 'csk.release-descriptor/v0',
    target_triple: runtimeVersions.target_triple,
    toolchains: {
      cargo: runtimeVersions.toolchains.cargo,
      dependency_version_manifest_digests: sortPathDigests(
        dependencyManifestDigests
      ),
      glibc: runtimeVersions.toolchains.glibc,
      node: runtimeVersions.toolchains.node,
      npm: runtimeVersions.toolchains.npm,
      rustc: runtimeVersions.toolchains.rustc,
      typescript: runtimeVersions.toolchains.typescript,
    },
  };
  const bytes = writeArtifactJson(descriptor);
  parseReleaseDescriptor(bytes);
  return Object.freeze({ bytes, descriptor });
}

export function buildReleaseManifest(archiveRoot, engineSha256) {
  const paths = regularFiles(archiveRoot).filter(
    (path) => path !== RELEASE_MANIFEST_PATH
  );
  const files = paths.map((path) => {
    const bytes = readFileSync(join(archiveRoot, ...path.split('/')));
    const sha256 = sha256Id(bytes);
    return {
      artifact_class: artifactClass(path),
      byte_length: bytes.length,
      expected_result: path === RELEASE_EXECUTABLE_PATH ? engineSha256 : sha256,
      generating_command: generatingCommand(path),
      path,
      sha256,
    };
  });
  return writeArtifactJson({ files, release_manifest: RELEASE_MANIFEST_TAG });
}

export function verifyReleaseManifest(archiveRoot, bytes, engineSha256) {
  return verifyReleaseManifestInventory(archiveRoot, bytes, engineSha256, null);
}

export function verifyReleaseManifestAfterPhaseOneCheckout(
  archiveRoot,
  bytes,
  engineSha256,
  checkoutRoot
) {
  const resolvedArchiveRoot = phaseOneArchiveRoot(archiveRoot, checkoutRoot);
  return verifyReleaseManifestInventory(
    resolvedArchiveRoot,
    bytes,
    engineSha256,
    'work'
  );
}

function verifyReleaseManifestInventory(
  archiveRoot,
  bytes,
  engineSha256,
  ignoredTopLevelDirectory
) {
  const value = canonicalArtifactJson(bytes);
  exactKeys(value, ['files', 'release_manifest'], 'release-manifest');
  if (
    value.release_manifest !== RELEASE_MANIFEST_TAG ||
    !Array.isArray(value.files)
  ) {
    throw new Error('release-manifest schema mismatch');
  }
  let previous = null;
  const listed = new Set();
  for (const [index, row] of value.files.entries()) {
    exactKeys(row, FILE_FIELDS, `release-manifest-row-${index}`);
    normalizedPath(row.path);
    if (
      !Number.isSafeInteger(row.byte_length) ||
      row.byte_length < 0 ||
      typeof row.artifact_class !== 'string' ||
      row.artifact_class.length === 0 ||
      typeof row.generating_command !== 'string' ||
      row.generating_command.length === 0 ||
      typeof row.expected_result !== 'string'
    ) {
      throw new Error(`${row.path}: invalid release-manifest row`);
    }
    if (
      listed.has(row.path) ||
      (previous !== null && utf8Compare(previous, row.path) >= 0)
    ) {
      throw new Error(`${row.path}: duplicate or unsorted release path`);
    }
    const path = join(archiveRoot, ...row.path.split('/'));
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`${row.path}: release path is not a regular file`);
    }
    const file = readFileSync(path);
    const digest = sha256Id(file);
    if (
      file.length !== row.byte_length ||
      digest !== row.sha256 ||
      row.artifact_class !== artifactClass(row.path) ||
      row.generating_command !== generatingCommand(row.path) ||
      row.expected_result !==
        (row.path === RELEASE_EXECUTABLE_PATH ? engineSha256 : digest)
    ) {
      throw new Error(`${row.path}: release-manifest observation mismatch`);
    }
    listed.add(row.path);
    previous = row.path;
  }
  const actual = regularFilesInventory(
    archiveRoot,
    ignoredTopLevelDirectory
  ).filter((path) => path !== RELEASE_MANIFEST_PATH);
  if (
    actual.length !== listed.size ||
    actual.some((path) => !listed.has(path))
  ) {
    throw new Error('release-manifest does not cover every archive path');
  }
  return value;
}

export function dependencyManifestDigests(repoRoot) {
  return [
    'Cargo.lock',
    'artifact/runtime-versions.json',
    'artifact/vendor-manifest.json',
    'package-lock.json',
  ].map((path) => ({
    path,
    sha256: sha256Id(readFileSync(join(repoRoot, ...path.split('/')))),
  }));
}

export function exactReleaseResults(archiveRoot) {
  const releaseRoot = join(archiveRoot, 'release');
  return regularFiles(releaseRoot)
    .map((path) => `release/${path}`)
    .filter(
      (path) =>
        path === RELEASE_EXECUTABLE_PATH ||
        path === 'release/replay-manifest.json' ||
        /^release\/receipts\/[^/]+\/(?:baseline|changed)\/payload\.json$/.test(
          path
        )
    )
    .map((path) => ({
      path,
      sha256: sha256Id(readFileSync(join(archiveRoot, ...path.split('/')))),
    }));
}

export function publicDataArchivePathPolicy(path) {
  const collectGeneratedJson =
    path.endsWith('.json') &&
    (path.startsWith('release/receipts/') ||
      path === 'release/replay-corpus.json' ||
      path.endsWith('workload-results.json'));
  const scanText =
    !path.startsWith('vendor/npm-cache/') &&
    !path.endsWith('.bundle') &&
    path !== RELEASE_EXECUTABLE_PATH;
  return Object.freeze({ collectGeneratedJson, scanText });
}

export function regularFiles(root) {
  return regularFilesInventory(root, null);
}

export function regularFilesAfterPhaseOneCheckout(archiveRoot, checkoutRoot) {
  return regularFilesInventory(
    phaseOneArchiveRoot(archiveRoot, checkoutRoot),
    'work'
  );
}

function phaseOneArchiveRoot(archiveRoot, checkoutRoot) {
  const resolvedArchiveRoot = resolve(archiveRoot);
  const resolvedCheckoutRoot = resolve(checkoutRoot);
  if (resolvedCheckoutRoot !== join(resolvedArchiveRoot, 'work')) {
    throw new Error('phase-1 checkout is not the archive-root work directory');
  }
  const checkoutStat = lstatSync(resolvedCheckoutRoot);
  if (!checkoutStat.isDirectory() || checkoutStat.isSymbolicLink()) {
    throw new Error('phase-1 checkout is not a regular directory');
  }
  return resolvedArchiveRoot;
}

function regularFilesInventory(root, ignoredTopLevelDirectory) {
  const files = [];
  const visit = (directory, depth) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (depth === 0 && entry.name === ignoredTopLevelDirectory) {
        if (!entry.isDirectory() || entry.isSymbolicLink()) {
          throw new Error('ignored archive-root entry is not a directory');
        }
        continue;
      }
      if (entry.isSymbolicLink()) {
        throw new Error(
          `${path}: symlinks are forbidden in the release archive`
        );
      }
      if (entry.isDirectory()) visit(path, depth + 1);
      else if (entry.isFile()) {
        files.push(relative(root, path).split(sep).join('/'));
      } else {
        throw new Error(`${path}: non-regular release entry`);
      }
    }
  };
  visit(root, 0);
  return files.sort(utf8Compare);
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function artifactClass(path) {
  if (path === RELEASE_COMMIT_PATH) return 'source-commit';
  if (path.endsWith('.bundle')) return 'source-bundle';
  if (path === RELEASE_EXECUTABLE_PATH) return 'release-executable';
  if (
    path.endsWith('/payload.json') ||
    path === 'release/replay-manifest.json'
  ) {
    return 'deterministic-payload';
  }
  if (path.endsWith('.dsse.json')) return 'release-signature';
  if (path.startsWith('release/receipts/')) return 'issuance-record';
  if (path === 'release/trust-policy.json') return 'release-trust-policy';
  if (path === 'release/replay-corpus.json') return 'replay-corpus';
  if (path.startsWith('vendor/npm-cache/')) return 'npm-offline-cache';
  return 'release-metadata';
}

function generatingCommand(path) {
  if (path.endsWith('.bundle')) return 'git bundle create';
  if (path === RELEASE_EXECUTABLE_PATH) {
    return 'cargo build --frozen --offline --release';
  }
  if (path.startsWith('release/receipts/')) return 'scored26-workload-runner';
  if (path.startsWith('vendor/npm-cache/')) return 'populate-npm-cache';
  return 'npm run scored26:assemble-release';
}

function exactKeys(value, expected, label) {
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== 'object' ||
    Object.keys(value).sort().join('\0') !== [...expected].sort().join('\0')
  ) {
    throw new Error(`${label}: closed schema mismatch`);
  }
}

function normalizedPath(value) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.includes('\0') ||
    value.startsWith('/') ||
    value
      .split('/')
      .some((part) => part === '' || part === '.' || part === '..')
  ) {
    throw new Error(`invalid normalized path ${String(value)}`);
  }
}

function sortPathDigests(rows) {
  if (!Array.isArray(rows) || rows.length === 0) {
    throw new Error('path-digest array must be nonempty');
  }
  const output = rows
    .map((row) => ({ path: row.path, sha256: row.sha256 }))
    .sort((left, right) => utf8Compare(left.path, right.path));
  const paths = new Set();
  for (const row of output) {
    normalizedPath(row.path);
    if (!/^sha256:[0-9a-f]{64}$/.test(row.sha256) || paths.has(row.path)) {
      throw new Error(`${row.path}: invalid or duplicate path digest`);
    }
    paths.add(row.path);
  }
  return output;
}

function utf8Compare(left, right) {
  return Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8'));
}
