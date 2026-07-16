// SPDX-License-Identifier: Apache-2.0

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';
import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';

import { verifyArchiveChunks } from './archive-chunks/verify-archive-chunks.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const defaultRoot = path.resolve(path.dirname(scriptPath), '..');

const C0 = '3e910c9ff87cc01d3bc241d63297218b44e75ede';
const BASE = 'ef7ef9bb4b56382ef5d413408a5f93a6898498c2';
const FREEZE = 'c90f97ddd6b1d662791a76fe4663b90e79c443ec';
const C0_TREE = 'c686334b180b3a9581b91c70f08da15528f93d9a';
const C0_FILE_COUNT = 2367;
const SYNTHETIC_BUNDLE_PATH =
  'source/synthetic-history/vouch-scored26.bundle';
const ARCHIVE_CHUNK_MANIFEST_PATH =
  'release/archive-chunks/archive-chunks.json';
const BUNDLE_RECONCILIATION_PATH =
  'release/audit/bundle-reconciliation.json';
const RELEASE_MANIFEST_PATH =
  'release/results/release-manifest.json';
const CONTRACT_SHA256 =
  'ecc294798be49f5843bd84e0ebad5d94a930f2b09f51db4852e42d2789addddc';
const HISTORICAL_CONTRACT_SHA256 =
  'edc53611c35f813f5e396d19b47524c13b8d064ac6cc79d288e3af2b718cbf76';
const RELEASE_KEY_ID =
  'sha256:dfad0e0c05811e9c83c5733eaf2e5009a9bf11c8877278400116d66d774bd982';
const BUILD_IMAGE_ID =
  'sha256:c40e87e9fbdf67f18850020696984308eda72bd8e9f89acc2b69c46bc550108e';
const MACHINE_RECORD_SHA256 =
  'cabff13cf9c34a3d96dfda4944d30ac681960eab007ee11267f09ca90200d556';
const SOURCE_MANIFEST_SHA256 =
  'f917b5e9623e4b3547882b2d8f12c2ad0c88d2be5309d9ce3ff8302f49b0f473';
const SOURCE_RIGHTS_SHA256 =
  '9e13cc2f139da73df3c8e566127e0a0ca7708f464f50cfa11efbc497ea301540';
const SOURCE_FILE_COUNT = 3155;
const SOURCE_BYTE_COUNT = 80329742;
const EXPECTED_RELEASE_FILE_SHA256 = Object.freeze({
  'machine-record/vouch-scored26-release-record.pdf': MACHINE_RECORD_SHA256,
  'release/chain/clean-run-report.json':
    'f0414f051e062f7b98a32f44b04ff526da79a61a6af00f2d95b62b024cc9ec2c',
  'release/chain/publication-report.json':
    '1922ac844a1dd0a90dc1664cacb5d315f3f27181a3e8aed6c7f0a99fa50a9149',
  'release/chain/release-descriptor.dsse.json':
    '8803773addc832543b66c99a6ab7a16ef3e6fea3f0dcce70e697d3a87102b99c',
  'release/chain/release-descriptor.json':
    'daca8fa97901d6396abd7e64c27cbd692929a23b70de82cc16f0d158220fd5ae',
  'release/chain/release-publication.json':
    '9855f8f3d67c64c87931f4347cbaebe31cf904a7586d962092ea5a42644f4a22',
  'release/chain/reproduction-observation.dsse.json':
    '4f2ccc76556fd88b836497c57b9439fcbf7e56517f44076d0a776db3275c90a5',
  'release/chain/reproduction-observation.json':
    'ff36863387b2d865a817d699e8d7ba73ceeb42dc4c3e78818293f01727fd7e81',
  'release/chain/native-release-public-key.json':
    'd08064f8e50982321a58a84a5b901441b246918a5e42f824faa32e695306429a',
  'release/chain/trust-policy.json':
    'f91781d30e296eb6c02bb2d0603fccbde46ccbab8ed8ff1b7bfa7b4565d08ed1',
  'release/results/exact-reproduction-comparisons.json':
    '634bb491aa90a02c69533e099bcdf759fa825991b30cbb294fc64aea7387128b',
  'release/results/fixture-results.json':
    'f6dc99af7c81ce6f0b8a8a580dba8e5c73b9f2fc9f597ac49676ee5dd07f55f7',
  'release/results/mutation-results.json':
    '4b8604da8b97fc6550f52005c88166a65592e8cc7b97def0338c908597e75fd4',
  'release/results/performance-results.json':
    '3c4c5bc8e487341acd998657fee61a1653675c4bd1fb58816252e00c2656e6ec',
  'release/results/workload-results.json':
    '60aaa12d73d36f3183b5bac04e447d70aece9da2a9cc4c5841548fb84047b0fb',
});
const PROFILE = 'csk.checked-profile/v1';
const DESCRIPTOR_TYPE =
  'application/vnd.csk.release-descriptor.v0+json';
const OBSERVATION_TYPE =
  'application/vnd.csk.reproduction-observation.v0+json';
const KEY_ID_DOMAIN = Buffer.from('csk/native-key-id/v0\0', 'utf8');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const MANIFEST_PATH = 'ARTIFACT-MANIFEST.json';
const VENDORED_CRYPTO_EXAMPLES = Object.freeze([
  'source/vendor/der/tests/examples/spki.der',
  'source/vendor/der/tests/examples/spki.pem',
  'source/vendor/ed25519-dalek/src/lib.rs',
  'source/vendor/ed25519-dalek/tests/examples/pkcs8-v1.der',
  'source/vendor/ed25519-dalek/tests/examples/pkcs8-v2.der',
  'source/vendor/ed25519-dalek/tests/examples/pubkey.der',
  'source/vendor/ed25519/src/pkcs8.rs',
  'source/vendor/ed25519/tests/examples/pkcs8-v1.der',
  'source/vendor/ed25519/tests/examples/pkcs8-v1.pem',
  'source/vendor/ed25519/tests/examples/pkcs8-v2.der',
  'source/vendor/ed25519/tests/examples/pkcs8-v2.pem',
  'source/vendor/ed25519/tests/examples/pubkey.der',
  'source/vendor/ed25519/tests/examples/pubkey.pem',
  'source/vendor/pkcs8/README.md',
  'source/vendor/pkcs8/src/traits.rs',
  'source/vendor/pkcs8/tests/examples/ed25519-encpriv-aes128-pbkdf2-sha1.der',
  'source/vendor/pkcs8/tests/examples/ed25519-encpriv-aes256-pbkdf2-sha256.der',
  'source/vendor/pkcs8/tests/examples/ed25519-encpriv-aes256-pbkdf2-sha256.pem',
  'source/vendor/pkcs8/tests/examples/ed25519-encpriv-aes256-scrypt.der',
  'source/vendor/pkcs8/tests/examples/ed25519-encpriv-aes256-scrypt.pem',
  'source/vendor/pkcs8/tests/examples/ed25519-encpriv-des-pbkdf2-sha256.der',
  'source/vendor/pkcs8/tests/examples/ed25519-encpriv-des3-pbkdf2-sha256.der',
  'source/vendor/pkcs8/tests/examples/ed25519-priv-pkcs8v1.der',
  'source/vendor/pkcs8/tests/examples/ed25519-priv-pkcs8v1.pem',
  'source/vendor/pkcs8/tests/examples/ed25519-priv-pkcs8v2.der',
  'source/vendor/pkcs8/tests/examples/ed25519-priv-pkcs8v2.pem',
  'source/vendor/pkcs8/tests/examples/ed25519-pub.der',
  'source/vendor/pkcs8/tests/examples/ed25519-pub.pem',
  'source/vendor/pkcs8/tests/examples/p256-priv.der',
  'source/vendor/pkcs8/tests/examples/p256-priv.pem',
  'source/vendor/pkcs8/tests/examples/p256-pub.der',
  'source/vendor/pkcs8/tests/examples/p256-pub.pem',
  'source/vendor/pkcs8/tests/examples/rsa2048-priv.der',
  'source/vendor/pkcs8/tests/examples/rsa2048-priv.pem',
  'source/vendor/pkcs8/tests/examples/rsa2048-pub.der',
  'source/vendor/pkcs8/tests/examples/rsa2048-pub.pem',
  'source/vendor/pkcs8/tests/examples/x25519-priv.der',
  'source/vendor/pkcs8/tests/examples/x25519-priv.pem',
  'source/vendor/spki/tests/examples/ed25519-pub.der',
  'source/vendor/spki/tests/examples/ed25519-pub.pem',
  'source/vendor/spki/tests/examples/p256-pub.der',
  'source/vendor/spki/tests/examples/p256-pub.pem',
  'source/vendor/spki/tests/examples/rsa2048-pub.der',
  'source/vendor/spki/tests/examples/rsa2048-pub.pem',
]);
const VENDORED_CRYPTO_EXAMPLE_SET = new Set(VENDORED_CRYPTO_EXAMPLES);

const RESULT_PATHS = Object.freeze({
  comparisons: 'release/results/exact-reproduction-comparisons.json',
  conditionMap: 'release/results/condition-map.json',
  fixtures: 'release/results/fixture-results.json',
  mutation: 'release/results/mutation-results.json',
  performance: 'release/results/performance-results.json',
  releaseManifest: RELEASE_MANIFEST_PATH,
  workload: 'release/results/workload-results.json',
});

const CHAIN_PATHS = Object.freeze({
  descriptor: 'release/chain/release-descriptor.json',
  descriptorEnvelope: 'release/chain/release-descriptor.dsse.json',
  cleanRun: 'release/chain/clean-run-report.json',
  finalize: 'release/chain/finalize-report.json',
  observation: 'release/chain/reproduction-observation.json',
  observationEnvelope: 'release/chain/reproduction-observation.dsse.json',
  publication: 'release/chain/release-publication.json',
  terminal: 'release/chain/publication-report.json',
  policy: 'release/chain/trust-policy.json',
  publicKey: 'release/chain/native-release-public-key.json',
});

const SOURCE_PATHS = Object.freeze({
  manifest: 'source/SOURCE-MANIFEST.json',
  rights: 'source/RIGHTS.md',
  bundle: SYNTHETIC_BUNDLE_PATH,
  package: 'source/package.json',
  activeContract:
    'source/artifact/contract/NATIVE-IMPLEMENTATION-CONDITIONS-v8.6.0.md',
  historicalContract:
    'source/artifact/contract/NATIVE-IMPLEMENTATION-CONDITIONS-v8.5.1.md',
  conditionMap: 'source/artifact/contract/condition-map.json',
  fixtureRegistry: 'source/artifact/fixtures/fixture-registry.json',
  activationResults: 'source/artifact/mutation/activation-results.json',
});

const AUDIT_PATHS = Object.freeze({
  anonymity: 'release/audit/anonymity-report.json',
  bundleReconciliation: BUNDLE_RECONCILIATION_PATH,
  lifecycleCommands: 'release/audit/lifecycle-command-record.md',
  lifecycleJson: 'release/audit/lifecycle-audit.json',
  sanitizedLogs: 'release/audit/sanitized-log-manifest.json',
  secret: 'release/audit/secret-scan-report.json',
  source: 'release/audit/source-projection-report.json',
});

const LIFECYCLE_LOG_SPECS = Object.freeze([
  Object.freeze({
    source: 'assembly/npm-ci.log',
    destination: 'release/audit/logs/00-npm-ci.log',
    completionMarker: null,
  }),
  Object.freeze({
    source: 'assembly/assembly.log',
    destination: 'release/audit/logs/01-assembly.log',
    completionMarker: 'SCORED26 release assembled',
  }),
  Object.freeze({
    source: 'trusted-bootstrap.log',
    destination: 'release/audit/logs/02-trusted-bootstrap.log',
    completionMarker: null,
  }),
  Object.freeze({
    source: 'phase1/phase1.log',
    destination: 'release/audit/logs/03-phase1.log',
    completionMarker: 'SCORED26 phase-1 clean-room gate passed',
  }),
  Object.freeze({
    source: 'phase2/phase2.log',
    destination: 'release/audit/logs/04-phase2.log',
    completionMarker: 'SCORED26 reproduction observation finalized',
  }),
  Object.freeze({
    source: 'phase3/phase3.log',
    destination: 'release/audit/logs/05-phase3.log',
    completionMarker: 'SCORED26 publication check passed (S=pass)',
  }),
]);

const FINAL_SCAN_LOG_PATHS = Object.freeze({
  'actual-key-secret-scan':
    'release/audit/logs/scan-actual-key-secret-scan.log',
  'generic-private-key-marker-scan':
    'release/audit/logs/scan-generic-private-key-marker-scan.log',
  'public-data-scan': 'release/audit/logs/scan-public-data-scan.log',
});

const ROOT_REQUIRED_PATHS = Object.freeze([
  'LICENSE-SCOPE.md',
  'README.md',
  'RUN.md',
  'machine-record/vouch-scored26-release-record.pdf',
  'package.json',
  'scripts/build-artifact-manifest.mjs',
  'scripts/archive-chunks/README.md',
  'scripts/archive-chunks/archive-chunk-lib.mjs',
  'scripts/archive-chunks/archive-chunks.mjs',
  'scripts/archive-chunks/self-test.mjs',
  'scripts/archive-chunks/verify-archive-chunks.mjs',
  'scripts/check-artifact-negative.mjs',
  'scripts/check-artifact.mjs',
  ARCHIVE_CHUNK_MANIFEST_PATH,
  ...LIFECYCLE_LOG_SPECS.map((entry) => entry.destination),
  ...Object.values(FINAL_SCAN_LOG_PATHS),
  ...Object.values(AUDIT_PATHS),
  ...Object.values(CHAIN_PATHS),
  ...Object.values(RESULT_PATHS),
  ...Object.values(SOURCE_PATHS),
]);

const OBSERVATIONAL_RELEASE_PATHS = Object.freeze([
  'artifact/mutation/mutation-results.json',
  'artifact/performance/performance-results.json',
  'artifact/results/fixture-results.json',
  'artifact/workload/workload-results.json',
]);

export async function verifyArtifact(
  root,
  { runSourceChecks = true, quiet = false } = {}
) {
  const absoluteRoot = path.resolve(root);
  const manifestState = await verifyArtifactManifest(absoluteRoot);
  await verifyExpectedReleaseFileDigests(absoluteRoot);
  const sourceState = await verifySourceProjection(absoluteRoot, manifestState);
  const resultState = await verifyContractAndResults(absoluteRoot);
  const releaseState = await verifyReleaseChain(absoluteRoot, resultState);
  await verifyBundleEvidence(absoluteRoot, releaseState);
  await verifyAuditReports(absoluteRoot, sourceState, manifestState);
  await scanDistributedTree(absoluteRoot, manifestState.manifest.files);
  await verifyMachineRecord(absoluteRoot);
  if (runSourceChecks) {
    await runIsolatedSourceChecks(absoluteRoot, [
      'check:projection',
      'check:projection-negative',
      'check:artifact',
      'check:consumer',
    ]);
    const afterSourceChecks = await verifyArtifactManifest(absoluteRoot);
    expectEqual(
      afterSourceChecks.manifestDigest,
      manifestState.manifestDigest,
      'artifact state after source checks'
    );
  }
  if (!quiet) console.log('Vouch artifact verification passed');
  return { manifestState, resultState, sourceState };
}

async function verifyExpectedReleaseFileDigests(root) {
  for (const [relative, expected] of Object.entries(
    EXPECTED_RELEASE_FILE_SHA256
  )) {
    expectEqual(
      sha256Hex(await readRequired(root, relative)),
      expected,
      `${relative} release identity`
    );
  }
}

async function verifyArtifactManifest(root) {
  const manifestFile = path.join(root, MANIFEST_PATH);
  const stat = await lstat(manifestFile).catch(() => null);
  if (stat === null || !stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`${MANIFEST_PATH} is missing or not a regular file`);
  }
  if (modeString(stat.mode) !== '0644') {
    throw new Error(`${MANIFEST_PATH} must have mode 0644`);
  }
  const { bytes: manifestBytes, value: manifest } = await readCanonicalJson(
    root,
    MANIFEST_PATH
  );
  exactKeys(
    manifest,
    ['artifact_manifest', 'directories', 'files'],
    'artifact manifest'
  );
  expectEqual(
    manifest.artifact_manifest,
    'vouch.scored26-artifact-manifest/v1',
    'artifact manifest tag'
  );
  requireArray(manifest.directories, 'artifact manifest directories');
  requireArray(manifest.files, 'artifact manifest files');

  validateManifestEntries(manifest.directories, 'directory');
  validateManifestEntries(manifest.files, 'file');
  const actual = await inventoryTree(root);
  if (!isDeepStrictEqual(manifest.directories, actual.directories)) {
    throw new Error('artifact directory inventory is not exact');
  }
  if (!isDeepStrictEqual(manifest.files, actual.files)) {
    throw new Error('artifact file inventory, hash, size, or mode mismatch');
  }
  const fileMap = new Map(manifest.files.map((entry) => [entry.path, entry]));
  const missing = ROOT_REQUIRED_PATHS.filter((entry) => !fileMap.has(entry));
  if (missing.length !== 0) {
    throw new Error(`required artifact paths are missing: ${missing.join(', ')}`);
  }
  if (fileMap.has(MANIFEST_PATH)) {
    throw new Error('artifact manifest must not list itself');
  }
  return { fileMap, manifest, manifestDigest: sha256Id(manifestBytes) };
}

function validateManifestEntries(entries, kind) {
  let previous = null;
  const seen = new Set();
  for (const [index, entry] of entries.entries()) {
    exactKeys(
      entry,
      kind === 'file'
        ? ['mode', 'path', 'sha256', 'size']
        : ['mode', 'path'],
      `${kind} manifest entry ${index}`
    );
    validateRelativePath(entry.path);
    if (seen.has(entry.path) || (previous !== null && utf8Compare(previous, entry.path) >= 0)) {
      throw new Error(`${kind} manifest entries are duplicated or unsorted`);
    }
    seen.add(entry.path);
    previous = entry.path;
    if (kind === 'directory') {
      expectEqual(entry.mode, '0755', `${entry.path} directory mode`);
    } else {
      if (!['0644', '0755'].includes(entry.mode)) {
        throw new Error(`${entry.path}: nonportable file mode`);
      }
      requireDigest(entry.sha256, `${entry.path} digest`);
      requireUint(entry.size, `${entry.path} size`);
    }
  }
}

export async function verifySourceProjection(root, manifestState) {
  const { bytes: sourceManifestBytes, value: sourceManifest } =
    await readJsonFile(root, SOURCE_PATHS.manifest);
  expectEqual(
    sha256Hex(sourceManifestBytes),
    SOURCE_MANIFEST_SHA256,
    'reviewed source-manifest SHA-256'
  );
  exactKeys(
    sourceManifest,
    [
      'excluded_categories',
      'files',
      'manifest_scope',
      'normative_contract',
      'review_toolchain',
      'rights',
      'source_projection',
      'source_snapshot',
      'synthetic_history',
      'summary',
      'transformations',
    ],
    'source manifest'
  );
  expectEqual(
    sourceManifest.source_projection,
    'vouch.scored26-source-projection/v2',
    'source manifest tag'
  );
  exactKeys(
    sourceManifest.source_snapshot,
    [
      'commit',
      'repository_locator',
      'working_tree_git_metadata_included',
    ],
    'source snapshot identity'
  );
  expectEqual(sourceManifest.source_snapshot.commit, C0, 'source derivation commit');
  expectEqual(
    sourceManifest.source_snapshot.repository_locator,
    null,
    'source repository locator'
  );
  expectEqual(
    sourceManifest.source_snapshot.working_tree_git_metadata_included,
    false,
    'source working-tree Git metadata boundary'
  );
  verifySyntheticHistory(sourceManifest.synthetic_history);
  exactKeys(
    sourceManifest.normative_contract,
    ['built_condition_count', 'condition_count', 'path', 'sha256'],
    'source normative contract'
  );
  expectEqual(
    sourceManifest.normative_contract.path,
    'artifact/contract/NATIVE-IMPLEMENTATION-CONDITIONS-v8.6.0.md',
    'source normative contract path'
  );
  expectEqual(
    sourceManifest.normative_contract.sha256,
    CONTRACT_SHA256,
    'source contract digest'
  );
  expectEqual(
    sourceManifest.normative_contract.condition_count,
    213,
    'source contract condition count'
  );
  expectEqual(
    sourceManifest.normative_contract.built_condition_count,
    213,
    'source built condition count'
  );
  exactKeys(
    sourceManifest.rights,
    [
      'commercial_use_permitted',
      'first_party_license',
      'general_license_granted',
      'limited_evaluation_permission',
      'notice',
      'permitted_acts',
      'purpose',
      'redistribution_permitted',
      'vendor_terms',
    ],
    'source rights declaration'
  );
  expectEqual(sourceManifest.rights.first_party_license, 'UNLICENSED', 'source license');
  expectEqual(
    sourceManifest.rights.limited_evaluation_permission,
    true,
    'source evaluation permission'
  );
  expectEqual(sourceManifest.rights.general_license_granted, false, 'source general license');
  expectEqual(sourceManifest.rights.redistribution_permitted, false, 'source redistribution');
  expectEqual(sourceManifest.rights.commercial_use_permitted, false, 'source commercial use');
  expectEqual(sourceManifest.rights.notice, 'RIGHTS.md', 'source rights path');
  requireArray(sourceManifest.rights.permitted_acts, 'source permitted acts');
  if (
    !isDeepStrictEqual(sourceManifest.rights.permitted_acts, [
      'download',
      'local reproduction',
      'compile',
      'execute',
      'evaluation-only modification',
    ])
  ) {
    throw new Error('source permitted acts changed');
  }
  expectEqual(
    sourceManifest.rights.purpose,
    'peer review and artifact evaluation only',
    'source rights purpose'
  );
  expectEqual(
    sourceManifest.rights.vendor_terms,
    'retained per dependency',
    'source vendor rights'
  );
  verifyReviewToolchain(sourceManifest.review_toolchain);

  exactKeys(
    sourceManifest.manifest_scope,
    ['self_excluded', 'transient_untracked_segments', 'vendor_exception'],
    'source manifest scope'
  );
  expectEqual(
    sourceManifest.manifest_scope.self_excluded,
    'SOURCE-MANIFEST.json',
    'source manifest self-exclusion'
  );
  requireArray(
    sourceManifest.manifest_scope.transient_untracked_segments,
    'source transient segments'
  );
  if (
    !isDeepStrictEqual(sourceManifest.manifest_scope.transient_untracked_segments, [
      'node_modules (root only; exact temporary nine-link toolchain)',
      'packages/vouch-consumer/dist',
      'target (root Cargo output only)',
    ])
  ) {
    throw new Error('source transient-segment policy changed');
  }
  requireArray(sourceManifest.excluded_categories, 'source excluded categories');
  requireArray(sourceManifest.transformations, 'source transformations');
  for (const value of sourceManifest.excluded_categories) {
    if (typeof value !== 'string' || value === '') {
      throw new Error('source excluded category is invalid');
    }
  }

  const rightsBytes = await readRequired(root, SOURCE_PATHS.rights);
  expectEqual(
    sha256Hex(rightsBytes),
    SOURCE_RIGHTS_SHA256,
    'reviewed source-rights SHA-256'
  );

  requireArray(sourceManifest.files, 'source manifest files');
  let previous = null;
  const sourcePaths = new Set();
  for (const [index, entry] of sourceManifest.files.entries()) {
    exactKeys(
      entry,
      ['bytes', 'class', 'origin', 'path', 'rights', 'sha256'],
      `source manifest row ${index}`
    );
    validateRelativePath(entry.path);
    if (
      sourcePaths.has(entry.path) ||
      (previous !== null && utf8Compare(previous, entry.path) >= 0)
    ) {
      throw new Error('source manifest rows are duplicated or unsorted');
    }
    sourcePaths.add(entry.path);
    previous = entry.path;
    requireUint(entry.bytes, `${entry.path} source byte count`);
    if (typeof entry.sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(entry.sha256)) {
      throw new Error(`${entry.path}: invalid source SHA-256`);
    }
    if (typeof entry.class !== 'string' || entry.class === '') {
      throw new Error(`${entry.path}: missing source class`);
    }
    if (
      ![
        'projection-authored',
        'source-snapshot-byte-exact',
        'synthetic-history-bundle',
      ].includes(entry.origin) &&
      !/^npm-package-(?:@types\/node|ajv|fast-deep-equal|fast-uri|json-schema-traverse|require-from-string|typescript|undici-types)-[0-9]+(?:\.[0-9]+){2}-byte-exact$/u.test(
        entry.origin
      )
    ) {
      throw new Error(`${entry.path}: invalid source origin`);
    }
    if (typeof entry.rights !== 'string' || entry.rights === '') {
      throw new Error(`${entry.path}: missing source rights classification`);
    }
  }
  const actualSourceFiles = manifestState.manifest.files
    .filter(
      (entry) =>
        entry.path.startsWith('source/') && entry.path !== SOURCE_PATHS.manifest
    )
    .map((entry) => ({ ...entry, path: entry.path.slice('source/'.length) }));
  if (sourceManifest.files.length !== actualSourceFiles.length) {
    throw new Error('source manifest file population differs from source/');
  }
  for (let index = 0; index < sourceManifest.files.length; index += 1) {
    const declared = sourceManifest.files[index];
    const actual = actualSourceFiles[index];
    if (
      declared.path !== actual.path ||
      declared.bytes !== actual.size ||
      `sha256:${declared.sha256}` !== actual.sha256
    ) {
      throw new Error(`source manifest mismatch at ${declared.path}`);
    }
  }
  const declaredToolchainLicensePaths = [
    sourceManifest.review_toolchain.license_path,
    ...sourceManifest.review_toolchain.type_dependencies.map(
      (entry) => entry.license_path
    ),
    ...sourceManifest.review_toolchain.runtime_dependencies.map(
      (entry) => entry.license_path
    ),
  ];
  for (const licensePath of declaredToolchainLicensePaths) {
    if (!sourcePaths.has(licensePath)) {
      throw new Error(
        `review-toolchain license path is absent with exact case: ${licensePath}`
      );
    }
  }

  verifySourceManifestSummary(sourceManifest);
  const { value: sourcePackage } = await readJsonFile(root, SOURCE_PATHS.package);
  requireObject(sourcePackage.scripts, 'source package scripts');
  for (const name of [
    'check:artifact',
    'check:consumer',
    'check:full',
    'check:source-full',
    'check:vouch-adversarial',
    'check:vouch-loop-example',
    'check:vouch-public-claims',
    'scored26:core-conformance',
  ]) {
    if (typeof sourcePackage.scripts[name] !== 'string' || sourcePackage.scripts[name] === '') {
      throw new Error(`source package is missing script ${name}`);
    }
  }

  return {
    fileCount: sourceManifest.files.length,
    manifestDigest: sha256Id(sourceManifestBytes),
    rightsDigest: sha256Id(rightsBytes),
  };
}

function verifySyntheticHistory(history) {
  exactKeys(
    history,
    [
      'base_commit',
      'bundle_authenticated_by_current_release',
      'bundle_path',
      'commit_count',
      'freeze_commit',
      'hash_algorithm',
      'identity',
      'lifecycle_status',
      'ref',
      'source_commit',
      'source_tree',
      'tracked_file_count',
    ],
    'synthetic history'
  );
  const expected = {
    base_commit: BASE,
    bundle_authenticated_by_current_release: true,
    bundle_path: 'synthetic-history/vouch-scored26.bundle',
    commit_count: 3,
    freeze_commit: FREEZE,
    hash_algorithm: 'sha1',
    identity: 'Artifact Maintainer <artifact@example.invalid>',
    lifecycle_status:
      'byte-identical to release/vouch-scored26.bundle in the D-bound release archive',
    ref: 'HEAD',
    source_commit: C0,
    source_tree: C0_TREE,
    tracked_file_count: C0_FILE_COUNT,
  };
  if (!isDeepStrictEqual(history, expected)) {
    throw new Error('synthetic history identity or release binding changed');
  }
}

function verifyReviewToolchain(toolchain) {
  exactKeys(
    toolchain,
    [
      'installation',
      'license',
      'license_path',
      'license_sha256',
      'npm_integrity',
      'package',
      'package_bytes',
      'package_file_count',
      'package_tree_sha256',
      'path',
      'runtime_dependencies',
      'split_transport',
      'type_dependencies',
      'version',
    ],
    'source review toolchain'
  );
  const packageKeys = [
    'license',
    'license_path',
    'license_sha256',
    'npm_integrity',
    'package',
    'package_bytes',
    'package_file_count',
    'package_tree_sha256',
    'path',
    'version',
  ];
  const primary = Object.fromEntries(
    packageKeys.map((key) => [key, toolchain[key]])
  );
  const expectedPrimary = {
    license: 'Apache-2.0',
    license_path: 'review-toolchain/typescript/LICENSE.txt',
    license_sha256:
      'a7d00bfd54525bc694b6e32f64c7ebcf5e6b7ae3657be5cc12767bce74654a47',
    npm_integrity:
      'sha512-aJn6wq13/afZp/jT9QZmwEjDqqvSGp1VT5GVg+f/t6/oVyrgXM6BY1h9BRh/O5p3PlUPAe+WuiEZOmb/49RqoQ==',
    package: 'typescript',
    package_bytes: 22866019,
    package_file_count: 130,
    package_tree_sha256:
      '261edf26930381acf18ff5fd333e20f28ffd5ebbe410afff203dc995ad31edf7',
    path: 'review-toolchain/typescript',
    version: '5.8.2',
  };
  if (!isDeepStrictEqual(primary, expectedPrimary)) {
    throw new Error('review TypeScript package identity changed');
  }
  expectEqual(
    toolchain.installation,
    'distributed offline; prepare:review-toolchain verifies and atomically reassembles the split TypeScript payload and creates nine temporary local links only in an OS temporary copy',
    'review-toolchain installation boundary'
  );
  const expectedSplitTransport = {
    distributed_file_limit_bytes: 8000000,
    manifest_path:
      'review-toolchain/chunks/typescript-5.8.2-typescript.js/manifest.json',
    ordered_part_paths: [
      'review-toolchain/chunks/typescript-5.8.2-typescript.js/part-0000',
      'review-toolchain/chunks/typescript-5.8.2-typescript.js/part-0001',
    ],
    original_bytes: 9065569,
    original_path: 'review-toolchain/typescript/lib/typescript.js',
    original_sha256:
      '795e49e46d497cc16e4b02916b50cbca257b4256d62cddc4cc504103f7961027',
    part_size_limit_bytes: 7340032,
    reassembly:
      'verify manifest and ordered parts, then atomically reconstruct only in an OS temporary copy',
  };
  if (!isDeepStrictEqual(toolchain.split_transport, expectedSplitTransport)) {
    throw new Error('review TypeScript split transport changed');
  }
  const expectedTypes = [
    {
      license: 'MIT',
      license_path: 'review-toolchain/types-node/LICENSE',
      license_sha256:
        'c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383',
      npm_integrity:
        'sha512-6oYBAi5ikg4Pl+kGsoYtawUMBT2zZMCvPNF7pVLnHZfd1zf38DRiWn/gT01RYCdUqkv7Fhr+C9ot4/tb+2sVvA==',
      package: '@types/node',
      package_bytes: 2288801,
      package_file_count: 69,
      package_tree_sha256:
        '4875fd8a4ba9bd648da35ec6f069793469a484855e6510be9fc7782c5c2814f7',
      path: 'review-toolchain/types-node',
      version: '20.19.43',
    },
    {
      license: 'MIT',
      license_path: 'review-toolchain/undici-types/LICENSE',
      license_sha256:
        'a6db8096b2707bc0102d256917d4d33f298ba36d8c3f25de067a2b5bb379db27',
      npm_integrity:
        'sha512-iwDZqg0QAGrg9Rav5H4n0M64c3mkR59cJ6wQp+7C4nI0gsmExaedaYLNO44eT4AtBBwjbTiGPMlt2Md0T9H9JQ==',
      package: 'undici-types',
      package_bytes: 83680,
      package_file_count: 41,
      package_tree_sha256:
        'f4b4e5b5e3aa89fde9544ecac9f3792ca436ca6e1699deeaf564d5c757a155e0',
      path: 'review-toolchain/undici-types',
      version: '6.21.0',
    },
  ];
  const expectedRuntime = [
    {
      license: 'MIT',
      license_path: 'review-toolchain/ajv/LICENSE',
      license_sha256:
        'a05350a88e318e4f5f2c2a1ff1e2e88daa4dd38e6e78b71cccae422bdc762cc3',
      npm_integrity:
        'sha512-B/gBuNg5SiMTrPkC+A2+cW0RszwxYmn6VYxB/inlBStS5nx6xHIt/ehKRhIMhqusl7a8LjQoZnjCs5vhwxOQ1g==',
      package: 'ajv',
      package_bytes: 1030888,
      package_file_count: 466,
      package_tree_sha256:
        '9cfef146f3453a96c9fd2ebc4b7ca8605fdbbafff57c6eb503ab61e6cac20704',
      path: 'review-toolchain/ajv',
      version: '8.17.1',
    },
    {
      license: 'MIT',
      license_path: 'review-toolchain/fast-deep-equal/LICENSE',
      license_sha256:
        '7bf9b2de73a6b356761c948d0e9eeb4be6c1270bd04c79cd489c1e400ffdfc1a',
      npm_integrity:
        'sha512-f3qQ9oQy9j2AhBe/H9VC91wLmKBCCU/gDOnKNAYG5hswO7BLKj09Hc5HYNz9cGI++xlpDCIgDaitVs03ATR84Q==',
      package: 'fast-deep-equal',
      package_bytes: 12966,
      package_file_count: 11,
      package_tree_sha256:
        '9304d4597f884478732c4c2a31fed626b64116083555b4055757ad96e6b44926',
      path: 'review-toolchain/fast-deep-equal',
      version: '3.1.3',
    },
    {
      license: 'BSD-3-Clause',
      license_path: 'review-toolchain/fast-uri/LICENSE',
      license_sha256:
        'b010b0dfdfdb23d7396e03b82cd4621fc9bb8f95d6b0aea70b9c24e12074c786',
      npm_integrity:
        'sha512-i70LwGWUduXqzicKXWshooq+sWL1K3WUU5rKZNG/0i3a1OSoX3HqhH5WbWwTmqWfor4urUakGPiRQcleRZTwOg==',
      package: 'fast-uri',
      package_bytes: 157708,
      package_file_count: 34,
      package_tree_sha256:
        '0d0104d40dd6c356fc38bf6458ddbf07b5a6d3ffe3f65da8b74a7624ed4c783e',
      path: 'review-toolchain/fast-uri',
      version: '3.1.3',
    },
    {
      license: 'MIT',
      license_path: 'review-toolchain/json-schema-traverse/LICENSE',
      license_sha256:
        '7bf9b2de73a6b356761c948d0e9eeb4be6c1270bd04c79cd489c1e400ffdfc1a',
      npm_integrity:
        'sha512-NM8/P9n3XjXhIZn1lLhkFaACTOURQXjWhV4BA/RnOv8xvgqtqpAX9IO4mRQxSx1Rlo4tqzeqb0sOlruaOy3dug==',
      package: 'json-schema-traverse',
      package_bytes: 22220,
      package_file_count: 12,
      package_tree_sha256:
        'd3038e49ea48f3d6954548c8c49298ab575e40e0a5914ad6573ae3f2b08e4991',
      path: 'review-toolchain/json-schema-traverse',
      version: '1.0.0',
    },
    {
      license: 'MIT',
      license_path: 'review-toolchain/require-from-string/license',
      license_sha256:
        '6ee0feb1f6ef996ff5a68600f8cf98909cf412d39ef3cdceaefd87d636fa1b7f',
      npm_integrity:
        'sha512-Xf0nWe6RseziFMu+Ap9biiUbmplq6S9/p+7w7YXP/JBHhrUDDUhwa+vANyubuqfZWTveU//DYVGsDG7RKL/vEw==',
      package: 'require-from-string',
      package_bytes: 3422,
      package_file_count: 4,
      package_tree_sha256:
        '910330a0f913b9a99df75e8da057e1db30fe6e3f2bdf93ddc06e4dce61983ccc',
      path: 'review-toolchain/require-from-string',
      version: '2.0.2',
    },
  ];
  verifyReviewToolchainPackages(
    toolchain.type_dependencies,
    expectedTypes,
    packageKeys,
    'type'
  );
  verifyReviewToolchainPackages(
    toolchain.runtime_dependencies,
    expectedRuntime,
    packageKeys,
    'runtime'
  );
}

function verifyReviewToolchainPackages(actual, expected, packageKeys, label) {
  requireArray(actual, `review-toolchain ${label} dependencies`);
  for (const [index, entry] of actual.entries()) {
    exactKeys(entry, packageKeys, `review-toolchain ${label} dependency ${index}`);
  }
  if (!isDeepStrictEqual(actual, expected)) {
    throw new Error(`review-toolchain ${label} dependency closure changed`);
  }
}

function verifySourceManifestSummary(sourceManifest) {
  exactKeys(
    sourceManifest.summary,
    [
      'bytes',
      'file_count',
      'files_by_class',
      'files_by_origin',
      'files_by_rights',
    ],
    'source manifest summary'
  );
  const byClass = {};
  const byOrigin = {};
  const byRights = {};
  let bytes = 0;
  for (const row of sourceManifest.files) {
    bytes += row.bytes;
    byClass[row.class] = (byClass[row.class] ?? 0) + 1;
    byOrigin[row.origin] = (byOrigin[row.origin] ?? 0) + 1;
    byRights[row.rights] = (byRights[row.rights] ?? 0) + 1;
  }
  expectEqual(
    sourceManifest.summary.file_count,
    sourceManifest.files.length,
    'source manifest summary file count'
  );
  expectEqual(sourceManifest.summary.bytes, bytes, 'source manifest summary bytes');
  expectEqual(sourceManifest.summary.file_count, SOURCE_FILE_COUNT, 'reviewed source file count');
  expectEqual(sourceManifest.summary.bytes, SOURCE_BYTE_COUNT, 'reviewed source byte count');
  expectEqual(
    byOrigin['source-snapshot-byte-exact'],
    C0_FILE_COUNT,
    'byte-exact C0 source population'
  );
  expectEqual(
    byOrigin['synthetic-history-bundle'],
    1,
    'synthetic history bundle population'
  );
  if (
    !isDeepStrictEqual(sourceManifest.summary.files_by_class, sortObject(byClass)) ||
    !isDeepStrictEqual(sourceManifest.summary.files_by_origin, sortObject(byOrigin)) ||
    !isDeepStrictEqual(sourceManifest.summary.files_by_rights, sortObject(byRights))
  ) {
    throw new Error('source manifest class/origin/rights summary changed');
  }
  const knownPaths = new Set(sourceManifest.files.map((row) => row.path));
  for (const [index, transformation] of sourceManifest.transformations.entries()) {
    exactKeys(transformation, ['paths', 'reason'], `source transformation ${index}`);
    requireArray(transformation.paths, `source transformation ${index} paths`);
    if (transformation.paths.length === 0) {
      throw new Error(`source transformation ${index} has no paths`);
    }
    requireUnique(transformation.paths, `source transformation ${index} path`);
    for (const transformedPath of transformation.paths) {
      if (!knownPaths.has(transformedPath)) {
        throw new Error(`source transformation names absent path ${transformedPath}`);
      }
    }
    if (typeof transformation.reason !== 'string' || transformation.reason === '') {
      throw new Error(`source transformation ${index} has no reason`);
    }
  }
}

export async function verifyContractAndResults(root) {
  const activeContract = await readRequired(root, SOURCE_PATHS.activeContract);
  const historicalContract = await readRequired(
    root,
    SOURCE_PATHS.historicalContract
  );
  expectEqual(
    sha256Hex(activeContract),
    CONTRACT_SHA256,
    'v8.6.0 contract SHA-256'
  );
  expectEqual(
    sha256Hex(historicalContract),
    HISTORICAL_CONTRACT_SHA256,
    'historical contract SHA-256'
  );

  const conditionIds = [
    ...activeContract
      .toString('utf8')
      .matchAll(/^### ((?:A|P)-\d+|C-[A-Z]+-\d+)\b/gm),
  ].map((match) => match[1]);
  requireUnique(conditionIds, 'contract condition');
  expectEqual(conditionIds.length, 213, 'contract condition population');

  const sourceMapRead = await readJsonFile(root, SOURCE_PATHS.conditionMap);
  const resultMapRead = await readJsonFile(root, RESULT_PATHS.conditionMap);
  if (!sourceMapRead.bytes.equals(resultMapRead.bytes)) {
    throw new Error('release condition map differs from the projected source map');
  }
  const conditionMap = resultMapRead.value;
  expectEqual(
    conditionMap.condition_map,
    'vouch.scored26-condition-map/v0',
    'condition-map tag'
  );
  expectEqual(
    conditionMap.contract_sha256,
    CONTRACT_SHA256,
    'condition-map contract digest'
  );
  requireArray(conditionMap.conditions, 'condition-map rows');
  expectEqual(conditionMap.conditions.length, 213, 'condition-map population');

  const { value: registry } = await readJsonFile(
    root,
    SOURCE_PATHS.fixtureRegistry
  );
  expectEqual(
    registry.fixture_registry,
    'vouch.scored26-fixture-registry/v0',
    'fixture registry tag'
  );
  expectEqual(
    registry.contract_sha256,
    CONTRACT_SHA256,
    'fixture registry contract digest'
  );
  requireArray(registry.fixtures, 'fixture registry rows');
  expectEqual(registry.fixtures.length, 165, 'fixture registry population');
  const fixtureIds = registry.fixtures.map((row) => row.fixture_id);
  requireUnique(fixtureIds, 'fixture registry');
  const fixtureSet = new Set(fixtureIds);

  const mappedIds = conditionMap.conditions.map((row) => row.condition_id);
  requireUnique(mappedIds, 'condition map');
  if (!isDeepStrictEqual(mappedIds, conditionIds)) {
    throw new Error('condition map is not the exact ordered contract projection');
  }
  for (const row of conditionMap.conditions) {
    expectEqual(row.scope, 'built', `${row.condition_id} scope`);
    expectEqual(
      row.implementation_status,
      'built',
      `${row.condition_id} implementation status`
    );
    requireArray(row.test_or_fixture_ids, `${row.condition_id} fixture owners`);
    if (row.test_or_fixture_ids.length === 0) {
      throw new Error(`${row.condition_id} has no fixture owner`);
    }
    requireUnique(row.test_or_fixture_ids, `${row.condition_id} fixture owner`);
    for (const fixtureId of row.test_or_fixture_ids) {
      if (!fixtureSet.has(fixtureId)) {
        throw new Error(`${row.condition_id} names unknown fixture ${fixtureId}`);
      }
    }
  }

  const fixtureRead = await readCanonicalJson(root, RESULT_PATHS.fixtures);
  const workloadRead = await readCanonicalJson(root, RESULT_PATHS.workload);
  const mutationRead = await readCanonicalJson(root, RESULT_PATHS.mutation);
  const performanceRead = await readCanonicalJson(root, RESULT_PATHS.performance);
  const comparisonsRead = await readCanonicalJson(root, RESULT_PATHS.comparisons);

  verifyFixtureResults(fixtureRead.value, fixtureSet);
  verifyWorkloadResults(workloadRead.value);
  verifyMutationResults(mutationRead.value);
  const { value: activationResults } = await readCanonicalJson(
    root,
    SOURCE_PATHS.activationResults
  );
  verifyActivationResults(activationResults);
  verifyPerformanceResults(performanceRead.value);
  const comparisons = verifyComparisons(comparisonsRead.value);

  return {
    comparisons,
    conditionMap: resultMapRead,
    fixtures: fixtureRead,
    mutation: mutationRead,
    performance: performanceRead,
    workload: workloadRead,
  };
}

function verifyFixtureResults(report, fixtureSet) {
  expectEqual(
    report.fixture_report,
    'vouch.scored26-fixture/v0',
    'fixture report tag'
  );
  verifyFixtureSummary(report.fixture_results);
  requireArray(report.results, 'fixture result rows');
  expectEqual(report.results.length, 165, 'fixture result population');
  const resultIds = report.results.map((row) => row.fixture_id);
  requireUnique(resultIds, 'fixture result');
  if (
    resultIds.some((id) => !fixtureSet.has(id)) ||
    [...fixtureSet].some((id) => !resultIds.includes(id))
  ) {
    throw new Error('fixture results are not an exact registry projection');
  }
  for (const row of report.results) {
    expectEqual(row.scope, 'built', `${row.fixture_id} scope`);
    expectEqual(row.implemented, true, `${row.fixture_id} implemented`);
    expectEqual(row.matched, true, `${row.fixture_id} match`);
  }
}

function verifyFixtureSummary(summary) {
  requireObject(summary, 'fixture summary');
  requireObject(summary.built, 'built fixture summary');
  requireObject(summary.design_target, 'design-target fixture summary');
  const expectedBuilt = {
    expected: 165,
    matched: 165,
    mismatched: 0,
    skipped: 0,
  };
  const expectedDesign = {
    implemented: 0,
    listed: 0,
    matched: 0,
    not_implemented: 0,
  };
  if (
    !isDeepStrictEqual(summary.built, expectedBuilt) ||
    !isDeepStrictEqual(summary.design_target, expectedDesign)
  ) {
    throw new Error('fixture summary is not 165/165 with zero skips and targets');
  }
}

function verifyWorkloadResults(report) {
  expectEqual(
    report.workload_report,
    'vouch.scored26-workload/v0',
    'workload report tag'
  );
  verifyWorkloadSummary(report.workload_summary);
  requireObject(report.coverage, 'workload coverage');
  requireArray(report.coverage.covered, 'covered identifiers');
  requireArray(report.coverage.uncovered, 'uncovered identifiers');
  const allCoverage = [...report.coverage.covered, ...report.coverage.uncovered];
  requireUnique(allCoverage, 'coverage identifier');
  for (const identifier of allCoverage) {
    if (
      !/^(?:baseline|changed):(?:node:\d{4}|branch:\d{4}:(?:alternate|consequent))$/u.test(
        identifier
      )
    ) {
      throw new Error(`coverage identifier is not version-qualified: ${identifier}`);
    }
  }
  const coveredNodes = report.coverage.covered.filter((id) => id.includes(':node:')).length;
  const coveredBranches = report.coverage.covered.filter((id) => id.includes(':branch:')).length;
  const totalNodes = allCoverage.filter((id) => id.includes(':node:')).length;
  const totalBranches = allCoverage.filter((id) => id.includes(':branch:')).length;
  if (
    coveredNodes !== 596 ||
    totalNodes !== 620 ||
    coveredBranches !== 102 ||
    totalBranches !== 120
  ) {
    throw new Error('workload coverage population changed');
  }
}

function verifyWorkloadSummary(summary) {
  requireObject(summary, 'workload summary');
  for (const [name, expected] of Object.entries({
    candidates: 1536,
    decision_flips: 76,
    decision_pair_count: 240,
    development: 192,
    excluded_from_matrix_count: 0,
    held_out: 48,
    held_out_flips: 13,
    selected_case_count: 240,
  })) {
    expectEqual(summary[name], expected, `workload ${name}`);
  }
  const expectedBaseline = {
    approve: 65,
    deny: 69,
    'invalid-input': 48,
    review: 58,
  };
  const expectedChanged = {
    approve: 69,
    deny: 53,
    'invalid-input': 48,
    review: 70,
  };
  const expectedMatrix = {
    approve: { approve: 37, deny: 0, 'invalid-input': 0, review: 28 },
    deny: { approve: 0, deny: 53, 'invalid-input': 0, review: 16 },
    'invalid-input': { approve: 0, deny: 0, 'invalid-input': 48, review: 0 },
    review: { approve: 32, deny: 0, 'invalid-input': 0, review: 26 },
  };
  if (
    !isDeepStrictEqual(summary.decision_distribution_baseline, expectedBaseline) ||
    !isDeepStrictEqual(summary.decision_distribution_changed, expectedChanged) ||
    !isDeepStrictEqual(summary.transition_matrix, expectedMatrix)
  ) {
    throw new Error('workload decision distributions or transition matrix changed');
  }
  const exceptions = summary.exception_count_by_kind;
  if (
    !isDeepStrictEqual(exceptions, {
      not_comparable_executions: 0,
      pipeline_failure_executions: 0,
      profile_escape_executions: 0,
    })
  ) {
    throw new Error('workload exception counts are not zero');
  }
}

function verifyMutationResults(report) {
  expectEqual(
    report.mutation_report,
    'vouch.scored26-mutation/v0',
    'mutation report tag'
  );
  verifyMutationSummary(report.mutation_summary);
  requireArray(report.rows, 'mutation rows');
  const total = report.rows.find((row) => row.class === 'Total');
  if (total === undefined) throw new Error('mutation report has no Total row');
  if (
    !isDeepStrictEqual(total.mutant_level, {
      activated_any: 5,
      built: 12,
      detected_any: 4,
      seeded: 12,
    }) ||
    !isDeepStrictEqual(total.case_level, {
      common_mode_cases: 7,
      disagreement_cases: 640,
      infrastructure_failure_cases: 0,
      pipeline_failure_cases: 0,
      survivor_cases: 0,
    })
  ) {
    throw new Error('mutation Total row changed');
  }
}

function verifyMutationSummary(summary) {
  requireObject(summary, 'mutation summary');
  const mutant = summary.mutant_level;
  const cases = summary.case_level;
  if (
    !isDeepStrictEqual(mutant, {
      activated_any: 5,
      built: 12,
      detected_any: 4,
      detection_rate: '33.3',
      seeded: 12,
    }) ||
    !isDeepStrictEqual(cases, {
      common_mode_cases: 7,
      disagreement_cases: 640,
      infrastructure_failure_cases: 0,
      pipeline_failure_cases: 0,
      survivor_cases: 0,
    })
  ) {
    throw new Error('mutation summary is not 12 built, 5 activated, 4 detected, 640/7');
  }
  const activatedPairs = cases.disagreement_cases + cases.common_mode_cases;
  expectEqual(activatedPairs, 647, 'activated mutant/case pairs');
  expectEqual(12 * 240 - activatedPairs, 2233, 'nonactivated mutant/case pairs');
}

function verifyActivationResults(report) {
  expectEqual(
    report.activation_report,
    'vouch.scored26-mutation-activation-results/v0',
    'mutation activation report tag'
  );
  expectEqual(
    report.empirical_counts_include_activation_witnesses,
    false,
    'activation witness/empirical separation'
  );
  requireArray(report.cases, 'mutation activation cases');
  expectEqual(report.cases.length, 12, 'dedicated mutation witness count');
  const expectedIds = Array.from(
    { length: 12 },
    (_, index) => `M${String(index + 1).padStart(2, '0')}`
  );
  const actualIds = report.cases.map((row) => row.mutant_id);
  if (!isDeepStrictEqual(actualIds, expectedIds)) {
    throw new Error('dedicated mutation witnesses are not the closed M01--M12 set');
  }
  let disagreement = 0;
  let commonMode = 0;
  for (const row of report.cases) {
    expectEqual(row.activated, true, `${row.mutant_id} witness activation`);
    expectEqual(
      row.observed_witness_class,
      row.expected_witness_class,
      `${row.mutant_id} witness class`
    );
    if (row.observed_witness_class === 'disagreement') disagreement += 1;
    else if (row.observed_witness_class === 'common-mode') commonMode += 1;
    else throw new Error(`${row.mutant_id}: unknown witness class`);
  }
  expectEqual(disagreement, 8, 'dedicated disagreement witnesses');
  expectEqual(commonMode, 4, 'dedicated common-mode witnesses');
}

function verifyPerformanceResults(report) {
  expectEqual(
    report.performance_report,
    'vouch.scored26-performance/v0',
    'performance report tag'
  );
  requireArray(report.measurements, 'performance measurements');
  expectEqual(report.measurements.length, 12, 'performance measurement rows');
  const expectedMetrics = [
    'envelope_bytes',
    'native_verification_latency',
    'peak_resident_memory',
    'selected_corpus_replay_latency',
  ];
  const expectedStatistics = ['maximum', 'median', 'p95'];
  const expectedUnits = {
    envelope_bytes: 'byte',
    native_verification_latency: 'microsecond',
    peak_resident_memory: 'byte',
    selected_corpus_replay_latency: 'microsecond',
  };
  const expectedPopulations = {
    envelope_bytes: 480,
    native_verification_latency: 14400,
    peak_resident_memory: 30,
    selected_corpus_replay_latency: 30,
  };
  const seen = new Set();
  for (const row of report.measurements) {
    if (!expectedMetrics.includes(row.metric) || !expectedStatistics.includes(row.statistic)) {
      throw new Error('unexpected performance metric or statistic');
    }
    requireUint(row.value, 'performance value');
    requireUint(row.population, 'performance population');
    expectEqual(row.unit, expectedUnits[row.metric], `${row.metric} unit`);
    expectEqual(
      row.population,
      expectedPopulations[row.metric],
      `${row.metric} population`
    );
    requireArray(row.excluded_ids, `${row.metric} exclusions`);
    expectEqual(row.excluded_ids.length, 0, `${row.metric} exclusion count`);
    const key = `${row.metric}\0${row.statistic}`;
    if (seen.has(key)) throw new Error(`duplicate performance row ${key}`);
    seen.add(key);
  }
  for (const metric of expectedMetrics) {
    for (const statistic of expectedStatistics) {
      if (!seen.has(`${metric}\0${statistic}`)) {
        throw new Error(`missing performance row ${metric}/${statistic}`);
      }
    }
  }
}

function verifyComparisons(report) {
  expectEqual(
    report.exact_reproduction_comparisons,
    'vouch.scored26-reproduction-comparisons/v0',
    'comparison report tag'
  );
  requireArray(report.comparisons, 'exact reproduction comparisons');
  expectEqual(report.comparisons.length, 482, 'exact reproduction population');
  let previous = null;
  const seen = new Set();
  for (const row of report.comparisons) {
    validateRelativePath(row.path);
    if (seen.has(row.path) || (previous !== null && utf8Compare(previous, row.path) >= 0)) {
      throw new Error('exact reproduction comparisons are duplicated or unsorted');
    }
    seen.add(row.path);
    previous = row.path;
    requireDigest(row.expected_sha256, `${row.path} expected digest`);
    requireDigest(row.observed_sha256, `${row.path} observed digest`);
    expectEqual(row.matched, true, `${row.path} reproduction match`);
    expectEqual(
      row.observed_sha256,
      row.expected_sha256,
      `${row.path} reproduced digest`
    );
  }
  const payloads = report.comparisons.filter((row) => row.path.endsWith('/payload.json'));
  if (payloads.length !== 480) {
    throw new Error('exact reproduction set does not contain 480 receipt payloads');
  }
  for (const required of [
    'release/replay-manifest.json',
    'release/scored26-workload-runner',
  ]) {
    if (!seen.has(required)) {
      throw new Error(`exact reproduction set is missing ${required}`);
    }
  }
  return report.comparisons;
}

async function verifyReleaseChain(root, results) {
  const descriptorRead = await readCanonicalJson(root, CHAIN_PATHS.descriptor);
  const descriptorEnvelopeRead = await readCanonicalJson(
    root,
    CHAIN_PATHS.descriptorEnvelope
  );
  const cleanRunRead = await readCanonicalJson(root, CHAIN_PATHS.cleanRun);
  const observationRead = await readCanonicalJson(root, CHAIN_PATHS.observation);
  const observationEnvelopeRead = await readCanonicalJson(
    root,
    CHAIN_PATHS.observationEnvelope
  );
  const publicationRead = await readCanonicalJson(root, CHAIN_PATHS.publication);
  const terminalRead = await readCanonicalJson(root, CHAIN_PATHS.terminal);
  const policyRead = await readCanonicalJson(root, CHAIN_PATHS.policy);
  const publicKeyRead = await readCanonicalJson(root, CHAIN_PATHS.publicKey);

  const publicKey = verifyPublicKeyRecord(publicKeyRead.value);
  const policyKey = verifyTrustPolicy(policyRead.value, publicKey);
  const descriptor = descriptorRead.value;
  verifyDescriptor(descriptor, results.comparisons);
  await verifyProjectedDependencyIdentities(root, descriptor);
  requireArray(policyKey.allowed_engine_sha256, 'policy engine identities');
  if (!policyKey.allowed_engine_sha256.includes(descriptor.engine_sha256)) {
    throw new Error('trust policy does not authorize the engine named by D');
  }
  verifyDsseEnvelope({
    envelope: descriptorEnvelopeRead.value,
    expectedPayload: descriptorRead.bytes,
    expectedPayloadType: DESCRIPTOR_TYPE,
    keyId: RELEASE_KEY_ID,
    publicKey,
    label: 'D',
  });

  if (policyKey.key_id !== descriptor.key_id) {
    throw new Error('D key is not the policy-selected release key');
  }
  const archiveTransport = await verifyArchiveChunkTransport(
    root,
    descriptor.archive_sha256
  );
  const dDigest = sha256Id(descriptorRead.bytes);
  const qDigest = sha256Id(cleanRunRead.bytes);
  const rDigest = sha256Id(observationRead.bytes);

  const q = cleanRunRead.value;
  expectEqual(q.reproduction_report, 'vouch.scored26-reproduction/v0', 'Q tag');
  expectEqual(q.status, 'pass', 'Q status');
  expectEqual(q.release_descriptor_sha256, dDigest, 'Q to D link');
  verifyFixtureSummary(q.fixture_results);
  verifyWorkloadSummaryObject(q.workload);
  verifyMutationSummary(q.mutation);
  expectEqual(q.fixture_report_sha256, sha256Id(results.fixtures.bytes), 'Q fixture digest');
  expectEqual(q.workload_report_sha256, sha256Id(results.workload.bytes), 'Q workload digest');
  expectEqual(q.mutation_report_sha256, sha256Id(results.mutation.bytes), 'Q mutation digest');
  expectEqual(
    q.performance_report_sha256,
    sha256Id(results.performance.bytes),
    'Q performance digest'
  );
  expectEqual(
    q.exact_reproduction_comparisons_sha256,
    sha256Id(await readRequired(root, RESULT_PATHS.comparisons)),
    'Q comparison digest'
  );
  expectEqual(q.release_private_key_present, false, 'Q release-key absence');
  expectEqual(q.public_data_scan, 'pass', 'Q public-data scan');
  expectEqual(q.worktree_clean, true, 'Q worktree state');
  requireUint(q.clean_run_runtime_seconds, 'Q clean-run duration');

  const r = observationRead.value;
  expectEqual(
    r.reproduction_observation,
    'csk.reproduction-observation/v0',
    'R tag'
  );
  expectEqual(r.release_descriptor_sha256, dDigest, 'R to D link');
  expectEqual(r.clean_run_report_sha256, qDigest, 'R to Q link');
  expectEqual(
    r.clean_run_runtime_seconds,
    q.clean_run_runtime_seconds,
    'R/Q duration derivation'
  );
  if (!isDeepStrictEqual(r.fixture_results, q.fixture_results)) {
    throw new Error('R fixture summary does not derive from Q');
  }
  expectEqual(
    r.workload_summary_sha256,
    sha256Id(results.workload.bytes),
    'R workload digest'
  );
  expectEqual(
    r.mutation_summary_sha256,
    sha256Id(results.mutation.bytes),
    'R mutation digest'
  );
  verifyRComparisons(r.reproduced_result_comparisons, results.comparisons);
  verifyRObservationalSet(r.verify_only_observational_results, results);
  verifyRPerformance(r.performance_observations, results.performance.value.measurements);
  verifyDsseEnvelope({
    envelope: observationEnvelopeRead.value,
    expectedPayload: observationRead.bytes,
    expectedPayloadType: OBSERVATION_TYPE,
    keyId: RELEASE_KEY_ID,
    publicKey,
    label: 'R',
  });

  const p = publicationRead.value;
  expectEqual(p.publication_record, 'csk.release-publication/v0', 'P tag');
  expectEqual(p.release_descriptor_sha256, dDigest, 'P to D link');
  expectEqual(p.reproduction_observation_sha256, rDigest, 'P to R link');

  const s = terminalRead.value;
  exactKeys(
    s,
    [
      'chain_verified',
      'claim_language_scan',
      'clean_run_report_sha256',
      'failed_check',
      'input_artifact',
      'paper_claims_matched',
      'primary_error',
      'publication_report',
      'release_descriptor_sha256',
      'reproduction_observation_sha256',
      'status',
      'underlying_error',
    ],
    'S terminal report'
  );
  expectEqual(s.publication_report, 'vouch.scored26-publication/v0', 'S tag');
  expectEqual(s.status, 'pass', 'S status');
  expectEqual(s.chain_verified, 'pass', 'S chain status');
  expectEqual(s.paper_claims_matched, true, 'S machine-record claim status');
  expectEqual(s.claim_language_scan, 'pass', 'S claim-language scan');
  expectEqual(s.release_descriptor_sha256, dDigest, 'S to D link');
  expectEqual(s.clean_run_report_sha256, qDigest, 'S to Q link');
  expectEqual(s.reproduction_observation_sha256, rDigest, 'S to R link');
  for (const name of ['failed_check', 'input_artifact', 'primary_error', 'underlying_error']) {
    expectEqual(s[name], null, `S ${name}`);
  }

  for (const [label, value] of [
    ['D', descriptor],
    ['R', r],
    ['P', p],
    ['S', s],
  ]) {
    if (containsProjectionAuthorityField(value)) {
      throw new Error(`${label} improperly claims authority over the review source projection`);
    }
  }
  return { archive: archiveTransport.archive, descriptor };
}

async function verifyArchiveChunkTransport(root, descriptorArchiveSha256) {
  const result = await verifyArchiveChunks({
    manifestPath: path.join(root, ...ARCHIVE_CHUNK_MANIFEST_PATH.split('/')),
  });
  expectEqual(
    `sha256:${result.archive.sha256}`,
    descriptorArchiveSha256,
    'D-bound release archive chunk transport'
  );
  return result;
}

export async function verifyBundleEvidence(root, releaseState) {
  requireObject(releaseState, 'verified release state');
  const descriptor = requireObject(
    releaseState.descriptor,
    'verified release descriptor'
  );
  const archive = requireObject(
    releaseState.archive,
    'verified archive transport identity'
  );
  requireUint(archive.bytes, 'verified archive byte count');
  if (typeof archive.sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(archive.sha256)) {
    throw new Error('verified archive transport identity: invalid SHA-256');
  }
  expectEqual(
    descriptor.archive_sha256,
    `sha256:${archive.sha256}`,
    'verified archive transport to D link'
  );

  const sourceBundleBytes = await readRequired(root, SYNTHETIC_BUNDLE_PATH);
  const sourceBundleSha256 = sha256Id(sourceBundleBytes);
  const { bytes: releaseManifestBytes, value: releaseManifest } =
    await readCanonicalJson(root, RELEASE_MANIFEST_PATH);
  exactKeys(
    releaseManifest,
    ['files', 'release_manifest'],
    'D-bound release manifest'
  );
  expectEqual(
    releaseManifest.release_manifest,
    'vouch.scored26-release-manifest/v0',
    'D-bound release-manifest tag'
  );
  requireArray(releaseManifest.files, 'D-bound release-manifest files');
  let previousPath = null;
  const seenPaths = new Set();
  for (const [index, row] of releaseManifest.files.entries()) {
    exactKeys(
      row,
      [
        'artifact_class',
        'byte_length',
        'expected_result',
        'generating_command',
        'path',
        'sha256',
      ],
      `D-bound release-manifest row ${index}`
    );
    validateRelativePath(row.path);
    if (
      seenPaths.has(row.path) ||
      (previousPath !== null && utf8Compare(previousPath, row.path) >= 0)
    ) {
      throw new Error('D-bound release-manifest paths are duplicated or unsorted');
    }
    seenPaths.add(row.path);
    previousPath = row.path;
    if (typeof row.artifact_class !== 'string' || row.artifact_class === '') {
      throw new Error(`${row.path}: empty release-manifest artifact class`);
    }
    if (typeof row.generating_command !== 'string' || row.generating_command === '') {
      throw new Error(`${row.path}: empty release-manifest generating command`);
    }
    requireUint(row.byte_length, `${row.path} release-manifest byte count`);
    requireDigest(row.sha256, `${row.path} release-manifest digest`);
    expectEqual(
      row.expected_result,
      row.sha256,
      `${row.path} release-manifest expected result`
    );
  }

  const bundleRows = releaseManifest.files.filter(
    (row) => row.path === 'release/vouch-scored26.bundle'
  );
  expectEqual(bundleRows.length, 1, 'D-bound release-manifest bundle row count');
  const expectedBundleRow = {
    artifact_class: 'source-bundle',
    byte_length: sourceBundleBytes.length,
    expected_result: sourceBundleSha256,
    generating_command: 'git bundle create',
    path: 'release/vouch-scored26.bundle',
    sha256: sourceBundleSha256,
  };
  if (!isDeepStrictEqual(bundleRows[0], expectedBundleRow)) {
    throw new Error(
      'D-bound release-manifest bundle row does not match the distributed bundle bytes'
    );
  }

  const { value: reconciliation } = await readCanonicalJson(
    root,
    BUNDLE_RECONCILIATION_PATH
  );
  exactKeys(
    reconciliation,
    [
      'archive_bundle',
      'bundle_reconciliation',
      'checks',
      'descriptor_archive',
      'release_manifest',
      'source_bundle',
      'source_projection_report_fact',
      'status',
    ],
    'bundle reconciliation'
  );
  expectEqual(
    reconciliation.bundle_reconciliation,
    'vouch.scored26-bundle-reconciliation/v1',
    'bundle reconciliation tag'
  );
  expectEqual(reconciliation.status, 'pass', 'bundle reconciliation status');

  exactKeys(
    reconciliation.descriptor_archive,
    ['byte_length', 'd_archive_sha256'],
    'bundle reconciliation descriptor archive'
  );
  expectEqual(
    reconciliation.descriptor_archive.byte_length,
    archive.bytes,
    'bundle reconciliation archive byte count'
  );
  expectEqual(
    reconciliation.descriptor_archive.d_archive_sha256,
    descriptor.archive_sha256,
    'bundle reconciliation D archive digest'
  );

  exactKeys(
    reconciliation.source_bundle,
    ['byte_length', 'distributed_path', 'sha256'],
    'bundle reconciliation source bundle'
  );
  expectEqual(
    reconciliation.source_bundle.distributed_path,
    SYNTHETIC_BUNDLE_PATH,
    'bundle reconciliation distributed source path'
  );
  expectEqual(
    reconciliation.source_bundle.byte_length,
    sourceBundleBytes.length,
    'bundle reconciliation source byte count'
  );
  expectEqual(
    reconciliation.source_bundle.sha256,
    sourceBundleSha256,
    'bundle reconciliation source digest'
  );

  exactKeys(
    reconciliation.archive_bundle,
    ['archive_member', 'byte_length', 'sha256'],
    'bundle reconciliation archive bundle'
  );
  expectEqual(
    reconciliation.archive_bundle.archive_member,
    'release/vouch-scored26.bundle',
    'bundle reconciliation archive member'
  );
  expectEqual(
    reconciliation.archive_bundle.byte_length,
    sourceBundleBytes.length,
    'bundle reconciliation archive-bundle byte count'
  );
  expectEqual(
    reconciliation.archive_bundle.sha256,
    sourceBundleSha256,
    'bundle reconciliation archive-bundle digest'
  );

  exactKeys(
    reconciliation.release_manifest,
    [
      'archive_member',
      'bundle_row',
      'byte_length',
      'distributed_copy',
      'sha256',
    ],
    'bundle reconciliation release manifest'
  );
  expectEqual(
    reconciliation.release_manifest.archive_member,
    'artifact/release-manifest.json',
    'bundle reconciliation release-manifest member'
  );
  expectEqual(
    reconciliation.release_manifest.distributed_copy,
    RELEASE_MANIFEST_PATH,
    'bundle reconciliation release-manifest destination'
  );
  expectEqual(
    reconciliation.release_manifest.byte_length,
    releaseManifestBytes.length,
    'bundle reconciliation release-manifest byte count'
  );
  expectEqual(
    reconciliation.release_manifest.sha256,
    sha256Id(releaseManifestBytes),
    'bundle reconciliation release-manifest digest'
  );
  if (!isDeepStrictEqual(reconciliation.release_manifest.bundle_row, expectedBundleRow)) {
    throw new Error('bundle reconciliation release-manifest row changed');
  }

  const expectedChecks = {
    d_archive_sha256_matches_extracted_archive: true,
    release_manifest_row_matches_archive_bundle: true,
    source_bundle_byte_identical_to_archive_bundle: true,
  };
  if (!isDeepStrictEqual(reconciliation.checks, expectedChecks)) {
    throw new Error('bundle reconciliation checks are not the exact passing set');
  }

  const expectedProjectionFact = {
    boundary:
      'The true equivalence and authentication values apply only to the exact distributed review bundle bytes; they do not authenticate or make archive-equivalent the whole source projection.',
    release_archive_equivalent: true,
    release_chain_authenticated: true,
    subject: SYNTHETIC_BUNDLE_PATH,
    whole_projection_release_archive_equivalent: false,
    whole_projection_release_chain_authenticated: false,
  };
  if (
    !isDeepStrictEqual(
      reconciliation.source_projection_report_fact,
      expectedProjectionFact
    )
  ) {
    throw new Error(
      'bundle reconciliation exact-bundle or whole-projection boundary changed'
    );
  }
  return {
    bundleRow: expectedBundleRow,
    reconciliation,
    releaseManifestDigest: sha256Id(releaseManifestBytes),
    sourceBundleByteLength: sourceBundleBytes.length,
    sourceBundleSha256,
  };
}

function verifyDescriptor(descriptor, comparisons) {
  expectEqual(
    descriptor.release_descriptor,
    'csk.release-descriptor/v0',
    'D tag'
  );
  expectEqual(descriptor.artifact_commit, C0, 'D C0 identity');
  expectEqual(descriptor.artifact_freeze_commit, FREEZE, 'D freeze identity');
  expectEqual(descriptor.key_id, RELEASE_KEY_ID, 'D key identifier');
  expectEqual(descriptor.build_image_sha256, BUILD_IMAGE_ID, 'D build image');
  expectEqual(descriptor.target_triple, 'x86_64-unknown-linux-gnu', 'D target');
  for (const name of ['archive_sha256', 'engine_sha256']) {
    requireDigest(descriptor[name], `D ${name}`);
  }
  requireArray(descriptor.exact_reproduction_results, 'D exact results');
  expectEqual(
    descriptor.exact_reproduction_results.length,
    482,
    'D exact result population'
  );
  const expected = comparisons.map((row) => ({
    path: row.path,
    sha256: row.expected_sha256,
  }));
  if (!isDeepStrictEqual(descriptor.exact_reproduction_results, expected)) {
    throw new Error('D exact-result set differs from the comparison population');
  }
  if (
    descriptor.exact_reproduction_results.some((row) =>
      row.path.toLowerCase().includes('source-manifest')
    )
  ) {
    throw new Error('D must not identify the later review source manifest');
  }
}

function verifyPublicKeyRecord(record) {
  exactKeys(
    record,
    ['algorithm', 'key_id', 'native_public_key', 'public_key'],
    'public-key record'
  );
  expectEqual(record.native_public_key, 'csk.native-public-key/v0', 'public-key tag');
  expectEqual(record.algorithm, 'ed25519', 'public-key algorithm');
  expectEqual(record.key_id, RELEASE_KEY_ID, 'public-key identifier');
  const raw = canonicalBase64(record.public_key, 'public key');
  expectEqual(raw.length, 32, 'Ed25519 public-key length');
  expectEqual(
    sha256Id(Buffer.concat([KEY_ID_DOMAIN, raw])),
    RELEASE_KEY_ID,
    'derived Ed25519 key identifier'
  );
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

function verifyTrustPolicy(policy, publicKeyObject) {
  const expectedPolicy = {
    keys: [
      {
        algorithm: 'ed25519',
        allowed_engine_sha256: [
          'sha256:c191e0fce9cdca4c3665b3d2a648beed1936b239f2cebbffdfc61071b3f2ce42',
        ],
        allowed_payload_types: [
          'application/vnd.csk.differential-receipt.v0+json',
          'application/vnd.csk.release-descriptor.v0+json',
          'application/vnd.csk.reproduction-observation.v0+json',
          'application/vnd.csk.replay-corpus-manifest.v0+json',
        ],
        allowed_profiles: [PROFILE],
        key_id: RELEASE_KEY_ID,
        public_key: 'TGLo2LTe+i6MquDF8FYp13GXKNNj7NsbiJyXkWjcW1A=',
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
  if (!isDeepStrictEqual(policy, expectedPolicy)) {
    throw new Error('trust policy differs from the closed reviewed policy');
  }
  expectEqual(policy.trust_policy, 'csk.native-trust-policy/v0', 'trust-policy tag');
  requireArray(policy.keys, 'trust-policy keys');
  expectEqual(policy.keys.length, 1, 'trust-policy key population');
  const selected = policy.keys[0];
  expectEqual(selected.algorithm, 'ed25519', 'policy key algorithm');
  expectEqual(selected.key_id, RELEASE_KEY_ID, 'policy key identifier');
  const raw = canonicalBase64(selected.public_key, 'policy public key');
  const policyObject = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
  if (
    !policyObject.export({ format: 'der', type: 'spki' }).equals(
      publicKeyObject.export({ format: 'der', type: 'spki' })
    )
  ) {
    throw new Error('trust policy public key differs from the public-key record');
  }
  requireArray(selected.allowed_payload_types, 'policy payload types');
  for (const payloadType of [DESCRIPTOR_TYPE, OBSERVATION_TYPE]) {
    if (!selected.allowed_payload_types.includes(payloadType)) {
      throw new Error(`trust policy does not authorize ${payloadType}`);
    }
  }
  requireArray(selected.allowed_profiles, 'policy profiles');
  if (!selected.allowed_profiles.includes(PROFILE)) {
    throw new Error(`trust policy does not authorize ${PROFILE}`);
  }
  return selected;
}

async function verifyProjectedDependencyIdentities(root, descriptor) {
  const expected = [
    {
      path: 'Cargo.lock',
      sha256:
        'sha256:cbd71eda2e5bbf00dbb7dcc2a1cdbdf2bb4cd33b4806e44768b8942a20f3703b',
    },
    {
      path: 'artifact/runtime-versions.json',
      sha256:
        'sha256:067644a9476bdea577326cbdd1c8d8dd484e5e89ab75c0a30f55d248300daba7',
    },
    {
      path: 'artifact/vendor-manifest.json',
      sha256:
        'sha256:d6e37c47d3156ed4cc1ed962dcbb96de6b5683d5cc99e4de196288464e6332a5',
    },
    {
      path: 'package-lock.json',
      sha256:
        'sha256:fa37811d3b66ac75156e31b0e0477222a4f0b9563aa1cf5401ae75df244d8098',
    },
  ];
  if (
    !isDeepStrictEqual(
      descriptor.toolchains?.dependency_version_manifest_digests,
      expected
    )
  ) {
    throw new Error('D dependency-manifest identities changed');
  }
  for (const row of expected) {
    expectEqual(
      sha256Id(await readRequired(root, `source/${row.path}`)),
      row.sha256,
      `projected ${row.path} identity from D`
    );
  }
}

function verifyDsseEnvelope({
  envelope,
  expectedPayload,
  expectedPayloadType,
  keyId,
  publicKey,
  label,
}) {
  exactKeys(envelope, ['payload', 'payloadType', 'signatures'], `${label} envelope`);
  expectEqual(envelope.payloadType, expectedPayloadType, `${label} payload type`);
  const payload = canonicalBase64(envelope.payload, `${label} payload`);
  if (!payload.equals(expectedPayload)) {
    throw new Error(`${label} envelope payload bytes differ from the submitted payload`);
  }
  requireArray(envelope.signatures, `${label} signatures`);
  expectEqual(envelope.signatures.length, 1, `${label} signature count`);
  const signature = envelope.signatures[0];
  exactKeys(signature, ['keyid', 'sig'], `${label} signature`);
  expectEqual(signature.keyid, keyId, `${label} signature key identifier`);
  const signatureBytes = canonicalBase64(signature.sig, `${label} signature`);
  expectEqual(signatureBytes.length, 64, `${label} signature length`);
  if (
    !verifySignature(
      null,
      dssePae(expectedPayloadType, payload),
      publicKey,
      signatureBytes
    )
  ) {
    throw new Error(`${label} Ed25519 signature is invalid`);
  }
}

function verifyWorkloadSummaryObject(summary) {
  verifyWorkloadSummary(summary);
}

function verifyRComparisons(rows, comparisons) {
  requireArray(rows, 'R reproduced comparisons');
  const expected = comparisons.map((row) => ({ matched: true, path: row.path }));
  if (!isDeepStrictEqual(rows, expected)) {
    throw new Error('R reproduced comparisons do not derive from the 482-row report');
  }
}

function verifyRObservationalSet(rows, results) {
  const digestByReleasePath = new Map([
    [OBSERVATIONAL_RELEASE_PATHS[0], sha256Id(results.mutation.bytes)],
    [OBSERVATIONAL_RELEASE_PATHS[1], sha256Id(results.performance.bytes)],
    [OBSERVATIONAL_RELEASE_PATHS[2], sha256Id(results.fixtures.bytes)],
    [OBSERVATIONAL_RELEASE_PATHS[3], sha256Id(results.workload.bytes)],
  ]);
  const expected = OBSERVATIONAL_RELEASE_PATHS.map((releasePath) => ({
    path: releasePath,
    sha256: digestByReleasePath.get(releasePath),
  }));
  if (!isDeepStrictEqual(rows, expected)) {
    throw new Error('R observational result set or digest changed');
  }
}

function verifyRPerformance(observations, measurements) {
  const expected = measurements.map(({ metric, statistic, unit, value }) => ({
    metric,
    statistic,
    unit,
    value,
  }));
  if (!isDeepStrictEqual(observations, expected)) {
    throw new Error('R performance observations do not derive from the owner report');
  }
}

async function verifyAuditReports(root, sourceState, manifestState) {
  const { value: anonymity } = await readCanonicalJson(root, AUDIT_PATHS.anonymity);
  exactKeys(
    anonymity,
    [
      'absolute_path_findings',
      'anonymity_report',
      'email_findings',
      'identity_findings',
      'repository_residue_findings',
      'scope',
      'status',
    ],
    'anonymity report'
  );
  expectEqual(anonymity.anonymity_report, 'vouch.scored26-anonymity/v1', 'anonymity tag');
  expectEqual(anonymity.scope, 'distributed-artifact', 'anonymity scope');
  expectEqual(anonymity.status, 'pass', 'anonymity status');
  for (const field of [
    'absolute_path_findings',
    'email_findings',
    'identity_findings',
    'repository_residue_findings',
  ]) {
    expectEqual(anonymity[field], 0, `anonymity ${field}`);
  }

  const { value: secret } = await readCanonicalJson(root, AUDIT_PATHS.secret);

  const { value: source } = await readCanonicalJson(root, AUDIT_PATHS.source);
  exactKeys(
    source,
    [
      'boundary_status',
      'derived_from_commit',
      'release_archive_equivalent',
      'release_chain_authenticated',
      'rights_sha256',
      'source_file_count',
      'source_manifest_sha256',
      'source_projection_report',
      'status',
    ],
    'source projection report'
  );
  expectEqual(
    source.source_projection_report,
    'vouch.scored26-source-projection-report/v1',
    'source projection report tag'
  );
  expectEqual(source.status, 'pass', 'source projection status');
  expectEqual(source.boundary_status, 'pass', 'source boundary status');
  expectEqual(source.derived_from_commit, C0, 'source report C0');
  expectEqual(source.release_archive_equivalent, false, 'source/archive equivalence claim');
  expectEqual(source.release_chain_authenticated, false, 'source chain-authentication claim');
  expectEqual(source.source_manifest_sha256, sourceState.manifestDigest, 'source manifest digest');
  expectEqual(source.rights_sha256, sourceState.rightsDigest, 'source rights digest');
  expectEqual(source.source_file_count, sourceState.fileCount, 'source file population');

  if (manifestState.manifest.files.length < sourceState.fileCount) {
    throw new Error('root manifest cannot contain fewer files than the source manifest');
  }

  const { value: lifecycle } = await readCanonicalJson(
    root,
    AUDIT_PATHS.lifecycleJson
  );
  const lifecycleState = await verifyLifecycleAudit(root, lifecycle);
  verifySecretScanReport(secret, lifecycleState.finalScans);
}

export async function verifyLifecycleAudit(root, value) {
  exactKeys(
    value,
    [
      'authoritative_sources',
      'bundle_evidence',
      'final_scans',
      'lifecycle_audit',
      'lifecycle_source',
      'log_evidence',
      'network',
      'phases',
      'signature_boundary',
    ],
    'lifecycle audit'
  );
  expectEqual(
    value.lifecycle_audit,
    'vouch.scored26-lifecycle-audit/v2',
    'lifecycle audit tag'
  );

  exactKeys(
    value.lifecycle_source,
    [
      'artifact_commit',
      'artifact_freeze_commit',
      'condition_contract_sha256',
    ],
    'lifecycle source'
  );
  expectEqual(value.lifecycle_source.artifact_commit, C0, 'lifecycle source C0');
  expectEqual(
    value.lifecycle_source.artifact_freeze_commit,
    FREEZE,
    'lifecycle source freeze'
  );
  expectEqual(
    value.lifecycle_source.condition_contract_sha256,
    CONTRACT_SHA256,
    'lifecycle source contract'
  );

  const authoritativeSources = [
    CHAIN_PATHS.descriptor,
    CHAIN_PATHS.descriptorEnvelope,
    CHAIN_PATHS.policy,
    CHAIN_PATHS.cleanRun,
    CHAIN_PATHS.observation,
    CHAIN_PATHS.observationEnvelope,
    CHAIN_PATHS.publication,
    CHAIN_PATHS.terminal,
    RESULT_PATHS.comparisons,
    RESULT_PATHS.fixtures,
    RESULT_PATHS.workload,
    RESULT_PATHS.mutation,
    RESULT_PATHS.performance,
    RESULT_PATHS.releaseManifest,
    AUDIT_PATHS.bundleReconciliation,
  ];
  if (!isDeepStrictEqual(value.authoritative_sources, authoritativeSources)) {
    throw new Error('lifecycle authoritative-source set or order changed');
  }

  exactKeys(
    value.log_evidence,
    [
      'authority',
      'distributed_form',
      'exit_code_basis',
      'raw_stdout_retained_locally',
      'transformation_manifest',
    ],
    'lifecycle log evidence'
  );
  expectEqual(
    value.log_evidence.raw_stdout_retained_locally,
    true,
    'raw lifecycle stdout retention'
  );
  expectEqual(
    value.log_evidence.distributed_form,
    'path-neutral-sanitized-copy',
    'distributed lifecycle log form'
  );
  expectEqual(
    value.log_evidence.transformation_manifest,
    AUDIT_PATHS.sanitizedLogs,
    'lifecycle log manifest path'
  );
  expectEqual(
    value.log_evidence.authority,
    'structured-lifecycle-objects-remain-authoritative',
    'lifecycle log authority'
  );
  expectEqual(
    value.log_evidence.exit_code_basis,
    'exit_code=0 records retained completion markers under the lifecycle wrapper set -euo pipefail boundary',
    'lifecycle exit-code basis'
  );

  const [
    descriptorRead,
    descriptorEnvelopeRead,
    cleanRunRead,
    finalizeRead,
    observationRead,
    observationEnvelopeRead,
    publicationRead,
    terminalRead,
    comparisonsRead,
    fixturesRead,
    workloadRead,
    mutationRead,
    performanceRead,
    releaseManifestRead,
    reconciliationRead,
    sourceBundleBytes,
    machineRecordBytes,
  ] = await Promise.all([
    readCanonicalJson(root, CHAIN_PATHS.descriptor),
    readCanonicalJson(root, CHAIN_PATHS.descriptorEnvelope),
    readCanonicalJson(root, CHAIN_PATHS.cleanRun),
    readCanonicalJson(root, CHAIN_PATHS.finalize),
    readCanonicalJson(root, CHAIN_PATHS.observation),
    readCanonicalJson(root, CHAIN_PATHS.observationEnvelope),
    readCanonicalJson(root, CHAIN_PATHS.publication),
    readCanonicalJson(root, CHAIN_PATHS.terminal),
    readCanonicalJson(root, RESULT_PATHS.comparisons),
    readCanonicalJson(root, RESULT_PATHS.fixtures),
    readCanonicalJson(root, RESULT_PATHS.workload),
    readCanonicalJson(root, RESULT_PATHS.mutation),
    readCanonicalJson(root, RESULT_PATHS.performance),
    readCanonicalJson(root, RESULT_PATHS.releaseManifest),
    readCanonicalJson(root, AUDIT_PATHS.bundleReconciliation),
    readRequired(root, SOURCE_PATHS.bundle),
    readRequired(root, 'machine-record/vouch-scored26-release-record.pdf'),
  ]);
  const descriptor = descriptorRead.value;
  const cleanRun = cleanRunRead.value;
  const terminal = terminalRead.value;
  expectEqual(descriptor.artifact_commit, C0, 'D/lifecycle C0 relationship');
  expectEqual(
    descriptor.artifact_freeze_commit,
    FREEZE,
    'D/lifecycle freeze relationship'
  );

  exactKeys(
    value.network,
    [
      'assembly_network_mode',
      'build_image_sha256',
      'container_platform',
      'dependency_install_mode',
      'dependency_install_network_mode',
      'final_scan_network_mode',
      'os_image_reference',
      'phase1_network_mode',
      'phase2_network_mode',
      'phase3_network_mode',
    ],
    'lifecycle network policy'
  );
  expectEqual(
    value.network.build_image_sha256,
    descriptor.build_image_sha256,
    'lifecycle/D build image relationship'
  );
  expectEqual(
    value.network.os_image_reference,
    descriptor.build_parameters?.os_image_reference,
    'lifecycle/D base image relationship'
  );
  expectEqual(value.network.container_platform, 'linux/amd64', 'container platform');
  expectEqual(
    value.network.dependency_install_network_mode,
    'none',
    'offline dependency-install network policy'
  );
  expectEqual(
    value.network.dependency_install_mode,
    'npm-ci-offline-from-local-cache-seed',
    'dependency-install mode'
  );
  expectEqual(
    value.network.assembly_network_mode,
    'enabled-for-lockfile-cache-population-before-D',
    'assembly network boundary'
  );
  for (const phase of ['phase1', 'phase2', 'phase3']) {
    expectEqual(value.network[`${phase}_network_mode`], 'none', `${phase} network mode`);
  }
  expectEqual(value.network.final_scan_network_mode, 'none', 'final-scan network mode');

  requireArray(value.phases, 'lifecycle phases');
  expectEqual(value.phases.length, 4, 'lifecycle phase count');
  const [assembly, phase1, phase2, phase3] = value.phases;

  exactKeys(
    assembly,
    ['completion_marker', 'exit_code', 'name', 'object_sha256'],
    'assembly lifecycle phase'
  );
  expectEqual(assembly.name, 'assembly', 'assembly phase name');
  expectEqual(assembly.exit_code, 0, 'assembly exit code');
  expectEqual(assembly.completion_marker, 'SCORED26 release assembled', 'assembly marker');
  exactKeys(
    assembly.object_sha256,
    ['archive', 'descriptor_envelope', 'descriptor_payload'],
    'assembly object digests'
  );
  requireDigest(descriptor.archive_sha256, 'D archive digest');
  expectRawDigest(
    assembly.object_sha256.archive,
    descriptor.archive_sha256.slice('sha256:'.length),
    'assembly archive/D relationship'
  );
  expectRawDigest(
    assembly.object_sha256.descriptor_payload,
    sha256Hex(descriptorRead.bytes),
    'assembly D payload digest'
  );
  expectRawDigest(
    assembly.object_sha256.descriptor_envelope,
    sha256Hex(descriptorEnvelopeRead.bytes),
    'assembly D envelope digest'
  );

  exactKeys(
    phase1,
    [
      'clean_run_runtime_seconds',
      'completion_marker',
      'exit_code',
      'name',
      'object_sha256',
    ],
    'phase-1 lifecycle phase'
  );
  expectEqual(phase1.name, 'phase1', 'phase-1 name');
  expectEqual(phase1.exit_code, 0, 'phase-1 exit code');
  expectEqual(
    phase1.completion_marker,
    'SCORED26 phase-1 clean-room gate passed',
    'phase-1 marker'
  );
  requireUint(phase1.clean_run_runtime_seconds, 'phase-1 duration');
  expectEqual(
    phase1.clean_run_runtime_seconds,
    cleanRun.clean_run_runtime_seconds,
    'phase-1/Q duration relationship'
  );
  exactKeys(
    phase1.object_sha256,
    [
      'clean_run_report',
      'exact_reproduction_comparisons',
      'fixture_results',
      'mutation_results',
      'performance_results',
      'workload_results',
    ],
    'phase-1 object digests'
  );
  const phase1Objects = [
    ['clean_run_report', cleanRunRead.bytes],
    ['exact_reproduction_comparisons', comparisonsRead.bytes],
    ['fixture_results', fixturesRead.bytes],
    ['mutation_results', mutationRead.bytes],
    ['performance_results', performanceRead.bytes],
    ['workload_results', workloadRead.bytes],
  ];
  for (const [name, bytes] of phase1Objects) {
    expectRawDigest(
      phase1.object_sha256[name],
      sha256Hex(bytes),
      `phase-1 ${name} digest`
    );
  }

  exactKeys(
    phase2,
    ['completion_marker', 'exit_code', 'name', 'object_sha256'],
    'phase-2 lifecycle phase'
  );
  expectEqual(phase2.name, 'phase2', 'phase-2 name');
  expectEqual(phase2.exit_code, 0, 'phase-2 exit code');
  expectEqual(
    phase2.completion_marker,
    'SCORED26 reproduction observation finalized',
    'phase-2 marker'
  );
  exactKeys(
    phase2.object_sha256,
    [
      'finalize_report',
      'publication_index',
      'reproduction_observation_envelope',
      'reproduction_observation_payload',
    ],
    'phase-2 object digests'
  );
  const phase2Objects = [
    ['finalize_report', finalizeRead.bytes],
    ['publication_index', publicationRead.bytes],
    ['reproduction_observation_envelope', observationEnvelopeRead.bytes],
    ['reproduction_observation_payload', observationRead.bytes],
  ];
  for (const [name, bytes] of phase2Objects) {
    expectRawDigest(
      phase2.object_sha256[name],
      sha256Hex(bytes),
      `phase-2 ${name} digest`
    );
  }

  exactKeys(
    phase3,
    [
      'completion_marker',
      'exit_code',
      'name',
      'object_sha256',
      'terminal_fields',
    ],
    'phase-3 lifecycle phase'
  );
  expectEqual(phase3.name, 'phase3', 'phase-3 name');
  expectEqual(phase3.exit_code, 0, 'phase-3 exit code');
  expectEqual(
    phase3.completion_marker,
    'SCORED26 publication check passed (S=pass)',
    'phase-3 marker'
  );
  exactKeys(
    phase3.object_sha256,
    ['machine_record_pdf', 'terminal_report'],
    'phase-3 object digests'
  );
  expectRawDigest(
    phase3.object_sha256.terminal_report,
    sha256Hex(terminalRead.bytes),
    'phase-3 S digest'
  );
  expectRawDigest(
    phase3.object_sha256.machine_record_pdf,
    sha256Hex(machineRecordBytes),
    'phase-3 machine-record digest'
  );
  exactKeys(
    phase3.terminal_fields,
    ['chain_verified', 'claim_language_scan', 'paper_claims_matched', 'status'],
    'phase-3 terminal fields'
  );
  for (const name of [
    'status',
    'chain_verified',
    'claim_language_scan',
    'paper_claims_matched',
  ]) {
    expectEqual(
      phase3.terminal_fields[name],
      terminal[name],
      `phase-3/S ${name} relationship`
    );
  }
  expectEqual(phase3.terminal_fields.status, 'pass', 'phase-3 terminal status');
  expectEqual(phase3.terminal_fields.chain_verified, 'pass', 'phase-3 chain status');
  expectEqual(
    phase3.terminal_fields.claim_language_scan,
    'pass',
    'phase-3 claim-language status'
  );
  expectEqual(
    phase3.terminal_fields.paper_claims_matched,
    true,
    'phase-3 paper-claim status'
  );

  await verifySanitizedLifecycleLogs(root);
  await verifyFinalLifecycleScans(root, value.final_scans);

  exactKeys(
    value.bundle_evidence,
    [
      'reconciliation_sha256',
      'release_manifest_sha256',
      'scope',
      'source_bundle_byte_length',
      'source_bundle_sha256',
      'status',
    ],
    'lifecycle bundle evidence'
  );
  expectEqual(value.bundle_evidence.status, 'pass', 'lifecycle bundle evidence status');
  expectEqual(
    value.bundle_evidence.scope,
    'exact-distributed-review-bundle-only-not-whole-source-projection',
    'lifecycle bundle evidence scope'
  );
  expectEqual(
    value.bundle_evidence.reconciliation_sha256,
    sha256Id(reconciliationRead.bytes),
    'lifecycle reconciliation digest'
  );
  expectEqual(
    value.bundle_evidence.release_manifest_sha256,
    sha256Id(releaseManifestRead.bytes),
    'lifecycle release-manifest digest'
  );
  expectEqual(
    value.bundle_evidence.source_bundle_sha256,
    sha256Id(sourceBundleBytes),
    'lifecycle source-bundle digest'
  );
  requireUint(
    value.bundle_evidence.source_bundle_byte_length,
    'lifecycle source-bundle byte length'
  );
  expectEqual(
    value.bundle_evidence.source_bundle_byte_length,
    sourceBundleBytes.length,
    'lifecycle source-bundle byte length'
  );

  exactKeys(
    value.signature_boundary,
    ['digest_or_derivation_checked_objects', 'signed_objects'],
    'lifecycle signature boundary'
  );
  if (
    !isDeepStrictEqual(value.signature_boundary.signed_objects, ['D', 'R']) ||
    !isDeepStrictEqual(
      value.signature_boundary.digest_or_derivation_checked_objects,
      ['Q', 'P', 'S']
    )
  ) {
    throw new Error('lifecycle signature boundary changed');
  }

  return { finalScans: value.final_scans };
}

async function verifySanitizedLifecycleLogs(root) {
  const { value: manifest } = await readCanonicalJson(root, AUDIT_PATHS.sanitizedLogs);
  exactKeys(manifest, ['log_manifest', 'logs', 'transformation'], 'sanitized log manifest');
  expectEqual(
    manifest.log_manifest,
    'vouch.scored26-sanitized-lifecycle-logs/v1',
    'sanitized log manifest tag'
  );
  const expectedTransformation = {
    ansi: 'removed',
    carriage_returns: 'normalized-to-lf',
    host_and_container_paths: 'replaced-with-angle-bracket-placeholders',
    'non-example_email_addresses': 'replaced-with-REDACTED_EMAIL',
    semantic_result_lines: 'otherwise-preserved',
  };
  exactKeys(
    manifest.transformation,
    Object.keys(expectedTransformation),
    'sanitized log transformation'
  );
  if (!isDeepStrictEqual(manifest.transformation, expectedTransformation)) {
    throw new Error('sanitized log transformation contract changed');
  }
  requireArray(manifest.logs, 'sanitized log records');
  expectEqual(manifest.logs.length, LIFECYCLE_LOG_SPECS.length, 'sanitized log count');

  for (let index = 0; index < LIFECYCLE_LOG_SPECS.length; index += 1) {
    const spec = LIFECYCLE_LOG_SPECS[index];
    const row = manifest.logs[index];
    exactKeys(
      row,
      [
        'completion_marker',
        'destination',
        'raw_bytes',
        'raw_sha256',
        'replacements',
        'sanitized_bytes',
        'sanitized_sha256',
        'source',
      ],
      `sanitized log record ${index}`
    );
    expectEqual(row.source, spec.source, `sanitized log ${index} source`);
    expectEqual(row.destination, spec.destination, `sanitized log ${index} destination`);
    expectEqual(
      row.completion_marker,
      spec.completionMarker,
      `sanitized log ${index} completion marker`
    );
    validateRelativePath(row.source);
    validateRelativePath(row.destination);
    requireUint(row.raw_bytes, `sanitized log ${index} raw byte length`);
    requireRawDigest(row.raw_sha256, `sanitized log ${index} raw digest`);
    requireUint(row.sanitized_bytes, `sanitized log ${index} byte length`);
    exactKeys(
      row.replacements,
      [
        'ansi_sequences',
        'carriage_returns',
        'container_paths',
        'email_addresses',
        'explicit_paths',
        'host_paths',
      ],
      `sanitized log ${index} replacement counts`
    );
    for (const [name, count] of Object.entries(row.replacements)) {
      requireUint(count, `sanitized log ${index} ${name} replacements`);
    }
    const bytes = await readRequired(root, spec.destination);
    expectEqual(bytes.length, row.sanitized_bytes, `${spec.destination} byte length`);
    expectRawDigest(
      row.sanitized_sha256,
      sha256Hex(bytes),
      `${spec.destination} digest`
    );
    const text = decodeUtf8(bytes, spec.destination);
    verifyPathNeutralLifecycleLog(text, spec.destination);
    if (spec.completionMarker !== null && !text.includes(spec.completionMarker)) {
      throw new Error(`${spec.destination}: completion marker is absent`);
    }
  }
}

async function verifyFinalLifecycleScans(root, scans) {
  exactKeys(
    scans,
    [
      'actual_key_secret_scan',
      'generic_private_key_marker_scan',
      'markers',
      'public_data_scan',
      'scope',
      'status',
      'surface',
    ],
    'lifecycle final scans'
  );
  expectEqual(
    scans.scope,
    're-extracted-release-plus-chain-owner-reports-sanitized-logs-and-machine-pdf',
    'final-scan scope'
  );
  for (const name of [
    'status',
    'actual_key_secret_scan',
    'generic_private_key_marker_scan',
    'public_data_scan',
  ]) {
    expectEqual(scans[name], 'pass', `final-scan ${name}`);
  }
  const expectedMarkers = {
    'actual-key-secret-scan':
      'SCORED26 release secret scan passed (archive/store/Git objects)',
    'generic-private-key-marker-scan':
      'SCORED26 generic private-key marker scan passed',
    'public-data-scan':
      'SCORED26 public-data scan passed (synthetic public inputs only)',
  };
  exactKeys(scans.markers, Object.keys(expectedMarkers), 'final-scan markers');
  if (!isDeepStrictEqual(scans.markers, expectedMarkers)) {
    throw new Error('final-scan completion markers changed');
  }
  exactKeys(
    scans.surface,
    ['regular_file_bytes', 'regular_file_count', 'symlink_count'],
    'final-scan surface'
  );
  requireUint(scans.surface.regular_file_count, 'final-scan regular-file count');
  requireUint(scans.surface.regular_file_bytes, 'final-scan regular-file bytes');
  requireUint(scans.surface.symlink_count, 'final-scan symlink count');
  expectEqual(scans.surface.symlink_count, 0, 'final-scan symlink count');

  for (const [name, relative] of Object.entries(FINAL_SCAN_LOG_PATHS)) {
    const bytes = await readRequired(root, relative);
    const text = decodeUtf8(bytes, relative);
    verifyPathNeutralLifecycleLog(text, relative);
    if (!text.includes(scans.markers[name])) {
      throw new Error(`${relative}: final-scan completion marker is absent`);
    }
  }
}

function verifySecretScanReport(secret, finalScans) {
  exactKeys(
    secret,
    [
      'actual_release_key_scan',
      'credential_findings',
      'generic_private_key_marker_scan',
      'key_handling',
      'private_key_findings',
      'public_data_findings',
      'public_data_scan',
      'scope',
      'secret_scan_report',
      'status',
      'surface',
    ],
    'secret scan report'
  );
  expectEqual(secret.secret_scan_report, 'vouch.scored26-secret-scan/v2', 'secret tag');
  expectEqual(secret.scope, 'final-release-audit-surface', 'secret scan scope');
  expectEqual(secret.status, finalScans.status, 'secret/final-scan status');
  expectEqual(
    secret.actual_release_key_scan,
    finalScans.actual_key_secret_scan,
    'secret actual-key scan status'
  );
  expectEqual(
    secret.generic_private_key_marker_scan,
    finalScans.generic_private_key_marker_scan,
    'secret generic-marker scan status'
  );
  expectEqual(
    secret.public_data_scan,
    finalScans.public_data_scan,
    'secret public-data scan status'
  );
  for (const name of [
    'credential_findings',
    'private_key_findings',
    'public_data_findings',
  ]) {
    expectEqual(secret[name], 0, `secret scan ${name}`);
  }
  expectEqual(
    secret.key_handling,
    'key path and key bytes are neither recorded nor distributed',
    'secret scan key-handling boundary'
  );
  if (!isDeepStrictEqual(secret.surface, finalScans.surface)) {
    throw new Error('secret scan surface differs from the lifecycle final-scan surface');
  }
}

function verifyPathNeutralLifecycleLog(text, label) {
  const forbidden = [
    /\/(?:Users|home)\//u,
    /\/(?:private\/var\/folders|var\/folders)\//u,
    /\/opt\/vouch-scored26\/(?:trusted-bootstrap|clean-room|release|source)(?:\/|\b)/u,
    /\/run\/secrets\/release-key-v0\.pk8\b/u,
    /\/root\/\.npm(?:\/|\b)/u,
    /[A-Z]:\\Users\\/iu,
  ];
  if (forbidden.some((pattern) => pattern.test(text))) {
    throw new Error(`${label}: sanitized lifecycle log retains a local or key path`);
  }
  const emails = text.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu) ?? [];
  if (
    emails.some(
      (email) => !/@(?:example\.(?:com|org)|example\.invalid)$/iu.test(email)
    )
  ) {
    throw new Error(`${label}: sanitized lifecycle log retains a non-example email`);
  }
}

function decodeUtf8(bytes, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label}: expected UTF-8 text`);
  }
}

function requireRawDigest(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`${label}: expected raw SHA-256 digest`);
  }
}

function expectRawDigest(actual, expected, label) {
  requireRawDigest(actual, label);
  expectEqual(actual, expected, label);
}

export async function scanDistributedTree(root, files) {
  const { value: archiveChunkManifest } = await readJsonFile(
    root,
    ARCHIVE_CHUNK_MANIFEST_PATH
  );
  const opaqueArchiveChunks = new Set(
    archiveChunkManifest.chunks.map(
      (chunk) => `release/archive-chunks/${chunk.path}`
    )
  );
  const forbiddenPathSuffixes = [
    '.der',
    '.env',
    '.jwk',
    '.jwk.json',
    '.key',
    '.keystore',
    '.p8',
    '.p12',
    '.pem',
    '.pfx',
    '.pk8',
    '.pkcs8',
  ];
  const emailPattern = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu;
  const localUnix = new RegExp(`/(?:${'Users'}|home)/[^/\\s]+/`, 'u');
  const localMac = new RegExp(`/(?:private/var/folders|${'Volumes'})/`, 'u');
  const localWindows = new RegExp(`${'C:'}\\\\${'Users'}\\\\`, 'iu');
  const hostedUrl = new RegExp(`https?://(?:www\\.)?${'git' + 'hub'}\\.com/[^\\s)>'\"]+`, 'giu');
  const companyPattern = /\b(?:Inc\.?|LLC|Ltd\.?|Corporation|GmbH|Studio|Code\/Engine)\b/u;
  const identityMetadata = /"(?:author|contributors|maintainers|repository|funding|bugs)"\s*:/u;
  const hashDeltaMetadata = new RegExp(
    `"(?:${'original' + '_(?:sha256|commit)'}|${'pre_' + 'anonymization_sha256'}|${'post_' + 'anonymization_sha256'}|${'hash_' + 'delta'})"\\s*:`,
    'u'
  );
  const workflowTerms = [
    'co' + 'dex',
    'clau' + 'de',
    'o' + 'pus',
    'fa' + 'ble',
    'ag' + 'ent workflow',
    'implementation ag' + 'ent',
    'review ag' + 'ent',
  ];
  const pemPrivate = new RegExp(
    `-----${'BEGIN'} (?:(?:RSA|EC|OPENSSH|ENCRYPTED) )?${'PRIVATE KEY'}-----`,
    'u'
  );
  const credentialPatterns = [
    new RegExp(`\\b${'gh' + 'p_'}[A-Za-z0-9]{30,}\\b`, 'u'),
    new RegExp(`\\b${'github_' + 'pat_'}[A-Za-z0-9_]{30,}\\b`, 'u'),
    new RegExp(`\\b${'AKIA'}[A-Z0-9]{16}\\b`, 'u'),
    new RegExp(`\\b${'xox' + '[abprs]-'}[A-Za-z0-9-]{20,}\\b`, 'u'),
  ];
  const diffHeader = new RegExp(`^${'diff --git '}|^${'index '}[0-9a-f]{7,}\\.\\.[0-9a-f]{7,}`, 'mu');

  for (const entry of files) {
    const relative = entry.path;
    rejectResiduePath(relative);
    if (relative === SYNTHETIC_BUNDLE_PATH) continue;
    const lower = relative.toLowerCase();
    const thirdPartyMetadata = isThirdPartyMetadata(relative);
    const publicWorkflowPathFragments = [
      'co' + 'dex',
      'clau' + 'de',
      'o' + 'pus',
      'fa' + 'ble',
      'hando' + 'ff',
      '-so' + 'l.',
    ];
    if (
      !relative.startsWith('scripts/check-artifact') &&
      publicWorkflowPathFragments.some((fragment) => lower.includes(fragment))
    ) {
      throw new Error(`development-workflow path found: ${relative}`);
    }
    const vendoredCryptoExample = VENDORED_CRYPTO_EXAMPLE_SET.has(relative);
    if (
      !thirdPartyMetadata &&
      ((relative.match(emailPattern) ?? []).length !== 0 ||
        companyPattern.test(relative))
    ) {
      throw new Error(`identity-bearing filename found: ${relative}`);
    }
    if (
      (!vendoredCryptoExample &&
        forbiddenPathSuffixes.some((suffix) => lower.endsWith(suffix))) ||
      /(?:^|\/)id_ed25519(?:\.|$)/u.test(lower)
    ) {
      throw new Error(`secret-bearing filename is forbidden: ${relative}`);
    }
    const bytes = await readRequired(root, relative);
    if (opaqueArchiveChunks.has(relative)) continue;
    const printable = printableText(bytes);
    const scannerImplementation =
      relative === 'scripts/check-artifact.mjs' ||
      relative === 'scripts/check-artifact-negative.mjs';
    const sourceSecretScanner =
      relative === 'source/artifact/scripts/scan-private-key-markers.mjs' ||
      relative === 'source/artifact/scripts/scan-release-secrets.mjs';
    const sourceReleaseSupplyScanner =
      relative === 'source/artifact/scripts/check-release-supply.mjs';
    const privateJwk =
      /"kty"\s*:/u.test(printable) && /"(?:d|k)"\s*:/u.test(printable);
    if (
      !scannerImplementation &&
      !sourceSecretScanner &&
      !vendoredCryptoExample &&
      (pemPrivate.test(printable) ||
        privateJwk ||
        parsesAsPrivateKeyDer(bytes))
    ) {
      throw new Error(`private-key material found in ${relative}`);
    }
    for (const pattern of credentialPatterns) {
      if (pattern.test(printable)) {
        throw new Error(`credential-shaped material found in ${relative}`);
      }
    }
    const nonExampleEmail = (printable.match(emailPattern) ?? []).find(
      (value) =>
        !/@(?:example\.com|example\.net|example\.org|example\.invalid)$/iu.test(
          value
        )
    );
    if (
      nonExampleEmail !== undefined &&
      !scannerImplementation &&
      !thirdPartyMetadata
    ) {
      throw new Error(`email identity found in ${relative}`);
    }
    if (
      !thirdPartyMetadata &&
      !sourceReleaseSupplyScanner &&
      (localUnix.test(printable) ||
        localMac.test(printable) ||
        localWindows.test(printable))
    ) {
      throw new Error(`local absolute path found in ${relative}`);
    }

    if (scannerImplementation || thirdPartyMetadata) continue;
    const lowerText = printable.toLowerCase();
    if (workflowTerms.some((term) => lowerText.includes(term))) {
      throw new Error(`development-workflow identity found in ${relative}`);
    }
    if (companyPattern.test(printable)) {
      throw new Error(`organization identity found in ${relative}`);
    }
    if (identityMetadata.test(printable)) {
      throw new Error(`identity-bearing package metadata found in ${relative}`);
    }
    if (
      relative !== SOURCE_PATHS.manifest &&
      hashDeltaMetadata.test(printable)
    ) {
      throw new Error(`original hash-delta metadata found in ${relative}`);
    }
    for (const match of printable.matchAll(hostedUrl)) {
      const value = match[0].toLowerCase();
      if (value.includes('vouch') || value.includes('lispex')) {
        throw new Error(`first-party repository URL found in ${relative}`);
      }
    }
    if (diffHeader.test(printable)) {
      throw new Error(`repository hash-delta material found in ${relative}`);
    }
  }
}

function parsesAsPrivateKeyDer(bytes) {
  for (const type of ['pkcs8', 'pkcs1', 'sec1']) {
    try {
      createPrivateKey({ key: bytes, format: 'der', type });
      return true;
    } catch {
      // Continue through the closed private-key DER formats.
    }
  }
  return false;
}

function isThirdPartyMetadata(relative) {
  return (
    relative.startsWith('source/vendor/') ||
    relative.startsWith('source/review-toolchain/') ||
    relative.startsWith('source/third-party/') ||
    relative.startsWith('source/artifact/vendor/') ||
    relative.endsWith('/Cargo.lock') ||
    relative.endsWith('/package-lock.json')
  );
}

async function verifyMachineRecord(root) {
  const bytes = await readRequired(
    root,
    'machine-record/vouch-scored26-release-record.pdf'
  );
  if (bytes.length < 1024 || !bytes.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
    throw new Error('machine release record is not a nonempty PDF');
  }
  expectEqual(
    sha256Hex(bytes),
    MACHINE_RECORD_SHA256,
    'machine release-record SHA-256'
  );
}

export async function runIsolatedSourceChecks(root, scripts) {
  const temporary = await mkdtemp(path.join(tmpdir(), 'vouch-source-check-'));
  const home = path.join(temporary, 'home');
  const childTemporary = path.join(temporary, 'tmp');
  const source = path.join(childTemporary, 'source');
  const npmCache = path.join(temporary, 'npm-cache');
  const cargoHome = path.join(temporary, 'cargo-home');
  const npmUserConfig = path.join(temporary, 'npmrc');
  try {
    await Promise.all(
      [home, childTemporary, npmCache, cargoHome].map((directory) =>
        mkdir(directory, { mode: 0o700, recursive: true })
      )
    );
    await writeFile(npmUserConfig, '', { mode: 0o600 });
    await cp(path.join(root, 'source'), source, { recursive: true });
    const environment = createSourceChildEnvironment({
      cargoHome,
      home,
      npmCache,
      npmUserConfig,
      rustBin:
        scripts.includes('check:artifact') || scripts.includes('check:full')
          ? resolveRustBin(source)
          : null,
      temporary: childTemporary,
    });
    runSourceProgram(
      source,
      process.execPath,
      ['tools/prepare-review-toolchain.mjs'],
      'vendored review-toolchain setup',
      environment
    );
    for (const script of scripts) {
      for (const command of sourceCommands(script)) {
        runSourceProgram(
          source,
          command.program,
          command.arguments,
          command.label,
          environment
        );
      }
    }
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
}

export function createSourceChildEnvironment({
  cargoHome,
  home,
  npmCache,
  npmUserConfig,
  rustBin,
  temporary,
}) {
  const executableDirectories = [path.dirname(process.execPath)];
  if (rustBin !== null) executableDirectories.push(rustBin);
  executableDirectories.push(
    '/usr/local/bin',
    '/usr/bin',
    '/bin',
    '/usr/sbin',
    '/sbin'
  );
  const environment = {
    CARGO_HOME: cargoHome,
    CARGO_NET_OFFLINE: 'true',
    CI: '1',
    HOME: home,
    LANG: 'C',
    LC_ALL: 'C',
    PATH: [...new Set(executableDirectories)].join(path.delimiter),
    TMPDIR: temporary,
    TZ: 'UTC',
    XDG_CACHE_HOME: path.join(temporary, 'xdg-cache'),
    XDG_CONFIG_HOME: path.join(temporary, 'xdg-config'),
    npm_config_audit: 'false',
    npm_config_cache: npmCache,
    npm_config_fund: 'false',
    npm_config_offline: 'true',
    npm_config_update_notifier: 'false',
    npm_config_userconfig: npmUserConfig,
  };
  assertScrubbedSourceEnvironment(environment, {
    cargoHome,
    home,
    npmCache,
    npmUserConfig,
    temporary,
  });
  return Object.freeze(environment);
}

function assertScrubbedSourceEnvironment(environment, locations) {
  const expectedKeys = [
    'CARGO_HOME',
    'CARGO_NET_OFFLINE',
    'CI',
    'HOME',
    'LANG',
    'LC_ALL',
    'PATH',
    'TMPDIR',
    'TZ',
    'XDG_CACHE_HOME',
    'XDG_CONFIG_HOME',
    'npm_config_audit',
    'npm_config_cache',
    'npm_config_fund',
    'npm_config_offline',
    'npm_config_update_notifier',
    'npm_config_userconfig',
  ].sort(utf8Compare);
  const actualKeys = Object.keys(environment).sort(utf8Compare);
  if (!isDeepStrictEqual(actualKeys, expectedKeys)) {
    throw new Error('source subprocess environment is not the closed allowlist');
  }
  const forbiddenKeys = [
    'ALL_PROXY',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'GH_TOKEN',
    'GITHUB_TOKEN',
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'NODE_OPTIONS',
    'NO_PROXY',
    'SSH_AUTH_SOCK',
  ];
  for (const key of forbiddenKeys) {
    if (Object.hasOwn(environment, key)) {
      throw new Error(`source subprocess environment leaked ${key}`);
    }
  }
  expectEqual(environment.HOME, locations.home, 'isolated source HOME');
  expectEqual(environment.TMPDIR, locations.temporary, 'isolated source TMPDIR');
  expectEqual(
    environment.CARGO_HOME,
    locations.cargoHome,
    'isolated source CARGO_HOME'
  );
  expectEqual(
    environment.npm_config_cache,
    locations.npmCache,
    'isolated source npm cache'
  );
  expectEqual(
    environment.npm_config_userconfig,
    locations.npmUserConfig,
    'isolated source npm user configuration'
  );
}

function resolveRustBin(source) {
  const result = spawnSync('rustc', ['--print', 'sysroot'], {
    cwd: source,
    encoding: 'utf8',
    env: process.env,
    timeout: 30_000,
  });
  if (result.error !== undefined) {
    throw new Error(`pinned Rust probe failed: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(
      `pinned Rust probe failed with status ${result.status}: ${result.stderr.trim()}`
    );
  }
  const sysroot = result.stdout.trim();
  if (sysroot === '' || !path.isAbsolute(sysroot)) {
    throw new Error('pinned Rust probe returned a non-absolute sysroot');
  }
  return path.join(sysroot, 'bin');
}

function sourceCommands(script) {
  const nodeTool = (path, label = script) => ({
    program: process.execPath,
    arguments: [path],
    label,
  });
  const npmScript = (name, label = name) => ({
    program: 'npm',
    arguments: ['run', name],
    label,
  });
  if (script === 'check:projection') {
    return [nodeTool('tools/check-source-projection.mjs')];
  }
  if (script === 'check:projection-negative') {
    return [nodeTool('tools/check-source-negative.mjs')];
  }
  if (script === 'check:artifact' || script === 'check:consumer') {
    return [npmScript(script)];
  }
  if (script === 'check:full') {
    return [
      nodeTool('tools/check-source-projection.mjs', 'source projection'),
      nodeTool('tools/check-source-negative.mjs', 'source projection negatives'),
      nodeTool('tools/check-synthetic-checkout.mjs', 'synthetic history checkout'),
      npmScript('check:artifact'),
      npmScript('check:consumer'),
      npmScript('check:vouch-public-claims'),
      npmScript('check:vouch-adversarial'),
      nodeTool('tools/check-fixture-results.mjs', 'fixture result report'),
      nodeTool(
        'tools/check-fixture-results-negative.mjs',
        'fixture result negatives'
      ),
      nodeTool(
        'tools/check-replay-manifest-portable.mjs',
        'portable replay manifest'
      ),
      nodeTool('tools/run-vouch-loop-example.mjs', 'public Vouch loop'),
      nodeTool('tools/run-fixture-conformance.mjs', 'full fixture conformance'),
    ];
  }
  throw new Error(`unknown isolated source lane: ${script}`);
}

function runSourceProgram(source, program, arguments_, label, environment) {
  const result = spawnSync(program, arguments_, {
    cwd: source,
    env: environment,
    stdio: 'inherit',
    timeout: 600_000,
  });
  if (result.error !== undefined) {
    throw new Error(`source ${label} failed to execute: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`source ${label} failed with status ${result.status}`);
  }
}

async function inventoryTree(root) {
  const directories = [];
  const files = [];
  await walk('');
  directories.sort((left, right) => utf8Compare(left.path, right.path));
  files.sort((left, right) => utf8Compare(left.path, right.path));
  return { directories, files };

  async function walk(relativeDirectory) {
    const absolute = path.join(root, relativeDirectory);
    const names = await readdir(absolute);
    names.sort(utf8Compare);
    for (const name of names) {
      const relative = relativeDirectory ? `${relativeDirectory}/${name}` : name;
      if (relative === '.git') {
        const metadataStat = await lstat(path.join(root, relative));
        if (
          metadataStat.isSymbolicLink() ||
          (!metadataStat.isDirectory() && !metadataStat.isFile())
        ) {
          throw new Error('root repository metadata is not a regular file or directory');
        }
        continue;
      }
      if (relative === MANIFEST_PATH) continue;
      validateRelativePath(relative);
      rejectResiduePath(relative);
      const stat = await lstat(path.join(root, ...relative.split('/')));
      if (stat.isSymbolicLink()) throw new Error(`symlink is forbidden: ${relative}`);
      if (stat.isDirectory()) {
        const mode = modeString(stat.mode);
        if (mode !== '0755') throw new Error(`${relative}: directory mode must be 0755`);
        directories.push({ mode, path: relative });
        await walk(relative);
      } else if (stat.isFile()) {
        const mode = modeString(stat.mode);
        if (!['0644', '0755'].includes(mode)) {
          throw new Error(`${relative}: file mode is not portable`);
        }
        const bytes = await readRequired(root, relative);
        if (bytes.length >= 8_000_000) {
          throw new Error(
            `${relative}: distributed file is ${bytes.length} bytes; every file must remain below 4open's 8 MB limit`
          );
        }
        files.push({ mode, path: relative, sha256: sha256Id(bytes), size: bytes.length });
      } else {
        throw new Error(`non-regular filesystem entry is forbidden: ${relative}`);
      }
    }
  }
}

function rejectResiduePath(relative) {
  const parts = relative.split('/');
  const vendoredSource = relative.startsWith('source/vendor/');
  const declaredBridgeTarget =
    relative === 'source/examples/vouch-bridge/target' ||
    relative.startsWith('source/examples/vouch-bridge/target/');
  const forbidden = new Set([
    '.cache',
    '.git',
    '.next',
    '.npm',
    '.pytest_cache',
    '.turbo',
    '__pycache__',
    'coverage',
    'node_modules',
    'target',
  ]);
  const last = parts.at(-1);
  if (
    parts.some(
      (part) =>
        forbidden.has(part) &&
        !(declaredBridgeTarget && part === 'target') &&
        !(vendoredSource && ['coverage', 'node_modules', 'target'].includes(part))
    ) ||
    last === '.DS_Store'
  ) {
    throw new Error(`cache or repository residue is forbidden: ${relative}`);
  }
  if (
    last === '.gitmodules' ||
    last === '.mailmap' ||
    last === 'packed-refs' ||
    (last.endsWith('.bundle') && relative !== SYNTHETIC_BUNDLE_PATH)
  ) {
    throw new Error(`repository history material is forbidden: ${relative}`);
  }
}

async function readCanonicalJson(root, relative) {
  const bytes = await readRequired(root, relative);
  if (bytes.length > 64 * 1024 * 1024) {
    throw new Error(`${relative}: JSON exceeds the review limit`);
  }
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`${relative}: invalid UTF-8 JSON`);
  }
  const canonical = writeCanonicalJson(value);
  if (!bytes.equals(canonical)) {
    throw new Error(`${relative}: JSON is not canonical sorted artifact JSON`);
  }
  return { bytes, value };
}

async function readJsonFile(root, relative) {
  const bytes = await readRequired(root, relative);
  if (bytes.length > 64 * 1024 * 1024) {
    throw new Error(`${relative}: JSON exceeds the review limit`);
  }
  try {
    const value = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    );
    return { bytes, value };
  } catch {
    throw new Error(`${relative}: invalid UTF-8 JSON`);
  }
}

async function readRequired(root, relative) {
  validateRelativePath(relative);
  try {
    return await readFile(path.join(root, ...relative.split('/')));
  } catch (error) {
    if (error?.code === 'ENOENT') throw new Error(`required path is missing: ${relative}`);
    throw error;
  }
}

function writeCanonicalJson(value) {
  const chunks = [];
  writeValue(value, 0, chunks);
  chunks.push('\n');
  return Buffer.from(chunks.join(''), 'utf8');
}

function writeValue(value, depth, chunks) {
  if (value === null) {
    chunks.push('null');
  } else if (typeof value === 'boolean') {
    chunks.push(value ? 'true' : 'false');
  } else if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new Error('canonical artifact JSON accepts only safe integers');
    }
    chunks.push(String(value));
  } else if (typeof value === 'string') {
    chunks.push(JSON.stringify(value));
  } else if (Array.isArray(value)) {
    if (value.length === 0) {
      chunks.push('[]');
      return;
    }
    chunks.push('[\n');
    value.forEach((item, index) => {
      chunks.push('  '.repeat(depth + 1));
      writeValue(item, depth + 1, chunks);
      chunks.push(index + 1 === value.length ? '\n' : ',\n');
    });
    chunks.push('  '.repeat(depth), ']');
  } else if (
    typeof value === 'object' &&
    Object.getPrototypeOf(value) === Object.prototype
  ) {
    const names = Object.keys(value).sort(utf8Compare);
    if (names.length === 0) {
      chunks.push('{}');
      return;
    }
    chunks.push('{\n');
    names.forEach((name, index) => {
      chunks.push('  '.repeat(depth + 1), JSON.stringify(name), ': ');
      writeValue(value[name], depth + 1, chunks);
      chunks.push(index + 1 === names.length ? '\n' : ',\n');
    });
    chunks.push('  '.repeat(depth), '}');
  } else {
    throw new Error('value is outside canonical artifact JSON');
  }
}

function containsProjectionAuthorityField(value) {
  if (Array.isArray(value)) return value.some(containsProjectionAuthorityField);
  if (value === null || typeof value !== 'object') return false;
  for (const [name, child] of Object.entries(value)) {
    const normalized = name.toLowerCase().replaceAll('-', '_');
    if (normalized.includes('source_manifest') || normalized.includes('source_projection')) {
      return true;
    }
    if (containsProjectionAuthorityField(child)) return true;
  }
  return false;
}

function canonicalBase64(value, label) {
  if (
    typeof value !== 'string' ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
    throw new Error(`${label}: noncanonical base64`);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) {
    throw new Error(`${label}: noncanonical base64`);
  }
  return bytes;
}

function dssePae(payloadType, payload) {
  const type = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, 'ascii'),
    type,
    Buffer.from(` ${payload.length} `, 'ascii'),
    payload,
  ]);
}

function exactKeys(value, names, label) {
  requireObject(value, label);
  const actual = Object.keys(value).sort(utf8Compare);
  const expected = [...names].sort(utf8Compare);
  if (!isDeepStrictEqual(actual, expected)) {
    throw new Error(`${label}: expected fields ${expected.join(', ')}`);
  }
  return value;
}

function requireObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label}: expected object`);
  }
  return value;
}

function requireArray(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label}: expected array`);
  return value;
}

function requireUint(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label}: expected unsigned safe integer`);
  }
}

function requireDigest(value, label) {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`${label}: expected SHA-256 identifier`);
  }
}

function requireUnique(values, label) {
  const seen = new Set();
  for (const value of values) {
    if (typeof value !== 'string' || value === '') {
      throw new Error(`${label}: invalid identifier`);
    }
    if (seen.has(value)) throw new Error(`${label}: duplicate ${value}`);
    seen.add(value);
  }
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function validateRelativePath(value) {
  if (
    typeof value !== 'string' ||
    value === '' ||
    value.includes('\\') ||
    value.includes('\0') ||
    value.includes('\n') ||
    value.startsWith('/') ||
    value.normalize('NFC') !== value ||
    value.split('/').some((part) => part === '' || part === '.' || part === '..')
  ) {
    throw new Error(`noncanonical artifact path: ${JSON.stringify(value)}`);
  }
}

function printableText(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return bytes
      .toString('latin1')
      .replace(/[^\x20-\x7e\r\n\t]+/gu, '\n')
      .split(/\r?\n/gu)
      .filter((line) => line.length >= 6)
      .join('\n');
  }
}

function modeString(mode) {
  return `0${(mode & 0o777).toString(8).padStart(3, '0')}`;
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha256Id(bytes) {
  return `sha256:${sha256Hex(bytes)}`;
}

function sortObject(value) {
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => utf8Compare(left, right))
  );
}

function utf8Compare(left, right) {
  const leftValue = typeof left === 'string' ? left : left.path;
  const rightValue = typeof right === 'string' ? right : right.path;
  return Buffer.compare(Buffer.from(leftValue, 'utf8'), Buffer.from(rightValue, 'utf8'));
}

const invokedPath = process.argv[1] === undefined ? null : path.resolve(process.argv[1]);
if (invokedPath === scriptPath) {
  const root = path.resolve(process.env.VOUCH_ARTIFACT_ROOT ?? defaultRoot);
  try {
    if (process.argv[2] === '--source-full' && process.argv.length === 3) {
      await verifyArtifact(root, { runSourceChecks: false, quiet: true });
      await runIsolatedSourceChecks(root, ['check:full']);
      console.log('Vouch full projected-source verification passed');
    } else if (process.argv.length === 2) {
      await verifyArtifact(root);
    } else {
      throw new Error('usage: check-artifact.mjs [--source-full]');
    }
  } catch (error) {
    console.error(`artifact verification failed: ${error.message}`);
    process.exitCode = 1;
  }
}
