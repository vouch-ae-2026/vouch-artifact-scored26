import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  RELEASE_AUDIT_TIMEOUT_MS,
  RELEASE_EXECUTABLE_PATH,
  RELEASE_MANIFEST_PATH,
  buildReleaseDescriptor,
  buildReleaseManifest,
  dependencyManifestDigests,
  exactReleaseResults,
  executionObservationHasReceipt,
  parsePublicKeyRecord,
  publicDataArchivePathPolicy,
  regularFiles,
  regularFilesAfterPhaseOneCheckout,
  releasePerformanceReceiptPopulation,
  verifyReleaseManifest,
  verifyReleaseManifestAfterPhaseOneCheckout,
} from './release-layer-lib.mjs';
import { parseCanonical, sha256Id } from './release-schema.mjs';

const root = fileURLToPath(new URL('../..', import.meta.url));
for (const path of [
  '.cargo/config.toml',
  '.nvmrc',
  'Cargo.lock',
  'Cargo.toml',
  'artifact/runtime-versions.json',
  'artifact/vendor-manifest.json',
  'package-lock.json',
  'package.json',
  'rust-toolchain.toml',
]) {
  assert.equal(statSync(join(root, path)).isFile(), true, `${path}: missing`);
}
assert.equal(statSync(join(root, 'vendor')).isDirectory(), true);
assert.throws(() => statSync(join(root, 'interp/Cargo.lock')));
assert.throws(() => statSync(join(root, 'vouch/Cargo.lock')));
assert.throws(() => statSync(join(root, 'wasm/Cargo.lock')));

const cargoConfig = readFileSync(join(root, '.cargo/config.toml'), 'utf8');
assert.match(cargoConfig, /replace-with\s*=\s*"vendored-sources"/);
assert.match(cargoConfig, /directory\s*=\s*"vendor"/);
const rustToolchain = readFileSync(join(root, 'rust-toolchain.toml'), 'utf8');
assert.match(rustToolchain, /channel\s*=\s*"1\.85\.1"/);
assert.match(rustToolchain, /x86_64-unknown-linux-gnu/);
assert.equal(readFileSync(join(root, '.nvmrc'), 'utf8'), '22.14.0\n');

const lockBytes = readFileSync(join(root, 'Cargo.lock'));
assert.equal(lockBytes.includes(Buffer.from('git+')), false);
for (const workspacePackage of [
  'lispex',
  'lispex-wasm',
  'scored26-release-anchor',
  'vouch',
]) {
  assert.match(
    lockBytes.toString('utf8'),
    new RegExp(`name = "${workspacePackage}"`),
    `${workspacePackage}: absent from the unified Cargo.lock`
  );
}
const packageLock = JSON.parse(readFileSync(join(root, 'package-lock.json')));
assert.equal(packageLock.lockfileVersion, 3);
const registryUrls = Object.values(packageLock.packages)
  .map((entry) => entry?.resolved)
  .filter((value) => typeof value === 'string');
assert.ok(registryUrls.length > 500);
assert.equal(
  registryUrls.every((value) =>
    value.startsWith('https://registry.npmjs.org/')
  ),
  true
);
const uniqueRegistryUrls = new Set(registryUrls);
assert.ok(uniqueRegistryUrls.size > 500);

const runtime = parseCanonical(
  readFileSync(join(root, 'artifact/runtime-versions.json')),
  'runtime-versions'
);
assert.equal(runtime.target_triple, 'x86_64-unknown-linux-gnu');
assert.equal(runtime.toolchains.node, 'v22.14.0');
assert.equal(runtime.toolchains.npm, '10.9.2');
const vendor = parseCanonical(
  readFileSync(join(root, 'artifact/vendor-manifest.json')),
  'vendor-manifest'
);
assert.ok(vendor.crates.length > 40);
assert.ok(vendor.file_count > 1_000);
const publicKey = parsePublicKeyRecord(
  readFileSync(join(root, 'artifact/trust/native-release-public-key.json'))
);
assert.equal(publicKey.rawPublicKey.length, 32);
assert.equal(RELEASE_AUDIT_TIMEOUT_MS, 30 * 60 * 1000);
assert.deepEqual(publicDataArchivePathPolicy('vendor/npm-cache/cache-entry'), {
  collectGeneratedJson: false,
  scanText: false,
});
assert.deepEqual(publicDataArchivePathPolicy('release/vouch-scored26.bundle'), {
  collectGeneratedJson: false,
  scanText: false,
});
assert.deepEqual(
  publicDataArchivePathPolicy('release/receipts/D001/baseline/payload.json'),
  { collectGeneratedJson: true, scanText: true }
);

assert.equal(
  executionObservationHasReceipt({
    outcome: { kind: 'decision', label: 'invalid-input' },
    receipt_payload_sha256: `sha256:${'0'.repeat(64)}`,
  }),
  true
);
assert.equal(
  executionObservationHasReceipt({
    outcome: { kind: 'profile-escape' },
    receipt_payload_sha256: null,
  }),
  false
);
assert.throws(
  () =>
    executionObservationHasReceipt({
      outcome: { kind: 'decision', label: 'approve' },
      receipt_payload_sha256: null,
    }),
  /receipt accounting mismatch/
);
assert.deepEqual(
  releasePerformanceReceiptPopulation({
    cases: [
      {
        baseline: {
          outcome: { kind: 'decision', label: 'approve' },
          receipt_payload_sha256: `sha256:${'1'.repeat(64)}`,
        },
        case_id: 'D001',
        changed: {
          outcome: { kind: 'profile-escape' },
          receipt_payload_sha256: null,
        },
      },
    ],
    receipt_count: 1,
  }),
  {
    coordinates: [{ caseId: 'D001', side: 'baseline' }],
    excluded: [{ case: 'D001', side: 'changed' }],
  }
);
assert.throws(
  () =>
    releasePerformanceReceiptPopulation({
      cases: [
        {
          baseline: {
            outcome: { kind: 'decision', label: 'approve' },
            receipt_payload_sha256: `sha256:${'2'.repeat(64)}`,
          },
          case_id: 'D001',
          changed: {
            outcome: { kind: 'profile-escape' },
            receipt_payload_sha256: null,
          },
        },
      ],
      receipt_count: 0,
    }),
  /performance receipt population mismatch/
);

for (const path of [
  'artifact/scripts/scan-public-data',
  'artifact/scripts/scan-release-secrets',
]) {
  assert.equal(statSync(join(root, path)).mode & 0o111, 0o111);
  const result = spawnSync(join(root, path), [], { encoding: 'utf8' });
  assert.notEqual(result.status, 0, `${path}: missing-argument control passed`);
  assert.doesNotMatch(result.stderr, /SyntaxError/);
  assert.match(result.stderr, /(?:required|usage:)/);
}

// Exercise ESM linking for the real assembler entrypoint. `node --check`
// catches syntax only and would not detect an import of a missing export.
{
  const path = 'artifact/scripts/assemble-release.mjs';
  const result = spawnSync(process.execPath, [join(root, path)], {
    cwd: root,
    encoding: 'utf8',
  });
  assert.notEqual(result.status, 0, `${path}: missing-argument control passed`);
  assert.doesNotMatch(result.stderr, /SyntaxError/);
  assert.match(result.stderr, /--source-root is required/);
}

const exactResults = [
  { path: RELEASE_EXECUTABLE_PATH, sha256: `sha256:${'1'.repeat(64)}` },
  {
    path: 'release/replay-manifest.json',
    sha256: `sha256:${'2'.repeat(64)}`,
  },
];
const descriptor = buildReleaseDescriptor({
  archiveSha256: `sha256:${'3'.repeat(64)}`,
  artifactCommit: '4'.repeat(40),
  artifactFreezeCommit: '5'.repeat(40),
  buildImageSha256: `sha256:${'6'.repeat(64)}`,
  buildParameters: {
    build_id_policy: 'rustc-default-deterministic',
    build_path_policy:
      'checkout=/opt/vouch-scored26/clean-room/vouch-scored26-artifact/work;target=work/target',
    linker: 'GNU ld 2.42',
    locale: 'C.UTF-8',
    os_image_reference: 'ubuntu:noble-test',
    source_date_epoch: 0,
  },
  dependencyManifestDigests: dependencyManifestDigests(root),
  engineSha256: exactResults[0].sha256,
  exactReproductionResults: exactResults,
  keyId: publicKey.key_id,
  runtimeVersions: runtime,
});
assert.equal(descriptor.descriptor.exact_reproduction_results.length, 2);

const temporary = mkdtempSync(join(tmpdir(), 'scored26-release-manifest-'));
try {
  const executable = Buffer.from('test-release-executable');
  const engine = sha256Id(executable);
  mkdirSync(join(temporary, 'release'), { recursive: true });
  writeFileSync(join(temporary, RELEASE_EXECUTABLE_PATH), executable);
  writeFileSync(join(temporary, 'release/COMMIT'), `${'4'.repeat(40)}\n`);
  writeFileSync(join(temporary, 'release/replay-manifest.json'), '{}\n');
  mkdirSync(join(temporary, 'work/node_modules/.bin'), { recursive: true });
  symlinkSync(
    '../acorn/bin/acorn',
    join(temporary, 'work/node_modules/.bin/acorn')
  );
  assert.deepEqual(
    exactReleaseResults(temporary).map((row) => row.path),
    ['release/replay-manifest.json', RELEASE_EXECUTABLE_PATH]
  );
  mkdirSync(join(temporary, 'release/receipts/D001/baseline'), {
    recursive: true,
  });
  symlinkSync(
    '../../../replay-manifest.json',
    join(temporary, 'release/receipts/D001/baseline/payload.json')
  );
  assert.throws(
    () => exactReleaseResults(temporary),
    /symlinks are forbidden in the release archive/
  );
  rmSync(join(temporary, 'release/receipts'), { recursive: true, force: true });
  rmSync(join(temporary, 'work'), { recursive: true, force: true });
  const manifest = buildReleaseManifest(temporary, engine);
  mkdirSync(join(temporary, 'artifact'));
  writeFileSync(join(temporary, RELEASE_MANIFEST_PATH), manifest);
  verifyReleaseManifest(temporary, manifest, engine);
  mkdirSync(join(temporary, 'work/node_modules/.bin'), { recursive: true });
  symlinkSync(
    '../acorn/bin/acorn',
    join(temporary, 'work/node_modules/.bin/acorn')
  );
  assert.throws(
    () => regularFiles(temporary),
    /symlinks are forbidden in the release archive/
  );
  assert.deepEqual(
    regularFilesAfterPhaseOneCheckout(temporary, join(temporary, 'work')),
    [
      RELEASE_MANIFEST_PATH,
      'release/COMMIT',
      'release/replay-manifest.json',
      RELEASE_EXECUTABLE_PATH,
    ]
  );
  assert.throws(
    () =>
      regularFilesAfterPhaseOneCheckout(temporary, join(temporary, 'other')),
    /phase-1 checkout is not the archive-root work directory/
  );
  assert.throws(
    () => verifyReleaseManifest(temporary, manifest, engine),
    /symlinks are forbidden in the release archive/
  );
  verifyReleaseManifestAfterPhaseOneCheckout(
    temporary,
    manifest,
    engine,
    join(temporary, 'work')
  );
  mkdirSync(join(temporary, 'unexpected'));
  writeFileSync(join(temporary, 'unexpected/file'), 'not in manifest');
  assert.throws(
    () =>
      verifyReleaseManifestAfterPhaseOneCheckout(
        temporary,
        manifest,
        engine,
        join(temporary, 'work')
      ),
    /release-manifest does not cover every archive path/
  );
  rmSync(join(temporary, 'unexpected'), { recursive: true, force: true });
  symlinkSync(
    'release/replay-manifest.json',
    join(temporary, 'unexpected-link')
  );
  assert.throws(
    () => regularFilesAfterPhaseOneCheckout(temporary, join(temporary, 'work')),
    /symlinks are forbidden in the release archive/
  );
  rmSync(join(temporary, 'unexpected-link'));
  writeFileSync(join(temporary, 'release/replay-manifest.json'), '{ }\n');
  assert.throws(() =>
    verifyReleaseManifestAfterPhaseOneCheckout(
      temporary,
      manifest,
      engine,
      join(temporary, 'work')
    )
  );
  writeFileSync(join(temporary, 'release/replay-manifest.json'), '{}\n');
  rmSync(join(temporary, 'work'), { recursive: true, force: true });
  symlinkSync('release', join(temporary, 'work'), 'dir');
  assert.throws(
    () =>
      verifyReleaseManifestAfterPhaseOneCheckout(
        temporary,
        manifest,
        engine,
        join(temporary, 'work')
      ),
    /phase-1 checkout is not a regular directory/
  );
  assert.throws(
    () => regularFilesAfterPhaseOneCheckout(temporary, join(temporary, 'work')),
    /phase-1 checkout is not a regular directory/
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}

const scanTemporary = mkdtempSync(join(tmpdir(), 'scored26-release-scan-'));
try {
  const archive = join(scanTemporary, 'archive');
  const checkout = join(archive, 'work');
  const repository = join(scanTemporary, 'repository');
  const bundle = join(archive, 'release/vouch-scored26.bundle');
  mkdirSync(join(archive, 'release'), { recursive: true });
  mkdirSync(join(checkout, 'node_modules/.bin'), { recursive: true });
  mkdirSync(repository);
  writeFileSync(join(repository, 'safe.txt'), 'synthetic public input\n');
  checkedCommand('git', ['init', '--quiet'], { cwd: repository });
  checkedCommand('git', ['add', 'safe.txt'], { cwd: repository });
  checkedCommand(
    'git',
    [
      '-c',
      'user.name=Artifact Maintainer',
      '-c',
      'user.email=artifact@example.invalid',
      'commit',
      '--quiet',
      '-m',
      'synthetic public input',
    ],
    { cwd: repository }
  );
  checkedCommand('git', ['bundle', 'create', bundle, '--all'], {
    cwd: repository,
  });
  symlinkSync('../acorn/bin/acorn', join(checkout, 'node_modules/.bin/acorn'));

  const publicScan = join(root, 'artifact/scripts/scan-public-data');
  const publicArgs = ['--root', archive, '--bundle', bundle];
  const strictPublic = spawnSync(publicScan, publicArgs, { encoding: 'utf8' });
  assert.notEqual(strictPublic.status, 0);
  assert.match(strictPublic.stderr, /symlinks are forbidden/);
  checkedCommand(publicScan, [...publicArgs, '--phase1-checkout', checkout]);

  const benign = join(archive, 'benign-identity-lookalikes.txt');
  writeFileSync(
    benign,
    'filename\nhttps://lispex.community\n/Users/cskernel2/project\n'
  );
  checkedCommand(publicScan, [...publicArgs, '--phase1-checkout', checkout]);
  rmSync(benign);

  const identityRepository = join(scanTemporary, 'identity-repository');
  const identityBundle = join(scanTemporary, 'identity.bundle');
  mkdirSync(identityRepository);
  writeFileSync(
    join(identityRepository, 'safe.txt'),
    'synthetic public input\n'
  );
  checkedCommand('git', ['init', '--quiet'], { cwd: identityRepository });
  checkedCommand('git', ['add', 'safe.txt'], { cwd: identityRepository });
  checkedCommand(
    'git',
    [
      '-c',
      'user.name=Anonymous',
      '-c',
      'user.email=anonymous@example.invalid',
      'commit',
      '--quiet',
      '-m',
      'synthetic public input',
    ],
    { cwd: identityRepository }
  );
  checkedCommand('git', ['bundle', 'create', identityBundle, '--all'], {
    cwd: identityRepository,
  });
  const identityFailure = spawnSync(
    publicScan,
    [
      '--root',
      archive,
      '--bundle',
      identityBundle,
      '--phase1-checkout',
      checkout,
    ],
    { encoding: 'utf8' }
  );
  assert.notEqual(identityFailure.status, 0);
  assert.match(identityFailure.stderr, /non-anonymous commit identity/);

  const messageRepository = join(scanTemporary, 'message-repository');
  const messageBundle = join(scanTemporary, 'message.bundle');
  mkdirSync(messageRepository);
  writeFileSync(
    join(messageRepository, 'safe.txt'),
    'synthetic public input\n'
  );
  checkedCommand('git', ['init', '--quiet'], { cwd: messageRepository });
  checkedCommand('git', ['add', 'safe.txt'], { cwd: messageRepository });
  const forbiddenMessage = String.fromCodePoint(
    115,
    111,
    117,
    114,
    99,
    101,
    32,
    97,
    99,
    99,
    111,
    117,
    110,
    116,
    32,
    99,
    108,
    97,
    118,
    101,
    102
  );
  checkedCommand(
    'git',
    [
      '-c',
      'user.name=Artifact Maintainer',
      '-c',
      'user.email=artifact@example.invalid',
      'commit',
      '--quiet',
      '-m',
      forbiddenMessage,
    ],
    { cwd: messageRepository }
  );
  checkedCommand('git', ['bundle', 'create', messageBundle, '--all'], {
    cwd: messageRepository,
  });
  const messageFailure = spawnSync(
    publicScan,
    [
      '--root',
      archive,
      '--bundle',
      messageBundle,
      '--phase1-checkout',
      checkout,
    ],
    { encoding: 'utf8' }
  );
  assert.notEqual(messageFailure.status, 0);
  assert.match(messageFailure.stderr, /forbidden source-account handle/);

  const expectPublicScanFailure = (name, bytes, diagnostic) => {
    const path = join(archive, name);
    writeFileSync(path, bytes);
    const result = spawnSync(
      publicScan,
      [...publicArgs, '--phase1-checkout', checkout],
      { encoding: 'utf8' }
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, diagnostic);
    rmSync(path);
  };
  expectPublicScanFailure(
    'package-lock.json',
    Buffer.from([
      104, 116, 116, 112, 115, 58, 47, 47, 103, 105, 116, 104, 117, 98, 46, 99,
      111, 109, 47, 99, 108, 97, 118, 101, 102, 47, 112, 114, 111, 106, 101, 99,
      116, 10,
    ]),
    /forbidden source-account handle/
  );
  expectPublicScanFailure(
    'subdomain.txt',
    Buffer.from([
      104, 116, 116, 112, 115, 58, 47, 47, 100, 111, 99, 115, 46, 108, 105, 115,
      112, 101, 120, 46, 99, 111, 109, 47, 109, 97, 110, 117, 97, 108, 10,
    ]),
    /forbidden first-party domain/
  );
  expectPublicScanFailure(
    'domain-suffix.txt',
    Buffer.from([
      104, 116, 116, 112, 115, 58, 47, 47, 108, 105, 115, 112, 101, 120, 46, 99,
      111, 109, 46, 101, 118, 105, 108, 47, 109, 97, 110, 117, 97, 108, 10,
    ]),
    /forbidden first-party domain/
  );
  expectPublicScanFailure(
    String.fromCodePoint(
      99,
      108,
      97,
      118,
      101,
      102,
      45,
      108,
      101,
      97,
      107,
      46,
      116,
      120,
      116
    ),
    Buffer.from('synthetic public input\n'),
    /forbidden source-account handle/
  );
  expectPublicScanFailure(
    'identity-binary.bin',
    Buffer.from([
      0xff, 47, 85, 115, 101, 114, 115, 47, 99, 115, 107, 101, 114, 110, 101,
      108, 47, 112, 114, 111, 106, 101, 99, 116,
    ]),
    /forbidden local user path/
  );
  expectPublicScanFailure(
    'phone.txt',
    Buffer.from([
      112, 104, 111, 110, 101, 58, 32, 43, 49, 32, 50, 48, 50, 32, 53, 53, 53,
      32, 48, 49, 52, 55, 10,
    ]),
    /telephone-shaped value/
  );
  expectPublicScanFailure(
    'national-id.txt',
    Buffer.from([
      110, 97, 116, 105, 111, 110, 97, 108, 95, 105, 100, 58, 32, 49, 50, 51,
      45, 52, 53, 45, 54, 55, 56, 57, 10,
    ]),
    /national-identifier-shaped value/
  );
  expectPublicScanFailure(
    'address.txt',
    Buffer.from([
      49, 50, 51, 32, 77, 97, 105, 110, 32, 83, 116, 114, 101, 101, 116, 10,
    ]),
    /street-address-shaped value/
  );
  expectPublicScanFailure(
    'proper-name.txt',
    Buffer.from([
      97, 117, 116, 104, 111, 114, 58, 32, 77, 97, 116, 116, 32, 80, 97, 114,
      107, 10,
    ]),
    /unapproved proper-name-shaped value/
  );

  const markerScan = join(
    root,
    'artifact/scripts/scan-private-key-markers.mjs'
  );
  const markerArgs = [markerScan, '--root', archive];
  const strictMarkers = spawnSync(process.execPath, markerArgs, {
    encoding: 'utf8',
  });
  assert.notEqual(strictMarkers.status, 0);
  assert.match(strictMarkers.stderr, /symlinks are forbidden/);
  checkedCommand(process.execPath, [
    ...markerArgs,
    '--phase1-checkout',
    checkout,
  ]);

  symlinkSync('release/vouch-scored26.bundle', join(archive, 'outside-link'));
  const outsideLink = spawnSync(
    publicScan,
    [...publicArgs, '--phase1-checkout', checkout],
    { encoding: 'utf8' }
  );
  assert.notEqual(outsideLink.status, 0);
  assert.match(outsideLink.stderr, /symlinks are forbidden/);
} finally {
  rmSync(scanTemporary, { recursive: true, force: true });
}

console.log(
  `SCORED26 release supply checks passed (${vendor.crates.length} crates/${vendor.file_count} vendored files/${uniqueRegistryUrls.size} npm tarballs)`
);

function checkedCommand(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: options.cwd,
    encoding: 'utf8',
  });
  assert.equal(
    result.status,
    0,
    `${program} ${args.join(' ')} failed\n${result.stdout}${result.stderr}`
  );
  return result;
}
