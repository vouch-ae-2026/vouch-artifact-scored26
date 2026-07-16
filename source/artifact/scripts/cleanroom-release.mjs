import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, readdirSync, rmSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

import {
  atomicPublish,
  captureBootstrapEntry,
  copyPrivateNpmCache,
  constructPhaseOneGate,
  encodeEnvironmentBuffer,
  readRegularFileOnce,
  selectFreshPhaseOneOutputRoot,
} from './cleanroom-driver-lib.mjs';
import { authenticateDescriptor } from './release-schema.mjs';

const options = parseArgs(process.argv.slice(2));
const cleanRoomRoot = resolve(options.get('--clean-room-root'));
const archivePath = resolve(options.get('--archive'));
const snapshotHelper = resolve(options.get('--snapshot-helper'));
const npm = resolve(options.get('--npm'));
const time = resolve(options.get('--time'));
const started = process.hrtime.bigint();

// C-REP-04 entry capture occurs before authentication or archive validation.
const entry = captureBootstrapEntry({
  trustPolicy: resolve(options.get('--trust-policy')),
  descriptor: resolve(options.get('--descriptor')),
  descriptorEnvelope: resolve(options.get('--descriptor-envelope')),
  archive: archivePath,
});

try {
  const authenticated = authenticateDescriptor({
    policyBytes: entry.buffers.trustPolicy,
    descriptorBytes: entry.buffers.descriptor,
    envelopeBytes: entry.buffers.descriptorEnvelope,
  });
  const descriptor = authenticated.descriptor;
  verifyAuthenticatedRuntime(descriptor);
  requireTrustedHelper(snapshotHelper);
  requireCleanRoomLayout(descriptor);

  const snapshot = spawnSync(
    snapshotHelper,
    [
      '--expected-sha256',
      descriptor.archive_sha256,
      '--extract-root',
      cleanRoomRoot,
    ],
    {
      cwd: cleanRoomRoot,
      encoding: 'utf8',
      env: trustedEnvironment(),
      maxBuffer: 16 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe', entry.archive],
      timeout: 30 * 60 * 1000,
    }
  );
  entry.closeArchive();
  if (snapshot.error || snapshot.status !== 0) {
    throw new Error(
      `archive-integrity-failure (status ${snapshot.status})\n` +
        `${snapshot.stdout ?? ''}${snapshot.stderr ?? ''}${snapshot.error?.message ?? ''}`
    );
  }
  process.stdout.write(snapshot.stdout);

  const artifactRoot = join(cleanRoomRoot, 'vouch-scored26-artifact');
  const sourceRoot = join(artifactRoot, 'work');
  const outputRoot = selectFreshPhaseOneOutputRoot(cleanRoomRoot);
  if (
    !existsSync(artifactRoot) ||
    existsSync(sourceRoot)
  ) {
    throw new Error('clean-room extraction or output precondition failed');
  }
  requireNetworkDisabled();
  command('git', ['clone', 'release/vouch-scored26.bundle', 'work'], {
    cwd: artifactRoot,
  });
  command('git', ['checkout', '--detach', descriptor.artifact_commit], {
    cwd: sourceRoot,
  });
  const privateNpmCache = copyPrivateNpmCache(
    join(artifactRoot, 'vendor/npm-cache'),
    join(cleanRoomRoot, '.phase1-npm-cache')
  );
  try {
    command(npm, ['ci', '--offline', '--cache', privateNpmCache], {
      cwd: sourceRoot,
      timeout: 30 * 60 * 1000,
    });
  } finally {
    rmSync(privateNpmCache, { recursive: true, force: true });
  }
  command('cargo', ['build', '--frozen', '--offline', '--release'], {
    cwd: sourceRoot,
    timeout: 30 * 60 * 1000,
  });
  // The inner reproducer exclusively claims and creates outputRoot. Creating it
  // here would violate its fresh-output boundary and permit prepopulation.
  command(npm, ['run', 'scored26:reproduce'], {
    cwd: sourceRoot,
    env: innerEnvironment({ artifactRoot, outputRoot }),
    timeout: 4 * 60 * 60 * 1000,
  });
  const stopped = process.hrtime.bigint();
  const cleanRunRuntimeSeconds = Number(
    (stopped - started + 999_999_999n) / 1_000_000_000n
  );

  const ownerBuffers = Object.freeze({
    fixtureReport: readRegularFileOnce(
      join(outputRoot, 'artifact/results/fixture-results.json')
    ),
    workloadReport: readRegularFileOnce(
      join(outputRoot, 'artifact/workload/workload-results.json')
    ),
    mutationReport: readRegularFileOnce(
      join(outputRoot, 'artifact/mutation/mutation-results.json')
    ),
    performanceReport: readRegularFileOnce(
      join(outputRoot, 'artifact/performance/performance-results.json')
    ),
  });
  const reproducedResultBuffers = new Map(
    descriptor.exact_reproduction_results.map((row) => [
      row.path,
      readRegularFileOnce(join(outputRoot, ...row.path.split('/'))),
    ])
  );
  const gate = constructPhaseOneGate({
    descriptor,
    descriptorBytes: entry.buffers.descriptor,
    ownerBuffers,
    reproducedResultBuffers,
    cleanRunRuntimeSeconds,
  });
  if (gate.exitCode !== 0) {
    process.stderr.write('PHASE_1_COMPARISON_MISMATCH\n');
    process.exitCode = gate.exitCode;
  } else {
    const external = join(cleanRoomRoot, 'external');
    atomicPublish(
      join(external, 'exact-reproduction-comparisons.json'),
      gate.comparisonBytes
    );
    atomicPublish(join(external, 'clean-run-report.json'), gate.qBytes);
    console.log(
      `SCORED26 phase-1 clean-room gate passed (${descriptor.artifact_commit.slice(0, 12)}, ${cleanRunRuntimeSeconds}s)`
    );
  }
} finally {
  entry.closeArchive();
}

function verifyAuthenticatedRuntime(descriptor) {
  const expected = {
    '--build-image-sha256': descriptor.build_image_sha256,
    '--os-image-reference': descriptor.build_parameters.os_image_reference,
    '--linker': descriptor.build_parameters.linker,
  };
  for (const [name, value] of Object.entries(expected)) {
    if (options.get(name) !== value) {
      throw new Error(`${name} differs from authenticated D`);
    }
  }
}

function requireCleanRoomLayout(descriptor) {
  const checkout = descriptor.build_parameters.build_path_policy.match(
    /^checkout=([^;]+);target=work\/target$/
  )?.[1];
  if (
    checkout !== join(cleanRoomRoot, 'vouch-scored26-artifact/work') ||
    basename(archivePath) !== 'vouch-scored26-artifact.tar.zst' ||
    !existsSync(cleanRoomRoot)
  ) {
    throw new Error('clean-room path differs from authenticated build policy');
  }
}

function requireTrustedHelper(path) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0) {
    throw new Error('--snapshot-helper is not a regular executable');
  }
}

function requireNetworkDisabled() {
  if (process.env.SCORED26_NETWORK_DISABLED !== '1') {
    throw new Error('network-disabled execution marker is absent');
  }
  const interfaces = readdirSync('/sys/class/net').sort();
  if (interfaces.length !== 1 || interfaces[0] !== 'lo') {
    throw new Error(
      `sandbox network is not disabled (${interfaces.join(',')})`
    );
  }
}

function innerEnvironment({ artifactRoot, outputRoot }) {
  return trustedEnvironment({
    SCORED26_RELEASE_ROOT: artifactRoot,
    SCORED26_OUTPUT_ROOT: outputRoot,
    ...encodeEnvironmentBuffer(
      'SCORED26_DESCRIPTOR_B64',
      entry.buffers.descriptor
    ),
    ...encodeEnvironmentBuffer(
      'SCORED26_DESCRIPTOR_ENVELOPE_B64',
      entry.buffers.descriptorEnvelope
    ),
    ...encodeEnvironmentBuffer(
      'SCORED26_TRUST_POLICY_B64',
      entry.buffers.trustPolicy
    ),
    SCORED26_NPM: npm,
    SCORED26_TIME: time,
    SCORED26_BUILD_IMAGE_SHA256: options.get('--build-image-sha256'),
    SCORED26_OS_IMAGE_REFERENCE: options.get('--os-image-reference'),
    SCORED26_LINKER: options.get('--linker'),
  });
}

function trustedEnvironment(additions = {}) {
  const env = {
    ...process.env,
    ...additions,
    CARGO_TERM_COLOR: 'never',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    SOURCE_DATE_EPOCH: '0',
  };
  for (const name of Object.keys(env)) {
    if (
      ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'SCORED_MUTANT'].includes(
        name
      ) ||
      /release.*(?:private|secret).*key/i.test(name)
    ) {
      delete env[name];
    }
  }
  return env;
}

function command(program, args, commandOptions = {}) {
  const result = spawnSync(program, args, {
    cwd: commandOptions.cwd ?? cleanRoomRoot,
    encoding: 'utf8',
    env: commandOptions.env ?? trustedEnvironment(),
    maxBuffer: 512 * 1024 * 1024,
    timeout: commandOptions.timeout ?? 10 * 60 * 1000,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${program} failed (status ${result.status})\n` +
        `${result.stdout ?? ''}${result.stderr ?? ''}${result.error?.message ?? ''}`
    );
  }
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  return result;
}

function parseArgs(raw) {
  const required = new Set([
    '--trust-policy',
    '--descriptor',
    '--descriptor-envelope',
    '--archive',
    '--clean-room-root',
    '--snapshot-helper',
    '--npm',
    '--time',
    '--build-image-sha256',
    '--os-image-reference',
    '--linker',
  ]);
  if (raw.length !== required.size * 2) {
    throw new Error(
      'clean-room driver requires every named option exactly once'
    );
  }
  const values = new Map();
  for (let index = 0; index < raw.length; index += 2) {
    const name = raw[index];
    const value = raw[index + 1];
    if (!required.has(name) || values.has(name) || !value) {
      throw new Error(`invalid or repeated option ${name}`);
    }
    values.set(name, value);
  }
  return values;
}
