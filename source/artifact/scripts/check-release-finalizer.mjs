import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { writeArtifactJson } from './artifact-json.mjs';
import {
  MemoryFinalizerKeyProvider,
  finalizeObservation,
} from './release-finalizer-lib.mjs';
import { MemoryAtomicDirectoryPublisher } from './release-io.mjs';
import {
  RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
  sha256Id,
  signEnvelope,
} from './release-schema.mjs';
import { buildReleaseTestFixture } from './release-test-fixtures.mjs';

let preKeyRefusalAccesses = 0;

// L10: without one usable --out-dir the CLI reports only on stderr.
{
  const result = spawnSync(
    process.execPath,
    ['artifact/scripts/finalize-observation.mjs'],
    { encoding: 'utf8' }
  );
  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage-error/);
  assert.equal(result.stdout, '');
}

// A usage error discovered after one usable --out-dir publishes a report.
{
  const root = mkdtempSync(join(tmpdir(), 'scored26-finalizer-usage-'));
  const output = join(root, 'out');
  try {
    const result = spawnSync(
      process.execPath,
      [
        'artifact/scripts/finalize-observation.mjs',
        '--out-dir',
        output,
        '--unknown-after-output',
        'value',
      ],
      { encoding: 'utf8' }
    );
    assert.equal(result.status, 2);
    const report = JSON.parse(
      readFileSync(join(output, 'finalize-report.json'), 'utf8')
    );
    assert.equal(report.status, 'refused');
    assert.equal(report.primary_error, 'usage-error');

    const beforeOutput = join(root, 'before-output');
    const before = spawnSync(
      process.execPath,
      [
        'artifact/scripts/finalize-observation.mjs',
        '--unknown-before-output',
        'value',
        '--out-dir',
        beforeOutput,
      ],
      { encoding: 'utf8' }
    );
    assert.equal(before.status, 2);
    assert.equal(existsSync(beforeOutput), false);

    const repeatedOutput = join(root, 'repeated-output');
    const repeated = spawnSync(
      process.execPath,
      [
        'artifact/scripts/finalize-observation.mjs',
        '--out-dir',
        repeatedOutput,
        '--out-dir',
        `${repeatedOutput}-second`,
      ],
      { encoding: 'utf8' }
    );
    assert.equal(repeated.status, 2);
    assert.equal(existsSync(repeatedOutput), false);
    assert.equal(existsSync(`${repeatedOutput}-second`), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

{
  const fixture = buildReleaseTestFixture();
  const { outcome, provider, publisher } = run(fixture);
  assert.equal(outcome.exitCode, 0);
  assert.equal(outcome.report.status, 'finalized');
  assert.equal(provider.totalAccesses() > 0, true);
  assert.deepEqual([...publisher.directory('/out').keys()].sort(), [
    'finalize-report.json',
    'release-publication.json',
    'reproduction-observation.dsse.json',
    'reproduction-observation.json',
  ]);
}

// L06: Q from another release is refused at the first release-binding check.
{
  const fixture = buildReleaseTestFixture();
  const q = clone(fixture.q);
  q.release_descriptor_sha256 = `sha256:${'f'.repeat(64)}`;
  fixture.buffers.cleanRunReport = writeArtifactJson(q);
  expectPreKeyRefusal(fixture, {
    error: 'release-binding-mismatch',
    check: 'rb-q-descriptor',
  });
}

// L07: a comparison cannot assert true when its digests differ.
{
  const fixture = buildReleaseTestFixture();
  const comparisons = clone(fixture.values.comparisons);
  comparisons.comparisons[0].observed_sha256 = `sha256:${'e'.repeat(64)}`;
  comparisons.comparisons[0].matched = true;
  fixture.buffers.comparisons = writeArtifactJson(comparisons);
  const q = clone(fixture.q);
  q.exact_reproduction_comparisons_sha256 = sha256Id(
    fixture.buffers.comparisons
  );
  fixture.buffers.cleanRunReport = writeArtifactJson(q);
  expectPreKeyRefusal(fixture, {
    error: 'clean-run-derivation-mismatch',
    check: 'qd-comparison-matched',
  });
}

// L08: path replacement after entry cannot mutate the captured buffers.
{
  const fixture = buildReleaseTestFixture();
  const captured = Object.fromEntries(
    Object.entries(fixture.buffers).map(([name, bytes]) => [
      name,
      Buffer.from(bytes),
    ])
  );
  fixture.buffers.workloadReport.fill(0x78);
  fixture.buffers = captured;
  const { outcome } = run(fixture);
  assert.equal(outcome.exitCode, 0);
}

// L11A: valid but noncanonical owner JSON is an input fault before the key.
{
  const fixture = buildReleaseTestFixture();
  fixture.buffers.workloadReport = Buffer.from(
    `${JSON.stringify(fixture.values.workloadReport)}\n`,
    'utf8'
  );
  expectPreKeyRefusal(fixture, {
    error: 'finalizer-input-invalid',
    input: 'workload-report',
    underlying: 'non-canonical-artifact-json',
  });
}

// L11B: raw owner report limit has precedence and no key access.
{
  const fixture = buildReleaseTestFixture();
  fixture.buffers.workloadReport = Buffer.alloc(16_777_217, 0x20);
  expectPreKeyRefusal(fixture, {
    error: 'finalizer-input-invalid',
    input: 'workload-report',
    underlying: 'artifact-resource-limit',
  });
}

// L13: summary-equivalent detail replacement is caught by the full-file digest.
{
  const fixture = buildReleaseTestFixture();
  const replacement = clone(fixture.values.workloadReport);
  replacement.details.fixture = 'B';
  fixture.buffers.workloadReport = writeArtifactJson(replacement);
  expectPreKeyRefusal(fixture, {
    error: 'clean-run-derivation-mismatch',
    check: 'qd-workload-bytes',
  });
}

// L16: descriptor payload key id must equal its signing key id.
{
  const fixture = buildReleaseTestFixture();
  const descriptor = clone(fixture.descriptor);
  descriptor.key_id = fixture.otherKey.keyId;
  fixture.buffers.descriptor = writeArtifactJson(descriptor);
  fixture.buffers.descriptorEnvelope = signEnvelope(
    RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
    fixture.buffers.descriptor,
    fixture.releaseKey.privateDer
  ).envelopeBytes;
  expectPreKeyRefusal(fixture, {
    error: 'descriptor-authentication-failed',
  });
}

// L20: a wrong loaded private key is a post-key refusal with no publication.
{
  const fixture = buildReleaseTestFixture();
  const provider = new MemoryFinalizerKeyProvider();
  provider.set(fixture.keyHandle, fixture.otherKey.privateDer);
  const publisher = new MemoryAtomicDirectoryPublisher();
  const outcome = finalizeObservation({
    buffers: fixture.buffers,
    keyHandle: fixture.keyHandle,
    keyProvider: provider,
    publisher,
    output: '/out',
  });
  assert.equal(outcome.exitCode, 4);
  assert.equal(outcome.report.primary_error, 'key-loading-or-signing-failure');
  assert.equal(provider.totalAccesses() > 0, true);
  assert.deepEqual(
    [...publisher.directory('/out').keys()],
    ['finalize-report.json']
  );
}

// L21: post-key atomic-publication failure leaves no final directory.
{
  const fixture = buildReleaseTestFixture();
  const provider = new MemoryFinalizerKeyProvider();
  provider.set(fixture.keyHandle, fixture.releaseKey.privateDer);
  const publisher = new MemoryAtomicDirectoryPublisher();
  publisher.setFault('final-rename-failure');
  const outcome = finalizeObservation({
    buffers: fixture.buffers,
    keyHandle: fixture.keyHandle,
    keyProvider: provider,
    publisher,
    output: '/out',
  });
  assert.equal(outcome.exitCode, 3);
  assert.equal(outcome.report.primary_error, 'input-output-failure');
  assert.equal(provider.totalAccesses() > 0, true);
  assert.equal(publisher.directory('/out'), null);
}

assert.equal(preKeyRefusalAccesses, 0);
console.log(
  'SCORED26 release finalizer passed (L06/L07/L08/L11A/L11B/L13/L16/L20/L21)'
);

function run(fixture) {
  const provider = new MemoryFinalizerKeyProvider();
  provider.set(fixture.keyHandle, fixture.releaseKey.privateDer);
  const publisher = new MemoryAtomicDirectoryPublisher();
  const outcome = finalizeObservation({
    buffers: fixture.buffers,
    keyHandle: fixture.keyHandle,
    keyProvider: provider,
    publisher,
    output: '/out',
  });
  return { outcome, provider, publisher };
}

function expectPreKeyRefusal(fixture, expected) {
  const { outcome, provider } = run(fixture);
  assert.equal(outcome.exitCode, 1);
  assert.equal(outcome.report.status, 'refused');
  assert.equal(outcome.report.primary_error, expected.error);
  assert.equal(outcome.report.failed_check, expected.check ?? null);
  assert.equal(outcome.report.input_artifact, expected.input ?? null);
  assert.equal(outcome.report.underlying_error, expected.underlying ?? null);
  assert.equal(provider.totalAccesses(), 0);
  preKeyRefusalAccesses += provider.totalAccesses();
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}
