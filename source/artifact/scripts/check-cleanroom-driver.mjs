import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { writeArtifactJson } from './artifact-json.mjs';
import {
  ENVIRONMENT_BUFFER_CHUNK_BYTES,
  PHASE_1_COMPARISON_MISMATCH,
  captureBootstrapEntry,
  consumeEnvironmentBuffer,
  copyPrivateNpmCache,
  constructPhaseOneGate,
  encodeEnvironmentBuffer,
  selectFreshPhaseOneOutputRoot,
} from './cleanroom-driver-lib.mjs';
import {
  authenticateDescriptor,
  parseCleanRunReport,
  sha256Id,
} from './release-schema.mjs';
import { buildReleaseTestFixture } from './release-test-fixtures.mjs';

class CountingIo {
  constructor(bytes) {
    this.bytes = { ...bytes };
    this.events = [];
    this.readCounts = Object.fromEntries(
      Object.keys(bytes).map((name) => [name, 0])
    );
    this.closed = new Set();
  }

  openInput(path) {
    this.events.push(`open-input:${path}`);
    return path;
  }

  openArchive(path) {
    this.events.push(`open-archive:${path}`);
    return path;
  }

  read(handle) {
    this.events.push(`read:${handle}`);
    this.readCounts[handle] += 1;
    return Buffer.from(this.bytes[handle]);
  }

  isRegular(handle) {
    this.events.push(`regular:${handle}`);
    return handle === 'archive';
  }

  close(handle) {
    assert.equal(this.closed.has(handle), false, `${handle} closed twice`);
    this.closed.add(handle);
    this.events.push(`close:${handle}`);
  }
}

// npm receives a private cache copy, so its logs and notifier state cannot
// mutate the authenticated archive inventory before manifest verification.
{
  const root = mkdtempSync(join(tmpdir(), 'scored26-private-npm-cache-'));
  try {
    const source = join(root, 'archive-cache');
    const destination = join(root, 'private-cache');
    mkdirSync(join(source, '_cacache/content-v2'), { recursive: true });
    writeFileSync(join(source, '_cacache/content-v2/blob'), 'cache-bytes');
    assert.equal(copyPrivateNpmCache(source, destination), destination);
    writeFileSync(join(destination, '_update-notifier-last-checked'), 'noise');
    assert.equal(
      readFileSync(join(source, '_cacache/content-v2/blob'), 'utf8'),
      'cache-bytes'
    );
    assert.equal(
      existsSync(join(source, '_update-notifier-last-checked')),
      false
    );
    assert.throws(
      () => copyPrivateNpmCache(source, destination),
      /private npm cache destination already exists/
    );
    rmSync(destination, { recursive: true, force: true });
    symlinkSync('content-v2/blob', join(source, '_cacache/link'));
    assert.throws(
      () => copyPrivateNpmCache(source, destination),
      /npm cache source contains a symlink/
    );
    assert.equal(existsSync(destination), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// The outer driver selects but never creates the phase-1 output directory.
// The inner reproducer remains its sole creator and rejects prepopulation.
{
  const cleanRoomRoot = mkdtempSync(join(tmpdir(), 'scored26-output-root-'));
  try {
    const outputRoot = selectFreshPhaseOneOutputRoot(cleanRoomRoot);
    assert.equal(outputRoot, join(cleanRoomRoot, 'phase1-results'));
    assert.equal(existsSync(outputRoot), false);
    mkdirSync(outputRoot);
    assert.throws(
      () => selectFreshPhaseOneOutputRoot(cleanRoomRoot),
      /phase-1 output directory already exists/
    );
  } finally {
    rmSync(cleanRoomRoot, { recursive: true, force: true });
  }
}

// Large authenticated entry buffers are split below Linux's per-string exec
// ceiling, round-trip byte-for-byte, and are removed once consumed.
{
  const bytes = Buffer.alloc(150_000, 0xa5);
  const environment = {
    UNRELATED: 'preserved',
    ...encodeEnvironmentBuffer('SCORED26_TEST_B64', bytes),
  };
  const chunkValues = Object.entries(environment)
    .filter(([name]) => /^SCORED26_TEST_B64_CHUNK_[0-9]{2}$/.test(name))
    .map(([, value]) => value);
  assert.ok(chunkValues.length > 1);
  assert.equal(
    chunkValues.every((value) => value.length <= ENVIRONMENT_BUFFER_CHUNK_BYTES),
    true
  );
  const spawned = spawnSync(
    process.execPath,
    [
      '-e',
      `const v=Object.entries(process.env).filter(([k])=>/^SCORED26_TEST_B64_CHUNK_[0-9]{2}$/.test(k));if(v.length<2||v.some(([,x])=>x.length>${ENVIRONMENT_BUFFER_CHUNK_BYTES}))process.exit(1)`,
    ],
    { encoding: 'utf8', env: { ...process.env, ...environment } }
  );
  assert.equal(
    spawned.status,
    0,
    `${spawned.error?.message ?? ''}${spawned.stderr}`
  );
  assert.deepEqual(
    consumeEnvironmentBuffer(environment, 'SCORED26_TEST_B64'),
    bytes
  );
  assert.deepEqual(environment, { UNRELATED: 'preserved' });

  const missing = {
    ...encodeEnvironmentBuffer('SCORED26_TEST_B64', bytes),
  };
  delete missing.SCORED26_TEST_B64_CHUNK_01;
  assert.throws(
    () => consumeEnvironmentBuffer(missing, 'SCORED26_TEST_B64'),
    /invalid environment chunk 1/
  );
  const legacy = {
    ...encodeEnvironmentBuffer('SCORED26_TEST_B64', bytes),
    SCORED26_TEST_B64: bytes.toString('base64'),
  };
  assert.throws(
    () => consumeEnvironmentBuffer(legacy, 'SCORED26_TEST_B64'),
    /unchunked environment buffer is forbidden/
  );
}

// Entry capture opens all four paths before any read or validation, then reads
// policy, D, and D-envelope exactly once. A later D-path replacement (L15)
// cannot alter the authenticated snapshot.
{
  const fixture = buildReleaseTestFixture();
  const io = new CountingIo({
    policy: fixture.buffers.trustPolicy,
    descriptor: fixture.buffers.descriptor,
    envelope: fixture.buffers.descriptorEnvelope,
    archive: Buffer.from('untrusted archive bytes'),
  });
  const entry = captureBootstrapEntry(
    {
      trustPolicy: 'policy',
      descriptor: 'descriptor',
      descriptorEnvelope: 'envelope',
      archive: 'archive',
    },
    io
  );
  assert.deepEqual(io.events.slice(0, 4), [
    'open-input:policy',
    'open-input:descriptor',
    'open-input:envelope',
    'open-archive:archive',
  ]);
  assert.deepEqual(io.readCounts, {
    policy: 1,
    descriptor: 1,
    envelope: 1,
    archive: 0,
  });
  const replacement = JSON.parse(fixture.buffers.descriptor.toString('utf8'));
  replacement.artifact_commit = 'b'.repeat(40);
  io.bytes.descriptor = writeArtifactJson(replacement);
  const authenticated = authenticateDescriptor({
    policyBytes: entry.buffers.trustPolicy,
    descriptorBytes: entry.buffers.descriptor,
    envelopeBytes: entry.buffers.descriptorEnvelope,
  });
  assert.equal(authenticated.descriptor.artifact_commit, 'a'.repeat(40));
  entry.closeArchive();
}

// A passing phase-1 gate derives both canonical artifacts from the same owner
// and exact-result buffers.
{
  const fixture = buildReleaseTestFixture();
  const gate = constructPhaseOneGate({
    descriptor: fixture.descriptor,
    descriptorBytes: fixture.buffers.descriptor,
    ownerBuffers: ownerBuffers(fixture),
    reproducedResultBuffers: new Map([
      [fixture.exactPath, Buffer.from(fixture.exactBytes)],
    ]),
    cleanRunRuntimeSeconds: 17,
  });
  assert.equal(gate.exitCode, 0);
  assert.equal(gate.q.status, 'pass');
  assert.equal(
    gate.q.exact_reproduction_comparisons_sha256,
    sha256Id(gate.comparisonBytes)
  );
  assert.equal(parseCleanRunReport(gate.qBytes).clean_run_runtime_seconds, 17);
}

// L18: a false exact comparison is the named phase-1 refusal and no Q can be
// produced or published.
{
  const fixture = buildReleaseTestFixture();
  const gate = constructPhaseOneGate({
    descriptor: fixture.descriptor,
    descriptorBytes: fixture.buffers.descriptor,
    ownerBuffers: ownerBuffers(fixture),
    reproducedResultBuffers: new Map([
      [fixture.exactPath, Buffer.from('mismatched regenerated bytes\n')],
    ]),
    cleanRunRuntimeSeconds: 18,
  });
  assert.equal(gate.exitCode, PHASE_1_COMPARISON_MISMATCH);
  assert.equal(gate.q, null);
  assert.equal(gate.qBytes, null);
  const comparisons = JSON.parse(gate.comparisonBytes.toString('utf8'));
  assert.equal(comparisons.comparisons[0].matched, false);
}

console.log(
  'SCORED26 clean-room outer driver passed (read-once entry, L15, L18, Q derivation)'
);

function ownerBuffers(fixture) {
  return Object.freeze({
    fixtureReport: fixture.buffers.fixtureReport,
    workloadReport: fixture.buffers.workloadReport,
    mutationReport: fixture.buffers.mutationReport,
    performanceReport: fixture.buffers.performanceReport,
  });
}
