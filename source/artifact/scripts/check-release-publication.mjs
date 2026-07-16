import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { writeArtifactJson } from './artifact-json.mjs';
import {
  MemoryFinalizerKeyProvider,
  finalizeObservation,
} from './release-finalizer-lib.mjs';
import { MemoryAtomicDirectoryPublisher } from './release-io.mjs';
import {
  publicationCheck,
  publishPublicationFailure,
} from './release-publication-lib.mjs';
import {
  RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
  REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
  sha256Id,
  signEnvelope,
} from './release-schema.mjs';
import { buildReleaseTestFixture } from './release-test-fixtures.mjs';

// A usage error discovered after one usable --out-dir publishes terminal S.
{
  const root = mkdtempSync(join(tmpdir(), 'scored26-publication-usage-'));
  const output = join(root, 'out');
  try {
    const result = spawnSync(
      process.execPath,
      [
        'artifact/scripts/publication-check.mjs',
        '--out-dir',
        output,
        '--unknown-after-output',
        'value',
      ],
      { encoding: 'utf8' }
    );
    assert.equal(result.status, 2);
    const report = JSON.parse(
      readFileSync(join(output, 'publication-report.json'), 'utf8')
    );
    assert.equal(report.status, 'fail');
    assert.equal(report.primary_error, 'usage-error');
    assert.equal(report.chain_verified, 'not-run');
    assert.equal(report.release_descriptor_sha256, null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

{
  const fixture = finalizedFixture();
  const { outcome, rendered } = runPublication(fixture);
  assert.equal(outcome.exitCode, 0);
  assert.equal(outcome.report.status, 'pass');
  assert.equal(outcome.report.chain_verified, 'pass');
  assert.equal(outcome.report.paper_claims_matched, true);
  assert.equal(outcome.report.claim_language_scan, 'pass');
  assert.equal(rendered.count, 1);
}

// L01: standalone R bytes and the decoded observation payload are one object.
{
  const fixture = finalizedFixture();
  const r = JSON.parse(fixture.buffers.observation.toString('utf8'));
  r.clean_run_runtime_seconds += 1;
  fixture.buffers.observation = writeArtifactJson(r);
  const { outcome, rendered } = runPublication(fixture);
  expectChainFailure(outcome, null);
  assert.equal(rendered.count, 0);
}

// L02: a policy-authorized key other than D.key_id cannot authenticate R.
{
  const fixture = finalizedFixture();
  fixture.buffers.observationEnvelope = signEnvelope(
    REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
    fixture.buffers.observation,
    fixture.otherKey.privateDer
  ).envelopeBytes;
  const { outcome } = runPublication(fixture);
  expectChainFailure(outcome, null);
}

// L03: P cannot combine D and R from different publication chains.
{
  const fixture = finalizedFixture();
  const p = JSON.parse(fixture.buffers.publicationRecord.toString('utf8'));
  p.reproduction_observation_sha256 = `sha256:${'f'.repeat(64)}`;
  fixture.buffers.publicationRecord = writeArtifactJson(p);
  const { outcome } = runPublication(fixture);
  expectChainFailure(outcome, null);
}

// L09: replacements outside the captured buffers do not reach the renderer.
{
  const fixture = finalizedFixture();
  const captured = Object.fromEntries(
    Object.entries(fixture.buffers).map(([name, bytes]) => [
      name,
      Buffer.from(bytes),
    ])
  );
  fixture.buffers.fixtureReport.fill(0x78);
  fixture.buffers = captured;
  const { outcome } = runPublication(fixture);
  assert.equal(outcome.exitCode, 0);
}

// L12: a missing Q publishes S, reports digests already captured, and does not run the chain.
{
  const fixture = finalizedFixture();
  delete fixture.buffers.cleanRunReport;
  const publisher = new MemoryAtomicDirectoryPublisher();
  const outcome = publishPublicationFailure({
    publisher,
    output: '/publication',
    buffers: fixture.buffers,
    exitCode: 3,
    primaryError: 'input-output-failure',
    inputArtifact: 'clean-run-report',
  });
  assert.equal(outcome.exitCode, 3);
  assert.equal(
    outcome.report.release_descriptor_sha256,
    sha256Id(fixture.buffers.descriptor)
  );
  assert.equal(outcome.report.clean_run_report_sha256, null);
  assert.equal(
    outcome.report.reproduction_observation_sha256,
    sha256Id(fixture.buffers.observation)
  );
  assert.equal(outcome.report.chain_verified, 'not-run');
}

// L17: even a correctly signed R cannot contradict Q's runtime.
{
  const fixture = finalizedFixture();
  const r = JSON.parse(fixture.buffers.observation.toString('utf8'));
  r.clean_run_runtime_seconds += 1;
  fixture.buffers.observation = writeArtifactJson(r);
  fixture.buffers.observationEnvelope = signEnvelope(
    REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
    fixture.buffers.observation,
    fixture.releaseKey.privateDer
  ).envelopeBytes;
  const p = JSON.parse(fixture.buffers.publicationRecord.toString('utf8'));
  p.reproduction_observation_sha256 = sha256Id(fixture.buffers.observation);
  fixture.buffers.publicationRecord = writeArtifactJson(p);
  const { outcome } = runPublication(fixture);
  expectChainFailure(outcome, 'p3-rd-runtime');
}

// Descriptor three-way identity mismatch is the first phase-3 check.
{
  const fixture = finalizedFixture();
  const d = JSON.parse(fixture.buffers.descriptor.toString('utf8'));
  d.key_id = fixture.otherKey.keyId;
  fixture.buffers.descriptor = writeArtifactJson(d);
  fixture.buffers.descriptorEnvelope = signEnvelope(
    RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
    fixture.buffers.descriptor,
    fixture.releaseKey.privateDer
  ).envelopeBytes;
  const { outcome } = runPublication(fixture);
  expectChainFailure(outcome, 'p3-descriptor-authentication');
}

// Paper provenance is checked after the cryptographic chain and before rendering.
{
  const fixture = finalizedFixture();
  fixture.paperSnapshot.worktreeClean = false;
  const { outcome, rendered } = runPublication(fixture);
  assert.equal(outcome.exitCode, 1);
  assert.equal(outcome.report.primary_error, 'paper-source-provenance-failed');
  assert.equal(outcome.report.failed_check, 'p3-paper-worktree-clean');
  assert.equal(outcome.report.chain_verified, 'pass');
  assert.equal(rendered.count, 0);
}

console.log(
  'SCORED26 publication chain passed (L01/L02/L03/L09/L12/L17 + provenance)'
);

function finalizedFixture() {
  const fixture = buildReleaseTestFixture();
  const provider = new MemoryFinalizerKeyProvider();
  provider.set(fixture.keyHandle, fixture.releaseKey.privateDer);
  const publisher = new MemoryAtomicDirectoryPublisher();
  const finalized = finalizeObservation({
    buffers: fixture.buffers,
    keyHandle: fixture.keyHandle,
    keyProvider: provider,
    publisher,
    output: '/finalized',
  });
  assert.equal(finalized.exitCode, 0);
  fixture.buffers = {
    ...fixture.buffers,
    observation: finalized.observationBytes,
    observationEnvelope: finalized.observationEnvelopeBytes,
    publicationRecord: finalized.publicationBytes,
  };
  fixture.paperSnapshot = {
    head: fixture.descriptor.artifact_commit,
    indexClean: true,
    worktreeClean: true,
    treeManifest: [],
    worktreeManifest: [],
    files: new Map(),
  };
  return fixture;
}

function runPublication(fixture) {
  const publisher = new MemoryAtomicDirectoryPublisher();
  const rendered = { count: 0 };
  const outcome = publicationCheck({
    buffers: fixture.buffers,
    paperSnapshot: fixture.paperSnapshot,
    renderer() {
      rendered.count += 1;
      return {
        claimsMatched: true,
        claimLanguageScan: 'pass',
        pdfBytes: Buffer.from('%PDF-fixture'),
      };
    },
    publisher,
    output: '/publication',
  });
  return { outcome, rendered, publisher };
}

function expectChainFailure(outcome, failedCheck) {
  assert.equal(outcome.exitCode, 1);
  assert.equal(outcome.report.status, 'fail');
  assert.equal(outcome.report.primary_error, 'chain-verification-failed');
  assert.equal(outcome.report.failed_check, failedCheck);
  assert.equal(outcome.report.chain_verified, 'fail');
  assert.equal(outcome.report.paper_claims_matched, null);
  assert.equal(outcome.report.claim_language_scan, 'not-run');
}
