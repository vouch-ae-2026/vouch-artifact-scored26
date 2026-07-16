import { generateKeyPairSync } from 'node:crypto';

import { writeArtifactJson } from './artifact-json.mjs';
import {
  NATIVE_PAYLOAD_TYPE,
  PERFORMANCE_METRICS,
  PERFORMANCE_STATISTICS,
  RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
  REPLAY_MANIFEST_PAYLOAD_TYPE,
  REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
  nativeKeyId,
  rawPublicKeyFromPrivate,
  sha256Id,
  signEnvelope,
} from './release-schema.mjs';

export function buildReleaseTestFixture() {
  const releaseKey = fixtureKey();
  const otherKey = fixtureKey();
  const artifactCommit = 'a'.repeat(40);
  const freezeCommit = '0'.repeat(40);
  const exactBytes = Buffer.from('deterministic-result\n', 'utf8');
  const exactPath = 'generated/workload-results.tex';
  const descriptor = {
    release_descriptor: 'csk.release-descriptor/v0',
    artifact_commit: artifactCommit,
    artifact_freeze_commit: freezeCommit,
    archive_sha256: digestByte('a'),
    engine_sha256: digestByte('b'),
    key_id: releaseKey.keyId,
    exact_reproduction_results: [
      { path: exactPath, sha256: sha256Id(exactBytes) },
    ],
    target_triple: 'x86_64-unknown-linux-gnu',
    toolchains: {
      rustc: 'rustc 1.85.1 (4eb161250 2025-03-15)',
      cargo: 'cargo 1.85.1 (d73d2caf9 2024-12-31)',
      node: 'v22.14.0',
      npm: '10.9.2',
      typescript: '5.8.2',
      glibc: '2.39',
      dependency_version_manifest_digests: [
        { path: 'artifact/vendor-manifest.json', sha256: digestByte('c') },
      ],
    },
    build_image_sha256: digestByte('d'),
    build_parameters: {
      linker: 'GNU ld 2.42',
      os_image_reference: 'ubuntu@sha256:' + 'e'.repeat(64),
      build_path_policy: '/opt/vouch-scored26/work',
      source_date_epoch: 1_700_000_000,
      locale: 'C.UTF-8',
      build_id_policy: 'none',
    },
    build_environment: { rustflags: '', cargo_encoded_rustflags: '' },
  };
  const descriptorBytes = writeArtifactJson(descriptor);
  const descriptorEnvelope = signEnvelope(
    RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
    descriptorBytes,
    releaseKey.privateDer
  ).envelopeBytes;
  const policy = trustPolicy([releaseKey, otherKey]);
  const policyBytes = writeArtifactJson(policy);

  const fixtureSummary = {
    built: { expected: 1, matched: 1, mismatched: 0, skipped: 0 },
    design_target: {
      listed: 0,
      implemented: 0,
      matched: 0,
      not_implemented: 0,
    },
  };
  const fixtureReport = {
    fixture_report: 'vouch.scored26-fixture/v0',
    fixture_results: fixtureSummary,
    results: [],
  };
  const workloadSummary = {
    candidates: 1536,
    selected_case_count: 240,
    decision_pair_count: 240,
    excluded_from_matrix_count: 0,
    development: 192,
    held_out: 48,
    decision_flips: 7,
    held_out_flips: 2,
    exception_count_by_kind: {
      profile_escape_executions: 0,
      not_comparable_executions: 0,
      pipeline_failure_executions: 0,
    },
    decision_distribution_baseline: distribution(60),
    decision_distribution_changed: distribution(60),
    transition_matrix: matrix(),
  };
  const workloadReport = {
    workload_report: 'vouch.scored26-workload/v0',
    workload_summary: workloadSummary,
    details: { fixture: 'A' },
  };
  const mutationSummary = {
    mutant_level: {
      seeded: 12,
      built: 12,
      activated_any: 5,
      detected_any: 4,
      detection_rate: '33.3',
    },
    case_level: {
      disagreement_cases: 638,
      common_mode_cases: 6,
      pipeline_failure_cases: 0,
      infrastructure_failure_cases: 0,
      survivor_cases: 0,
    },
  };
  const mutationReport = {
    mutation_report: 'vouch.scored26-mutation/v0',
    mutation_summary: mutationSummary,
    rows: [],
  };
  const measurements = [];
  for (const metric of Object.keys(PERFORMANCE_METRICS)) {
    for (const statistic of PERFORMANCE_STATISTICS) {
      measurements.push({
        metric,
        unit: PERFORMANCE_METRICS[metric],
        statistic,
        value: 10 + measurements.length,
        population: metric === 'envelope_bytes' ? 480 : 30,
        excluded_ids: [],
      });
    }
  }
  const performanceReport = {
    performance_report: 'vouch.scored26-performance/v0',
    measurements,
  };
  const comparisons = {
    exact_reproduction_comparisons:
      'vouch.scored26-reproduction-comparisons/v0',
    comparisons: [
      {
        path: exactPath,
        expected_sha256: sha256Id(exactBytes),
        observed_sha256: sha256Id(exactBytes),
        matched: true,
      },
    ],
  };

  const buffers = {
    descriptor: descriptorBytes,
    descriptorEnvelope,
    trustPolicy: policyBytes,
    fixtureReport: writeArtifactJson(fixtureReport),
    workloadReport: writeArtifactJson(workloadReport),
    mutationReport: writeArtifactJson(mutationReport),
    performanceReport: writeArtifactJson(performanceReport),
    comparisons: writeArtifactJson(comparisons),
  };
  const q = {
    reproduction_report: 'vouch.scored26-reproduction/v0',
    status: 'pass',
    fixture_results: fixtureSummary,
    workload: workloadSummary,
    mutation: mutationSummary,
    clean_run_runtime_seconds: 321,
    fixture_report_sha256: sha256Id(buffers.fixtureReport),
    workload_report_sha256: sha256Id(buffers.workloadReport),
    mutation_report_sha256: sha256Id(buffers.mutationReport),
    performance_report_sha256: sha256Id(buffers.performanceReport),
    exact_reproduction_comparisons_sha256: sha256Id(buffers.comparisons),
    release_descriptor_sha256: sha256Id(buffers.descriptor),
    release_private_key_present: false,
    public_data_scan: 'pass',
    worktree_clean: true,
  };
  buffers.cleanRunReport = writeArtifactJson(q);
  return {
    buffers,
    descriptor,
    q,
    releaseKey,
    otherKey,
    keyHandle: 'pkcs8-file:///fixture/release-key.pk8',
    exactBytes,
    exactPath,
    values: {
      fixtureReport,
      workloadReport,
      mutationReport,
      performanceReport,
      comparisons,
    },
  };
}

export function fixtureKey() {
  const { privateKey } = generateKeyPairSync('ed25519');
  const privateDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  const rawPublicKey = rawPublicKeyFromPrivate(privateDer).rawPublicKey;
  return {
    privateDer,
    rawPublicKey,
    keyId: nativeKeyId(rawPublicKey),
  };
}

function trustPolicy(keys) {
  return {
    trust_policy: 'csk.native-trust-policy/v0',
    minimum_versions: {
      native_receipt: 0,
      release_descriptor: 0,
      replay_corpus_manifest: 0,
      reproduction_observation: 0,
    },
    keys: keys.map((key) => ({
      key_id: key.keyId,
      algorithm: 'ed25519',
      public_key: key.rawPublicKey.toString('base64'),
      allowed_payload_types: [
        NATIVE_PAYLOAD_TYPE,
        RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
        REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
        REPLAY_MANIFEST_PAYLOAD_TYPE,
      ],
      allowed_profiles: ['csk.checked-profile/v1'],
      allowed_engine_sha256: [digestByte('b')],
    })),
  };
}

function distribution(value) {
  return { approve: value, deny: value, review: value, 'invalid-input': value };
}

function matrix() {
  return {
    approve: { approve: 58, deny: 1, review: 1, 'invalid-input': 0 },
    deny: { approve: 1, deny: 58, review: 1, 'invalid-input': 0 },
    review: { approve: 1, deny: 1, review: 58, 'invalid-input': 0 },
    'invalid-input': { approve: 0, deny: 0, review: 0, 'invalid-input': 60 },
  };
}

function digestByte(value) {
  return `sha256:${value.repeat(64)}`;
}
