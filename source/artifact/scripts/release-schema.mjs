import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import {
  ArtifactJsonError,
  canonicalArtifactJson,
  writeArtifactJson,
} from './artifact-json.mjs';

export const RELEASE_DESCRIPTOR_PAYLOAD_TYPE =
  'application/vnd.csk.release-descriptor.v0+json';
export const REPRODUCTION_OBSERVATION_PAYLOAD_TYPE =
  'application/vnd.csk.reproduction-observation.v0+json';
export const NATIVE_PAYLOAD_TYPE =
  'application/vnd.csk.differential-receipt.v0+json';
export const REPLAY_MANIFEST_PAYLOAD_TYPE =
  'application/vnd.csk.replay-corpus-manifest.v0+json';

export const OBSERVATIONAL_PATHS = Object.freeze([
  'artifact/mutation/mutation-results.json',
  'artifact/performance/performance-results.json',
  'artifact/results/fixture-results.json',
  'artifact/workload/workload-results.json',
]);

export const PERFORMANCE_METRICS = Object.freeze({
  envelope_bytes: 'byte',
  native_verification_latency: 'microsecond',
  peak_resident_memory: 'byte',
  selected_corpus_replay_latency: 'microsecond',
});
export const PERFORMANCE_STATISTICS = Object.freeze([
  'maximum',
  'median',
  'p95',
]);

const HEX64 = /^[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const KEY_ID_DOMAIN = Buffer.from('csk/native-key-id/v0\0', 'utf8');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ALLOWED_PAYLOAD_TYPES = new Set([
  NATIVE_PAYLOAD_TYPE,
  RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
  REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
  REPLAY_MANIFEST_PAYLOAD_TYPE,
]);

export class ReleaseSchemaError extends Error {
  constructor(code, detail = null) {
    super(detail === null ? code : `${code}: ${detail}`);
    this.name = 'ReleaseSchemaError';
    this.code = code;
    this.detail = detail;
  }
}

export function sha256Id(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function nativeKeyId(rawPublicKey) {
  if (!Buffer.isBuffer(rawPublicKey) || rawPublicKey.length !== 32) {
    throw new ReleaseSchemaError('schema-invalid', 'ed25519-public-key');
  }
  return sha256Id(Buffer.concat([KEY_ID_DOMAIN, rawPublicKey]));
}

export function publicKeyFromRaw(rawPublicKey) {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
    format: 'der',
    type: 'spki',
  });
}

export function rawPublicKeyFromPrivate(privateKeyBytes) {
  const privateKey = createPrivateKey({
    key: privateKeyBytes,
    format: 'der',
    type: 'pkcs8',
  });
  const spki = createPublicKey(privateKey).export({
    format: 'der',
    type: 'spki',
  });
  if (
    spki.length !== ED25519_SPKI_PREFIX.length + 32 ||
    !spki.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    throw new ReleaseSchemaError('schema-invalid', 'ed25519-private-key');
  }
  return { privateKey, rawPublicKey: spki.subarray(-32) };
}

export function dssePae(payloadType, payloadBytes) {
  const typeBytes = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${typeBytes.length} `, 'ascii'),
    typeBytes,
    Buffer.from(` ${payloadBytes.length} `, 'ascii'),
    payloadBytes,
  ]);
}

export function signEnvelope(payloadType, payloadBytes, privateKeyBytes) {
  const { privateKey, rawPublicKey } = rawPublicKeyFromPrivate(privateKeyBytes);
  const keyId = nativeKeyId(rawPublicKey);
  const signature = ed25519Sign(
    null,
    dssePae(payloadType, payloadBytes),
    privateKey
  );
  const value = {
    payload: payloadBytes.toString('base64'),
    payloadType,
    signatures: [{ keyid: keyId, sig: signature.toString('base64') }],
  };
  return Object.freeze({
    envelopeBytes: writeArtifactJson(value),
    keyId,
    rawPublicKey: Buffer.from(rawPublicKey),
  });
}

export function parseCanonical(bytes, label) {
  try {
    return canonicalArtifactJson(bytes);
  } catch (error) {
    if (error instanceof ArtifactJsonError) throw error;
    throw new ReleaseSchemaError('schema-invalid', label);
  }
}

export function parseTrustPolicy(bytes) {
  const value = parseCanonical(bytes, 'trust-policy');
  const root = exactObject(
    value,
    ['keys', 'minimum_versions', 'trust_policy'],
    'trust-policy'
  );
  literal(root.trust_policy, 'csk.native-trust-policy/v0', 'trust-policy-tag');
  const minimum = exactObject(
    root.minimum_versions,
    [
      'native_receipt',
      'release_descriptor',
      'replay_corpus_manifest',
      'reproduction_observation',
    ],
    'trust-policy-minimum-versions'
  );
  for (const name of Object.keys(minimum))
    uint(minimum[name], `minimum-${name}`);
  array(root.keys, 'trust-policy-keys', { nonempty: true });
  const keyIds = new Set();
  const publicKeys = new Set();
  const keys = root.keys.map((entry, index) => {
    const key = exactObject(
      entry,
      [
        'algorithm',
        'allowed_engine_sha256',
        'allowed_payload_types',
        'allowed_profiles',
        'key_id',
        'public_key',
      ],
      `trust-key-${index}`
    );
    literal(key.algorithm, 'ed25519', `trust-key-${index}-algorithm`);
    digest(key.key_id, `trust-key-${index}-id`);
    const raw = canonicalBase64(
      key.public_key,
      `trust-key-${index}-public-key`
    );
    if (raw.length !== 32 || nativeKeyId(raw) !== key.key_id) {
      throw schema(`trust-key-${index}-identity`);
    }
    if (keyIds.has(key.key_id) || publicKeys.has(raw.toString('hex'))) {
      throw schema(`trust-key-${index}-duplicate`);
    }
    keyIds.add(key.key_id);
    publicKeys.add(raw.toString('hex'));
    uniqueStrings(
      key.allowed_payload_types,
      `trust-key-${index}-payload-types`,
      (item) => ALLOWED_PAYLOAD_TYPES.has(item)
    );
    uniqueStrings(
      key.allowed_profiles,
      `trust-key-${index}-profiles`,
      profileIdentifier
    );
    uniqueStrings(
      key.allowed_engine_sha256,
      `trust-key-${index}-engines`,
      (item) => DIGEST.test(item)
    );
    return Object.freeze({ ...key, rawPublicKey: raw });
  });
  return Object.freeze({ value, minimum, keys });
}

export function parseEnvelope(bytes, expectedPayloadType, label = 'envelope') {
  const value = parseCanonical(bytes, label);
  const envelope = exactObject(
    value,
    ['payload', 'payloadType', 'signatures'],
    label
  );
  literal(envelope.payloadType, expectedPayloadType, `${label}-payload-type`);
  const payload = canonicalBase64(envelope.payload, `${label}-payload`);
  array(envelope.signatures, `${label}-signatures`);
  if (envelope.signatures.length !== 1) throw schema(`${label}-signatures`);
  const signature = exactObject(
    envelope.signatures[0],
    ['keyid', 'sig'],
    `${label}-signature`
  );
  digest(signature.keyid, `${label}-keyid`);
  const signatureBytes = canonicalBase64(signature.sig, `${label}-signature`);
  if (signatureBytes.length !== 64) throw schema(`${label}-signature-length`);
  return Object.freeze({
    value,
    payload,
    payloadType: envelope.payloadType,
    keyId: signature.keyid,
    signature: signatureBytes,
  });
}

export function authenticateDescriptor({
  policyBytes,
  descriptorBytes,
  envelopeBytes,
}) {
  const policy = parseTrustPolicy(policyBytes);
  const envelope = parseEnvelope(
    envelopeBytes,
    RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
    'descriptor-envelope'
  );
  const selected = policy.keys.find((key) => key.key_id === envelope.keyId);
  if (!selected)
    throw new ReleaseSchemaError('descriptor-authentication-failed');
  if (
    !selected.allowed_payload_types.includes(RELEASE_DESCRIPTOR_PAYLOAD_TYPE)
  ) {
    throw new ReleaseSchemaError('descriptor-authentication-failed');
  }
  if (
    !ed25519Verify(
      null,
      dssePae(envelope.payloadType, envelope.payload),
      publicKeyFromRaw(selected.rawPublicKey),
      envelope.signature
    )
  ) {
    throw new ReleaseSchemaError('descriptor-authentication-failed');
  }
  const descriptor = parseReleaseDescriptor(envelope.payload);
  if (!envelope.payload.equals(descriptorBytes)) {
    throw new ReleaseSchemaError('descriptor-authentication-failed');
  }
  if (
    descriptor.key_id !== envelope.keyId ||
    descriptor.key_id !== selected.key_id
  ) {
    throw new ReleaseSchemaError('descriptor-authentication-failed');
  }
  if (policy.minimum.release_descriptor > 0) {
    throw new ReleaseSchemaError('descriptor-authentication-failed');
  }
  return Object.freeze({ descriptor, envelope, policy, selectedKey: selected });
}

export function authenticateObservation({
  policy,
  descriptor,
  observationBytes,
  envelopeBytes,
}) {
  const envelope = parseEnvelope(
    envelopeBytes,
    REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
    'observation-envelope'
  );
  const selected = policy.keys.find((key) => key.key_id === envelope.keyId);
  if (
    !selected ||
    envelope.keyId !== descriptor.key_id ||
    !selected.allowed_payload_types.includes(
      REPRODUCTION_OBSERVATION_PAYLOAD_TYPE
    )
  ) {
    throw new ReleaseSchemaError('observation-wrong-release-key');
  }
  if (
    !ed25519Verify(
      null,
      dssePae(envelope.payloadType, envelope.payload),
      publicKeyFromRaw(selected.rawPublicKey),
      envelope.signature
    )
  ) {
    throw new ReleaseSchemaError('observation-signature-invalid');
  }
  const observation = parseReproductionObservation(envelope.payload);
  if (!envelope.payload.equals(observationBytes)) {
    throw new ReleaseSchemaError('observation-json-payload-mismatch');
  }
  if (policy.minimum.reproduction_observation > 0) {
    throw new ReleaseSchemaError('observation-version-below-policy');
  }
  return observation;
}

export function parseReleaseDescriptor(bytes) {
  const root = exactObject(
    parseCanonical(bytes, 'descriptor'),
    [
      'archive_sha256',
      'artifact_commit',
      'artifact_freeze_commit',
      'build_environment',
      'build_image_sha256',
      'build_parameters',
      'engine_sha256',
      'exact_reproduction_results',
      'key_id',
      'release_descriptor',
      'target_triple',
      'toolchains',
    ],
    'descriptor'
  );
  literal(
    root.release_descriptor,
    'csk.release-descriptor/v0',
    'descriptor-tag'
  );
  commit(root.artifact_commit, 'artifact-commit');
  commit(root.artifact_freeze_commit, 'artifact-freeze-commit');
  for (const name of [
    'archive_sha256',
    'engine_sha256',
    'key_id',
    'build_image_sha256',
  ])
    digest(root[name], name);
  string(root.target_triple, 'target-triple');
  sortedPathDigests(
    root.exact_reproduction_results,
    'exact-reproduction-results'
  );
  const toolchains = exactObject(
    root.toolchains,
    [
      'cargo',
      'dependency_version_manifest_digests',
      'glibc',
      'node',
      'npm',
      'rustc',
      'typescript',
    ],
    'toolchains'
  );
  for (const name of ['cargo', 'glibc', 'node', 'npm', 'rustc', 'typescript']) {
    string(toolchains[name], `toolchains-${name}`);
  }
  sortedPathDigests(
    toolchains.dependency_version_manifest_digests,
    'dependency-version-manifest-digests'
  );
  const parameters = exactObject(
    root.build_parameters,
    [
      'build_id_policy',
      'build_path_policy',
      'linker',
      'locale',
      'os_image_reference',
      'source_date_epoch',
    ],
    'build-parameters'
  );
  for (const name of [
    'build_id_policy',
    'build_path_policy',
    'linker',
    'locale',
    'os_image_reference',
  ])
    string(parameters[name], `build-parameters-${name}`);
  uint(parameters.source_date_epoch, 'source-date-epoch');
  const environment = exactObject(
    root.build_environment,
    ['cargo_encoded_rustflags', 'rustflags'],
    'build-environment'
  );
  literal(environment.rustflags, '', 'rustflags');
  literal(environment.cargo_encoded_rustflags, '', 'cargo-encoded-rustflags');
  return root;
}

export function parseCleanRunReport(bytes) {
  const root = exactObject(
    parseCanonical(bytes, 'clean-run-report'),
    [
      'clean_run_runtime_seconds',
      'exact_reproduction_comparisons_sha256',
      'fixture_report_sha256',
      'fixture_results',
      'mutation',
      'mutation_report_sha256',
      'performance_report_sha256',
      'public_data_scan',
      'release_descriptor_sha256',
      'release_private_key_present',
      'reproduction_report',
      'status',
      'workload',
      'workload_report_sha256',
      'worktree_clean',
    ],
    'clean-run-report'
  );
  literal(root.reproduction_report, 'vouch.scored26-reproduction/v0', 'q-tag');
  literal(root.status, 'pass', 'q-status');
  validateFixtureSummary(root.fixture_results);
  validateWorkloadSummary(root.workload);
  validateMutationSummary(root.mutation);
  uint(root.clean_run_runtime_seconds, 'clean-run-runtime-seconds');
  for (const name of [
    'fixture_report_sha256',
    'workload_report_sha256',
    'mutation_report_sha256',
    'performance_report_sha256',
    'exact_reproduction_comparisons_sha256',
    'release_descriptor_sha256',
  ])
    digest(root[name], name);
  literal(
    root.release_private_key_present,
    false,
    'release-private-key-present'
  );
  literal(root.public_data_scan, 'pass', 'public-data-scan');
  literal(root.worktree_clean, true, 'worktree-clean');
  return root;
}

export function parseFixtureReport(bytes) {
  const root = object(
    parseCanonical(bytes, 'fixture-report'),
    'fixture-report'
  );
  literal(
    root.fixture_report,
    'vouch.scored26-fixture/v0',
    'fixture-report-tag'
  );
  validateFixtureSummary(root.fixture_results);
  return root;
}

export function parseWorkloadReport(bytes) {
  const root = object(
    parseCanonical(bytes, 'workload-report'),
    'workload-report'
  );
  literal(
    root.workload_report,
    'vouch.scored26-workload/v0',
    'workload-report-tag'
  );
  validateWorkloadSummary(root.workload_summary);
  return root;
}

export function parseMutationReport(bytes) {
  const root = object(
    parseCanonical(bytes, 'mutation-report'),
    'mutation-report'
  );
  literal(
    root.mutation_report,
    'vouch.scored26-mutation/v0',
    'mutation-report-tag'
  );
  validateMutationSummary(root.mutation_summary);
  return root;
}

export function parsePerformanceReport(bytes) {
  const root = object(
    parseCanonical(bytes, 'performance-report'),
    'performance-report'
  );
  literal(
    root.performance_report,
    'vouch.scored26-performance/v0',
    'performance-report-tag'
  );
  array(root.measurements, 'performance-measurements');
  if (root.measurements.length !== 12)
    throw schema('performance-measurements-count');
  const seen = new Set();
  let previous = null;
  for (const [index, rowValue] of root.measurements.entries()) {
    const row = exactObject(
      rowValue,
      ['excluded_ids', 'metric', 'population', 'statistic', 'unit', 'value'],
      `performance-row-${index}`
    );
    if (!Object.hasOwn(PERFORMANCE_METRICS, row.metric))
      throw schema('performance-metric');
    if (!PERFORMANCE_STATISTICS.includes(row.statistic))
      throw schema('performance-statistic');
    literal(row.unit, PERFORMANCE_METRICS[row.metric], 'performance-unit');
    uint(row.value, 'performance-value');
    uint(row.population, 'performance-population');
    array(row.excluded_ids, 'performance-excluded-ids');
    let excludedPrevious = null;
    const excludedSeen = new Set();
    for (const itemValue of row.excluded_ids) {
      const item = exactObject(
        itemValue,
        ['case', 'side'],
        'performance-excluded-id'
      );
      string(item.case, 'performance-excluded-case');
      if (!['baseline', 'changed'].includes(item.side))
        throw schema('performance-excluded-side');
      const key = `${item.case}\0${item.side}`;
      if (
        excludedSeen.has(key) ||
        (excludedPrevious !== null && utf8Compare(excludedPrevious, key) >= 0)
      ) {
        throw schema('performance-excluded-order');
      }
      excludedSeen.add(key);
      excludedPrevious = key;
    }
    const key = `${row.metric}\0${row.statistic}`;
    if (
      seen.has(key) ||
      (previous !== null && utf8Compare(previous, key) >= 0)
    ) {
      throw schema('performance-order');
    }
    seen.add(key);
    previous = key;
  }
  for (const metric of Object.keys(PERFORMANCE_METRICS)) {
    for (const statistic of PERFORMANCE_STATISTICS) {
      if (!seen.has(`${metric}\0${statistic}`))
        throw schema('performance-closed-set');
    }
  }
  return root;
}

export function parseComparisons(bytes) {
  const root = exactObject(
    parseCanonical(bytes, 'reproduction-comparisons'),
    ['comparisons', 'exact_reproduction_comparisons'],
    'reproduction-comparisons'
  );
  literal(
    root.exact_reproduction_comparisons,
    'vouch.scored26-reproduction-comparisons/v0',
    'reproduction-comparisons-tag'
  );
  array(root.comparisons, 'reproduction-comparisons');
  let previous = null;
  const seen = new Set();
  for (const [index, rowValue] of root.comparisons.entries()) {
    const row = exactObject(
      rowValue,
      ['expected_sha256', 'matched', 'observed_sha256', 'path'],
      `comparison-${index}`
    );
    normalizedPath(row.path, `comparison-${index}-path`);
    digest(row.expected_sha256, `comparison-${index}-expected`);
    digest(row.observed_sha256, `comparison-${index}-observed`);
    boolean(row.matched, `comparison-${index}-matched`);
    if (
      seen.has(row.path) ||
      (previous !== null && utf8Compare(previous, row.path) >= 0)
    ) {
      throw schema('comparison-order');
    }
    seen.add(row.path);
    previous = row.path;
  }
  return root;
}

export function parseReproductionObservation(bytes) {
  const root = exactObject(
    parseCanonical(bytes, 'observation'),
    [
      'clean_run_report_sha256',
      'clean_run_runtime_seconds',
      'fixture_results',
      'mutation_summary_sha256',
      'performance_observations',
      'release_descriptor_sha256',
      'reproduced_result_comparisons',
      'reproduction_observation',
      'verify_only_observational_results',
      'workload_summary_sha256',
    ],
    'observation'
  );
  literal(
    root.reproduction_observation,
    'csk.reproduction-observation/v0',
    'observation-tag'
  );
  for (const name of [
    'release_descriptor_sha256',
    'clean_run_report_sha256',
    'workload_summary_sha256',
    'mutation_summary_sha256',
  ])
    digest(root[name], name);
  uint(root.clean_run_runtime_seconds, 'observation-runtime');
  validateFixtureSummary(root.fixture_results);
  validatePerformanceObservations(root.performance_observations);
  sortedPathMatches(root.reproduced_result_comparisons, 'reproduced-results');
  sortedPathDigests(
    root.verify_only_observational_results,
    'observational-results'
  );
  if (
    !sameArray(
      root.verify_only_observational_results.map((row) => row.path),
      OBSERVATIONAL_PATHS
    )
  ) {
    throw schema('observational-results-closed-set');
  }
  return root;
}

export function parsePublicationRecord(bytes) {
  const root = exactObject(
    parseCanonical(bytes, 'publication-record'),
    [
      'publication_record',
      'release_descriptor_sha256',
      'reproduction_observation_sha256',
    ],
    'publication-record'
  );
  literal(
    root.publication_record,
    'csk.release-publication/v0',
    'publication-record-tag'
  );
  digest(root.release_descriptor_sha256, 'publication-descriptor-digest');
  digest(
    root.reproduction_observation_sha256,
    'publication-observation-digest'
  );
  return root;
}

export function deriveFixtureSummary(report) {
  return report.fixture_results;
}

export function deriveWorkloadSummary(report) {
  return report.workload_summary;
}

export function deriveMutationSummary(report) {
  return report.mutation_summary;
}

export function derivePerformanceObservations(report) {
  return report.measurements.map(({ metric, statistic, unit, value }) => ({
    metric,
    statistic,
    unit,
    value,
  }));
}

export function deriveComparisonMatches(report) {
  return report.comparisons.map(({ path, matched }) => ({ path, matched }));
}

export function canonicalEqual(left, right) {
  return writeArtifactJson(left).equals(writeArtifactJson(right));
}

export function plainDeepEqual(left, right) {
  return isDeepStrictEqual(
    JSON.parse(JSON.stringify(left)),
    JSON.parse(JSON.stringify(right))
  );
}

export function validateFixtureSummary(value) {
  const summary = exactObject(
    value,
    ['built', 'design_target'],
    'fixture-summary'
  );
  const built = exactObject(
    summary.built,
    ['expected', 'matched', 'mismatched', 'skipped'],
    'fixture-summary-built'
  );
  const design = exactObject(
    summary.design_target,
    ['implemented', 'listed', 'matched', 'not_implemented'],
    'fixture-summary-design-target'
  );
  for (const value of [...Object.values(built), ...Object.values(design)])
    uint(value, 'fixture-count');
  return summary;
}

export function validateWorkloadSummary(value) {
  const summary = exactObject(
    value,
    [
      'candidates',
      'decision_distribution_baseline',
      'decision_distribution_changed',
      'decision_flips',
      'decision_pair_count',
      'development',
      'exception_count_by_kind',
      'excluded_from_matrix_count',
      'held_out',
      'held_out_flips',
      'selected_case_count',
      'transition_matrix',
    ],
    'workload-summary'
  );
  for (const name of [
    'candidates',
    'decision_flips',
    'decision_pair_count',
    'development',
    'excluded_from_matrix_count',
    'held_out',
    'held_out_flips',
    'selected_case_count',
  ])
    uint(summary[name], `workload-${name}`);
  const labels = ['approve', 'deny', 'invalid-input', 'review'];
  for (const name of [
    'decision_distribution_baseline',
    'decision_distribution_changed',
  ]) {
    const counts = exactObject(summary[name], labels, name);
    for (const value of Object.values(counts)) uint(value, name);
  }
  const exceptions = exactObject(
    summary.exception_count_by_kind,
    [
      'not_comparable_executions',
      'pipeline_failure_executions',
      'profile_escape_executions',
    ],
    'workload-exceptions'
  );
  for (const value of Object.values(exceptions))
    uint(value, 'workload-exception-count');
  const matrix = exactObject(
    summary.transition_matrix,
    labels,
    'transition-matrix'
  );
  for (const row of Object.values(matrix)) {
    const counts = exactObject(row, labels, 'transition-matrix-row');
    for (const value of Object.values(counts)) uint(value, 'transition-count');
  }
  return summary;
}

export function validateMutationSummary(value) {
  const summary = exactObject(
    value,
    ['case_level', 'mutant_level'],
    'mutation-summary'
  );
  const mutant = exactObject(
    summary.mutant_level,
    ['activated_any', 'built', 'detected_any', 'detection_rate', 'seeded'],
    'mutation-mutant-level'
  );
  for (const name of ['activated_any', 'built', 'detected_any', 'seeded'])
    uint(mutant[name], name);
  if (!/^(?:100|[0-9]{1,2})\.[0-9]$/.test(mutant.detection_rate))
    throw schema('detection-rate');
  const cases = exactObject(
    summary.case_level,
    [
      'common_mode_cases',
      'disagreement_cases',
      'infrastructure_failure_cases',
      'pipeline_failure_cases',
      'survivor_cases',
    ],
    'mutation-case-level'
  );
  for (const value of Object.values(cases)) uint(value, 'mutation-case-count');
  return summary;
}

export function validatePerformanceObservations(value) {
  array(value, 'performance-observations');
  if (value.length !== 12) throw schema('performance-observations-count');
  let previous = null;
  const seen = new Set();
  for (const itemValue of value) {
    const item = exactObject(
      itemValue,
      ['metric', 'statistic', 'unit', 'value'],
      'performance-observation'
    );
    if (!Object.hasOwn(PERFORMANCE_METRICS, item.metric))
      throw schema('performance-observation-metric');
    if (!PERFORMANCE_STATISTICS.includes(item.statistic))
      throw schema('performance-observation-statistic');
    literal(
      item.unit,
      PERFORMANCE_METRICS[item.metric],
      'performance-observation-unit'
    );
    uint(item.value, 'performance-observation-value');
    const key = `${item.metric}\0${item.statistic}`;
    if (seen.has(key) || (previous !== null && utf8Compare(previous, key) >= 0))
      throw schema('performance-observation-order');
    seen.add(key);
    previous = key;
  }
  return value;
}

export function exactObject(value, names, label) {
  const result = object(value, label);
  const actual = Object.keys(result).sort(utf8Compare);
  const expected = [...names].sort(utf8Compare);
  if (!sameArray(actual, expected)) throw schema(label);
  return result;
}

export function object(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw schema(label);
  }
  return value;
}

export function array(value, label, { nonempty = false } = {}) {
  if (!Array.isArray(value) || (nonempty && value.length === 0))
    throw schema(label);
  return value;
}

export function string(value, label) {
  if (typeof value !== 'string') throw schema(label);
  return value;
}

export function boolean(value, label) {
  if (typeof value !== 'boolean') throw schema(label);
  return value;
}

export function uint(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw schema(label);
  return value;
}

export function literal(value, expected, label) {
  if (value !== expected) throw schema(label);
  return value;
}

export function digest(value, label) {
  if (typeof value !== 'string' || !DIGEST.test(value)) throw schema(label);
  return value;
}

export function commit(value, label) {
  if (typeof value !== 'string' || !COMMIT.test(value)) throw schema(label);
  return value;
}

export function normalizedPath(value, label) {
  string(value, label);
  if (
    value.length === 0 ||
    value.includes('\\') ||
    value.includes('\0') ||
    value.startsWith('/') ||
    value
      .split('/')
      .some((part) => part === '' || part === '.' || part === '..')
  )
    throw schema(label);
  return value;
}

export function canonicalBase64(value, label) {
  string(value, label);
  if (
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value
    )
  ) {
    throw schema(label);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) throw schema(label);
  return bytes;
}

function sortedPathDigests(value, label) {
  array(value, label, { nonempty: true });
  let previous = null;
  const seen = new Set();
  for (const [index, entryValue] of value.entries()) {
    const entry = exactObject(
      entryValue,
      ['path', 'sha256'],
      `${label}-${index}`
    );
    normalizedPath(entry.path, `${label}-${index}-path`);
    digest(entry.sha256, `${label}-${index}-digest`);
    if (
      seen.has(entry.path) ||
      (previous !== null && utf8Compare(previous, entry.path) >= 0)
    )
      throw schema(`${label}-order`);
    seen.add(entry.path);
    previous = entry.path;
  }
  return value;
}

function sortedPathMatches(value, label) {
  array(value, label);
  let previous = null;
  const seen = new Set();
  for (const [index, entryValue] of value.entries()) {
    const entry = exactObject(
      entryValue,
      ['matched', 'path'],
      `${label}-${index}`
    );
    normalizedPath(entry.path, `${label}-${index}-path`);
    boolean(entry.matched, `${label}-${index}-matched`);
    if (
      seen.has(entry.path) ||
      (previous !== null && utf8Compare(previous, entry.path) >= 0)
    )
      throw schema(`${label}-order`);
    seen.add(entry.path);
    previous = entry.path;
  }
  return value;
}

function uniqueStrings(value, label, predicate) {
  array(value, label, { nonempty: true });
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== 'string' || !predicate(item) || seen.has(item))
      throw schema(label);
    seen.add(item);
  }
  return value;
}

function profileIdentifier(value) {
  return (
    typeof value === 'string' &&
    /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*\/v(?:0|[1-9][0-9]*)$/.test(value)
  );
}

function utf8Compare(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function sameArray(left, right) {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function schema(detail) {
  return new ReleaseSchemaError('schema-invalid', detail);
}

export function isDigest(value) {
  return typeof value === 'string' && DIGEST.test(value);
}

export function isHex64(value) {
  return typeof value === 'string' && HEX64.test(value);
}
