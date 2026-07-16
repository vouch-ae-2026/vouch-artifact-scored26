import { readFileSync } from 'node:fs';

import { ArtifactJsonError, writeArtifactJson } from './artifact-json.mjs';
import { ReleaseIoError } from './release-io.mjs';
import {
  OBSERVATIONAL_PATHS,
  REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
  ReleaseSchemaError,
  authenticateDescriptor,
  authenticateObservation,
  canonicalEqual,
  deriveComparisonMatches,
  deriveFixtureSummary,
  deriveMutationSummary,
  derivePerformanceObservations,
  deriveWorkloadSummary,
  nativeKeyId,
  parseCleanRunReport,
  parseComparisons,
  parseFixtureReport,
  parseMutationReport,
  parsePerformanceReport,
  parseWorkloadReport,
  rawPublicKeyFromPrivate,
  sha256Id,
  signEnvelope,
} from './release-schema.mjs';

const INPUT_ORDER = Object.freeze([
  ['cleanRunReport', 'clean-run-report', parseCleanRunReport],
  ['fixtureReport', 'fixture-report', parseFixtureReport],
  ['workloadReport', 'workload-report', parseWorkloadReport],
  ['mutationReport', 'mutation-report', parseMutationReport],
  ['performanceReport', 'performance-report', parsePerformanceReport],
  ['comparisons', 'reproduction-comparisons', parseComparisons],
]);

export const FINALIZER_CHECKS = Object.freeze([
  'rb-q-descriptor',
  'qd-fixture-bytes',
  'qd-fixture',
  'qd-workload-bytes',
  'qd-workload',
  'qd-mutation-bytes',
  'qd-mutation',
  'qd-performance',
  'qd-comparisons',
  'qd-comparison-expected',
  'qd-comparison-matched',
  'rb-r-descriptor',
  'rb-r-cleanrun',
  'rd-runtime',
  'rd-fixture',
  'rd-performance',
  'rd-workload-digest',
  'rd-mutation-digest',
  'rd-comparisons',
  'rd-comparison-paths',
  'rd-comparisons-matched',
  'rd-observational-set',
]);

export class Pkcs8FileKeyProvider {
  #counts = {
    metadata: 0,
    resolution: 0,
    open: 0,
    query: 0,
    authentication: 0,
    load: 0,
    signing: 0,
  };

  resolve(handle) {
    this.#counts.resolution += 1;
    const path = keyHandlePath(handle);
    let bytes;
    try {
      this.#counts.open += 1;
      bytes = readFileSync(path);
    } catch {
      throw new ReleaseSchemaError('key-loading-or-signing-failure');
    }
    try {
      const parsed = rawPublicKeyFromPrivate(bytes);
      this.#counts.load += 1;
      return Object.freeze({
        privateKeyBytes: Buffer.from(bytes),
        keyId: nativeKeyId(parsed.rawPublicKey),
      });
    } catch {
      throw new ReleaseSchemaError('key-loading-or-signing-failure');
    }
  }

  sign(loaded, payloadBytes) {
    this.#counts.signing += 1;
    return signEnvelope(
      REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
      payloadBytes,
      loaded.privateKeyBytes
    );
  }

  counts() {
    return Object.freeze({ ...this.#counts });
  }

  totalAccesses() {
    return Object.values(this.#counts).reduce((sum, value) => sum + value, 0);
  }
}

export class MemoryFinalizerKeyProvider {
  #keys = new Map();
  #counts = {
    metadata: 0,
    resolution: 0,
    open: 0,
    query: 0,
    authentication: 0,
    load: 0,
    signing: 0,
  };

  set(handle, bytes) {
    this.#keys.set(handle, Buffer.from(bytes));
  }

  resolve(handle) {
    this.#counts.resolution += 1;
    const bytes = this.#keys.get(handle);
    if (bytes === undefined)
      throw new ReleaseSchemaError('key-loading-or-signing-failure');
    this.#counts.open += 1;
    const parsed = rawPublicKeyFromPrivate(bytes);
    this.#counts.load += 1;
    return Object.freeze({
      privateKeyBytes: Buffer.from(bytes),
      keyId: nativeKeyId(parsed.rawPublicKey),
    });
  }

  sign(loaded, payloadBytes) {
    this.#counts.signing += 1;
    return signEnvelope(
      REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
      payloadBytes,
      loaded.privateKeyBytes
    );
  }

  counts() {
    return Object.freeze({ ...this.#counts });
  }

  totalAccesses() {
    return Object.values(this.#counts).reduce((sum, value) => sum + value, 0);
  }
}

export function keyHandleSyntaxValid(handle) {
  if (
    typeof handle !== 'string' ||
    handle.includes('\0') ||
    handle.includes('%')
  )
    return false;
  try {
    const url = new URL(handle);
    return (
      url.protocol === 'pkcs8-file:' &&
      url.hostname === '' &&
      url.username === '' &&
      url.password === '' &&
      url.search === '' &&
      url.hash === '' &&
      url.pathname.startsWith('/') &&
      url.pathname.length > 1
    );
  } catch {
    return false;
  }
}

export function keyHandlePath(handle) {
  if (!keyHandleSyntaxValid(handle)) {
    throw new ReleaseSchemaError('usage-error', 'key-handle');
  }
  return new URL(handle).pathname;
}

/**
 * Phase-2 core. Every input is already a private entry buffer; this function
 * has no path API and therefore cannot reopen or swap an input.
 */
export function finalizeObservation({
  buffers,
  keyHandle,
  keyProvider,
  publisher,
  output,
}) {
  if (!keyHandleSyntaxValid(keyHandle)) {
    return publishFinalizerRefusal({
      publisher,
      output,
      exitCode: 2,
      primaryError: 'usage-error',
    });
  }

  let authenticated;
  try {
    authenticated = authenticateDescriptor({
      policyBytes: buffers.trustPolicy,
      descriptorBytes: buffers.descriptor,
      envelopeBytes: buffers.descriptorEnvelope,
    });
  } catch {
    return publishFinalizerRefusal({
      publisher,
      output,
      exitCode: 1,
      primaryError: 'descriptor-authentication-failed',
    });
  }

  const parsed = {};
  for (const [member, inputArtifact, parser] of INPUT_ORDER) {
    try {
      parsed[member] = parser(buffers[member]);
    } catch (error) {
      return publishFinalizerRefusal({
        publisher,
        output,
        exitCode: 1,
        primaryError: 'finalizer-input-invalid',
        inputArtifact,
        underlyingError: inputError(error),
      });
    }
  }

  const descriptor = authenticated.descriptor;
  const q = parsed.cleanRunReport;
  const descriptorDigest = sha256Id(buffers.descriptor);
  const cleanRunDigest = sha256Id(buffers.cleanRunReport);
  const reportDigests = Object.freeze({
    fixture: sha256Id(buffers.fixtureReport),
    workload: sha256Id(buffers.workloadReport),
    mutation: sha256Id(buffers.mutationReport),
    performance: sha256Id(buffers.performanceReport),
    comparisons: sha256Id(buffers.comparisons),
  });

  const dResults = new Map(
    descriptor.exact_reproduction_results.map((row) => [row.path, row.sha256])
  );
  const qChecks = [
    ['rb-q-descriptor', q.release_descriptor_sha256 === descriptorDigest],
    ['qd-fixture-bytes', q.fixture_report_sha256 === reportDigests.fixture],
    [
      'qd-fixture',
      canonicalEqual(
        q.fixture_results,
        deriveFixtureSummary(parsed.fixtureReport)
      ),
    ],
    ['qd-workload-bytes', q.workload_report_sha256 === reportDigests.workload],
    [
      'qd-workload',
      canonicalEqual(q.workload, deriveWorkloadSummary(parsed.workloadReport)),
    ],
    ['qd-mutation-bytes', q.mutation_report_sha256 === reportDigests.mutation],
    [
      'qd-mutation',
      canonicalEqual(q.mutation, deriveMutationSummary(parsed.mutationReport)),
    ],
    [
      'qd-performance',
      q.performance_report_sha256 === reportDigests.performance,
    ],
    [
      'qd-comparisons',
      q.exact_reproduction_comparisons_sha256 === reportDigests.comparisons,
    ],
    [
      'qd-comparison-expected',
      parsed.comparisons.comparisons.every(
        (row) => dResults.get(row.path) === row.expected_sha256
      ),
    ],
    [
      'qd-comparison-matched',
      parsed.comparisons.comparisons.every(
        (row) => row.matched === (row.expected_sha256 === row.observed_sha256)
      ),
    ],
  ];
  for (const [failedCheck, passed] of qChecks) {
    if (!passed) {
      return publishFinalizerRefusal({
        publisher,
        output,
        exitCode: 1,
        primaryError: failedCheck.startsWith('rb-')
          ? 'release-binding-mismatch'
          : 'clean-run-derivation-mismatch',
        failedCheck,
      });
    }
  }

  const observationalDigestByPath = new Map([
    ['artifact/results/fixture-results.json', reportDigests.fixture],
    ['artifact/workload/workload-results.json', reportDigests.workload],
    ['artifact/mutation/mutation-results.json', reportDigests.mutation],
    [
      'artifact/performance/performance-results.json',
      reportDigests.performance,
    ],
  ]);
  const observation = {
    reproduction_observation: 'csk.reproduction-observation/v0',
    release_descriptor_sha256: descriptorDigest,
    clean_run_report_sha256: cleanRunDigest,
    clean_run_runtime_seconds: q.clean_run_runtime_seconds,
    performance_observations: derivePerformanceObservations(
      parsed.performanceReport
    ),
    reproduced_result_comparisons: deriveComparisonMatches(parsed.comparisons),
    verify_only_observational_results: OBSERVATIONAL_PATHS.map((path) => ({
      path,
      sha256: observationalDigestByPath.get(path),
    })),
    fixture_results: deriveFixtureSummary(parsed.fixtureReport),
    workload_summary_sha256: reportDigests.workload,
    mutation_summary_sha256: reportDigests.mutation,
  };

  const observationPaths = observation.reproduced_result_comparisons.map(
    (row) => row.path
  );
  const descriptorPaths = descriptor.exact_reproduction_results.map(
    (row) => row.path
  );
  const expectedObservational = OBSERVATIONAL_PATHS.map((path) => ({
    path,
    sha256: observationalDigestByPath.get(path),
  }));
  const rChecks = [
    [
      'rb-r-descriptor',
      observation.release_descriptor_sha256 === q.release_descriptor_sha256,
    ],
    ['rb-r-cleanrun', observation.clean_run_report_sha256 === cleanRunDigest],
    [
      'rd-runtime',
      observation.clean_run_runtime_seconds === q.clean_run_runtime_seconds,
    ],
    [
      'rd-fixture',
      canonicalEqual(observation.fixture_results, q.fixture_results),
    ],
    [
      'rd-performance',
      canonicalEqual(
        observation.performance_observations,
        derivePerformanceObservations(parsed.performanceReport)
      ),
    ],
    [
      'rd-workload-digest',
      observation.workload_summary_sha256 === reportDigests.workload,
    ],
    [
      'rd-mutation-digest',
      observation.mutation_summary_sha256 === reportDigests.mutation,
    ],
    [
      'rd-comparisons',
      canonicalEqual(
        observation.reproduced_result_comparisons,
        deriveComparisonMatches(parsed.comparisons)
      ),
    ],
    ['rd-comparison-paths', canonicalEqual(observationPaths, descriptorPaths)],
    [
      'rd-comparisons-matched',
      observation.reproduced_result_comparisons.every(
        (row) => row.matched === true
      ),
    ],
    [
      'rd-observational-set',
      canonicalEqual(
        observation.verify_only_observational_results,
        expectedObservational
      ) &&
        observation.verify_only_observational_results.every(
          (row) => observationalDigestByPath.get(row.path) === row.sha256
        ),
    ],
  ];
  for (const [failedCheck, passed] of rChecks) {
    if (!passed) {
      return publishFinalizerRefusal({
        publisher,
        output,
        exitCode: 1,
        primaryError: failedCheck.startsWith('rb-')
          ? 'release-binding-mismatch'
          : 'observation-derivation-mismatch',
        failedCheck,
      });
    }
  }

  const observationBytes = writeArtifactJson(observation);
  let signed;
  try {
    const loaded = keyProvider.resolve(keyHandle);
    if (loaded.keyId !== descriptor.key_id) {
      throw new ReleaseSchemaError('key-loading-or-signing-failure');
    }
    signed = keyProvider.sign(loaded, observationBytes);
    if (signed.keyId !== descriptor.key_id) {
      throw new ReleaseSchemaError('key-loading-or-signing-failure');
    }
    authenticateObservation({
      policy: authenticated.policy,
      descriptor,
      observationBytes,
      envelopeBytes: signed.envelopeBytes,
    });
  } catch {
    return publishFinalizerRefusal({
      publisher,
      output,
      exitCode: 4,
      primaryError: 'key-loading-or-signing-failure',
    });
  }

  const publication = {
    publication_record: 'csk.release-publication/v0',
    release_descriptor_sha256: descriptorDigest,
    reproduction_observation_sha256: sha256Id(observationBytes),
  };
  const report = finalizeReport({ status: 'finalized' });
  const files = new Map([
    ['reproduction-observation.json', observationBytes],
    ['reproduction-observation.dsse.json', signed.envelopeBytes],
    ['release-publication.json', writeArtifactJson(publication)],
    ['finalize-report.json', writeArtifactJson(report)],
  ]);
  try {
    publisher.publish(output, files);
  } catch {
    return Object.freeze({
      exitCode: 3,
      report: finalizeReport({
        status: 'refused',
        primaryError: 'input-output-failure',
      }),
      published: false,
      stderrOnly: true,
    });
  }
  return Object.freeze({
    exitCode: 0,
    report,
    published: true,
    stderrOnly: false,
    observationBytes,
    observationEnvelopeBytes: signed.envelopeBytes,
    publicationBytes: writeArtifactJson(publication),
  });
}

export function publishFinalizerRefusal({
  publisher,
  output,
  exitCode,
  primaryError,
  failedCheck = null,
  inputArtifact = null,
  underlyingError = null,
}) {
  const report = finalizeReport({
    status: 'refused',
    primaryError,
    failedCheck,
    inputArtifact,
    underlyingError,
  });
  try {
    publisher.publish(
      output,
      new Map([['finalize-report.json', writeArtifactJson(report)]])
    );
  } catch (error) {
    const outputExists =
      error instanceof ReleaseIoError && error.code === 'output-exists';
    return Object.freeze({
      exitCode: outputExists ? 2 : 3,
      report,
      published: false,
      stderrOnly: true,
    });
  }
  return Object.freeze({
    exitCode,
    report,
    published: true,
    stderrOnly: false,
  });
}

function finalizeReport({
  status,
  primaryError = null,
  failedCheck = null,
  inputArtifact = null,
  underlyingError = null,
}) {
  return {
    finalize_report: 'vouch.scored26-finalize-report/v0',
    status,
    primary_error: primaryError,
    failed_check: failedCheck,
    input_artifact: inputArtifact,
    underlying_error: underlyingError,
  };
}

function inputError(error) {
  if (error instanceof ArtifactJsonError) return error.code;
  if (error instanceof ReleaseSchemaError) return 'schema-invalid';
  return 'schema-invalid';
}
