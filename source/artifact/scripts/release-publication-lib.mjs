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
  parseCleanRunReport,
  parseComparisons,
  parseEnvelope,
  parseFixtureReport,
  parseMutationReport,
  parsePerformanceReport,
  parsePublicationRecord,
  parseReproductionObservation,
  parseWorkloadReport,
  sha256Id,
} from './release-schema.mjs';

const VALIDATED_INPUTS = Object.freeze([
  ['cleanRunReport', 'clean-run-report', parseCleanRunReport],
  ['observation', 'observation', parseReproductionObservation],
  [
    'observationEnvelope',
    'observation-envelope',
    (bytes) =>
      parseEnvelope(
        bytes,
        REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
        'observation-envelope'
      ),
  ],
  ['publicationRecord', 'publication-record', parsePublicationRecord],
  ['fixtureReport', 'fixture-report', parseFixtureReport],
  ['workloadReport', 'workload-report', parseWorkloadReport],
  ['mutationReport', 'mutation-report', parseMutationReport],
  ['performanceReport', 'performance-report', parsePerformanceReport],
  ['comparisons', 'reproduction-comparisons', parseComparisons],
]);

export const PUBLICATION_IDENTIFIED_CHECKS = Object.freeze([
  'p3-descriptor-authentication',
  'p3-qd-fixture-summary',
  'p3-qd-workload-summary',
  'p3-qd-mutation-summary',
  'p3-rd-runtime',
  'p3-rd-fixture',
  'p3-rd-performance',
  'p3-rd-comparisons',
  'p3-rd-comparison-paths',
  'p3-rd-observational-set',
  'p3-paper-head',
  'p3-paper-index-clean',
  'p3-paper-worktree-clean',
  'p3-paper-manifest-c0',
]);

/**
 * Phase-3 core over immutable entry buffers and an immutable paper snapshot.
 */
export function publicationCheck({
  buffers,
  paperSnapshot,
  renderer,
  publisher,
  output,
}) {
  const parsed = {};
  for (const [member, inputArtifact, parser] of VALIDATED_INPUTS) {
    try {
      parsed[member] = parser(buffers[member]);
    } catch (error) {
      return publishPublicationFailure({
        publisher,
        output,
        buffers,
        exitCode: 1,
        primaryError: 'publication-input-invalid',
        inputArtifact,
        underlyingError: inputError(error),
      });
    }
  }

  let authenticated;
  try {
    authenticated = authenticateDescriptor({
      policyBytes: buffers.trustPolicy,
      descriptorBytes: buffers.descriptor,
      envelopeBytes: buffers.descriptorEnvelope,
    });
  } catch {
    return publishChainFailure({
      publisher,
      output,
      buffers,
      failedCheck: 'p3-descriptor-authentication',
    });
  }
  const d = authenticated.descriptor;
  const q = parsed.cleanRunReport;
  let r;
  try {
    r = authenticateObservation({
      policy: authenticated.policy,
      descriptor: d,
      observationBytes: buffers.observation,
      envelopeBytes: buffers.observationEnvelope,
    });
  } catch {
    return publishChainFailure({ publisher, output, buffers });
  }
  const p = parsed.publicationRecord;
  const descriptorDigest = sha256Id(buffers.descriptor);
  const qDigest = sha256Id(buffers.cleanRunReport);
  const observationDigest = sha256Id(buffers.observation);
  const reportDigests = Object.freeze({
    fixture: sha256Id(buffers.fixtureReport),
    workload: sha256Id(buffers.workloadReport),
    mutation: sha256Id(buffers.mutationReport),
    performance: sha256Id(buffers.performanceReport),
    comparisons: sha256Id(buffers.comparisons),
  });
  const dResults = new Map(
    d.exact_reproduction_results.map((row) => [row.path, row.sha256])
  );
  const qDigestByPath = new Map([
    ['artifact/results/fixture-results.json', q.fixture_report_sha256],
    ['artifact/workload/workload-results.json', q.workload_report_sha256],
    ['artifact/mutation/mutation-results.json', q.mutation_report_sha256],
    [
      'artifact/performance/performance-results.json',
      q.performance_report_sha256,
    ],
  ]);
  const observedDigestByPath = new Map([
    ['artifact/results/fixture-results.json', reportDigests.fixture],
    ['artifact/workload/workload-results.json', reportDigests.workload],
    ['artifact/mutation/mutation-results.json', reportDigests.mutation],
    [
      'artifact/performance/performance-results.json',
      reportDigests.performance,
    ],
  ]);

  const chainChecks = [
    p.release_descriptor_sha256 === descriptorDigest,
    p.reproduction_observation_sha256 === observationDigest,
    r.release_descriptor_sha256 === descriptorDigest,
    r.clean_run_report_sha256 === qDigest,
    q.release_descriptor_sha256 === descriptorDigest,
    r.release_descriptor_sha256 === q.release_descriptor_sha256,
    q.fixture_report_sha256 === reportDigests.fixture,
    q.workload_report_sha256 === reportDigests.workload,
    q.mutation_report_sha256 === reportDigests.mutation,
    r.workload_summary_sha256 === reportDigests.workload,
    r.mutation_summary_sha256 === reportDigests.mutation,
    q.performance_report_sha256 === reportDigests.performance,
    q.exact_reproduction_comparisons_sha256 === reportDigests.comparisons,
    parsed.comparisons.comparisons.every(
      (row) => dResults.get(row.path) === row.expected_sha256
    ),
    parsed.comparisons.comparisons.every(
      (row) => row.matched === (row.expected_sha256 === row.observed_sha256)
    ),
    r.verify_only_observational_results.every(
      (row) =>
        observedDigestByPath.get(row.path) === row.sha256 &&
        qDigestByPath.get(row.path) === row.sha256
    ),
    r.reproduced_result_comparisons.every((row) => row.matched === true),
  ];
  if (chainChecks.some((passed) => !passed)) {
    return publishChainFailure({ publisher, output, buffers });
  }

  const replayChecks = [
    [
      'p3-qd-fixture-summary',
      canonicalEqual(
        q.fixture_results,
        deriveFixtureSummary(parsed.fixtureReport)
      ),
    ],
    [
      'p3-qd-workload-summary',
      canonicalEqual(q.workload, deriveWorkloadSummary(parsed.workloadReport)),
    ],
    [
      'p3-qd-mutation-summary',
      canonicalEqual(q.mutation, deriveMutationSummary(parsed.mutationReport)),
    ],
    [
      'p3-rd-runtime',
      r.clean_run_runtime_seconds === q.clean_run_runtime_seconds,
    ],
    ['p3-rd-fixture', canonicalEqual(r.fixture_results, q.fixture_results)],
    [
      'p3-rd-performance',
      canonicalEqual(
        r.performance_observations,
        derivePerformanceObservations(parsed.performanceReport)
      ),
    ],
    [
      'p3-rd-comparisons',
      canonicalEqual(
        r.reproduced_result_comparisons,
        deriveComparisonMatches(parsed.comparisons)
      ),
    ],
    [
      'p3-rd-comparison-paths',
      canonicalEqual(
        r.reproduced_result_comparisons.map((row) => row.path),
        d.exact_reproduction_results.map((row) => row.path)
      ),
    ],
    [
      'p3-rd-observational-set',
      canonicalEqual(
        r.verify_only_observational_results,
        OBSERVATIONAL_PATHS.map((path) => ({
          path,
          sha256: observedDigestByPath.get(path),
        }))
      ),
    ],
  ];
  for (const [failedCheck, passed] of replayChecks) {
    if (!passed) {
      return publishChainFailure({
        publisher,
        output,
        buffers,
        failedCheck,
      });
    }
  }

  const provenanceChecks = [
    ['p3-paper-head', paperSnapshot?.head === d.artifact_commit],
    ['p3-paper-index-clean', paperSnapshot?.indexClean === true],
    ['p3-paper-worktree-clean', paperSnapshot?.worktreeClean === true],
    [
      'p3-paper-manifest-c0',
      paperSnapshot?.treeManifest !== undefined &&
        canonicalEqual(
          paperSnapshot.treeManifest,
          paperSnapshot.worktreeManifest
        ),
    ],
  ];
  for (const [failedCheck, passed] of provenanceChecks) {
    if (!passed) {
      return publishPublicationFailure({
        publisher,
        output,
        buffers,
        exitCode: 1,
        primaryError: 'paper-source-provenance-failed',
        failedCheck,
        chainVerified: 'pass',
      });
    }
  }

  let rendered;
  try {
    rendered = renderer({
      descriptor: d,
      cleanRunReport: q,
      observation: r,
      publicationRecord: p,
      fixtureReport: parsed.fixtureReport,
      workloadReport: parsed.workloadReport,
      mutationReport: parsed.mutationReport,
      performanceReport: parsed.performanceReport,
      comparisons: parsed.comparisons,
      paperSnapshot,
    });
  } catch {
    return publishPublicationFailure({
      publisher,
      output,
      buffers,
      exitCode: 1,
      primaryError: 'paper-render-failed',
      chainVerified: 'pass',
    });
  }
  if (rendered.claimsMatched !== true) {
    return publishPublicationFailure({
      publisher,
      output,
      buffers,
      exitCode: 1,
      primaryError: 'paper-claim-mismatch',
      chainVerified: 'pass',
      paperClaimsMatched: false,
      claimLanguageScan: 'not-run',
    });
  }
  if (rendered.claimLanguageScan !== 'pass') {
    return publishPublicationFailure({
      publisher,
      output,
      buffers,
      exitCode: 1,
      primaryError: 'claim-language-scan-failed',
      chainVerified: 'pass',
      paperClaimsMatched: true,
      claimLanguageScan: 'fail',
    });
  }
  const report = publicationReport({
    status: 'pass',
    buffers,
    chainVerified: 'pass',
    paperClaimsMatched: true,
    claimLanguageScan: 'pass',
  });
  const files = new Map([
    ['publication-report.json', writeArtifactJson(report)],
  ]);
  if (Buffer.isBuffer(rendered.pdfBytes)) {
    files.set('vouch-scored26-paper.pdf', rendered.pdfBytes);
  }
  try {
    publisher.publish(output, files);
  } catch {
    return Object.freeze({
      exitCode: 3,
      report: publicationReport({
        status: 'fail',
        buffers,
        primaryError: 'input-output-failure',
        chainVerified: 'pass',
        paperClaimsMatched: true,
        claimLanguageScan: 'pass',
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
  });
}

function publishChainFailure({
  publisher,
  output,
  buffers,
  failedCheck = null,
}) {
  return publishPublicationFailure({
    publisher,
    output,
    buffers,
    exitCode: 1,
    primaryError: 'chain-verification-failed',
    failedCheck,
    chainVerified: 'fail',
  });
}

export function publishPublicationFailure({
  publisher,
  output,
  buffers,
  exitCode,
  primaryError,
  failedCheck = null,
  inputArtifact = null,
  underlyingError = null,
  chainVerified = 'not-run',
  paperClaimsMatched = null,
  claimLanguageScan = 'not-run',
}) {
  const report = publicationReport({
    status: 'fail',
    buffers,
    primaryError,
    failedCheck,
    inputArtifact,
    underlyingError,
    chainVerified,
    paperClaimsMatched,
    claimLanguageScan,
  });
  try {
    publisher.publish(
      output,
      new Map([['publication-report.json', writeArtifactJson(report)]])
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

function publicationReport({
  status,
  buffers,
  chainVerified,
  paperClaimsMatched,
  claimLanguageScan,
  primaryError = null,
  failedCheck = null,
  inputArtifact = null,
  underlyingError = null,
}) {
  return {
    publication_report: 'vouch.scored26-publication/v0',
    status,
    release_descriptor_sha256: digestIfRead(buffers?.descriptor),
    clean_run_report_sha256: digestIfRead(buffers?.cleanRunReport),
    reproduction_observation_sha256: digestIfRead(buffers?.observation),
    chain_verified: chainVerified,
    paper_claims_matched: paperClaimsMatched,
    claim_language_scan: claimLanguageScan,
    primary_error: primaryError,
    failed_check: failedCheck,
    input_artifact: inputArtifact,
    underlying_error: underlyingError,
  };
}

function digestIfRead(bytes) {
  return Buffer.isBuffer(bytes) ? sha256Id(bytes) : null;
}

function inputError(error) {
  if (error instanceof ArtifactJsonError) return error.code;
  if (error instanceof ReleaseSchemaError) return 'schema-invalid';
  return 'schema-invalid';
}
