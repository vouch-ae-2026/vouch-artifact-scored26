import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { writeArtifactJson } from './artifact-json.mjs';

export const MUTANT_IDS = Object.freeze(
  Array.from(
    { length: 12 },
    (_, index) => `M${String(index + 1).padStart(2, '0')}`
  )
);

export const CLASS_ORDER = Object.freeze([
  'Lowering',
  'Graph evaluator',
  'Source evaluator',
  'Shared numeric',
  'Path serialization',
  'Shared reader and normalizer',
]);

export const MUTATION_PATHS = Object.freeze({
  manifest: 'artifact/mutation/mutation-manifest.json',
  results: 'artifact/mutation/mutation-results.json',
  csv: 'artifact/mutation/mutation-results.csv',
  tex: 'generated/mutation-results.tex',
  activation: 'artifact/mutation/activation-results.json',
});

export const MUTATION_REGISTRY = Object.freeze([
  entry(
    'M01',
    'Lowering',
    'interp/src/vouch_native/graph.rs',
    'Meaning Environment lowering',
    'Lower `and` using `or`'
  ),
  entry(
    'M02',
    'Lowering',
    'interp/src/vouch_native/graph.rs',
    'Meaning Environment lowering',
    'Reverse subtraction arguments during lowering'
  ),
  entry(
    'M03',
    'Graph evaluator',
    'interp/src/vouch_native/meaning_trace.rs',
    'Meaning Environment evaluator',
    'Swap true and false graph successors of `if`'
  ),
  entry(
    'M04',
    'Graph evaluator',
    'interp/src/vouch_native/meaning_trace.rs',
    'Meaning Environment evaluator',
    'Treat graph `<=` as `<`'
  ),
  entry(
    'M05',
    'Source evaluator',
    'interp/src/eval.rs',
    'Reference evaluator',
    'Swap source evaluator branches of `if`'
  ),
  entry(
    'M06',
    'Source evaluator',
    'interp/src/eval.rs',
    'Reference evaluator',
    'Reverse source evaluator subtraction operands'
  ),
  entry(
    'M07',
    'Shared numeric',
    'interp/src/number.rs',
    'Shared numeric substrate',
    'Treat shared inclusive comparison as strict on equality'
  ),
  entry(
    'M08',
    'Shared numeric',
    'interp/src/value.rs',
    'Shared numeric substrate',
    'Normalize a negative rational with the wrong sign'
  ),
  entry(
    'M09',
    'Path serialization',
    'interp/src/vouch_native/meaning_trace.rs',
    'Meaning Environment path serialization',
    'Replace the final graph-side value event with a different canonical value of the same schema'
  ),
  entry(
    'M10',
    'Path serialization',
    'interp/src/vouch_native/reference_trace.rs',
    'Reference path serialization',
    'Replace U+000A in a string value with U+005C followed by U+006E before the shared canonical writer'
  ),
  entry(
    'M11',
    'Shared reader and normalizer',
    'interp/src/vouch_native/checked_profile.rs',
    'Shared checked-profile normalizer',
    'Reverse subtraction operands in the shared normalizer'
  ),
  entry(
    'M12',
    'Shared reader and normalizer',
    'interp/src/reader.rs',
    'Shared reader',
    'Decode `#f` as `#t` in the shared reader'
  ),
]);

const OUTCOME_FIELDS = Object.freeze([
  'disagreement_cases',
  'common_mode_cases',
  'pipeline_failure_cases',
  'infrastructure_failure_cases',
  'survivor_cases',
]);
const MUTANT_LEVEL_FIELDS = Object.freeze([
  'seeded',
  'built',
  'activated_any',
  'detected_any',
]);
const EXECUTION_ROOT_FIELDS = Object.freeze([
  'activation_cases',
  'binary_sha256',
  'mutation_execution_report',
  'selected_mutant',
  'workload_cases',
]);

function entry(mutantId, className, sourceFile, component, transformation) {
  return Object.freeze({
    mutantId,
    className,
    sourceFile,
    component,
    transformation,
  });
}

export function activationPayloadPath(mutantId) {
  return `artifact/mutation/activation-payloads/${mutantId}.json`;
}

export function buildMutationArtifacts(
  repoRoot,
  executions,
  mutationSourceCommit,
  { includePresentation = true } = {}
) {
  if (!/^[0-9a-f]{40}$/.test(mutationSourceCommit)) {
    throw new Error('mutation source commit must be full lowercase 40-hex');
  }
  const suite = readCanonical(
    repoRoot,
    'artifact/mutation/activation-suite.json'
  );
  validateActivationSuite(suite);
  const split = readCanonical(
    repoRoot,
    'artifact/workload/workload-split.json'
  );
  if (!Array.isArray(split.cases) || split.cases.length !== 240) {
    throw new Error('frozen workload split must contain 240 cases');
  }

  const normalized = new Map();
  for (const id of ['baseline', ...MUTANT_IDS]) {
    const execution = executions.get(id);
    if (!execution) throw new Error(`${id}: missing execution record`);
    const report = parseCanonicalBytes(
      execution.reportBytes,
      `${id} execution report`
    );
    normalized.set(id, {
      ...validateExecutionReport(report, id, suite, split),
      payloadRoot: execution.payloadRoot,
    });
  }
  const binaryDigests = [...normalized.values()].map(
    (record) => record.binarySha256
  );
  if (new Set(binaryDigests).size !== binaryDigests.length) {
    throw new Error(
      'baseline and twelve mutant binary digests must all be unique'
    );
  }

  const baseline = normalized.get('baseline');
  const activationRows = [];
  const manifestRows = [];
  const activationPayloads = new Map();
  for (const registry of MUTATION_REGISTRY) {
    const mutant = normalized.get(registry.mutantId);
    const witnessIndex = MUTANT_IDS.indexOf(registry.mutantId);
    const baselineWitness = baseline.activationCases[witnessIndex];
    const mutantWitness = mutant.activationCases[witnessIndex];
    const expected = suite.cases[witnessIndex].expected_witness_class;
    const witnessOutcome = classifyObservationPair(
      baselineWitness.observation,
      mutantWitness.observation,
      `${registry.mutantId} activation witness`
    );
    if (!witnessOutcome.activated || witnessOutcome.outcome !== expected) {
      throw new Error(
        `${registry.mutantId}: expected ${expected} witness, observed ${witnessOutcome.outcome ?? 'not-activated'}`
      );
    }
    const payloadRelativePath = receiptPayloadPath(
      mutantWitness.observation,
      registry.mutantId
    );
    const payloadBytes = readFileSync(
      join(mutant.payloadRoot, payloadRelativePath)
    );
    validateUnsignedPayload(
      payloadBytes,
      mutantWitness.observation,
      registry.mutantId,
      {
        binarySha256: mutant.binarySha256,
        buildCommit: mutationSourceCommit,
      }
    );
    const destination = activationPayloadPath(registry.mutantId);
    activationPayloads.set(destination, payloadBytes);
    activationRows.push({
      activated: true,
      baseline: projectionRecord(baselineWitness.observation),
      case_id: baselineWitness.case_id,
      expected_witness_class: expected,
      mutant: projectionRecord(mutantWitness.observation),
      mutant_id: registry.mutantId,
      observed_witness_class: witnessOutcome.outcome,
      unsigned_payload: {
        path: destination,
        sha256: digestId(payloadBytes),
      },
    });

    const development = emptyOutcomeCounts();
    const heldOut = emptyOutcomeCounts();
    const activationCaseIds = [];
    for (let index = 0; index < baseline.workloadCases.length; index += 1) {
      const baseCase = baseline.workloadCases[index];
      const mutantCase = mutant.workloadCases[index];
      const classified = classifyWorkloadCase(baseCase, mutantCase);
      if (!classified.activated) continue;
      activationCaseIds.push(baseCase.case_id);
      const counts =
        baseCase.partition === 'development' ? development : heldOut;
      counts[outcomeField(classified.outcome)] += 1;
    }
    manifestRows.push({
      activation_case_ids: activationCaseIds,
      baseline_binary_sha256: baseline.binarySha256,
      class: registry.className,
      component: registry.component,
      development_case_outcomes: development,
      heldout_case_outcomes: heldOut,
      mutant_id: registry.mutantId,
      mutated_binary_sha256: mutant.binarySha256,
      one_line_transformation: registry.transformation,
      source_file: registry.sourceFile,
      source_location: markerLocation(repoRoot, registry),
    });
  }

  const manifest = {
    mutation_source_commit: mutationSourceCommit,
    mutation_manifest: 'vouch.scored26-mutation-manifest/v0',
    mutants: manifestRows,
  };
  const activation = {
    activation_report: 'vouch.scored26-mutation-activation-results/v0',
    cases: activationRows,
    empirical_counts_include_activation_witnesses: false,
  };
  const results = deriveResults(manifestRows);
  const files = new Map([
    [MUTATION_PATHS.manifest, writeArtifactJson(manifest)],
    [MUTATION_PATHS.results, writeArtifactJson(results)],
    [MUTATION_PATHS.csv, Buffer.from(buildCsv(results), 'utf8')],
    [MUTATION_PATHS.activation, writeArtifactJson(activation)],
    ...activationPayloads,
  ]);
  if (includePresentation) {
    files.set(MUTATION_PATHS.tex, Buffer.from(buildTex(results), 'utf8'));
  }
  return { files, values: { manifest, results, activation } };
}

export function validateCommittedMutationArtifacts(repoRoot) {
  const errors = [];
  try {
    const manifest = readCanonical(repoRoot, MUTATION_PATHS.manifest);
    const results = readCanonical(repoRoot, MUTATION_PATHS.results);
    const activation = readCanonical(repoRoot, MUTATION_PATHS.activation);
    validateManifest(repoRoot, manifest);
    validateActivationResults(repoRoot, activation, manifest);
    const expectedResults = deriveResults(manifest.mutants);
    if (!deepEqual(results, expectedResults)) {
      errors.push(
        'mutation-results.json does not derive from mutation-manifest.json'
      );
    }
    compareBytes(
      repoRoot,
      MUTATION_PATHS.csv,
      Buffer.from(buildCsv(expectedResults), 'utf8'),
      errors
    );
    compareBytes(
      repoRoot,
      MUTATION_PATHS.tex,
      Buffer.from(buildTex(expectedResults), 'utf8'),
      errors
    );
  } catch (error) {
    errors.push(error.message);
  }
  return errors;
}

export function validateMutationNegativeControls(repoRoot) {
  const errors = [];
  const manifest = readCanonical(repoRoot, MUTATION_PATHS.manifest);
  const results = readCanonical(repoRoot, MUTATION_PATHS.results);
  const activation = readCanonical(repoRoot, MUTATION_PATHS.activation);
  const trials = [
    [
      'duplicate-binary',
      (value) => {
        value.mutants[1].mutated_binary_sha256 =
          value.mutants[0].mutated_binary_sha256;
      },
    ],
    [
      'prescribed-activation',
      (value) => {
        value.mutants[0].activation_case_ids = ['W-M01'];
      },
    ],
    [
      'outcome-arithmetic',
      (value) => {
        value.mutants[0].development_case_outcomes.survivor_cases += 1;
      },
    ],
  ];
  for (const [name, mutate] of trials) {
    const value = structuredClone(manifest);
    mutate(value);
    try {
      validateManifest(repoRoot, value);
      if (deepEqual(deriveResults(value.mutants), results)) {
        errors.push(`negative-${name}: mutation was accepted`);
      }
    } catch {
      // Rejection is the expected negative-control result.
    }
  }
  const resultTrial = structuredClone(results);
  resultTrial.mutation_summary.case_level.disagreement_cases += 1;
  if (deepEqual(resultTrial, deriveResults(manifest.mutants))) {
    errors.push('negative-result-arithmetic: mutation was accepted');
  }
  const witness = activation.cases[0];
  const authenticatedShape = readCanonical(
    repoRoot,
    witness.unsigned_payload.path
  );
  authenticatedShape.payloadType = 'application/vnd.in-toto+json';
  authenticatedShape.signatures = [];
  const authenticatedBytes = writeArtifactJson(authenticatedShape);
  try {
    validateUnsignedPayload(
      authenticatedBytes,
      {
        ...witness.mutant,
        payload_sha256: digestId(authenticatedBytes),
      },
      'M01',
      {
        binarySha256: manifest.mutants[0].mutated_binary_sha256,
        buildCommit: manifest.mutation_source_commit,
      }
    );
    errors.push(
      'negative-authenticated-shape: DSSE-shaped output was accepted'
    );
  } catch {
    // Rejection is the expected no-release-authentication result.
  }
  return errors;
}

function validateExecutionReport(report, id, suite, split) {
  exactKeys(report, EXECUTION_ROOT_FIELDS, `${id} execution report`);
  if (
    report.mutation_execution_report !==
      'vouch.scored26-mutation-execution/v0' ||
    report.selected_mutant !== (id === 'baseline' ? null : id) ||
    !digest(report.binary_sha256) ||
    !Array.isArray(report.activation_cases) ||
    report.activation_cases.length !== 12 ||
    !Array.isArray(report.workload_cases) ||
    report.workload_cases.length !== 240
  ) {
    throw new Error(`${id}: execution report header/count mismatch`);
  }
  const activationCases = report.activation_cases.map((row, index) => {
    exactKeys(
      row,
      ['case_id', 'expected_witness_class', 'mutant_id', 'observation'],
      `${id} activation ${index}`
    );
    const expected = suite.cases[index];
    if (
      row.case_id !== expected.case_id ||
      row.mutant_id !== expected.mutant_id ||
      row.expected_witness_class !== expected.expected_witness_class
    ) {
      throw new Error(`${id}: activation suite identity mismatch at ${index}`);
    }
    return {
      ...row,
      observation: validateObservation(row.observation, `${id}:${row.case_id}`),
    };
  });
  const workloadCases = report.workload_cases.map((row, index) => {
    exactKeys(
      row,
      ['baseline', 'case_id', 'changed', 'partition'],
      `${id} workload ${index}`
    );
    const expected = split.cases[index];
    if (
      row.case_id !== expected.case_id ||
      row.partition !== expected.partition
    ) {
      throw new Error(
        `${id}:${row.case_id}: frozen workload identity mismatch`
      );
    }
    return {
      ...row,
      baseline: validateObservation(
        row.baseline,
        `${id}:${row.case_id}:baseline`
      ),
      changed: validateObservation(row.changed, `${id}:${row.case_id}:changed`),
    };
  });
  return { activationCases, binarySha256: report.binary_sha256, workloadCases };
}

function validateObservation(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label}: observation must be an object`);
  }
  if (value.kind === 'pipeline-failure') {
    exactKeys(value, ['error_code', 'kind'], label);
    if (typeof value.error_code !== 'string' || value.error_code === '') {
      throw new Error(`${label}: invalid pipeline error`);
    }
    return value;
  }
  if (value.kind === 'receipt') {
    exactKeys(
      value,
      [
        'comparison_status',
        'kind',
        'meaning_projection_sha256',
        'payload_relative_path',
        'payload_sha256',
        'reference_projection_sha256',
      ],
      label
    );
    if (
      !['agree', 'disagree', 'not-comparable'].includes(
        value.comparison_status
      ) ||
      !digest(value.reference_projection_sha256) ||
      !digest(value.meaning_projection_sha256) ||
      !digest(value.payload_sha256) ||
      typeof value.payload_relative_path !== 'string' ||
      value.payload_relative_path.startsWith('/') ||
      value.payload_relative_path.includes('..')
    ) {
      throw new Error(`${label}: malformed receipt observation`);
    }
    return value;
  }
  throw new Error(`${label}: unknown observation kind`);
}

function classifyWorkloadCase(baseline, mutant) {
  if (
    baseline.case_id !== mutant.case_id ||
    baseline.partition !== mutant.partition
  ) {
    throw new Error('baseline/mutant workload case mismatch');
  }
  const outcomes = ['baseline', 'changed'].map((side) =>
    classifyObservationPair(
      baseline[side],
      mutant[side],
      `${mutant.case_id}:${side}`
    )
  );
  const activated = outcomes.filter((outcome) => outcome.activated);
  if (activated.length === 0) return { activated: false, outcome: null };
  const kinds = new Set(activated.map((outcome) => outcome.outcome));
  if (kinds.size !== 1) {
    throw new Error(
      `${mutant.case_id}: mixed outcome classes across rule versions`
    );
  }
  return { activated: true, outcome: [...kinds][0] };
}

function classifyObservationPair(baseline, mutant, label) {
  if (observationsSemanticallyEqual(baseline, mutant)) {
    return { activated: false, outcome: null };
  }
  if (mutant.kind === 'pipeline-failure') {
    return { activated: true, outcome: 'pipeline-failure' };
  }
  if (mutant.comparison_status === 'not-comparable') {
    return { activated: true, outcome: 'infrastructure-failure' };
  }
  if (mutant.comparison_status === 'disagree') {
    return { activated: true, outcome: 'disagreement' };
  }
  if (baseline.kind === 'receipt' && mutant.kind === 'receipt') {
    const referenceChanged =
      baseline.reference_projection_sha256 !==
      mutant.reference_projection_sha256;
    const meaningChanged =
      baseline.meaning_projection_sha256 !== mutant.meaning_projection_sha256;
    if (
      mutant.comparison_status === 'agree' &&
      referenceChanged &&
      meaningChanged &&
      mutant.reference_projection_sha256 === mutant.meaning_projection_sha256
    ) {
      return { activated: true, outcome: 'common-mode' };
    }
  }
  if (mutant.kind !== 'receipt')
    throw new Error(`${label}: invalid mutated observation`);
  return { activated: true, outcome: 'survivor' };
}

function observationsSemanticallyEqual(left, right) {
  if (left.kind !== right.kind) return false;
  if (left.kind === 'pipeline-failure')
    return left.error_code === right.error_code;
  return (
    left.comparison_status === right.comparison_status &&
    left.reference_projection_sha256 === right.reference_projection_sha256 &&
    left.meaning_projection_sha256 === right.meaning_projection_sha256
  );
}

function projectionRecord(observation) {
  if (observation.kind !== 'receipt') {
    return { error_code: observation.error_code, kind: observation.kind };
  }
  return {
    comparison_status: observation.comparison_status,
    kind: observation.kind,
    meaning_projection_sha256: observation.meaning_projection_sha256,
    reference_projection_sha256: observation.reference_projection_sha256,
  };
}

function receiptPayloadPath(observation, mutantId) {
  if (observation.kind !== 'receipt') {
    throw new Error(
      `${mutantId}: activation witness did not produce a receipt`
    );
  }
  return observation.payload_relative_path;
}

function validateUnsignedPayload(bytes, observation, mutantId, expected = {}) {
  if (digestId(bytes) !== observation.payload_sha256) {
    throw new Error(`${mutantId}: activation payload digest mismatch`);
  }
  const payload = parseCanonicalBytes(bytes, `${mutantId} activation payload`);
  const referenceProjection = digestId(
    writeArtifactJson(payload.reference?.transcript)
  );
  const meaningProjection = digestId(
    writeArtifactJson(payload.meaning_env?.transcript)
  );
  if (
    payload.payloadType !== undefined ||
    payload.signatures !== undefined ||
    payload.differential_receipt !== 'csk.differential-receipt/v0' ||
    payload.execution?.mutant_id !== mutantId ||
    payload.execution?.build_variant !== 'mutant' ||
    observation.kind !== 'receipt' ||
    payload.comparison?.status !== observation.comparison_status ||
    referenceProjection !== observation.reference_projection_sha256 ||
    meaningProjection !== observation.meaning_projection_sha256 ||
    (expected.binarySha256 !== undefined &&
      (payload.execution?.executable_sha256 !== expected.binarySha256 ||
        payload.engine?.executable_sha256 !== expected.binarySha256)) ||
    (expected.buildCommit !== undefined &&
      payload.execution?.build_commit !== expected.buildCommit)
  ) {
    throw new Error(
      `${mutantId}: activation payload is authenticated or has wrong experiment metadata`
    );
  }
}

function validateManifest(repoRoot, manifest) {
  exactKeys(
    manifest,
    ['mutants', 'mutation_manifest', 'mutation_source_commit'],
    'mutation manifest'
  );
  if (
    manifest.mutation_manifest !== 'vouch.scored26-mutation-manifest/v0' ||
    !/^[0-9a-f]{40}$/.test(manifest.mutation_source_commit) ||
    !Array.isArray(manifest.mutants) ||
    manifest.mutants.length !== 12
  ) {
    throw new Error('mutation manifest header/count mismatch');
  }
  const digests = new Set();
  const split = readCanonical(
    repoRoot,
    'artifact/workload/workload-split.json'
  );
  const partitions = new Map(
    split.cases.map((row) => [row.case_id, row.partition])
  );
  let baseline;
  manifest.mutants.forEach((row, index) => {
    const registry = MUTATION_REGISTRY[index];
    exactKeys(
      row,
      [
        'activation_case_ids',
        'baseline_binary_sha256',
        'class',
        'component',
        'development_case_outcomes',
        'heldout_case_outcomes',
        'mutant_id',
        'mutated_binary_sha256',
        'one_line_transformation',
        'source_file',
        'source_location',
      ],
      `manifest ${registry.mutantId}`
    );
    if (
      row.mutant_id !== registry.mutantId ||
      row.class !== registry.className ||
      row.source_file !== registry.sourceFile ||
      row.component !== registry.component ||
      row.one_line_transformation !== registry.transformation ||
      row.source_location !== markerLocation(repoRoot, registry) ||
      !digest(row.baseline_binary_sha256) ||
      !digest(row.mutated_binary_sha256)
    ) {
      throw new Error(`${registry.mutantId}: registry or digest mismatch`);
    }
    baseline ??= row.baseline_binary_sha256;
    if (
      row.baseline_binary_sha256 !== baseline ||
      digests.has(row.mutated_binary_sha256)
    ) {
      throw new Error(
        `${registry.mutantId}: duplicate or inconsistent binary digest`
      );
    }
    digests.add(row.mutated_binary_sha256);
    if (row.mutated_binary_sha256 === baseline) {
      throw new Error(`${registry.mutantId}: mutant digest equals baseline`);
    }
    if (
      !Array.isArray(row.activation_case_ids) ||
      new Set(row.activation_case_ids).size !==
        row.activation_case_ids.length ||
      !isSorted(row.activation_case_ids) ||
      row.activation_case_ids.some((id) => !/^[DH][0-9]{3}$/.test(id))
    ) {
      throw new Error(
        `${registry.mutantId}: activation identifiers are malformed or prescribed witnesses`
      );
    }
    validateOutcomeCounts(
      row.development_case_outcomes,
      `${registry.mutantId} development`
    );
    validateOutcomeCounts(
      row.heldout_case_outcomes,
      `${registry.mutantId} held-out`
    );
    const counted =
      sumCounts(row.development_case_outcomes) +
      sumCounts(row.heldout_case_outcomes);
    if (counted !== row.activation_case_ids.length) {
      throw new Error(
        `${registry.mutantId}: activation/outcome arithmetic mismatch`
      );
    }
    const developmentIds = row.activation_case_ids.filter(
      (id) => partitions.get(id) === 'development'
    );
    const heldOutIds = row.activation_case_ids.filter(
      (id) => partitions.get(id) === 'held-out'
    );
    if (
      developmentIds.length !== sumCounts(row.development_case_outcomes) ||
      heldOutIds.length !== sumCounts(row.heldout_case_outcomes) ||
      developmentIds.length + heldOutIds.length !==
        row.activation_case_ids.length
    ) {
      throw new Error(
        `${registry.mutantId}: activation identifiers do not match frozen partitions`
      );
    }
  });
}

function validateActivationResults(repoRoot, report, manifest) {
  exactKeys(
    report,
    [
      'activation_report',
      'cases',
      'empirical_counts_include_activation_witnesses',
    ],
    'activation results'
  );
  if (
    report.activation_report !==
      'vouch.scored26-mutation-activation-results/v0' ||
    report.empirical_counts_include_activation_witnesses !== false ||
    !Array.isArray(report.cases) ||
    report.cases.length !== 12
  ) {
    throw new Error('activation results header/count mismatch');
  }
  report.cases.forEach((row, index) => {
    const id = MUTANT_IDS[index];
    exactKeys(
      row,
      [
        'activated',
        'baseline',
        'case_id',
        'expected_witness_class',
        'mutant',
        'mutant_id',
        'observed_witness_class',
        'unsigned_payload',
      ],
      `${id} activation result`
    );
    if (
      row.activated !== true ||
      row.case_id !== `W-${id}` ||
      row.mutant_id !== id ||
      row.expected_witness_class !== row.observed_witness_class ||
      row.expected_witness_class !==
        (index < 6 || index === 8 || index === 9
          ? 'disagreement'
          : 'common-mode') ||
      row.unsigned_payload?.path !== activationPayloadPath(id) ||
      !digest(row.unsigned_payload?.sha256)
    ) {
      throw new Error(`${id}: activation result mismatch`);
    }
    validateProjectionObservation(row.baseline, `${id} baseline projection`);
    validateProjectionObservation(row.mutant, `${id} mutant projection`);
    const classified = classifyObservationPair(
      row.baseline,
      row.mutant,
      `${id} committed activation witness`
    );
    if (
      !classified.activated ||
      classified.outcome !== row.observed_witness_class
    ) {
      throw new Error(`${id}: activation projections do not establish outcome`);
    }
    const bytes = readFileSync(join(repoRoot, row.unsigned_payload.path));
    if (digestId(bytes) !== row.unsigned_payload.sha256) {
      throw new Error(`${id}: committed activation payload digest mismatch`);
    }
    const manifestRow = manifest.mutants[index];
    validateUnsignedPayload(
      bytes,
      { ...row.mutant, payload_sha256: row.unsigned_payload.sha256 },
      id,
      {
        binarySha256: manifestRow.mutated_binary_sha256,
        buildCommit: manifest.mutation_source_commit,
      }
    );
  });
}

function validateProjectionObservation(value, label) {
  if (value?.kind === 'pipeline-failure') {
    exactKeys(value, ['error_code', 'kind'], label);
    if (typeof value.error_code !== 'string' || value.error_code === '') {
      throw new Error(`${label}: malformed pipeline projection`);
    }
    return;
  }
  exactKeys(
    value,
    [
      'comparison_status',
      'kind',
      'meaning_projection_sha256',
      'reference_projection_sha256',
    ],
    label
  );
  if (
    value.kind !== 'receipt' ||
    !['agree', 'disagree', 'not-comparable'].includes(
      value.comparison_status
    ) ||
    !digest(value.reference_projection_sha256) ||
    !digest(value.meaning_projection_sha256)
  ) {
    throw new Error(`${label}: malformed receipt projection`);
  }
}

function deriveResults(mutants) {
  const classRows = CLASS_ORDER.map((className) =>
    deriveRow(
      className,
      mutants.filter((row) => row.class === className)
    )
  );
  const total = deriveRow('Total', mutants);
  const development = derivePartition(mutants, 'development_case_outcomes');
  const heldOut = derivePartition(mutants, 'heldout_case_outcomes');
  const withoutHeldOut = mutants
    .filter((row) => row.activation_case_ids.every((id) => !id.startsWith('H')))
    .map((row) => row.mutant_id)
    .sort(compareUtf8);
  return {
    mutation_report: 'vouch.scored26-mutation/v0',
    mutation_summary: {
      mutant_level: {
        ...total.mutant_level,
        detection_rate: percentage(
          total.mutant_level.detected_any,
          total.mutant_level.seeded
        ),
      },
      case_level: total.case_level,
    },
    partitions: {
      development,
      held_out: heldOut,
      mutants_without_held_out_activation: withoutHeldOut,
    },
    rows: [...classRows, total],
  };
}

function deriveRow(className, mutants) {
  const caseLevel = emptyOutcomeCounts();
  for (const mutant of mutants) {
    addCounts(caseLevel, mutant.development_case_outcomes);
    addCounts(caseLevel, mutant.heldout_case_outcomes);
  }
  return {
    case_level: caseLevel,
    class: className,
    mutant_level: {
      activated_any: mutants.filter((row) => row.activation_case_ids.length > 0)
        .length,
      built: mutants.length,
      detected_any: mutants.filter(
        (row) =>
          row.development_case_outcomes.disagreement_cases +
            row.heldout_case_outcomes.disagreement_cases >
          0
      ).length,
      seeded: mutants.length,
    },
  };
}

function derivePartition(mutants, field) {
  const counts = {
    activated: 0,
    common_mode: 0,
    detected: 0,
    infrastructure_failures: 0,
    pipeline_failures: 0,
    survivors: 0,
  };
  for (const mutant of mutants) {
    const outcomes = mutant[field];
    counts.detected += outcomes.disagreement_cases;
    counts.common_mode += outcomes.common_mode_cases;
    counts.pipeline_failures += outcomes.pipeline_failure_cases;
    counts.infrastructure_failures += outcomes.infrastructure_failure_cases;
    counts.survivors += outcomes.survivor_cases;
    counts.activated += sumCounts(outcomes);
  }
  return counts;
}

function buildCsv(results) {
  const header = ['class', ...MUTANT_LEVEL_FIELDS, ...OUTCOME_FIELDS];
  const rows = results.rows.map((row) => [
    row.class,
    ...MUTANT_LEVEL_FIELDS.map((field) => row.mutant_level[field]),
    ...OUTCOME_FIELDS.map((field) => row.case_level[field]),
  ]);
  return `${[header, ...rows].map((row) => row.map(csvCell).join(',')).join('\n')}\n`;
}

function buildTex(results) {
  const lines = [
    '% Generated from artifact/mutation/mutation-results.json; do not edit.',
    '\\begin{tabular}{lrrrrrrrrr}',
    '\\toprule',
    'Class & Seeded & Built & Activated & Detected & Disagree & Common & Pipeline & Infra & Survivor \\\\',
    '\\midrule',
  ];
  for (const row of results.rows) {
    lines.push(
      `${texEscape(row.class)} & ${row.mutant_level.seeded} & ${row.mutant_level.built} & ` +
        `${row.mutant_level.activated_any} & ${row.mutant_level.detected_any} & ` +
        `${row.case_level.disagreement_cases} & ${row.case_level.common_mode_cases} & ` +
        `${row.case_level.pipeline_failure_cases} & ${row.case_level.infrastructure_failure_cases} & ` +
        `${row.case_level.survivor_cases} \\\\`
    );
  }
  lines.push(
    '\\bottomrule',
    '\\end{tabular}',
    `\\newcommand{\\MutationDetectionRate}{${results.mutation_summary.mutant_level.detection_rate}\\%}`,
    ''
  );
  return lines.join('\n');
}

function markerLocation(repoRoot, registry) {
  const text = readFileSync(join(repoRoot, registry.sourceFile), 'utf8');
  const marker = `SCORED-MUTATION-SITE ${registry.mutantId}`;
  const lines = text.split('\n');
  const matches = [];
  lines.forEach((line, index) => {
    if (line.includes(marker)) matches.push(index + 1);
  });
  if (matches.length !== 1) {
    throw new Error(
      `${registry.mutantId}: expected exactly one registered semantic site`
    );
  }
  return `${registry.sourceFile}:${matches[0]}`;
}

function validateActivationSuite(suite) {
  exactKeys(suite, ['activation_suite', 'cases'], 'activation suite');
  if (
    suite.activation_suite !== 'vouch.scored26-mutation-activation/v0' ||
    !Array.isArray(suite.cases) ||
    suite.cases.length !== 12
  ) {
    throw new Error('activation suite header/count mismatch');
  }
  suite.cases.forEach((row, index) => {
    const id = MUTANT_IDS[index];
    exactKeys(
      row,
      ['case_id', 'expected_witness_class', 'input', 'mutant_id', 'source'],
      `${id} activation case`
    );
    const expected =
      index < 6 || index === 8 || index === 9 ? 'disagreement' : 'common-mode';
    if (
      row.case_id !== `W-${id}` ||
      row.mutant_id !== id ||
      row.expected_witness_class !== expected ||
      typeof row.source !== 'string' ||
      row.input?.input !== 'csk.checked-input/v1'
    ) {
      throw new Error(`${id}: activation suite row mismatch`);
    }
  });
}

function validateOutcomeCounts(value, label) {
  exactKeys(value, OUTCOME_FIELDS, label);
  if (OUTCOME_FIELDS.some((field) => !uint(value[field]))) {
    throw new Error(`${label}: outcome counts must be unsigned integers`);
  }
}

function emptyOutcomeCounts() {
  return {
    common_mode_cases: 0,
    disagreement_cases: 0,
    infrastructure_failure_cases: 0,
    pipeline_failure_cases: 0,
    survivor_cases: 0,
  };
}

function addCounts(target, source) {
  for (const field of OUTCOME_FIELDS) target[field] += source[field];
}

function sumCounts(value) {
  return OUTCOME_FIELDS.reduce((sum, field) => sum + value[field], 0);
}

function outcomeField(outcome) {
  return {
    disagreement: 'disagreement_cases',
    'common-mode': 'common_mode_cases',
    'pipeline-failure': 'pipeline_failure_cases',
    'infrastructure-failure': 'infrastructure_failure_cases',
    survivor: 'survivor_cases',
  }[outcome];
}

function percentage(numerator, denominator) {
  if (denominator === 0) return '0.0';
  const tenths = Math.floor((1000 * numerator + denominator / 2) / denominator);
  return `${Math.floor(tenths / 10)}.${tenths % 10}`;
}

function parseCanonicalBytes(bytes, label) {
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new Error(`${label}: invalid JSON: ${error.message}`);
  }
  if (!writeArtifactJson(value).equals(bytes)) {
    throw new Error(`${label}: not canonical csk.artifact-json/v0`);
  }
  return value;
}

function readCanonical(repoRoot, path) {
  return parseCanonicalBytes(readFileSync(join(repoRoot, path)), path);
}

function exactKeys(value, names, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label}: must be an object`);
  }
  const actual = Object.keys(value).sort(compareUtf8);
  const expected = [...names].sort(compareUtf8);
  if (!deepEqual(actual, expected)) {
    throw new Error(`${label}: object members are not the exact closed set`);
  }
}

function compareBytes(repoRoot, path, expected, errors) {
  let actual;
  try {
    actual = readFileSync(join(repoRoot, path));
  } catch (error) {
    errors.push(`${path}: ${error.message}`);
    return;
  }
  if (!actual.equals(expected))
    errors.push(`${path}: differs from owner report`);
}

function digest(value) {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
}

function digestId(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function uint(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function isSorted(values) {
  return values.every(
    (value, index) => index === 0 || compareUtf8(values[index - 1], value) < 0
  );
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function deepEqual(left, right) {
  return writeArtifactJson(left).equals(writeArtifactJson(right));
}

function csvCell(value) {
  const text = String(value);
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function texEscape(value) {
  return value.replaceAll('&', '\\&');
}

export const mutationInternalsForTest = Object.freeze({
  deriveResults,
  validateActivationSuite,
  validateManifest,
});
