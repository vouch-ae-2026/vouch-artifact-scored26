import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { writeArtifactJson } from './artifact-json.mjs';

export const RESULT_PATHS = Object.freeze({
  results: 'artifact/workload/workload-results.json',
  metrics: 'artifact/workload/workload-metrics.csv',
  smoke: 'artifact/workload/smoke-suite.json',
  tex: 'generated/workload-results.tex',
});

const LABELS = Object.freeze(['approve', 'deny', 'review', 'invalid-input']);
const EXCEPTIONS = Object.freeze([
  'profile-escape',
  'not-comparable',
  'pipeline-failure',
]);
const EXECUTION_ROOT_FIELDS = Object.freeze([
  'cases',
  'checked_profile',
  'coverage',
  'execution_count',
  'receipt_count',
  'selected_case_count',
  'workload_execution_report',
]);
const RESULT_ROOT_FIELDS = Object.freeze([
  'coverage',
  'development_flips',
  'held_out_flip_records',
  'smoke_suite',
  'workload_report',
  'workload_summary',
]);
const SUMMARY_FIELDS = Object.freeze([
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
]);

export function buildWorkloadResultArtifacts(
  repoRoot,
  executionBytes,
  { includePresentation = true } = {}
) {
  const execution = parseCanonical(executionBytes, 'execution report');
  const split = readJson(repoRoot, 'artifact/workload/workload-split.json');
  const candidates = readJson(
    repoRoot,
    'artifact/workload/workload-candidates.json'
  );
  const holdout = readJson(repoRoot, 'artifact/workload/holdout-plan.json');
  const normalized = validateExecution(execution, split);
  const result = deriveOwnerResult(normalized, split, candidates, holdout);
  const smoke = deriveSmokeSuite(normalized, split);
  const metrics = buildMetricsCsv(result, smoke, holdout);
  const tex = buildWorkloadTex(result, smoke, holdout);
  const values = { results: result, smoke };
  const files = new Map([
    [RESULT_PATHS.results, writeArtifactJson(result)],
    [RESULT_PATHS.metrics, Buffer.from(metrics, 'utf8')],
    [RESULT_PATHS.smoke, writeArtifactJson(smoke)],
  ]);
  if (includePresentation) {
    files.set(RESULT_PATHS.tex, Buffer.from(tex, 'utf8'));
  }
  return {
    files,
    values,
  };
}

export function validateCommittedWorkloadResults(repoRoot) {
  const errors = [];
  let result;
  let smoke;
  try {
    result = readCanonical(repoRoot, RESULT_PATHS.results);
  } catch (error) {
    return [`results:${error.message}`];
  }
  try {
    smoke = readCanonical(repoRoot, RESULT_PATHS.smoke);
  } catch (error) {
    return [`smoke:${error.message}`];
  }
  const split = readJson(repoRoot, 'artifact/workload/workload-split.json');
  const candidates = readJson(
    repoRoot,
    'artifact/workload/workload-candidates.json'
  );
  const holdout = readJson(repoRoot, 'artifact/workload/holdout-plan.json');

  validateOwnerResult(result, smoke, split, candidates, holdout, errors);
  try {
    const expectedMetrics = buildMetricsCsv(result, smoke, holdout);
    const expectedTex = buildWorkloadTex(result, smoke, holdout);
    compareText(repoRoot, RESULT_PATHS.metrics, expectedMetrics, errors);
    compareText(repoRoot, RESULT_PATHS.tex, expectedTex, errors);
    validateSuppliedCorpusWording(expectedTex, RESULT_PATHS.tex, errors);
  } catch (error) {
    errors.push(`generated-presentations:${error.message}`);
  }
  return errors;
}

export function validateWorkloadResultNegativeControls(repoRoot) {
  const result = readCanonical(repoRoot, RESULT_PATHS.results);
  const smoke = readCanonical(repoRoot, RESULT_PATHS.smoke);
  const split = readJson(repoRoot, 'artifact/workload/workload-split.json');
  const candidates = readJson(
    repoRoot,
    'artifact/workload/workload-candidates.json'
  );
  const holdout = readJson(repoRoot, 'artifact/workload/holdout-plan.json');
  const errors = [];
  const trials = [
    {
      name: 'transition-matrix-arithmetic',
      mutate(trialResult) {
        trialResult.workload_summary.transition_matrix.approve.review += 1;
      },
    },
    {
      name: 'held-out-order',
      mutate(trialResult) {
        [
          trialResult.held_out_flip_records[0],
          trialResult.held_out_flip_records[1],
        ] = [
          trialResult.held_out_flip_records[1],
          trialResult.held_out_flip_records[0],
        ];
      },
    },
    {
      name: 'coverage-overlap',
      mutate(trialResult) {
        trialResult.coverage.uncovered = [
          ...trialResult.coverage.uncovered,
          trialResult.coverage.covered[0],
        ].sort(compareUtf8);
      },
    },
    {
      name: 'smoke-role',
      mutate(_trialResult, trialSmoke) {
        trialSmoke.role = 'Principal workload result.';
      },
    },
    {
      name: 'smoke-selection',
      mutate(_trialResult, trialSmoke) {
        const replacement = split.cases.find(
          (record) =>
            record.partition === 'development' &&
            !trialSmoke.cases.some((row) => row.case_id === record.case_id)
        );
        trialSmoke.cases[0] = {
          ...trialSmoke.cases[0],
          case_id: replacement.case_id,
          candidate_class: replacement.candidate_class,
          stratum_id: replacement.stratum_id,
        };
      },
    },
  ];
  for (const trial of trials) {
    const trialResult = structuredClone(result);
    const trialSmoke = structuredClone(smoke);
    trial.mutate(trialResult, trialSmoke);
    const trialErrors = [];
    validateOwnerResult(
      trialResult,
      trialSmoke,
      split,
      candidates,
      holdout,
      trialErrors
    );
    if (trialErrors.length === 0) {
      errors.push(`negative-${trial.name}:mutation was accepted`);
    }
  }
  const wordingErrors = [];
  validateSuppliedCorpusWording(
    'The corpus is complete for all possible inputs.',
    'negative wording',
    wordingErrors
  );
  if (wordingErrors.length === 0) {
    errors.push('negative-supplied-corpus-wording:mutation was accepted');
  }
  return errors;
}

function validateExecution(execution, split) {
  exactKeys(execution, EXECUTION_ROOT_FIELDS, 'execution report');
  if (
    execution.workload_execution_report !==
      'vouch.scored26-workload-execution/v0' ||
    execution.checked_profile !== 'csk.checked-profile/v1' ||
    execution.selected_case_count !== 240 ||
    execution.execution_count !== 480 ||
    !uint(execution.receipt_count) ||
    !Array.isArray(execution.cases) ||
    execution.cases.length !== 240
  ) {
    throw new Error('execution report header/count mismatch');
  }
  if (!Array.isArray(split.cases) || split.cases.length !== 240) {
    throw new Error('frozen split must contain 240 cases');
  }
  const cases = execution.cases.map((record, index) => {
    exactKeys(
      record,
      [
        'baseline',
        'candidate_class',
        'case_id',
        'changed',
        'partition',
        'stratum_id',
      ],
      `execution case ${index}`
    );
    const frozen = split.cases[index];
    for (const field of [
      'case_id',
      'candidate_class',
      'partition',
      'stratum_id',
    ]) {
      if (record[field] !== frozen[field]) {
        throw new Error(`${record.case_id ?? index}: ${field} mismatch`);
      }
    }
    return {
      ...record,
      baseline: validateExecutionSide(
        record.baseline,
        record.case_id,
        'baseline'
      ),
      changed: validateExecutionSide(record.changed, record.case_id, 'changed'),
    };
  });
  const receiptCount = cases.reduce(
    (sum, record) =>
      sum +
      Number(record.baseline.kind === 'decision') +
      Number(record.changed.kind === 'decision'),
    0
  );
  if (receiptCount !== execution.receipt_count) {
    throw new Error('receipt count is not the number of decision receipts');
  }
  const coverage = validateExecutionCoverage(execution.coverage);
  return { cases, coverage, receiptCount };
}

function validateExecutionSide(value, caseId, version) {
  exactKeys(
    value,
    ['outcome', 'receipt_payload_sha256'],
    `${caseId}/${version}`
  );
  if (!plainObject(value.outcome) || typeof value.outcome.kind !== 'string') {
    throw new Error(`${caseId}/${version}: malformed outcome`);
  }
  const kind = value.outcome.kind;
  if (kind === 'decision') {
    exactKeys(value.outcome, ['kind', 'label'], `${caseId}/${version} outcome`);
    if (
      !LABELS.includes(value.outcome.label) ||
      !digestId(value.receipt_payload_sha256)
    ) {
      throw new Error(`${caseId}/${version}: malformed decision receipt`);
    }
    return {
      kind,
      label: value.outcome.label,
      receipt_payload_sha256: value.receipt_payload_sha256,
    };
  }
  exactKeys(value.outcome, ['kind'], `${caseId}/${version} outcome`);
  if (!EXCEPTIONS.includes(kind) || value.receipt_payload_sha256 !== null) {
    throw new Error(`${caseId}/${version}: malformed exceptional outcome`);
  }
  return { kind, label: null, receipt_payload_sha256: null };
}

function validateExecutionCoverage(value) {
  exactKeys(value, ['covered', 'total', 'uncovered'], 'execution coverage');
  for (const name of ['covered', 'total', 'uncovered']) {
    sortedUniqueStrings(value[name], `execution coverage ${name}`);
    for (const identifier of value[name]) {
      if (
        !/^(?:baseline|changed):(?:node:[0-9]{4}|branch:[0-9]{4}:(?:consequent|alternate))$/.test(
          identifier
        )
      ) {
        throw new Error(`invalid coverage identifier ${identifier}`);
      }
    }
  }
  const covered = new Set(value.covered);
  const total = new Set(value.total);
  const expectedUncovered = value.total.filter(
    (identifier) => !covered.has(identifier)
  );
  if (
    value.covered.some((identifier) => !total.has(identifier)) ||
    !sameArray(value.uncovered, expectedUncovered)
  ) {
    throw new Error('coverage partition mismatch');
  }
  return {
    covered: [...value.covered],
    uncovered: [...value.uncovered],
    total: [...value.total],
  };
}

function deriveOwnerResult(execution, split, candidates, holdout) {
  const baselineDistribution = labelCounts();
  const changedDistribution = labelCounts();
  const transition = transitionMatrix();
  const exceptions = {
    profile_escape_executions: 0,
    not_comparable_executions: 0,
    pipeline_failure_executions: 0,
  };
  let decisionPairs = 0;
  let decisionFlips = 0;
  let developmentFlips = 0;
  const heldOutFlipRecords = [];

  for (const record of execution.cases) {
    countExecution(record.baseline, baselineDistribution, exceptions);
    countExecution(record.changed, changedDistribution, exceptions);
    if (
      record.baseline.kind !== 'decision' ||
      record.changed.kind !== 'decision'
    ) {
      continue;
    }
    decisionPairs += 1;
    transition[record.baseline.label][record.changed.label] += 1;
    if (record.baseline.label === record.changed.label) continue;
    decisionFlips += 1;
    if (record.partition === 'development') {
      developmentFlips += 1;
    } else {
      heldOutFlipRecords.push({
        case_id: record.case_id,
        stratum_id: record.stratum_id,
        baseline: record.baseline.label,
        changed: record.changed.label,
      });
    }
  }
  heldOutFlipRecords.sort((left, right) =>
    compareUtf8(left.case_id, right.case_id)
  );
  const smokeCases = selectSmokeCases(execution.cases, split);
  const smokePassed = smokeCases.filter(
    (record) =>
      record.baseline.kind === 'decision' && record.changed.kind === 'decision'
  ).length;
  const development = split.counts?.development?.total;
  const heldOut = split.counts?.held_out?.total;
  const candidateTotal = candidates.counts?.total;
  if (
    development !== 192 ||
    heldOut !== 48 ||
    candidateTotal !== 1536 ||
    execution.cases.length !== development + heldOut
  ) {
    throw new Error('frozen workload quantities changed');
  }
  const predicted = new Set(holdout.predicted_affected_strata);
  for (const record of heldOutFlipRecords) {
    if (!predicted.has(record.stratum_id)) {
      // This is not a conformance failure; it is kept visible in the reports.
      break;
    }
  }
  return {
    workload_report: 'vouch.scored26-workload/v0',
    workload_summary: {
      candidates: candidateTotal,
      selected_case_count: execution.cases.length,
      decision_pair_count: decisionPairs,
      excluded_from_matrix_count: execution.cases.length - decisionPairs,
      development,
      held_out: heldOut,
      decision_flips: decisionFlips,
      held_out_flips: heldOutFlipRecords.length,
      exception_count_by_kind: exceptions,
      decision_distribution_baseline: baselineDistribution,
      decision_distribution_changed: changedDistribution,
      transition_matrix: transition,
    },
    held_out_flip_records: heldOutFlipRecords,
    development_flips: developmentFlips,
    coverage: {
      covered: execution.coverage.covered,
      uncovered: execution.coverage.uncovered,
    },
    smoke_suite: {
      cases: smokeCases.length,
      passed: smokePassed,
      failed: smokeCases.length - smokePassed,
    },
  };
}

function deriveSmokeSuite(execution, split) {
  const selected = selectSmokeCases(execution.cases, split);
  const rows = selected.map((record) => {
    const baseline = outcomeLabel(record.baseline);
    const changed = outcomeLabel(record.changed);
    return {
      case_id: record.case_id,
      candidate_class: record.candidate_class,
      stratum_id: record.stratum_id,
      baseline,
      changed,
      decision_flip:
        record.baseline.kind === 'decision' &&
        record.changed.kind === 'decision'
          ? baseline !== changed
          : null,
    };
  });
  const passed = rows.filter((row) => row.decision_flip !== null).length;
  return {
    smoke_suite: 'vouch.scored26-smoke-suite/v0',
    role: 'Retained smoke suite; not the principal workload result.',
    selection_protocol:
      'Four lowest split hashes per candidate class in the development partition.',
    cases: rows,
    summary: {
      cases: rows.length,
      passed,
      failed: rows.length - passed,
      decision_flips: rows.filter((row) => row.decision_flip === true).length,
    },
  };
}

function selectSmokeCases(executionCases, split) {
  const byId = new Map(
    executionCases.map((record) => [record.case_id, record])
  );
  const selected = [];
  for (const candidateClass of ['boundary', 'interior', 'invalid']) {
    const rows = split.cases
      .filter(
        (record) =>
          record.partition === 'development' &&
          record.candidate_class === candidateClass
      )
      .sort((left, right) =>
        Buffer.compare(
          parseDigest(left.split_sha256),
          parseDigest(right.split_sha256)
        )
      )
      .slice(0, 4);
    if (rows.length !== 4)
      throw new Error(`smoke ${candidateClass}: expected four cases`);
    selected.push(...rows.map((record) => byId.get(record.case_id)));
  }
  if (selected.some((record) => !record)) {
    throw new Error('smoke suite references a missing execution');
  }
  return selected.sort((left, right) =>
    compareUtf8(left.case_id, right.case_id)
  );
}

function validateOwnerResult(
  result,
  smoke,
  split,
  candidates,
  holdout,
  errors
) {
  try {
    exactKeys(result, RESULT_ROOT_FIELDS, 'workload result');
    exactKeys(result.workload_summary, SUMMARY_FIELDS, 'workload summary');
    if (result.workload_report !== 'vouch.scored26-workload/v0') {
      throw new Error('wrong result tag');
    }
    const summary = result.workload_summary;
    for (const name of [
      'candidates',
      'selected_case_count',
      'decision_pair_count',
      'excluded_from_matrix_count',
      'development',
      'held_out',
      'decision_flips',
      'held_out_flips',
    ]) {
      if (!uint(summary[name])) throw new Error(`${name} is not uint`);
    }
    if (
      summary.candidates !== candidates.counts.total ||
      summary.selected_case_count !== 240 ||
      summary.development !== split.counts.development.total ||
      summary.held_out !== split.counts.held_out.total ||
      summary.development + summary.held_out !== summary.selected_case_count ||
      summary.decision_pair_count + summary.excluded_from_matrix_count !==
        summary.selected_case_count
    ) {
      throw new Error('summary/frozen count mismatch');
    }
    validateClosedCounts(summary.decision_distribution_baseline, 'baseline');
    validateClosedCounts(summary.decision_distribution_changed, 'changed');
    const matrixTotal = validateMatrix(summary.transition_matrix);
    const offDiagonal = LABELS.reduce(
      (sum, baseline) =>
        sum +
        LABELS.reduce(
          (row, changed) =>
            row +
            (baseline === changed
              ? 0
              : summary.transition_matrix[baseline][changed]),
          0
        ),
      0
    );
    const baselineDecisionCount = sumCounts(
      summary.decision_distribution_baseline
    );
    const changedDecisionCount = sumCounts(
      summary.decision_distribution_changed
    );
    if (
      matrixTotal !== summary.decision_pair_count ||
      offDiagonal !== summary.decision_flips ||
      baselineDecisionCount < matrixTotal ||
      changedDecisionCount < matrixTotal
    ) {
      throw new Error('decision matrix arithmetic mismatch');
    }
    exactKeys(
      summary.exception_count_by_kind,
      [
        'not_comparable_executions',
        'pipeline_failure_executions',
        'profile_escape_executions',
      ],
      'exception counts'
    );
    for (const value of Object.values(summary.exception_count_by_kind)) {
      if (!uint(value)) throw new Error('exception count is not uint');
    }
    const exceptionalExecutionCount = sumCounts(
      summary.exception_count_by_kind
    );
    if (
      baselineDecisionCount +
        changedDecisionCount +
        exceptionalExecutionCount !==
      summary.selected_case_count * 2
    ) {
      throw new Error('execution outcome tally mismatch');
    }
    if (!uint(result.development_flips)) {
      throw new Error('development_flips is not uint');
    }
    if (
      result.development_flips + summary.held_out_flips !==
      summary.decision_flips
    ) {
      throw new Error('partition flip arithmetic mismatch');
    }
    validateHeldOutRecords(result, split, holdout);
    validateOwnerCoverage(result.coverage);
    exactKeys(
      result.smoke_suite,
      ['cases', 'failed', 'passed'],
      'owner smoke summary'
    );
    for (const value of Object.values(result.smoke_suite)) {
      if (!uint(value)) throw new Error('owner smoke count is not uint');
    }
    validateSmoke(smoke, result, split);
  } catch (error) {
    errors.push(error.message);
  }
}

function validateHeldOutRecords(result, split, holdout) {
  if (!Array.isArray(result.held_out_flip_records)) {
    throw new Error('held-out flip records must be an array');
  }
  const held = new Map(
    split.cases
      .filter((record) => record.partition === 'held-out')
      .map((record) => [record.case_id, record])
  );
  let previous = null;
  for (const row of result.held_out_flip_records) {
    exactKeys(
      row,
      ['baseline', 'case_id', 'changed', 'stratum_id'],
      'held-out flip'
    );
    if (
      !held.has(row.case_id) ||
      held.get(row.case_id).stratum_id !== row.stratum_id ||
      !LABELS.includes(row.baseline) ||
      !LABELS.includes(row.changed) ||
      row.baseline === row.changed ||
      (previous !== null && compareUtf8(previous, row.case_id) >= 0)
    ) {
      throw new Error('invalid, duplicate, or unsorted held-out flip record');
    }
    previous = row.case_id;
  }
  if (
    result.held_out_flip_records.length !==
      result.workload_summary.held_out_flips ||
    !Array.isArray(holdout.predicted_affected_strata)
  ) {
    throw new Error('held-out flip/prediction count mismatch');
  }
}

function validateOwnerCoverage(coverage) {
  exactKeys(coverage, ['covered', 'uncovered'], 'owner coverage');
  sortedUniqueStrings(coverage.covered, 'covered identifiers');
  sortedUniqueStrings(coverage.uncovered, 'uncovered identifiers');
  const seen = new Set(coverage.covered);
  if (coverage.uncovered.some((identifier) => seen.has(identifier))) {
    throw new Error('coverage identifiers overlap');
  }
  for (const identifier of [...coverage.covered, ...coverage.uncovered]) {
    if (
      !/^(?:baseline|changed):(?:node:[0-9]{4}|branch:[0-9]{4}:(?:consequent|alternate))$/.test(
        identifier
      )
    ) {
      throw new Error(`invalid coverage identifier ${identifier}`);
    }
  }
}

function validateSmoke(smoke, result, split) {
  exactKeys(
    smoke,
    ['cases', 'role', 'selection_protocol', 'smoke_suite', 'summary'],
    'smoke suite'
  );
  if (
    smoke.smoke_suite !== 'vouch.scored26-smoke-suite/v0' ||
    smoke.role !== 'Retained smoke suite; not the principal workload result.' ||
    smoke.selection_protocol !==
      'Four lowest split hashes per candidate class in the development partition.' ||
    !Array.isArray(smoke.cases) ||
    smoke.cases.length !== 12
  ) {
    throw new Error('smoke suite header mismatch');
  }
  exactKeys(
    smoke.summary,
    ['cases', 'decision_flips', 'failed', 'passed'],
    'smoke summary'
  );
  const frozen = new Map(split.cases.map((record) => [record.case_id, record]));
  const expectedCases = selectSmokeCases(split.cases, split).map(
    (record) => record.case_id
  );
  let flips = 0;
  for (const [index, row] of smoke.cases.entries()) {
    exactKeys(
      row,
      [
        'baseline',
        'candidate_class',
        'case_id',
        'changed',
        'decision_flip',
        'stratum_id',
      ],
      'smoke case'
    );
    const source = frozen.get(row.case_id);
    if (
      !source ||
      source.partition !== 'development' ||
      source.candidate_class !== row.candidate_class ||
      source.stratum_id !== row.stratum_id ||
      ![...LABELS, ...EXCEPTIONS].includes(row.baseline) ||
      ![...LABELS, ...EXCEPTIONS].includes(row.changed) ||
      ![true, false, null].includes(row.decision_flip) ||
      row.case_id !== expectedCases[index]
    ) {
      throw new Error('invalid smoke case');
    }
    const expectedFlip =
      LABELS.includes(row.baseline) && LABELS.includes(row.changed)
        ? row.baseline !== row.changed
        : null;
    if (row.decision_flip !== expectedFlip) {
      throw new Error('smoke decision-flip mismatch');
    }
    flips += Number(row.decision_flip === true);
  }
  const passed = smoke.cases.filter((row) => row.decision_flip !== null).length;
  if (
    smoke.summary.cases !== 12 ||
    smoke.summary.passed !== passed ||
    smoke.summary.failed !== 12 - passed ||
    smoke.summary.decision_flips !== flips ||
    result.smoke_suite.cases !== smoke.summary.cases ||
    result.smoke_suite.passed !== smoke.summary.passed ||
    result.smoke_suite.failed !== smoke.summary.failed
  ) {
    throw new Error('smoke summary mismatch');
  }
}

function buildMetricsCsv(result, smoke, holdout) {
  const summary = result.workload_summary;
  const prediction = predictionComparison(result, holdout);
  const coverage = coverageCounts(result.coverage);
  const rows = [
    ['principal', 'candidates', summary.candidates],
    ['principal', 'selected_case_count', summary.selected_case_count],
    ['principal', 'decision_pair_count', summary.decision_pair_count],
    [
      'principal',
      'excluded_from_matrix_count',
      summary.excluded_from_matrix_count,
    ],
    ['partition', 'development', summary.development],
    ['partition', 'held_out', summary.held_out],
    ['principal', 'decision_flips', summary.decision_flips],
    ['partition', 'development_flips', result.development_flips],
    ['partition', 'held_out_flips', summary.held_out_flips],
    [
      'exception',
      'profile_escape_executions',
      summary.exception_count_by_kind.profile_escape_executions,
    ],
    [
      'exception',
      'not_comparable_executions',
      summary.exception_count_by_kind.not_comparable_executions,
    ],
    [
      'exception',
      'pipeline_failure_executions',
      summary.exception_count_by_kind.pipeline_failure_executions,
    ],
  ];
  for (const label of LABELS) {
    rows.push([
      'baseline_distribution',
      label,
      summary.decision_distribution_baseline[label],
    ]);
    rows.push([
      'changed_distribution',
      label,
      summary.decision_distribution_changed[label],
    ]);
  }
  for (const baseline of LABELS) {
    for (const changed of LABELS) {
      rows.push([
        'transition_matrix',
        `${baseline}->${changed}`,
        summary.transition_matrix[baseline][changed],
      ]);
    }
  }
  rows.push(
    ['coverage', 'covered_graph_nodes', coverage.coveredNodes],
    ['coverage', 'total_graph_nodes', coverage.totalNodes],
    ['coverage', 'covered_source_branches', coverage.coveredBranches],
    ['coverage', 'total_source_branches', coverage.totalBranches],
    [
      'held_out_prediction',
      'predicted_affected_strata',
      prediction.predicted.length,
    ],
    ['held_out_prediction', 'observed_flip_strata', prediction.observed.length],
    [
      'held_out_prediction',
      'predicted_and_observed_strata',
      prediction.intersection.length,
    ],
    [
      'held_out_prediction',
      'observed_unpredicted_strata',
      prediction.unpredicted.length,
    ],
    ['smoke', 'cases', smoke.summary.cases],
    ['smoke', 'passed', smoke.summary.passed],
    ['smoke', 'failed', smoke.summary.failed],
    ['smoke', 'decision_flips', smoke.summary.decision_flips]
  );
  return `scope,metric,value\n${rows
    .map(([scope, metric, value]) => `${scope},${metric},${value}`)
    .join('\n')}\n`;
}

export function buildWorkloadTex(result, smoke, holdout) {
  const summary = result.workload_summary;
  const prediction = predictionComparison(result, holdout);
  const coverage = coverageCounts(result.coverage);
  const macro = (name, value) => `\\newcommand{\\${name}}{${value}}`;
  const lines = [
    '% Generated from artifact/workload/workload-results.json.',
    '% Do not edit by hand.',
    macro('ScoredWorkloadCandidates', summary.candidates),
    macro('ScoredWorkloadSelected', summary.selected_case_count),
    macro('ScoredWorkloadDevelopment', summary.development),
    macro('ScoredWorkloadHeldOut', summary.held_out),
    macro('ScoredWorkloadDecisionPairs', summary.decision_pair_count),
    macro('ScoredWorkloadExcluded', summary.excluded_from_matrix_count),
    macro('ScoredWorkloadFlips', summary.decision_flips),
    macro('ScoredWorkloadDevelopmentFlips', result.development_flips),
    macro('ScoredWorkloadHeldOutFlips', summary.held_out_flips),
    macro(
      'ScoredWorkloadProfileEscapes',
      summary.exception_count_by_kind.profile_escape_executions
    ),
    macro(
      'ScoredWorkloadNotComparable',
      summary.exception_count_by_kind.not_comparable_executions
    ),
    macro(
      'ScoredWorkloadPipelineFailures',
      summary.exception_count_by_kind.pipeline_failure_executions
    ),
    macro('ScoredWorkloadCoveredNodes', coverage.coveredNodes),
    macro('ScoredWorkloadTotalNodes', coverage.totalNodes),
    macro('ScoredWorkloadCoveredBranches', coverage.coveredBranches),
    macro('ScoredWorkloadTotalBranches', coverage.totalBranches),
    macro('ScoredWorkloadPredictedStrata', prediction.predicted.length),
    macro('ScoredWorkloadObservedStrata', prediction.observed.length),
    macro('ScoredWorkloadUnpredictedStrata', prediction.unpredicted.length),
    macro('ScoredWorkloadSmokeCases', smoke.summary.cases),
    macro('ScoredWorkloadSmokeFlips', smoke.summary.decision_flips),
    '',
    '\\paragraph{Scope.}',
    `The principal result is complete over the supplied corpus of ${summary.selected_case_count} selected cases (${summary.development} development and ${summary.held_out} held out).`,
    '',
    '\\paragraph{Decision distributions.}',
    '\\begin{tabular}{lrr}',
    'Decision & Baseline & Changed \\\\',
    '\\hline',
    ...LABELS.map(
      (label) =>
        `${texLabel(label)} & ${summary.decision_distribution_baseline[label]} & ${summary.decision_distribution_changed[label]} \\\\`
    ),
    '\\end{tabular}',
    '',
    '\\paragraph{Transition matrix.}',
    '\\begin{tabular}{lrrrr}',
    'Baseline $\\backslash$ changed & approve & deny & review & invalid-input \\\\',
    '\\hline',
    ...LABELS.map(
      (baseline) =>
        `${texLabel(baseline)} & ${LABELS.map(
          (changed) => summary.transition_matrix[baseline][changed]
        ).join(' & ')} \\\\`
    ),
    '\\end{tabular}',
    '',
    '\\paragraph{Held-out prediction comparison.}',
    `The frozen plan predicted ${prediction.predicted.length} affected strata; observed held-out flips occurred in ${prediction.observed.length} strata, with ${prediction.intersection.length} predicted-and-observed and ${prediction.unpredicted.length} unpredicted strata.`,
    '\\begin{verbatim}',
    `predicted: ${prediction.predicted.join(',') || 'none'}`,
    `observed: ${prediction.observed.join(',') || 'none'}`,
    '\\end{verbatim}',
    '',
    '\\paragraph{Held-out flip records.}',
    '\\begin{verbatim}',
    ...(result.held_out_flip_records.length === 0
      ? ['none']
      : result.held_out_flip_records.map(
          (row) =>
            `${row.case_id} ${row.stratum_id} ${row.baseline}->${row.changed}`
        )),
    '\\end{verbatim}',
    '',
    '\\paragraph{Execution outcomes.}',
    `All ${summary.selected_case_count * 2} executions are recorded: ${sumCounts(summary.decision_distribution_baseline) + sumCounts(summary.decision_distribution_changed)} decisions, ${summary.exception_count_by_kind.profile_escape_executions} profile escapes, ${summary.exception_count_by_kind.not_comparable_executions} not-comparable executions, and ${summary.exception_count_by_kind.pipeline_failure_executions} pipeline failures.`,
    '',
    '\\paragraph{Coverage identifiers.}',
    '\\begin{verbatim}',
    'covered:',
    ...result.coverage.covered,
    'uncovered:',
    ...(result.coverage.uncovered.length === 0
      ? ['none']
      : result.coverage.uncovered),
    '\\end{verbatim}',
    '',
    '\\paragraph{Smoke suite.}',
    `The retained ${smoke.summary.cases}-case smoke suite observed ${smoke.summary.decision_flips} decision flips. It is a smoke suite and is not the principal workload result.`,
    '',
  ];
  return lines.join('\n');
}

function predictionComparison(result, holdout) {
  const predicted = sortedUnique(
    holdout.predicted_affected_strata,
    'predicted affected strata'
  );
  const observed = sortedUnique(
    result.held_out_flip_records.map((row) => row.stratum_id),
    'observed flip strata'
  );
  const predictedSet = new Set(predicted);
  return {
    predicted,
    observed,
    intersection: observed.filter((value) => predictedSet.has(value)),
    unpredicted: observed.filter((value) => !predictedSet.has(value)),
  };
}

function coverageCounts(coverage) {
  const all = [...coverage.covered, ...coverage.uncovered];
  return {
    coveredNodes: coverage.covered.filter((value) => value.includes(':node:'))
      .length,
    totalNodes: all.filter((value) => value.includes(':node:')).length,
    coveredBranches: coverage.covered.filter((value) =>
      value.includes(':branch:')
    ).length,
    totalBranches: all.filter((value) => value.includes(':branch:')).length,
  };
}

function countExecution(execution, distribution, exceptions) {
  if (execution.kind === 'decision') {
    distribution[execution.label] += 1;
    return;
  }
  const field = {
    'profile-escape': 'profile_escape_executions',
    'not-comparable': 'not_comparable_executions',
    'pipeline-failure': 'pipeline_failure_executions',
  }[execution.kind];
  exceptions[field] += 1;
}

function labelCounts() {
  return Object.fromEntries(LABELS.map((label) => [label, 0]));
}

function transitionMatrix() {
  return Object.fromEntries(
    LABELS.map((baseline) => [baseline, labelCounts()])
  );
}

function validateClosedCounts(value, label) {
  exactKeys(value, LABELS, `${label} distribution`);
  for (const count of Object.values(value)) {
    if (!uint(count))
      throw new Error(`${label} distribution count is not uint`);
  }
}

function validateMatrix(value) {
  exactKeys(value, LABELS, 'transition matrix');
  let total = 0;
  for (const baseline of LABELS) {
    validateClosedCounts(value[baseline], `transition ${baseline}`);
    total += sumCounts(value[baseline]);
  }
  return total;
}

function sumCounts(value) {
  return Object.values(value).reduce((sum, count) => sum + count, 0);
}

function outcomeLabel(execution) {
  return execution.kind === 'decision' ? execution.label : execution.kind;
}

function parseDigest(value) {
  if (!digestId(value)) throw new Error(`malformed digest ${value}`);
  return Buffer.from(value.slice(7), 'hex');
}

function digestId(value) {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
}

function readJson(repoRoot, path) {
  return JSON.parse(readFileSync(join(repoRoot, path), 'utf8'));
}

function readCanonical(repoRoot, path) {
  const bytes = readFileSync(join(repoRoot, path));
  return parseCanonical(bytes, path);
}

function parseCanonical(bytes, label) {
  let value;
  try {
    value = JSON.parse(bytes);
  } catch (error) {
    throw new Error(`${label} is not JSON: ${error.message}`);
  }
  if (!writeArtifactJson(value).equals(bytes)) {
    throw new Error(`${label} is not canonical csk.artifact-json/v0`);
  }
  return value;
}

function compareText(repoRoot, path, expected, errors) {
  let actual;
  try {
    actual = readFileSync(join(repoRoot, path), 'utf8');
  } catch (error) {
    errors.push(`${path}:${error.message}`);
    return;
  }
  if (actual !== expected) errors.push(`${path}:generated bytes differ`);
}

function validateSuppliedCorpusWording(text, label, errors) {
  if (!/complete over the supplied corpus/i.test(text)) {
    errors.push(`${label}:missing supplied-corpus scope wording`);
  }
  const unqualifiedPatterns = [
    /\bcomplete corpus\b/i,
    /\bcorpus is complete\b/i,
    /\bcomplete (?:for|over) all (?:possible )?inputs\b/i,
    /\bcomplete over (?:the )?(?:entire|full) corpus\b/i,
  ];
  if (unqualifiedPatterns.some((pattern) => pattern.test(text))) {
    errors.push(`${label}:unqualified corpus-completeness wording`);
  }
}

function exactKeys(value, expected, label) {
  if (!plainObject(value)) throw new Error(`${label} must be an object`);
  const names = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (!sameArray(names, wanted)) {
    throw new Error(`${label} has wrong fields`);
  }
}

function sortedUniqueStrings(value, label) {
  if (
    !Array.isArray(value) ||
    !value.every((item) => typeof item === 'string')
  ) {
    throw new Error(`${label} must be a string array`);
  }
  for (let index = 1; index < value.length; index += 1) {
    if (compareUtf8(value[index - 1], value[index]) >= 0) {
      throw new Error(`${label} must be bytewise sorted and unique`);
    }
  }
}

function sortedUnique(value, label) {
  if (
    !Array.isArray(value) ||
    !value.every((item) => typeof item === 'string')
  ) {
    throw new Error(`${label} must be a string array`);
  }
  return [...new Set(value)].sort(compareUtf8);
}

function sameArray(left, right) {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function uint(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function texLabel(value) {
  return value.replace('-', '--');
}
