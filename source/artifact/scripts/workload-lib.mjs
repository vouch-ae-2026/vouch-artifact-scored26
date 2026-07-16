import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { writeArtifactJson } from './artifact-json.mjs';

export const AMOUNT_MIN = 0;
export const AMOUNT_MAX = 1_000_000;
export const INVALID_BASE_AMOUNT = 0;
export const CHECKED_INPUT_TAG = 'csk.checked-input/v1';
export const CHECKED_PROFILE = 'csk.checked-profile/v1';
export const DECISIONS = ['approve', 'deny', 'review', 'invalid-input'];
export const CLASSES = ['boundary', 'interior', 'invalid'];

const RULE_PARAMETER_TAG = 'vouch.scored26-rule-parameters/v0';
const RULE_HASH_DOMAIN = 'vouch/rule-source/v0';
const INTERIOR_DOMAIN = 'vouch/workload-interior/v0';
const SELECTION_DOMAIN = 'vouch/workload-selection/v0';
const SPLIT_DOMAIN = 'vouch/workload-split/v0';

const PERIODS = [
  [2025, '2025'],
  [2026, '2026'],
];
const HOUSEHOLDS = [
  [0, 'single'],
  [1, 'couple'],
  [2, 'single-parent'],
  [3, 'multi-adult'],
];
const DEPENDENTS = [
  [0, 'none'],
  [1, 'one'],
  [2, 'two-plus'],
];
const RESIDENCIES = [
  [0, 'resident'],
  [1, 'temporary'],
];

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest();
}

export function digestId(bytes) {
  return `sha256:${sha256(bytes).toString('hex')}`;
}

export function domainDigestId(domain, bytes) {
  return `sha256:${createHash('sha256')
    .update(domain, 'utf8')
    .update(Buffer.from([0]))
    .update(bytes)
    .digest('hex')}`;
}

export function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

export function enumerateStrata() {
  const strata = [];
  for (const [periodCode, period] of PERIODS) {
    for (const [householdCode, household] of HOUSEHOLDS) {
      for (const [dependentsCode, dependents] of DEPENDENTS) {
        for (const [residencyCode, residency] of RESIDENCIES) {
          const number = strata.length + 1;
          strata.push({
            stratum_id: `S${String(number).padStart(2, '0')}`,
            codes: [periodCode, householdCode, dependentsCode, residencyCode],
            labels: { period, household, dependents, residency },
          });
        }
      }
    }
  }
  return strata;
}

export function checkedInput(value) {
  return { input: CHECKED_INPUT_TAG, value };
}

export function canonicalInputBytes(value) {
  return writeArtifactJson(checkedInput(value));
}

function canonicalIntegerInputParts(codes) {
  const full = canonicalInputBytes([...codes, 0]).toString('utf8');
  const needle = '    0\n  ]\n}\n';
  if (!full.endsWith(needle)) {
    throw new Error('canonical checked-input integer template drift');
  }
  return [
    Buffer.from(full.slice(0, -needle.length) + '    ', 'utf8'),
    Buffer.from('\n  ]\n}\n', 'utf8'),
  ];
}

function canonicalIntegerInputBytes(codes, amount) {
  const [prefix, suffix] = canonicalIntegerInputParts(codes);
  return Buffer.concat([prefix, Buffer.from(String(amount), 'utf8'), suffix]);
}

function selectionDigest(stratumId, candidateClass, inputBytes) {
  return createHash('sha256')
    .update(SELECTION_DOMAIN, 'utf8')
    .update(Buffer.from([0]))
    .update(stratumId, 'utf8')
    .update(Buffer.from([0]))
    .update(candidateClass, 'utf8')
    .update(Buffer.from([0]))
    .update(inputBytes)
    .digest();
}

function splitDigest(selectionHash, stratumId, inputBytes) {
  return createHash('sha256')
    .update(SPLIT_DOMAIN, 'utf8')
    .update(Buffer.from([0]))
    .update(selectionHash)
    .update(stratumId, 'utf8')
    .update(Buffer.from([0]))
    .update(inputBytes)
    .digest();
}

function parseParameters(repoRoot, version) {
  const path = `artifact/workload/parameters/${version}.json`;
  const bytes = readFileSync(join(repoRoot, path));
  let value;
  try {
    value = JSON.parse(bytes);
  } catch (error) {
    throw new Error(`${path}: invalid JSON: ${error.message}`);
  }
  if (!writeArtifactJson(value).equals(bytes)) {
    throw new Error(`${path}: not canonical csk.artifact-json/v0`);
  }
  if (
    value?.rule_parameters !== RULE_PARAMETER_TAG ||
    value?.rule_version !== version ||
    !Array.isArray(value.thresholds) ||
    value.thresholds.length !== 6 ||
    !Array.isArray(value.interval_decisions) ||
    value.interval_decisions.length !== 7 ||
    Object.keys(value).sort(compareUtf8).join('\0') !==
      ['interval_decisions', 'rule_parameters', 'rule_version', 'thresholds']
        .sort(compareUtf8)
        .join('\0')
  ) {
    throw new Error(`${path}: closed rule-parameter schema mismatch`);
  }
  if (
    value.interval_decisions.some(
      (decision) =>
        !DECISIONS.includes(decision) || decision === 'invalid-input'
    )
  ) {
    throw new Error(
      `${path}: interval decision is outside the closed valid-input set`
    );
  }
  validateThresholds(value.thresholds, path);
  return { path, bytes, value };
}

function validateThresholds(thresholds, subject) {
  if (
    thresholds.some((value) => !Number.isSafeInteger(value)) ||
    thresholds[0] < AMOUNT_MIN + 2 ||
    thresholds.at(-1) > AMOUNT_MAX - 2
  ) {
    throw new Error(
      `${subject}: thresholds violate the admitted boundary domain`
    );
  }
  for (let index = 1; index < thresholds.length; index += 1) {
    if (thresholds[index] - thresholds[index - 1] < 4) {
      throw new Error(
        `${subject}: threshold spacing leaves an empty interior pool`
      );
    }
  }
}

function decisionForm(decision) {
  return `(decision-${decision})`;
}

export function renderRuleSource(parameters) {
  const [t1, t2, t3, t4, t5, t6] = parameters.thresholds;
  const [d1, d2, d3, d4, d5, d6, d7] =
    parameters.interval_decisions.map(decisionForm);
  return Buffer.from(
    `(define exact-five?\n` +
      `  (lambda (xs)\n` +
      `    (if (pair? xs)\n` +
      `      (if (pair? (cdr xs))\n` +
      `          (if (pair? (cdr (cdr xs)))\n` +
      `              (if (pair? (cdr (cdr (cdr xs))))\n` +
      `                  (if (pair? (cdr (cdr (cdr (cdr xs)))))\n` +
      `                      (null? (cdr (cdr (cdr (cdr (cdr xs))))))\n` +
      `                      #f)\n` +
      `                  #f)\n` +
      `              #f)\n` +
      `          #f)\n` +
      `      #f)))\n` +
      `(define exact-integer-five?\n` +
      `  (lambda (xs)\n` +
      `    (if (exact-integer? (car xs))\n` +
      `        (if (exact-integer? (car (cdr xs)))\n` +
      `            (if (exact-integer? (car (cdr (cdr xs))))\n` +
      `                (if (exact-integer? (car (cdr (cdr (cdr xs)))))\n` +
      `                    (exact-integer? (car (cdr (cdr (cdr (cdr xs))))))\n` +
      `                    #f)\n` +
      `                #f)\n` +
      `            #f)\n` +
      `        #f)))\n` +
      `(define known-period? (lambda (x) (if (= x 2025) #t (= x 2026))))\n` +
      `(define known-household?\n` +
      `  (lambda (x) (if (= x 0) #t (if (= x 1) #t (if (= x 2) #t (= x 3))))))\n` +
      `(define known-dependents?\n` +
      `  (lambda (x) (if (= x 0) #t (if (= x 1) #t (= x 2)))))\n` +
      `(define known-residency? (lambda (x) (if (= x 0) #t (= x 1))))\n` +
      `(define decide-amount\n` +
      `  (lambda (amount)\n` +
      `    (if (< amount ${AMOUNT_MIN})\n` +
      `      (decision-invalid-input)\n` +
      `      (if (> amount ${AMOUNT_MAX})\n` +
      `          (decision-invalid-input)\n` +
      `          (if (< amount ${t1})\n` +
      `              ${d1}\n` +
      `              (if (< amount ${t2})\n` +
      `                  ${d2}\n` +
      `                  (if (< amount ${t3})\n` +
      `                      ${d3}\n` +
      `                      (if (< amount ${t4})\n` +
      `                          ${d4}\n` +
      `                          (if (< amount ${t5})\n` +
      `                              ${d5}\n` +
      `                              (if (< amount ${t6}) ${d6} ${d7}))))))))))\n` +
      `(if (exact-five? input)\n` +
      `    (if (exact-integer-five? input)\n` +
      `        (if (known-period? (car input))\n` +
      `            (if (known-household? (car (cdr input)))\n` +
      `                (if (known-dependents? (car (cdr (cdr input))))\n` +
      `                    (if (known-residency? (car (cdr (cdr (cdr input)))))\n` +
      `                        (decide-amount (car (cdr (cdr (cdr (cdr input))))))\n` +
      `                        (decision-invalid-input))\n` +
      `                    (decision-invalid-input))\n` +
      `                (decision-invalid-input))\n` +
      `            (decision-invalid-input))\n` +
      `        (decision-invalid-input))\n` +
      `    (decision-invalid-input))\n`,
    'utf8'
  );
}

function invalidValues(codes) {
  const base = [...codes, INVALID_BASE_AMOUNT];
  const rational = { $rat: { d: '2', n: '1' } };
  return [
    { invalid_id: 'I1', value: base.filter((_, index) => index !== 3) },
    { invalid_id: 'I2', value: [...base, 0] },
    { invalid_id: 'I3', value: [rational, ...base.slice(1)] },
    { invalid_id: 'I4', value: [base[0], rational, ...base.slice(2)] },
    { invalid_id: 'I5', value: [base[0], base[1], 3, base[3], base[4]] },
    { invalid_id: 'I6', value: [base[0], base[1], base[2], 2, base[4]] },
    { invalid_id: 'I7', value: [base[0], base[1], base[2], base[3], -1] },
  ];
}

function intervals(thresholds) {
  const bounds = [AMOUNT_MIN, ...thresholds, AMOUNT_MAX + 1];
  return Array.from({ length: 7 }, (_, index) => ({
    interval_id: String(index + 1),
    lower: bounds[index],
    upper: bounds[index + 1],
  }));
}

function findInteriorForStratum(stratum, thresholds) {
  const excluded = new Set();
  for (const threshold of thresholds) {
    excluded.add(threshold - 1);
    excluded.add(threshold);
    excluded.add(threshold + 1);
  }
  const [inputPrefix, inputSuffix] = canonicalIntegerInputParts(stratum.codes);
  return intervals(thresholds).map(({ interval_id, lower, upper }) => {
    const baseHash = createHash('sha256')
      .update(INTERIOR_DOMAIN, 'utf8')
      .update(Buffer.from([0]))
      .update(stratum.stratum_id, 'utf8')
      .update(Buffer.from([0]))
      .update(interval_id, 'utf8')
      .update(Buffer.from([0]))
      .update(inputPrefix);
    let bestDigest = null;
    let bestAmount = null;
    for (let amount = lower; amount < upper; amount += 1) {
      if (excluded.has(amount)) continue;
      const digest = baseHash
        .copy()
        .update(String(amount), 'utf8')
        .update(inputSuffix)
        .digest();
      if (bestDigest === null || Buffer.compare(digest, bestDigest) < 0) {
        bestDigest = digest;
        bestAmount = amount;
      }
    }
    if (bestDigest === null) {
      throw new Error(
        `${stratum.stratum_id} interval ${interval_id}: empty workload interior`
      );
    }
    return {
      interval_id,
      amount: bestAmount,
      interior_sha256: `sha256:${bestDigest.toString('hex')}`,
    };
  });
}

async function findAllInteriors(strata, thresholds) {
  const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
  const run = spawnSync(
    'cargo',
    [
      'run',
      '--quiet',
      '--release',
      '--manifest-path',
      'vouch/Cargo.toml',
      '--bin',
      'scored26-workload-interiors',
      '--',
      ...thresholds.map(String),
    ],
    { cwd: repoRoot, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }
  );
  if (run.status !== 0) {
    throw new Error(
      `Rust interior oracle failed\nstdout:\n${run.stdout}\nstderr:\n${run.stderr}`
    );
  }
  const output = new Map(strata.map((stratum) => [stratum.stratum_id, []]));
  for (const line of run.stdout.trim().split('\n')) {
    const [stratumId, intervalId, amount, digest] = line.split('\t');
    if (
      !output.has(stratumId) ||
      !/^[1-7]$/.test(intervalId) ||
      !/^(0|[1-9][0-9]*)$/.test(amount) ||
      !/^[0-9a-f]{64}$/.test(digest)
    ) {
      throw new Error(`malformed Rust interior-oracle record: ${line}`);
    }
    output.get(stratumId).push({
      interval_id: intervalId,
      amount: Number(amount),
      interior_sha256: `sha256:${digest}`,
    });
  }
  for (const [stratumId, interiors] of output) {
    if (interiors.length !== 7) {
      throw new Error(
        `${stratumId}: Rust interior oracle returned ${interiors.length} values`
      );
    }
  }
  return output;
}

function candidateRecord({
  candidateId,
  stratum,
  candidateClass,
  value,
  descriptor,
}) {
  const input = checkedInput(value);
  const inputBytes = writeArtifactJson(input);
  const selected = selectionDigest(
    stratum.stratum_id,
    candidateClass,
    inputBytes
  );
  return {
    candidate_id: candidateId,
    candidate_class: candidateClass,
    descriptor,
    input,
    canonical_input_sha256: digestId(inputBytes),
    selection_sha256: `sha256:${selected.toString('hex')}`,
    stratum_id: stratum.stratum_id,
  };
}

function countsByClass(records) {
  return {
    boundary: records.filter((record) => record.candidate_class === 'boundary')
      .length,
    interior: records.filter((record) => record.candidate_class === 'interior')
      .length,
    invalid: records.filter((record) => record.candidate_class === 'invalid')
      .length,
    total: records.length,
  };
}

function assertCounts(actual, expected, subject) {
  if (Object.keys(expected).some((name) => actual[name] !== expected[name])) {
    throw new Error(
      `${subject}: expected ${JSON.stringify(expected)}, observed ${JSON.stringify(actual)}`
    );
  }
}

function parseDigestId(value, subject) {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${subject}: malformed SHA-256 identifier`);
  }
  return Buffer.from(value.slice(7), 'hex');
}

function buildSourceIdentity(version, parameters, sourceBytes) {
  return {
    parameter_file: parameters.path,
    parameter_sha256: digestId(parameters.bytes),
    rule_hash_domain: RULE_HASH_DOMAIN,
    rule_sha256: domainDigestId(RULE_HASH_DOMAIN, sourceBytes),
    rule_source: `artifact/workload/rules/${version}.lspx`,
    rule_version: version,
  };
}

export async function generateFreezeArtifacts(
  repoRoot,
  {
    thresholdShift = 0,
    thresholdAdjustments = [0, 0, 0, 0, 0, 0],
    enforcePartition = true,
  } = {}
) {
  const baseline = parseParameters(repoRoot, 'baseline');
  const changed = parseParameters(repoRoot, 'changed');
  if (
    !Number.isSafeInteger(thresholdShift) ||
    !Array.isArray(thresholdAdjustments) ||
    thresholdAdjustments.length !== 6 ||
    thresholdAdjustments.some((value) => !Number.isSafeInteger(value))
  ) {
    throw new Error(
      'diagnostic threshold adjustment must contain six safe integers'
    );
  }
  if (
    thresholdShift !== 0 ||
    thresholdAdjustments.some((value) => value !== 0)
  ) {
    const adjust = (thresholds) =>
      thresholds.map(
        (value, index) => value + thresholdShift + thresholdAdjustments[index]
      );
    baseline.value = {
      ...baseline.value,
      thresholds: adjust(baseline.value.thresholds),
    };
    changed.value = {
      ...changed.value,
      thresholds: adjust(changed.value.thresholds),
    };
  }
  const thresholdUnion = [
    ...new Set([...baseline.value.thresholds, ...changed.value.thresholds]),
  ].sort((left, right) => left - right);
  if (thresholdUnion.length !== 6) {
    throw new Error(
      'the two parameter tables do not yield exactly six applicable thresholds'
    );
  }
  validateThresholds(thresholdUnion, 'threshold union');

  const sources = {
    baseline: renderRuleSource(baseline.value),
    changed: renderRuleSource(changed.value),
  };
  const identities = [
    buildSourceIdentity('baseline', baseline, sources.baseline),
    buildSourceIdentity('changed', changed, sources.changed),
  ];
  const strata = enumerateStrata();
  const thresholdRecords = thresholdUnion.map((value) => ({
    sources: [baseline, changed]
      .filter((parameters) => parameters.value.thresholds.includes(value))
      .map((parameters) => ({
        json_path: `/thresholds/${parameters.value.thresholds.indexOf(value)}`,
        rule_version: parameters.value.rule_version,
        source_file: parameters.path,
        value,
      })),
    value,
  }));
  const space = {
    amount_domain: { maximum: AMOUNT_MAX, minimum: AMOUNT_MIN },
    artifact_schema_versions: {
      checked_input: CHECKED_INPUT_TAG,
      workload_candidates: 'vouch.scored26-workload-candidates/v0',
      workload_selection: 'vouch.scored26-workload-selection/v0',
      workload_split: 'vouch.scored26-workload-split/v0',
    },
    category_codes: {
      dependents: Object.fromEntries(
        DEPENDENTS.map(([code, label]) => [String(code), label])
      ),
      household: Object.fromEntries(
        HOUSEHOLDS.map(([code, label]) => [String(code), label])
      ),
      period: Object.fromEntries(
        PERIODS.map(([code, label]) => [String(code), label])
      ),
      residency: Object.fromEntries(
        RESIDENCIES.map(([code, label]) => [String(code), label])
      ),
    },
    checked_profile: CHECKED_PROFILE,
    rule_versions: identities,
    strata: strata.map((stratum) => ({
      ...stratum,
      thresholds: thresholdRecords,
    })),
    workload_space: 'vouch.scored26-workload-space/v0',
  };
  const spaceBytes = writeArtifactJson(space);

  const interiorByStratum = await findAllInteriors(strata, thresholdUnion);
  const candidates = [];
  let candidateNumber = 0;
  const nextId = () => `C${String(++candidateNumber).padStart(4, '0')}`;
  for (const stratum of strata) {
    thresholdUnion.forEach((threshold, thresholdIndex) => {
      [-1, 0, 1].forEach((delta) => {
        candidates.push(
          candidateRecord({
            candidateId: nextId(),
            stratum,
            candidateClass: 'boundary',
            value: [...stratum.codes, threshold + delta],
            descriptor: {
              boundary_delta: delta,
              threshold_index: thresholdIndex + 1,
              threshold_value: threshold,
            },
          })
        );
      });
    });
    for (const interior of interiorByStratum.get(stratum.stratum_id)) {
      candidates.push(
        candidateRecord({
          candidateId: nextId(),
          stratum,
          candidateClass: 'interior',
          value: [...stratum.codes, interior.amount],
          descriptor: interior,
        })
      );
    }
    for (const invalid of invalidValues(stratum.codes)) {
      candidates.push(
        candidateRecord({
          candidateId: nextId(),
          stratum,
          candidateClass: 'invalid',
          value: invalid.value,
          descriptor: { invalid_id: invalid.invalid_id },
        })
      );
    }
  }
  assertCounts(
    countsByClass(candidates),
    { boundary: 864, interior: 336, invalid: 336, total: 1536 },
    'candidate quantities'
  );
  const candidateArtifact = {
    candidates,
    counts: countsByClass(candidates),
    workload_candidates: 'vouch.scored26-workload-candidates/v0',
    workload_space_sha256: digestId(spaceBytes),
  };
  const candidateBytes = writeArtifactJson(candidateArtifact);

  const selected = [];
  for (const stratum of strata) {
    const members = candidates.filter(
      (record) => record.stratum_id === stratum.stratum_id
    );
    for (const [candidateClass, quantity] of [
      ['boundary', 3],
      ['interior', 1],
      ['invalid', 1],
    ]) {
      const ranked = members
        .filter((record) => record.candidate_class === candidateClass)
        .sort((left, right) =>
          Buffer.compare(
            parseDigestId(left.selection_sha256, left.candidate_id),
            parseDigestId(right.selection_sha256, right.candidate_id)
          )
        );
      selected.push(...ranked.slice(0, quantity));
    }
  }
  assertCounts(
    countsByClass(selected),
    { boundary: 144, interior: 48, invalid: 48, total: 240 },
    'selection quantities'
  );
  const selectionArtifact = {
    counts: countsByClass(selected),
    selected,
    workload_candidates_sha256: digestId(candidateBytes),
    workload_selection: 'vouch.scored26-workload-selection/v0',
  };
  const selectionBytes = writeArtifactJson(selectionArtifact);

  const splitMembers = selected.map((record) => {
    const inputBytes = writeArtifactJson(record.input);
    const digest = splitDigest(
      parseDigestId(record.selection_sha256, record.candidate_id),
      record.stratum_id,
      inputBytes
    );
    return {
      ...record,
      split_sha256: `sha256:${digest.toString('hex')}`,
      _split_digest: digest,
    };
  });
  const heldCandidateIds = new Set();
  for (const stratum of strata) {
    const ranked = splitMembers
      .filter((record) => record.stratum_id === stratum.stratum_id)
      .sort((left, right) =>
        Buffer.compare(left._split_digest, right._split_digest)
      );
    heldCandidateIds.add(ranked[0].candidate_id);
  }
  const development = splitMembers
    .filter((record) => !heldCandidateIds.has(record.candidate_id))
    .sort((left, right) =>
      Buffer.compare(left._split_digest, right._split_digest)
    );
  const heldOut = splitMembers
    .filter((record) => heldCandidateIds.has(record.candidate_id))
    .sort((left, right) =>
      Buffer.compare(left._split_digest, right._split_digest)
    );
  const stripPrivate = ({ _split_digest, ...record }) => record;
  const cases = [
    ...development.map((record, index) => ({
      ...stripPrivate(record),
      case_id: `D${String(index + 1).padStart(3, '0')}`,
      partition: 'development',
    })),
    ...heldOut.map((record, index) => ({
      ...stripPrivate(record),
      case_id: `H${String(index + 1).padStart(3, '0')}`,
      partition: 'held-out',
    })),
  ].sort((left, right) => compareUtf8(left.case_id, right.case_id));
  const developmentCounts = countsByClass(
    cases.filter((record) => record.partition === 'development')
  );
  const heldOutCounts = countsByClass(
    cases.filter((record) => record.partition === 'held-out')
  );
  const expectedDevelopment = {
    boundary: 116,
    interior: 37,
    invalid: 39,
    total: 192,
  };
  const expectedHeldOut = { boundary: 28, interior: 11, invalid: 9, total: 48 };
  const partitionMatched =
    Object.keys(expectedDevelopment).every(
      (name) => developmentCounts[name] === expectedDevelopment[name]
    ) &&
    Object.keys(expectedHeldOut).every(
      (name) => heldOutCounts[name] === expectedHeldOut[name]
    );
  if (enforcePartition) {
    assertCounts(
      developmentCounts,
      expectedDevelopment,
      'development partition quantities'
    );
    assertCounts(
      heldOutCounts,
      expectedHeldOut,
      'held-out partition quantities'
    );
  }
  const splitArtifact = {
    cases,
    counts: { development: developmentCounts, held_out: heldOutCounts },
    workload_selection_sha256: digestId(selectionBytes),
    workload_split: 'vouch.scored26-workload-split/v0',
  };
  const splitBytes = writeArtifactJson(splitArtifact);

  const changedIntervals = baseline.value.interval_decisions
    .map((decision, index) => ({
      baseline: decision,
      changed: changed.value.interval_decisions[index],
      interval_id: String(index + 1),
    }))
    .filter((entry) => entry.baseline !== entry.changed);
  const predictedAffectedStrata =
    changedIntervals.length === 0
      ? []
      : strata.map((entry) => entry.stratum_id);
  const holdoutPlan = {
    held_out_case_ids: cases
      .filter((record) => record.partition === 'held-out')
      .map((record) => record.case_id),
    holdout_plan: 'vouch.scored26-holdout-plan/v0',
    predicted_affected_strata: predictedAffectedStrata,
    prediction: {
      changed_intervals: changedIntervals,
      protocol: 'vouch/parameter-decision-map-diff/v0',
      statement: 'Predictions are frozen before held-out execution.',
    },
    workload_split_sha256: digestId(splitBytes),
  };

  return {
    files: new Map([
      ['artifact/workload/rules/baseline.lspx', sources.baseline],
      ['artifact/workload/rules/changed.lspx', sources.changed],
      ['artifact/workload/workload-space.json', spaceBytes],
      ['artifact/workload/workload-candidates.json', candidateBytes],
      ['artifact/workload/workload-selection.json', selectionBytes],
      ['artifact/workload/workload-split.json', splitBytes],
      ['artifact/workload/holdout-plan.json', writeArtifactJson(holdoutPlan)],
    ]),
    values: {
      space,
      candidates: candidateArtifact,
      selection: selectionArtifact,
      split: splitArtifact,
      holdoutPlan,
      partitionMatched,
    },
  };
}
