import { createHash } from 'node:crypto';

import {
  parseArtifactJson,
  writeArtifactJson,
} from '../artifact/scripts/artifact-json.mjs';
import {
  buildReplayManifest,
  REPLAY_CORPUS_TAG,
  REPLAY_MANIFEST_TAG,
} from '../artifact/scripts/replay-manifest-lib.mjs';
import { projectionRoot } from './source-projection-lib.mjs';

const root = projectionRoot(import.meta.url);
const generated = buildReplayManifest(root);
const valid = validate({
  corpusBytes: generated.corpusBytes,
  files: generated.files,
  payloadBytes: generated.payloadBytes,
});

let rejected = 0;
expectRejected('missing-case', ({ payload }) => payload.ordered_cases.pop());
expectRejected('duplicate-case-id', ({ payload }) => {
  payload.ordered_cases[1].case_id = payload.ordered_cases[0].case_id;
});
expectRejected('changed-corpus-input', ({ corpus }) => {
  corpus.cases[0].input = corpus.cases[1].input;
});
expectRejected('unknown-payload-field', ({ payload }) => {
  payload.unexpected = true;
});
try {
  validate({
    corpusBytes: generated.corpusBytes,
    files: generated.files,
    payloadBytes: Buffer.concat([generated.payloadBytes, Buffer.from(' ')]),
  });
  throw new Error('negative control was accepted: noncanonical-payload');
} catch (error) {
  if (error.message === 'negative control was accepted: noncanonical-payload') {
    throw error;
  }
  rejected += 1;
}
try {
  validate({
    corpusBytes: generated.corpusBytes,
    files: {
      ...generated.files,
      baselineRule: Buffer.concat([generated.files.baselineRule, Buffer.from('\n')]),
    },
    payloadBytes: generated.payloadBytes,
  });
  throw new Error('negative control was accepted: changed-rule-bytes');
} catch (error) {
  if (error.message === 'negative control was accepted: changed-rule-bytes') {
    throw error;
  }
  rejected += 1;
}

console.log(
  `portable replay-manifest check passed (${valid.caseCount} cases, ${rejected}/6 negatives rejected; Rust signature and verifier checks remain in check:full)`
);

function expectRejected(label, mutate) {
  const payload = structuredClone(generated.payload);
  const corpus = structuredClone(generated.corpus);
  mutate({ corpus, payload });
  try {
    validate({
      corpusBytes: writeArtifactJson(corpus),
      files: generated.files,
      payloadBytes: writeArtifactJson(payload),
    });
    throw new Error(`negative control was accepted: ${label}`);
  } catch (error) {
    if (error.message === `negative control was accepted: ${label}`) throw error;
    rejected += 1;
  }
}

function validate({ corpusBytes, files, payloadBytes }) {
  const payload = parseArtifactJson(payloadBytes, { canonical: true }).value;
  const corpus = parseArtifactJson(corpusBytes, { canonical: true }).value;
  exactKeys(
    payload,
    [
      'artifact_schema_versions',
      'baseline_rule_sha256',
      'changed_rule_sha256',
      'checked_profile',
      'expected_case_count',
      'holdout_plan_sha256',
      'ordered_cases',
      'replay_corpus_manifest',
      'workload_selection_sha256',
      'workload_space_sha256',
      'workload_split_sha256',
    ],
    'payload'
  );
  exactKeys(corpus, ['cases', 'replay_corpus'], 'corpus');
  exactKeys(
    payload.artifact_schema_versions,
    [
      'checked_input',
      'holdout_plan',
      'workload_selection',
      'workload_space',
      'workload_split',
    ],
    'artifact_schema_versions'
  );
  const expectedVersions = {
    checked_input: 'csk.checked-input/v1',
    holdout_plan: 'vouch.scored26-holdout-plan/v0',
    workload_selection: 'vouch.scored26-workload-selection/v0',
    workload_space: 'vouch.scored26-workload-space/v0',
    workload_split: 'vouch.scored26-workload-split/v0',
  };
  if (
    JSON.stringify(payload.artifact_schema_versions) !==
    JSON.stringify(expectedVersions)
  ) {
    throw new Error('artifact schema versions differ from the frozen set');
  }
  if (payload.replay_corpus_manifest !== REPLAY_MANIFEST_TAG) {
    throw new Error('replay manifest discriminator mismatch');
  }
  if (corpus.replay_corpus !== REPLAY_CORPUS_TAG) {
    throw new Error('replay corpus discriminator mismatch');
  }
  if (payload.checked_profile !== 'csk.checked-profile/v1') {
    throw new Error('checked profile mismatch');
  }
  if (!Array.isArray(payload.ordered_cases) || !Array.isArray(corpus.cases)) {
    throw new Error('replay cases must be arrays');
  }
  if (
    payload.expected_case_count !== 240 ||
    payload.ordered_cases.length !== 240 ||
    corpus.cases.length !== 240
  ) {
    throw new Error('replay case accounting mismatch');
  }

  const split = parseArtifactJson(files.workloadSplit, { canonical: true }).value;
  if (!Array.isArray(split.cases) || split.cases.length !== 240) {
    throw new Error('workload split accounting mismatch');
  }
  for (const bytes of [
    files.workloadSpace,
    files.workloadSelection,
    files.holdoutPlan,
  ]) {
    parseArtifactJson(bytes, { canonical: true });
  }
  const seen = new Set();
  payload.ordered_cases.forEach((record, index) => {
    exactKeys(record, ['canonical_input_sha256', 'case_id'], `ordered_cases[${index}]`);
    const corpusRecord = corpus.cases[index];
    const splitRecord = split.cases[index];
    exactKeys(corpusRecord, ['case_id', 'input'], `corpus.cases[${index}]`);
    if (
      record.case_id !== corpusRecord.case_id ||
      record.case_id !== splitRecord.case_id
    ) {
      throw new Error(`case order mismatch at ${index}`);
    }
    if (seen.has(record.case_id)) throw new Error(`duplicate case id ${record.case_id}`);
    seen.add(record.case_id);
    const inputBytes = writeArtifactJson(corpusRecord.input);
    if (!inputBytes.equals(writeArtifactJson(splitRecord.input))) {
      throw new Error(`split input mismatch at ${index}`);
    }
    const expectedInput = digestId(inputBytes);
    if (
      record.canonical_input_sha256 !== expectedInput ||
      splitRecord.canonical_input_sha256 !== expectedInput
    ) {
      throw new Error(`canonical input digest mismatch at ${index}`);
    }
  });

  const expectedDigests = {
    baseline_rule_sha256: ruleHash(files.baselineRule),
    changed_rule_sha256: ruleHash(files.changedRule),
    holdout_plan_sha256: digestId(files.holdoutPlan),
    workload_selection_sha256: digestId(files.workloadSelection),
    workload_space_sha256: digestId(files.workloadSpace),
    workload_split_sha256: digestId(files.workloadSplit),
  };
  for (const [name, expected] of Object.entries(expectedDigests)) {
    if (payload[name] !== expected) throw new Error(`${name} mismatch`);
  }
  return { caseCount: payload.ordered_cases.length };
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label}: object required`);
  }
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label}: closed schema mismatch`);
  }
}

function digestId(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function ruleHash(bytes) {
  return `sha256:${createHash('sha256')
    .update('vouch/rule-source/v0', 'utf8')
    .update(Buffer.from([0]))
    .update(bytes)
    .digest('hex')}`;
}

function compareUtf8(left, right) {
  return Buffer.from(left).compare(Buffer.from(right));
}
