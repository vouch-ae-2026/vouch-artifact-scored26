import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { writeArtifactJson } from './artifact-json.mjs';

export const REPLAY_MANIFEST_TAG = 'csk.replay-corpus-manifest/v0';
export const REPLAY_CORPUS_TAG = 'csk.replay-corpus/v0';
export const REPLAY_PAYLOAD_TYPE =
  'application/vnd.csk.replay-corpus-manifest.v0+json';
export const NATIVE_PAYLOAD_TYPE =
  'application/vnd.csk.differential-receipt.v0+json';
const RULE_HASH_DOMAIN = 'vouch/rule-source/v0';
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest();
}

function digestId(bytes) {
  return `sha256:${sha256(bytes).toString('hex')}`;
}

function ruleHash(bytes) {
  return `sha256:${createHash('sha256')
    .update(RULE_HASH_DOMAIN, 'utf8')
    .update(Buffer.from([0]))
    .update(bytes)
    .digest('hex')}`;
}

function pae(payloadType, payload) {
  const type = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, 'ascii'),
    type,
    Buffer.from(` ${payload.length} `, 'ascii'),
    payload,
  ]);
}

function rawPublicKey(privateKey) {
  const spki = createPublicKey(privateKey).export({
    format: 'der',
    type: 'spki',
  });
  if (
    spki.length !== SPKI_ED25519_PREFIX.length + 32 ||
    !spki.subarray(0, SPKI_ED25519_PREFIX.length).equals(SPKI_ED25519_PREFIX)
  ) {
    throw new Error('unexpected Ed25519 SPKI encoding');
  }
  return spki.subarray(SPKI_ED25519_PREFIX.length);
}

function nativeKeyId(publicKey) {
  return `sha256:${createHash('sha256')
    .update('csk/native-key-id/v0', 'utf8')
    .update(Buffer.from([0]))
    .update(publicKey)
    .digest('hex')}`;
}

export function buildReplayManifest(repoRoot) {
  const read = (path) => readFileSync(join(repoRoot, path));
  const baselineRule = read('artifact/workload/rules/baseline.lspx');
  const changedRule = read('artifact/workload/rules/changed.lspx');
  const workloadSpace = read('artifact/workload/workload-space.json');
  const workloadSelection = read('artifact/workload/workload-selection.json');
  const workloadSplit = read('artifact/workload/workload-split.json');
  const holdoutPlan = read('artifact/workload/holdout-plan.json');
  const split = JSON.parse(workloadSplit);
  if (
    split?.workload_split !== 'vouch.scored26-workload-split/v0' ||
    !Array.isArray(split.cases) ||
    split.cases.length !== 240
  ) {
    throw new Error('frozen workload split has the wrong schema or case count');
  }
  const corpus = {
    cases: split.cases.map((record) => ({
      case_id: record.case_id,
      input: record.input,
    })),
    replay_corpus: REPLAY_CORPUS_TAG,
  };
  const orderedCases = corpus.cases.map((record) => {
    const canonicalInput = writeArtifactJson(record.input);
    const inputSha256 = digestId(canonicalInput);
    const splitRecord = split.cases.find(
      (entry) => entry.case_id === record.case_id
    );
    if (splitRecord.canonical_input_sha256 !== inputSha256) {
      throw new Error(
        `${record.case_id}: split input hash differs from canonical bytes`
      );
    }
    return { case_id: record.case_id, canonical_input_sha256: inputSha256 };
  });
  const payload = {
    artifact_schema_versions: {
      checked_input: 'csk.checked-input/v1',
      holdout_plan: 'vouch.scored26-holdout-plan/v0',
      workload_selection: 'vouch.scored26-workload-selection/v0',
      workload_space: 'vouch.scored26-workload-space/v0',
      workload_split: 'vouch.scored26-workload-split/v0',
    },
    baseline_rule_sha256: ruleHash(baselineRule),
    changed_rule_sha256: ruleHash(changedRule),
    checked_profile: 'csk.checked-profile/v1',
    expected_case_count: orderedCases.length,
    holdout_plan_sha256: digestId(holdoutPlan),
    ordered_cases: orderedCases,
    replay_corpus_manifest: REPLAY_MANIFEST_TAG,
    workload_selection_sha256: digestId(workloadSelection),
    workload_space_sha256: digestId(workloadSpace),
    workload_split_sha256: digestId(workloadSplit),
  };
  return {
    payload,
    payloadBytes: writeArtifactJson(payload),
    corpus,
    corpusBytes: writeArtifactJson(corpus),
    files: {
      baselineRule,
      changedRule,
      workloadSpace,
      workloadSelection,
      workloadSplit,
      holdoutPlan,
    },
  };
}

export function signReplayManifest(
  payloadBytes,
  privateKeyDer,
  allowedEngineSha256 = `sha256:${'1'.repeat(64)}`
) {
  if (!/^sha256:[0-9a-f]{64}$/.test(allowedEngineSha256)) {
    throw new Error('allowed engine digest is malformed');
  }
  const privateKey = createPrivateKey({
    key: privateKeyDer,
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = rawPublicKey(privateKey);
  const keyId = nativeKeyId(publicKey);
  const signature = signBytes(
    null,
    pae(REPLAY_PAYLOAD_TYPE, payloadBytes),
    privateKey
  );
  const envelope = {
    payload: payloadBytes.toString('base64'),
    payloadType: REPLAY_PAYLOAD_TYPE,
    signatures: [{ keyid: keyId, sig: signature.toString('base64') }],
  };
  const policy = {
    keys: [
      {
        algorithm: 'ed25519',
        allowed_engine_sha256: [allowedEngineSha256],
        allowed_payload_types: [NATIVE_PAYLOAD_TYPE, REPLAY_PAYLOAD_TYPE],
        allowed_profiles: ['csk.checked-profile/v1'],
        key_id: keyId,
        public_key: publicKey.toString('base64'),
      },
    ],
    minimum_versions: {
      native_receipt: 0,
      release_descriptor: 0,
      replay_corpus_manifest: 0,
      reproduction_observation: 0,
    },
    trust_policy: 'csk.native-trust-policy/v0',
  };
  return {
    envelope,
    envelopeBytes: writeArtifactJson(envelope),
    keyId,
    policy,
    policyBytes: writeArtifactJson(policy),
    publicKey,
  };
}

export function replaceEnvelopePayload(envelope, payloadBytes) {
  return writeArtifactJson({
    ...envelope,
    payload: payloadBytes.toString('base64'),
  });
}
