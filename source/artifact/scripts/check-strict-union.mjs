import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

import { writeArtifactJson } from './artifact-json.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const schema = JSON.parse(
  readFileSync(join(repoRoot, 'artifact/strict-union-schema.json'), 'utf8')
);
const ajv = new Ajv2020({ allErrors: true, strict: true });
const validateUnion = ajv.compile(schema);
const validateNative = ajv.compile(schema.$defs.native);
const validateBridge = ajv.compile(schema.$defs.bridge);

const b01 = bridgeReport();
const n02Bytes = readFileSync(
  join(repoRoot, 'artifact/mutation/activation-payloads/M01.json')
);
const n02 = JSON.parse(n02Bytes);

assert.equal(validateUnion(b01), true);
assert.equal(validateBridge(b01), true);
assert.equal(validateNative(b01), false);
assert.equal(validateUnion(n02), true);
assert.equal(validateNative(n02), true);
assert.equal(validateBridge(n02), false);

const { verifyNativeEvidence } = await import(
  pathToFileURL(join(repoRoot, 'packages/vouch-consumer/dist/index.js')).href
);
const result = verifyNativeEvidence(n02Bytes, minimalPolicy(), {
  profile: 'csk.checked-profile/v1',
  source: Buffer.alloc(0),
  input: Buffer.alloc(0),
});
assert.equal(result.ok, false);
assert.equal(result.error.code, 'missing-native-attestation');

console.log(
  'SCORED26 strict union baseline passed (B01=Bridge branch; N02=native-shaped branch)'
);

function bridgeReport() {
  return {
    bridge_report: 'vouch.bridge-report/v0',
    comparison_status: 'agree',
    decision: 'approve',
    diagnostics: [],
    engine_sha256: `sha256:${'1'.repeat(64)}`,
    input_canonical_value_sha256: '2'.repeat(64),
    input_sha256: '3'.repeat(64),
    profile: 'csk.checked-profile/v1',
    source_sha256: '4'.repeat(64),
  };
}

function minimalPolicy() {
  const publicKey = generateKeyPairSync('ed25519')
    .publicKey.export({ format: 'der', type: 'spki' })
    .subarray(-32);
  const keyId = `sha256:${createHash('sha256')
    .update('csk/native-key-id/v0')
    .update(Buffer.of(0))
    .update(publicKey)
    .digest('hex')}`;
  return writeArtifactJson({
    keys: [
      {
        algorithm: 'ed25519',
        allowed_engine_sha256: [`sha256:${'1'.repeat(64)}`],
        allowed_payload_types: [
          'application/vnd.csk.differential-receipt.v0+json',
        ],
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
  });
}
