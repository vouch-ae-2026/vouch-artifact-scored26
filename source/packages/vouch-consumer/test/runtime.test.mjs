import assert from 'node:assert/strict';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from 'node:crypto';
import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import vm from 'node:vm';

import { writeArtifactJson } from '../../../artifact/scripts/artifact-json.mjs';
import { canonicalGate } from '../dist/artifact-json.js';
import { graphFromNormalized, normalizeCheckedSource } from '../dist/core.js';
import { verifyExpectedInput } from '../dist/structural.js';
import {
  AuthenticatedNativeDecision,
  AuthenticatedNativeEvidence,
  CheckedBridgeEvidence,
  promoteNativeDecision,
  renderBridgeEvidence,
  renderNativeDecision,
  verifyBridgeEvidence,
  verifyNativeEvidence,
} from '../dist/index.js';

const SOURCE = Buffer.from(
  '(if (< input 10) (decision-approve) (decision-review))\n'
);
const CHECKED_INPUT = 'csk.checked-input/v1';
const INPUT = writeArtifactJson({ input: CHECKED_INPUT, value: 7 });
const PROFILE = 'csk.checked-profile/v1';
const ENGINE = `sha256:${'1'.repeat(64)}`;
const BRIDGE_SOURCE = Buffer.from('bridge source\n');
const BRIDGE_INPUT = Buffer.from('bridge input\n');
const BRIDGE_INPUT_VALUE = '2'.repeat(64);

for (const [source, normalized] of [
  ['#true\n', '(quote #t)'],
  ['#false\n', '(quote #f)'],
  ['2/4\n', '(quote 1/2)'],
  ['2/2\n', '(quote 1)'],
  ['"\\x41;\\x0a;"\n', '(quote "A\\n")'],
  ['#| outer #| nested |# comment |# 1\n', '(quote 1)'],
]) {
  assert.equal(
    Buffer.from(normalizeCheckedSource(Buffer.from(source))).toString('utf8'),
    `lispex.core.canonical/v0\n${normalized}\n`
  );
}
assert.throws(() => normalizeCheckedSource(Buffer.from('#:t0\n')));
const shadowedPrimitiveGraph = graphFromNormalized(
  normalizeCheckedSource(Buffer.from('(lambda (+) (+ 1 2))\n'))
);
assert.equal(shadowedPrimitiveGraph.nodes[2].op, 'var');
assert.equal(shadowedPrimitiveGraph.nodes[2].name, '+');

for (const rule of ['baseline.lspx', 'changed.lspx']) {
  const source = await readFile(resolve('../../artifact/workload/rules', rule));
  const normalized = normalizeCheckedSource(source);
  const graph = graphFromNormalized(normalized);
  assert.ok(
    graph.nodes.some(
      (node) => node.op === 'prim' && node.name === 'exact-integer?'
    ),
    `${rule} did not lower exact-integer? as a checked primitive`
  );
}

for (const value of [
  { $rat: { d: '0', n: '1' } },
  { $rat: { d: '1', n: '1' } },
  { $rat: { d: '2', n: '0' } },
  { $rat: { d: '4', n: '2' } },
  { $sym: 'exact-integer?' },
]) {
  assertInputProfileRejected(writeArtifactJson({ input: CHECKED_INPUT, value }));
}
assertInputAccepted(
  writeArtifactJson({
    input: CHECKED_INPUT,
    value: { $rat: { d: '2', n: '-1' } },
  }),
  { t: 'rat', n: '-1', d: '2' }
);

const prototypeKey = canonicalGate(
  Buffer.from('{\n  "__proto__": {\n    "polluted": true\n  }\n}\n')
).value;
assert.equal(Object.hasOwn(prototypeKey, '__proto__'), true);
assert.equal({}.polluted, undefined);

const fixture = nativeFixture();
const ordinaryExpected = { profile: PROFILE, source: SOURCE, input: INPUT };
const rawNative = verifyNativeEvidence(
  fixture.payload,
  fixture.policy,
  ordinaryExpected
);
assert.equal(rawNative.ok, false);
assert.equal(rawNative.error.code, 'missing-native-attestation');
const rawBridgeAsNative = verifyNativeEvidence(
  writeArtifactJson({ bridge_report: 'vouch.bridge-report/v0' }),
  fixture.policy,
  ordinaryExpected
);
assert.equal(rawBridgeAsNative.ok, false);
assert.equal(rawBridgeAsNative.error.code, 'missing-native-attestation');
const tamperedObject = JSON.parse(
  Buffer.from(fixture.envelope).toString('utf8')
);
tamperedObject.payload = `${tamperedObject.payload[0] === 'A' ? 'B' : 'A'}${tamperedObject.payload.slice(1)}`;
const tampered = verifyNativeEvidence(
  writeArtifactJson(tamperedObject),
  fixture.policy,
  ordinaryExpected
);
assert.equal(tampered.ok, false);
assert.equal(tampered.error.code, 'native-signature-invalid');

let reads = { profile: 0, source: 0, input: 0 };
const expected = Object.defineProperties(
  {},
  {
    profile: {
      enumerable: true,
      get() {
        reads.profile += 1;
        fixture.envelope.fill(0);
        fixture.policy.fill(0);
        return PROFILE;
      },
    },
    source: {
      enumerable: true,
      get() {
        reads.source += 1;
        return SOURCE;
      },
    },
    input: {
      enumerable: true,
      get() {
        reads.input += 1;
        SOURCE[0] = 0;
        return INPUT;
      },
    },
  }
);
const verified = verifyNativeEvidence(
  fixture.envelope,
  fixture.policy,
  expected
);
assert.equal(verified.ok, true);
assert.deepEqual(reads, { profile: 1, source: 1, input: 1 });
const evidence = verified.value;

fixture.envelope.fill(0);
fixture.policy.fill(0);
SOURCE.fill(0, 0, 1);
INPUT.fill(0, 0, 1);
const promoted = promoteNativeDecision(evidence);
assert.equal(promoted.ok, true);
assert.equal(
  renderNativeDecision(promoted.value),
  'Authenticated native decision'
);

const bridgeBytes = writeArtifactJson(bridgeReport());
let bridgeReads = { profile: 0, engine: 0, source: 0, input: 0, canonical: 0 };
const bridgeExpected = Object.defineProperties(
  {},
  {
    profile: {
      enumerable: true,
      get() {
        bridgeReads.profile += 1;
        bridgeBytes.fill(0);
        return PROFILE;
      },
    },
    engineSha256: {
      enumerable: true,
      get() {
        bridgeReads.engine += 1;
        return ENGINE;
      },
    },
    source: {
      enumerable: true,
      get() {
        bridgeReads.source += 1;
        return BRIDGE_SOURCE;
      },
    },
    input: {
      enumerable: true,
      get() {
        bridgeReads.input += 1;
        BRIDGE_SOURCE.fill(0);
        return BRIDGE_INPUT;
      },
    },
    inputCanonicalValueSha256: {
      enumerable: true,
      get() {
        bridgeReads.canonical += 1;
        BRIDGE_INPUT.fill(0);
        return BRIDGE_INPUT_VALUE;
      },
    },
  }
);
const bridge = verifyBridgeEvidence(bridgeBytes, bridgeExpected);
assert.equal(bridge.ok, true);
assert.deepEqual(bridgeReads, {
  profile: 1,
  engine: 1,
  source: 1,
  input: 1,
  canonical: 1,
});
assert.equal(renderBridgeEvidence(bridge.value), 'External evidence checked');
bridgeBytes.fill(0);
BRIDGE_SOURCE.fill(0);
BRIDGE_INPUT.fill(0);
assert.equal(renderBridgeEvidence(bridge.value), 'External evidence checked');

const ordinaryBridgeExpected = freshBridgeExpected();
const validBridgeBytes = writeArtifactJson(bridgeReport());
const oversizedBridge = verifyBridgeEvidence(
  new Uint8Array(16_777_217),
  ordinaryBridgeExpected
);
assert.equal(oversizedBridge.ok, false);
assert.equal(oversizedBridge.error.code, 'artifact-resource-limit');
const oversizedSource = verifyBridgeEvidence(validBridgeBytes, {
  ...ordinaryBridgeExpected,
  source: new Uint8Array(1_048_577),
});
assert.equal(oversizedSource.ok, false);
assert.equal(oversizedSource.error.code, 'artifact-resource-limit');
const compactBridge = verifyBridgeEvidence(
  Buffer.from('{"bridge_report":"vouch.bridge-report/v1"}\n'),
  ordinaryBridgeExpected
);
assert.equal(compactBridge.ok, false);
assert.equal(compactBridge.error.code, 'non-canonical-artifact-json');
assertBridgeError(
  { bridge_report: 'vouch.bridge-report/v1' },
  'unsupported-bridge-version'
);
assertBridgeError(
  { bridge_report: 'vouch.bridge-report/v01' },
  'unsupported-bridge-version'
);
assertBridgeError(
  { bridge_report: 'vouch.bridge-report/v0' },
  'bridge-report-schema'
);
assertBridgeError(
  bridgeReport({ profile: 'other.profile/v0' }),
  'bridge-profile-mismatch'
);
assertBridgeError(
  bridgeReport({ engine_sha256: `sha256:${'3'.repeat(64)}` }),
  'bridge-engine-mismatch'
);
assertBridgeError(
  bridgeReport({ source_sha256: '3'.repeat(64) }),
  'bridge-source-mismatch'
);
assertBridgeError(
  bridgeReport({ input_sha256: '3'.repeat(64) }),
  'bridge-input-mismatch'
);
assertBridgeError(
  bridgeReport({ input_canonical_value_sha256: '3'.repeat(64) }),
  'bridge-input-canonical-value-mismatch'
);
assertBridgeError({ ...bridgeReport(), extra: true }, 'bridge-report-schema');
assertBridgeError(
  bridgeReport({ comparison_status: 'disagree', decision: 'approve' }),
  'bridge-report-schema'
);
assertBridgeError(
  bridgeReport({
    diagnostics: [{ code: 'leak', message: '/private/example/key.pem' }],
  }),
  'bridge-report-schema'
);
assertBridgeError(
  { differential_receipt: 'csk.differential-receipt/v0' },
  'bridge-report-schema'
);
assertWrong(() => renderNativeDecision(bridge.value));
assertWrong(() => renderNativeDecision(evidence));
assertWrong(() => renderBridgeEvidence(bridgeReport()));
assertWrong(() => renderBridgeEvidence(validBridgeBytes));
assertWrong(() =>
  renderBridgeEvidence({
    bridge_verify_report: 'vouch.bridge-verify-report/v0',
  })
);
assertWrong(() => renderBridgeEvidence(evidence));
assertWrong(() => renderBridgeEvidence(promoted.value));
assertWrong(() => renderBridgeEvidence(new Proxy({}, {})));
assertWrong(() => renderBridgeEvidence(structuredClone(bridge.value)));

const capabilities = [
  [AuthenticatedNativeEvidence, evidence],
  [AuthenticatedNativeDecision, promoted.value],
  [CheckedBridgeEvidence, bridge.value],
];
for (const [Capability, live] of capabilities) {
  assertWrong(() => new Capability());
  assertWrong(() => Reflect.construct(Capability, []));
  class Subclass extends Capability {}
  assertWrong(() => new Subclass());
  const originalPrototype = Object.getPrototypeOf(Capability.prototype);
  Object.setPrototypeOf(Capability.prototype, {});
  assertWrong(() => new Capability());
  Object.setPrototypeOf(Capability.prototype, originalPrototype);
  const forged = Object.create(Capability.prototype);
  assertCapabilityRejected(forged);
  Object.setPrototypeOf(forged, {});
  assertCapabilityRejected(forged);
  Object.setPrototypeOf(forged, Capability.prototype);
  assertCapabilityRejected(forged);
  assert.throws(() => Object.setPrototypeOf(live, {}), TypeError);
}

assertWrongResult(promoteNativeDecision({}));
assertWrongResult(promoteNativeDecision(new Proxy({}, {})));
assertWrongResult(promoteNativeDecision(structuredClone(evidence)));
const liveAcrossRealm = vm.runInNewContext('capability', {
  capability: evidence,
});
assert.equal(promoteNativeDecision(liveAcrossRealm).ok, true);

const temporary = await mkdtemp(join(tmpdir(), 'vouch-consumer-copy-'));
try {
  await cp(resolve('dist'), temporary, { recursive: true });
  await cp(resolve('package.json'), join(temporary, 'package.json'));
  const other = await import(pathToFileURL(join(temporary, 'index.js')).href);
  const otherBridge = other.verifyBridgeEvidence(
    validBridgeBytes,
    ordinaryBridgeExpected
  );
  assert.equal(otherBridge.ok, true);
  assertWrong(() => renderBridgeEvidence(otherBridge.value));
} finally {
  await rm(temporary, { recursive: true, force: true });
}

console.log('vouch-consumer Stage 7 runtime fixtures passed');

function freshBridgeExpected() {
  return {
    profile: PROFILE,
    engineSha256: ENGINE,
    source: Buffer.from('bridge source\n'),
    input: Buffer.from('bridge input\n'),
    inputCanonicalValueSha256: BRIDGE_INPUT_VALUE,
  };
}

function bridgeReport(overrides = {}) {
  const expected = freshBridgeExpected();
  return {
    bridge_report: 'vouch.bridge-report/v0',
    profile: expected.profile,
    engine_sha256: expected.engineSha256,
    source_sha256: createHash('sha256').update(expected.source).digest('hex'),
    input_sha256: createHash('sha256').update(expected.input).digest('hex'),
    input_canonical_value_sha256: expected.inputCanonicalValueSha256,
    comparison_status: 'agree',
    decision: 'approve',
    diagnostics: [],
    ...overrides,
  };
}

function assertBridgeError(report, code) {
  const result = verifyBridgeEvidence(
    writeArtifactJson(report),
    freshBridgeExpected()
  );
  assert.equal(result.ok, false);
  assert.equal(result.error.code, code);
}

function assertInputProfileRejected(input) {
  assert.throws(
    () => verifyExpectedInput(inputReceipt(input, '0'.repeat(64)), input),
    (error) => error?.kind === 'input-profile'
  );
}

function assertInputAccepted(input, mapped) {
  assert.doesNotThrow(() =>
    verifyExpectedInput(
      inputReceipt(
        input,
        domain('csk.v0.input-canonical-value', writeArtifactJson(mapped))
      ),
      input
    )
  );
}

function inputReceipt(input, canonicalValueSha256) {
  const receipt = {
    input: {
      sha256: domain('csk.v0.input', input),
      byte_length: input.length,
      canonical_value_sha256: canonicalValueSha256,
    },
  };
  return receipt;
}

function assertCapabilityRejected(value) {
  const promotion = promoteNativeDecision(value);
  if (!promotion.ok)
    assert.equal(promotion.error.code, 'wrong-evidence-capability');
  assertWrong(() => renderNativeDecision(value));
  assertWrong(() => renderBridgeEvidence(value));
}

function assertWrongResult(result) {
  assert.equal(result.ok, false);
  assert.equal(result.error.code, 'wrong-evidence-capability');
}

function assertWrong(operation) {
  assert.throws(
    operation,
    (error) =>
      error?.code === 'wrong-evidence-capability' &&
      error?.name === 'wrong-evidence-capability'
  );
}

function nativeFixture() {
  const normalized = Buffer.from(
    'lispex.core.canonical/v0\n(if (< input (quote 10)) (decision-approve) (decision-review))\n'
  );
  const graph = {
    graph: 'csk.graph/v0',
    roots: [0],
    nodes: [
      { id: 0, op: 'if', test: 1, consequent: 5, alternate: 7 },
      { id: 1, op: 'app', operator: 2, arguments: [3, 4] },
      { id: 2, op: 'prim', name: '<' },
      { id: 3, op: 'var', name: 'input' },
      { id: 4, op: 'lit', value: { t: 'int', v: '10' } },
      { id: 5, op: 'app', operator: 6, arguments: [] },
      { id: 6, op: 'prim', name: 'decision-approve' },
      { id: 7, op: 'app', operator: 8, arguments: [] },
      { id: 8, op: 'prim', name: 'decision-review' },
    ],
  };
  const transcript = {
    transcript: 'csk.transcript/v0',
    events: [
      { kind: 'value', form_index: 0, value: { t: 'decision', v: 'approve' } },
    ],
    terminal: { kind: 'completed' },
  };
  const inputValue = { t: 'int', v: '7' };
  const inputValueDigest = domain(
    'csk.v0.input-canonical-value',
    writeArtifactJson(inputValue)
  );
  const context = {
    normalized_bytes_b64: normalized.toString('base64'),
    input_canonical_value_sha256: inputValueDigest,
    profile: PROFILE,
    engine_executable_sha256: ENGINE,
  };
  const graphDigest = domain('csk.v0.graph', writeArtifactJson(graph));
  const receipt = {
    differential_receipt: 'csk.differential-receipt/v0',
    engine: {
      executable_sha256: ENGINE,
      target_triple: 'x86_64-unknown-linux-gnu',
    },
    execution: {
      invocation: 'native-checked',
      context_digest: domain(
        'csk.v0.execution-context',
        writeArtifactJson(context)
      ),
      profile: PROFILE,
      lispex_version: '1.4.0',
      build_commit: '2'.repeat(40),
      build_variant: 'release',
      mutant_id: null,
      target_triple: 'x86_64-unknown-linux-gnu',
      executable_sha256: ENGINE,
    },
    source: {
      sha256: domain('csk.v0.source', SOURCE),
      byte_length: SOURCE.length,
    },
    input: {
      sha256: domain('csk.v0.input', INPUT),
      byte_length: INPUT.length,
      canonical_value_sha256: inputValueDigest,
    },
    canonical: {
      normalized_sha256: domain('csk.v0.canonical', normalized),
      normalized_bytes_b64: normalized.toString('base64'),
    },
    graph: {
      graph_sha256: graphDigest,
      node_count: graph.nodes.length,
      value: graph,
    },
    reference: {
      transcript_sha256: domain(
        'csk.v0.reference',
        writeArtifactJson(transcript)
      ),
      terminal: transcript.terminal,
      transcript,
    },
    meaning_env: {
      meaning_env: 'csk.meaning-env-report/v0',
      graph_sha256: graphDigest,
      transcript_sha256: domain(
        'csk.v0.meaning_env',
        writeArtifactJson(transcript)
      ),
      node_count: graph.nodes.length,
      terminal: transcript.terminal,
      transcript,
    },
    comparison: {
      status: 'agree',
      first_divergence_index: null,
      comparison_unavailable_at: null,
    },
    diagnostics: [],
    boundary: {
      statement_sha256: domain(
        'csk.v0.boundary',
        Buffer.from(
          'This receipt records structural consistency only. It is not authentication, an independent witness, or evidence of freshness. Deterministic gates may veto a result. Only a human operator gives final approval.'
        )
      ),
    },
  };
  const payload = writeArtifactJson(receipt);
  const seed = Buffer.alloc(32, 3);
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      seed,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey)
    .export({ format: 'der', type: 'spki' })
    .subarray(-32);
  const keyId = `sha256:${createHash('sha256').update('csk/native-key-id/v0').update(Buffer.of(0)).update(publicKey).digest('hex')}`;
  const payloadType = 'application/vnd.csk.differential-receipt.v0+json';
  const signature = sign(null, pae(payloadType, payload), privateKey);
  const envelope = writeArtifactJson({
    payloadType,
    payload: payload.toString('base64'),
    signatures: [{ keyid: keyId, sig: signature.toString('base64') }],
  });
  const policy = writeArtifactJson({
    trust_policy: 'csk.native-trust-policy/v0',
    minimum_versions: {
      native_receipt: 0,
      release_descriptor: 0,
      replay_corpus_manifest: 0,
      reproduction_observation: 0,
    },
    keys: [
      {
        key_id: keyId,
        algorithm: 'ed25519',
        public_key: publicKey.toString('base64'),
        allowed_payload_types: [payloadType],
        allowed_profiles: [PROFILE],
        allowed_engine_sha256: [ENGINE],
      },
    ],
  });
  return {
    envelope: Uint8Array.from(envelope),
    policy: Uint8Array.from(policy),
    payload: Uint8Array.from(payload),
  };
}

function domain(label, bytes) {
  return createHash('sha256')
    .update(label)
    .update(Buffer.of(0x1f))
    .update(bytes)
    .digest('hex');
}

function pae(payloadType, payload) {
  const type = Buffer.from(payloadType);
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `),
    type,
    Buffer.from(` ${payload.length} `),
    payload,
  ]);
}
