import {
  createHash,
  createPublicKey,
  verify as verifySignature,
  type KeyObject,
} from 'node:crypto';

import {
  ArtifactJsonError,
  canonicalGate,
  exactObject,
  type JsonValue,
} from './artifact-json.js';
import {
  mintNativeEvidence,
  type AuthenticatedNativeEvidence,
  type VerifiedNativeSnapshot,
} from './evidence.js';
import {
  ContextFault,
  decodeBase64,
  domainHash,
  ordinaryHash,
  StructuralFault,
  verifyExpectedInput,
  verifyExpectedSource,
  verifyReceiptIntrinsic,
} from './structural.js';
import {
  err,
  type NativeExpectedContext,
  type NativeVerificationErrorCode,
  ok,
  type Result,
  type VerificationError,
} from './types.js';

const NATIVE_PAYLOAD_TYPE = 'application/vnd.csk.differential-receipt.v0+json';
const PAYLOAD_TYPES = new Set([
  NATIVE_PAYLOAD_TYPE,
  'application/vnd.csk.release-descriptor.v0+json',
  'application/vnd.csk.reproduction-observation.v0+json',
  'application/vnd.csk.replay-corpus-manifest.v0+json',
]);
const PROFILE = 'csk.checked-profile/v1';
const MAX_ARTIFACT = 16_777_216;
const MAX_CONTEXT = 1_048_576;

type TrustKey = Readonly<{
  keyId: string;
  publicKey: Uint8Array;
  keyObject: KeyObject;
  payloadTypes: ReadonlySet<string>;
  profiles: ReadonlySet<string>;
  engines: ReadonlySet<string>;
}>;

type Policy = Readonly<{
  minimumNativeVersion: number;
  keys: ReadonlyMap<string, TrustKey>;
}>;

type ParsedEnvelope = Readonly<{
  payloadType: string;
  payloadText: string;
  signatureText: string;
  keyId: string;
}>;

export function verifyNativeEvidence(
  envelopeBytes: Uint8Array,
  trustPolicyBytes: Uint8Array,
  expected: NativeExpectedContext
): Result<
  AuthenticatedNativeEvidence,
  VerificationError<NativeVerificationErrorCode>
> {
  // C-CAP-04: take every caller observation exactly once, then consult copies only.
  let envelope: Uint8Array;
  let trustPolicy: Uint8Array;
  let profile: string;
  let source: Uint8Array;
  let input: Uint8Array;
  try {
    envelope = Uint8Array.from(envelopeBytes);
    trustPolicy = Uint8Array.from(trustPolicyBytes);
    const observedProfile = expected.profile;
    if (typeof observedProfile !== 'string') throw new TypeError('profile');
    profile = observedProfile;
    source = Uint8Array.from(expected.source);
    input = Uint8Array.from(expected.input);
    const names = Object.keys(expected).sort();
    if (names.join('\0') !== ['input', 'profile', 'source'].join('\0')) {
      return err('native-profile-disallowed');
    }
  } catch {
    return err('native-profile-disallowed');
  }

  // 1. Consolidated raw resource ceiling.
  if (
    envelope.byteLength > MAX_ARTIFACT ||
    trustPolicy.byteLength > MAX_ARTIFACT ||
    source.byteLength > MAX_CONTEXT ||
    input.byteLength > MAX_CONTEXT
  ) {
    return err('artifact-resource-limit');
  }

  // 2. Policy canonical bytes and closed schema.
  let policy: Policy;
  try {
    policy = parsePolicy(trustPolicy);
  } catch (error) {
    if (error instanceof ArtifactJsonError) {
      return err(
        error.kind === 'resource'
          ? 'artifact-resource-limit'
          : 'non-canonical-artifact-json'
      );
    }
    return err('native-trust-policy-invalid');
  }

  // 3. Generic submitted-byte canonical gate.
  let submitted: JsonValue;
  try {
    submitted = canonicalGate(envelope).value;
  } catch (error) {
    return gateError(error);
  }

  // 4. A canonical raw receipt or Bridge report has no native attestation.
  const raw = asObject(submitted);
  if (
    raw?.differential_receipt === 'csk.differential-receipt/v0' ||
    raw?.bridge_report === 'vouch.bridge-report/v0'
  ) {
    return err('missing-native-attestation');
  }

  // 5. Closed one-signature DSSE schema.
  const parsed = parseEnvelope(submitted);
  if (!parsed) return err('native-envelope-schema');

  // 6. Exact payload type, then canonical base64 round trips.
  if (parsed.payloadType !== NATIVE_PAYLOAD_TYPE)
    return err('native-payload-type');
  let payload: Uint8Array;
  let signature: Uint8Array;
  try {
    payload = decodeBase64(parsed.payloadText);
    signature = decodeBase64(parsed.signatureText);
  } catch {
    return err('native-base64-invalid');
  }

  // 7. Key selection is exact and local.
  const selected = policy.keys.get(parsed.keyId);
  if (!selected) return err('untrusted-native-key');

  // 8. Profile authorization uses only the selected key.
  if (!selected.profiles.has(profile)) return err('native-profile-disallowed');

  // 9. Payload authorization uses only the selected key.
  if (!selected.payloadTypes.has(parsed.payloadType))
    return err('native-payload-type-disallowed');

  // 10. Signature verification completes before payload parsing.
  if (
    signature.byteLength !== 64 ||
    !verifySignature(
      null,
      pae(parsed.payloadType, payload),
      selected.keyObject,
      signature
    )
  ) {
    return err('native-signature-invalid');
  }

  // 11. Canonical payload, version floor, closed receipt, and intrinsic checks.
  let payloadValue: JsonValue;
  try {
    payloadValue = canonicalGate(payload).value;
  } catch (error) {
    return gateError(error);
  }
  const discriminator = asObject(payloadValue)?.differential_receipt;
  if (discriminator !== 'csk.differential-receipt/v0') {
    if (
      typeof discriminator === 'string' &&
      discriminator.startsWith('csk.differential-receipt/v')
    ) {
      return err('unsupported-native-version');
    }
    return err('native-receipt-schema');
  }
  if (policy.minimumNativeVersion > 0)
    return err('native-schema-version-below-policy');
  let receipt: Readonly<Record<string, JsonValue>>;
  try {
    receipt = verifyReceiptIntrinsic(payloadValue);
  } catch (error) {
    if (error instanceof StructuralFault && error.resource)
      return err('artifact-resource-limit');
    if (error instanceof StructuralFault && error.schema)
      return err('native-receipt-schema');
    return err('native-receipt-inconsistent');
  }

  // 12. The authenticated receipt profile is the checked profile in v0.
  if (profile !== PROFILE) return err('native-profile-mismatch');

  // 13a. Engine authorization precedes every context check.
  const engine = stringField(receipt.engine, 'executable_sha256');
  if (!engine || !selected.engines.has(engine))
    return err('native-engine-disallowed');

  // 13b. Source raw identity and deterministic normalization.
  try {
    verifyExpectedSource(receipt, source);
  } catch (error) {
    if (error instanceof StructuralFault && error.resource)
      return err('artifact-resource-limit');
    return err('native-source-mismatch');
  }

  // 13c. Input identity, parse/profile class, and mapped canonical value.
  try {
    verifyExpectedInput(receipt, input);
  } catch (error) {
    if (error instanceof StructuralFault && error.resource)
      return err('artifact-resource-limit');
    if (error instanceof ContextFault) {
      if (error.kind === 'input-parse') return err('native-input-parse-failed');
      if (error.kind === 'input-profile')
        return err('native-input-profile-invalid');
    }
    return err('native-input-mismatch');
  }

  const execution = asObject(receipt.execution)!;
  const inputIdentity = asObject(receipt.input)!;
  const sourceIdentity = asObject(receipt.source)!;
  const snapshot: VerifiedNativeSnapshot = {
    canonical_payload_bytes: Object.freeze(Array.from(payload)),
    receipt,
    source_sha256: String(sourceIdentity.sha256),
    input_sha256: String(inputIdentity.sha256),
    input_canonical_value_sha256: String(inputIdentity.canonical_value_sha256),
    profile,
    engine_sha256: engine,
    key_id: selected.keyId,
    build_variant: execution.build_variant as 'release' | 'mutant',
    mutant_id: execution.mutant_id as string | null,
  };
  void ordinaryHash(envelope);
  void ordinaryHash(payload);
  return ok(mintNativeEvidence(snapshot));
}

function parsePolicy(bytes: Uint8Array): Policy {
  const value = canonicalGate(bytes).value;
  const root = exactObject(value, ['trust_policy', 'minimum_versions', 'keys']);
  if (!root || root.trust_policy !== 'csk.native-trust-policy/v0')
    throw new Error('policy');
  const versions = exactObject(root.minimum_versions!, [
    'native_receipt',
    'release_descriptor',
    'replay_corpus_manifest',
    'reproduction_observation',
  ]);
  if (!versions) throw new Error('policy');
  for (const version of Object.values(versions))
    if (!isUint(version)) throw new Error('policy');
  if (!Array.isArray(root.keys) || root.keys.length === 0)
    throw new Error('policy');
  const keys = new Map<string, TrustKey>();
  const publicKeys = new Set<string>();
  for (const value of root.keys) {
    const key = exactObject(value, [
      'key_id',
      'algorithm',
      'public_key',
      'allowed_payload_types',
      'allowed_profiles',
      'allowed_engine_sha256',
    ]);
    if (
      !key ||
      key.algorithm !== 'ed25519' ||
      typeof key.key_id !== 'string' ||
      !digest(key.key_id)
    )
      throw new Error('policy');
    if (keys.has(key.key_id)) throw new Error('policy');
    let publicKey: Uint8Array;
    try {
      publicKey = decodeBase64(String(key.public_key));
    } catch {
      throw new Error('policy');
    }
    if (
      publicKey.byteLength !== 32 ||
      !validEd25519Point(publicKey) ||
      nativeKeyId(publicKey) !== key.key_id
    )
      throw new Error('policy');
    const publicText = Buffer.from(publicKey).toString('hex');
    if (publicKeys.has(publicText)) throw new Error('policy');
    publicKeys.add(publicText);
    let keyObject: KeyObject;
    try {
      keyObject = createPublicKey({
        key: Buffer.concat([
          Buffer.from('302a300506032b6570032100', 'hex'),
          Buffer.from(publicKey),
        ]),
        format: 'der',
        type: 'spki',
      });
    } catch {
      throw new Error('policy');
    }
    const payloadTypes = stringSet(key.allowed_payload_types, (item) =>
      PAYLOAD_TYPES.has(item)
    );
    const profiles = stringSet(key.allowed_profiles, profileIdentifier);
    const engines = stringSet(key.allowed_engine_sha256, digest);
    keys.set(
      key.key_id,
      Object.freeze({
        keyId: key.key_id,
        publicKey,
        keyObject,
        payloadTypes,
        profiles,
        engines,
      })
    );
  }
  return Object.freeze({
    minimumNativeVersion: versions.native_receipt as number,
    keys,
  });
}

function parseEnvelope(value: JsonValue): ParsedEnvelope | undefined {
  const root = exactObject(value, ['payloadType', 'payload', 'signatures']);
  if (
    !root ||
    typeof root.payloadType !== 'string' ||
    typeof root.payload !== 'string' ||
    !Array.isArray(root.signatures) ||
    root.signatures.length !== 1
  )
    return undefined;
  const signature = exactObject(root.signatures[0]!, ['keyid', 'sig']);
  if (
    !signature ||
    typeof signature.keyid !== 'string' ||
    typeof signature.sig !== 'string'
  )
    return undefined;
  return Object.freeze({
    payloadType: root.payloadType,
    payloadText: root.payload,
    signatureText: signature.sig,
    keyId: signature.keyid,
  });
}

function pae(payloadType: string, payload: Uint8Array): Uint8Array {
  const type = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.byteLength} `),
    type,
    Buffer.from(` ${payload.byteLength} `),
    Buffer.from(payload),
  ]);
}

function nativeKeyId(publicKey: Uint8Array): string {
  const digest = createHash('sha256')
    .update('csk/native-key-id/v0', 'utf8')
    .update(Uint8Array.of(0))
    .update(publicKey)
    .digest('hex');
  return `sha256:${digest}`;
}

function validEd25519Point(encoded: Uint8Array): boolean {
  if (encoded.byteLength !== 32) return false;
  const copy = Uint8Array.from(encoded);
  const sign = copy[31]! >>> 7;
  copy[31] &= 0x7f;
  let y = 0n;
  for (let index = 31; index >= 0; index -= 1)
    y = (y << 8n) | BigInt(copy[index]!);
  const p = (1n << 255n) - 19n;
  if (y >= p) return false;
  const d = mod(-121665n * inverse(121666n, p), p);
  const y2 = mod(y * y, p);
  const x2 = mod((y2 - 1n) * inverse(d * y2 + 1n, p), p);
  let x = power(x2, (p + 3n) / 8n, p);
  if (mod(x * x - x2, p) !== 0n) {
    const sqrtMinusOne = power(2n, (p - 1n) / 4n, p);
    x = mod(x * sqrtMinusOne, p);
  }
  if (mod(x * x - x2, p) !== 0n || (x === 0n && sign === 1)) return false;
  return true;
}

function inverse(value: bigint, modulus: bigint): bigint {
  return power(mod(value, modulus), modulus - 2n, modulus);
}

function power(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let factor = mod(base, modulus);
  let remaining = exponent;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = mod(result * factor, modulus);
    factor = mod(factor * factor, modulus);
    remaining >>= 1n;
  }
  return result;
}

function mod(value: bigint, modulus: bigint): bigint {
  const result = value % modulus;
  return result < 0n ? result + modulus : result;
}

function gateError(
  error: unknown
): Result<never, VerificationError<NativeVerificationErrorCode>> {
  if (error instanceof ArtifactJsonError && error.kind === 'resource')
    return err('artifact-resource-limit');
  return err('non-canonical-artifact-json');
}

function asObject(
  value: JsonValue | undefined
): Record<string, JsonValue> | undefined {
  return value && !Array.isArray(value) && typeof value === 'object'
    ? value
    : undefined;
}

function stringField(
  value: JsonValue | undefined,
  name: string
): string | undefined {
  const object = asObject(value);
  const member = object?.[name];
  return typeof member === 'string' ? member : undefined;
}

function stringSet(
  value: JsonValue,
  validate: (value: string) => boolean
): ReadonlySet<string> {
  if (!Array.isArray(value) || value.length === 0) throw new Error('policy');
  const result = new Set<string>();
  for (const item of value) {
    if (typeof item !== 'string' || !validate(item) || result.has(item))
      throw new Error('policy');
    result.add(item);
  }
  return result;
}

function profileIdentifier(value: string): boolean {
  return /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*\/v(?:0|[1-9][0-9]*)$/.test(value);
}
function digest(value: string): boolean {
  return /^sha256:[0-9a-f]{64}$/.test(value);
}
function isUint(value: JsonValue): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}
