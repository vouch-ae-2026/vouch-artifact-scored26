import { WrongEvidenceCapabilityError } from './types.js';

const nativeEvidenceBrand: unique symbol = Symbol(
  'AuthenticatedNativeEvidence'
);
const nativeDecisionBrand: unique symbol = Symbol(
  'AuthenticatedNativeDecision'
);
const bridgeEvidenceBrand: unique symbol = Symbol('CheckedBridgeEvidence');

const nativeEvidenceSecret = Object.freeze({});
const nativeDecisionSecret = Object.freeze({});
const bridgeEvidenceSecret = Object.freeze({});

const nativeEvidenceMembers = new WeakSet<object>();
const nativeDecisionMembers = new WeakSet<object>();
const bridgeEvidenceMembers = new WeakSet<object>();

export type CanonicalDecision = 'approve' | 'deny' | 'review' | 'invalid-input';

type ImmutableJson =
  | null
  | boolean
  | number
  | string
  | readonly ImmutableJson[]
  | Readonly<{ [key: string]: ImmutableJson }>;

export type VerifiedNativeSnapshot = Readonly<{
  canonical_payload_bytes: readonly number[];
  receipt: Readonly<Record<string, ImmutableJson>>;
  source_sha256: string;
  input_sha256: string;
  input_canonical_value_sha256: string;
  profile: string;
  engine_sha256: string;
  key_id: string;
  build_variant: 'release' | 'mutant';
  mutant_id: string | null;
}>;

export type NativeDecisionSnapshot = Readonly<{
  decision: CanonicalDecision;
}>;

export type BridgeSnapshot = Readonly<{
  canonical_report_bytes: readonly number[];
  report: Readonly<Record<string, ImmutableJson>>;
  profile: string;
  engine_sha256: string;
  source_sha256: string;
  input_sha256: string;
  input_canonical_value_sha256: string;
}>;

const nativeSnapshots = new WeakMap<object, VerifiedNativeSnapshot>();
const decisionSnapshots = new WeakMap<object, NativeDecisionSnapshot>();
const bridgeSnapshots = new WeakMap<object, BridgeSnapshot>();
const bridgeStatuses = new WeakMap<object, 'checked-external'>();

export class AuthenticatedNativeEvidence {
  declare private readonly [nativeEvidenceBrand]: void;

  constructor(token: never) {
    if ((token as unknown) !== nativeEvidenceSecret) {
      throw new WrongEvidenceCapabilityError();
    }
    Object.freeze(this);
  }
}

export class AuthenticatedNativeDecision {
  declare private readonly [nativeDecisionBrand]: void;

  constructor(token: never) {
    if ((token as unknown) !== nativeDecisionSecret) {
      throw new WrongEvidenceCapabilityError();
    }
    Object.freeze(this);
  }
}

export class CheckedBridgeEvidence {
  declare private readonly [bridgeEvidenceBrand]: void;

  constructor(token: never) {
    if ((token as unknown) !== bridgeEvidenceSecret) {
      throw new WrongEvidenceCapabilityError();
    }
    Object.freeze(this);
  }
}

export function deepImmutable<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>)) {
      deepImmutable(nested);
    }
    Object.freeze(value);
  }
  return value;
}

export function mintNativeEvidence(
  snapshot: VerifiedNativeSnapshot
): AuthenticatedNativeEvidence {
  const capability = new AuthenticatedNativeEvidence(
    nativeEvidenceSecret as never
  );
  const owned = deepImmutable(structuredClone(snapshot));
  nativeEvidenceMembers.add(capability);
  nativeSnapshots.set(capability, owned);
  return capability;
}

export function requireNativeSnapshot(value: unknown): VerifiedNativeSnapshot {
  if (
    (typeof value !== 'object' && typeof value !== 'function') ||
    value === null
  ) {
    throw new WrongEvidenceCapabilityError();
  }
  let member = false;
  try {
    member = nativeEvidenceMembers.has(value);
  } catch {
    throw new WrongEvidenceCapabilityError();
  }
  const snapshot = member ? nativeSnapshots.get(value) : undefined;
  if (!snapshot) throw new WrongEvidenceCapabilityError();
  return snapshot;
}

export function mintNativeDecision(
  decision: CanonicalDecision
): AuthenticatedNativeDecision {
  const capability = new AuthenticatedNativeDecision(
    nativeDecisionSecret as never
  );
  nativeDecisionMembers.add(capability);
  decisionSnapshots.set(capability, Object.freeze({ decision }));
  return capability;
}

export function requireNativeDecision(value: unknown): NativeDecisionSnapshot {
  if (
    (typeof value !== 'object' && typeof value !== 'function') ||
    value === null
  ) {
    throw new WrongEvidenceCapabilityError();
  }
  let member = false;
  try {
    member = nativeDecisionMembers.has(value);
  } catch {
    throw new WrongEvidenceCapabilityError();
  }
  const snapshot = member ? decisionSnapshots.get(value) : undefined;
  if (!snapshot) throw new WrongEvidenceCapabilityError();
  return snapshot;
}

export function mintBridgeEvidence(
  snapshot: BridgeSnapshot
): CheckedBridgeEvidence {
  const capability = new CheckedBridgeEvidence(bridgeEvidenceSecret as never);
  const owned = deepImmutable(structuredClone(snapshot));
  bridgeEvidenceMembers.add(capability);
  bridgeSnapshots.set(capability, owned);
  bridgeStatuses.set(capability, 'checked-external');
  return capability;
}

export function requireBridgeSnapshot(value: unknown): BridgeSnapshot {
  if (
    (typeof value !== 'object' && typeof value !== 'function') ||
    value === null
  ) {
    throw new WrongEvidenceCapabilityError();
  }
  let member = false;
  try {
    member = bridgeEvidenceMembers.has(value);
  } catch {
    throw new WrongEvidenceCapabilityError();
  }
  const snapshot = member ? bridgeSnapshots.get(value) : undefined;
  if (!snapshot || bridgeStatuses.get(value) !== 'checked-external')
    throw new WrongEvidenceCapabilityError();
  return snapshot;
}
