export type Result<T, E> =
  | Readonly<{ ok: true; value: T }>
  | Readonly<{ ok: false; error: E }>;

export type VerificationError<C extends string> = Readonly<{ code: C }>;

export type NativeVerificationErrorCode =
  | 'artifact-resource-limit'
  | 'non-canonical-artifact-json'
  | 'native-trust-policy-invalid'
  | 'missing-native-attestation'
  | 'native-envelope-schema'
  | 'native-payload-type'
  | 'native-base64-invalid'
  | 'untrusted-native-key'
  | 'native-profile-disallowed'
  | 'native-payload-type-disallowed'
  | 'native-signature-invalid'
  | 'unsupported-native-version'
  | 'native-schema-version-below-policy'
  | 'native-receipt-schema'
  | 'native-receipt-inconsistent'
  | 'native-profile-mismatch'
  | 'native-engine-disallowed'
  | 'native-source-mismatch'
  | 'native-input-mismatch'
  | 'native-input-parse-failed'
  | 'native-input-profile-invalid';

export type BridgeVerificationErrorCode =
  | 'artifact-resource-limit'
  | 'non-canonical-artifact-json'
  | 'bridge-report-schema'
  | 'unsupported-bridge-version'
  | 'bridge-profile-mismatch'
  | 'bridge-engine-mismatch'
  | 'bridge-source-mismatch'
  | 'bridge-input-mismatch'
  | 'bridge-input-canonical-value-mismatch';

export type NativeExpectedContext = Readonly<{
  profile: string;
  source: Uint8Array;
  input: Uint8Array;
}>;

export type BridgeExpectedContext = Readonly<{
  profile: string;
  engineSha256: `sha256:${string}`;
  source: Uint8Array;
  input: Uint8Array;
  inputCanonicalValueSha256: string;
}>;

export type PromotionReason =
  | 'comparison-not-agree'
  | 'terminal-not-completed'
  | 'final-value-not-decision'
  | 'diagnostics-present'
  | 'mutant-build';

export type PromotionError =
  | Readonly<{ code: 'wrong-evidence-capability' }>
  | Readonly<{
      code: 'native-decision-promotion-ineligible';
      reason: PromotionReason;
    }>;

export type CapabilityVerificationReport =
  | Readonly<{
      authentication_status: 'authenticated';
      comparison_status: 'agree' | 'disagree' | 'not-comparable';
      decision_promotion: 'eligible' | 'ineligible';
    }>
  | Readonly<{
      authentication_status: 'rejected';
      comparison_status: null;
      decision_promotion: 'not-evaluated';
      primary_error: NativeVerificationErrorCode;
    }>;

export class WrongEvidenceCapabilityError extends TypeError {
  readonly code = 'wrong-evidence-capability' as const;

  constructor() {
    super('wrong-evidence-capability');
    this.name = 'wrong-evidence-capability';
  }
}

export function ok<T>(value: T): Result<T, never> {
  return Object.freeze({ ok: true as const, value });
}

export function err<C extends string>(
  code: C
): Result<never, VerificationError<C>> {
  return Object.freeze({ ok: false as const, error: Object.freeze({ code }) });
}
