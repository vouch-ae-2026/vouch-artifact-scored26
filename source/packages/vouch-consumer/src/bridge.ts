import { createHash } from 'node:crypto';

import {
  ArtifactJsonError,
  canonicalGate,
  exactObject,
  type JsonValue,
} from './artifact-json.js';
import { mintBridgeEvidence, type CheckedBridgeEvidence } from './evidence.js';
import {
  err,
  type BridgeExpectedContext,
  type BridgeVerificationErrorCode,
  ok,
  type Result,
  type VerificationError,
} from './types.js';

const MAX_ARTIFACT = 16_777_216;
const MAX_CONTEXT = 1_048_576;
const PROFILE = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*\/v(?:0|[1-9][0-9]*)$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ENGINE = /^sha256:[0-9a-f]{64}$/;
const VERSION = /^vouch\.bridge-report\/v([0-9]+)$/;
const SENSITIVE_DIAGNOSTIC =
  /(?:\b(?:secret|private[- ]?key|public[- ]?key|panic)\b|(?:^|\s)\/(?:[^\s/]+\/)*[^\s/]+|\b[A-Za-z]:\\)/i;

type BridgeReport = Readonly<Record<string, JsonValue>>;

type OwnedBridgeContext = Readonly<{
  profile: string;
  engineSha256: string;
  source: Uint8Array;
  input: Uint8Array;
  inputCanonicalValueSha256: string;
}>;

/** Verify canonical external Bridge evidence against a caller-owned context. */
export function verifyBridgeEvidence(
  reportBytes: Uint8Array,
  expected: BridgeExpectedContext
): Result<
  CheckedBridgeEvidence,
  VerificationError<BridgeVerificationErrorCode>
> {
  // C-BR-03: observe every property once, then use only private entry copies.
  let reportCopy: Uint8Array;
  let context: OwnedBridgeContext;
  try {
    reportCopy = Uint8Array.from(reportBytes);
    const names = Object.keys(expected).sort();
    const profile = expected.profile;
    const engineSha256 = expected.engineSha256;
    const source = Uint8Array.from(expected.source);
    const input = Uint8Array.from(expected.input);
    const inputCanonicalValueSha256 = expected.inputCanonicalValueSha256;
    if (
      typeof profile !== 'string' ||
      typeof engineSha256 !== 'string' ||
      typeof inputCanonicalValueSha256 !== 'string' ||
      names.join('\0') !==
        [
          'engineSha256',
          'input',
          'inputCanonicalValueSha256',
          'profile',
          'source',
        ].join('\0') ||
      !PROFILE.test(profile) ||
      !ENGINE.test(engineSha256) ||
      !HEX64.test(inputCanonicalValueSha256)
    ) {
      return err('bridge-report-schema');
    }
    context = Object.freeze({
      profile,
      engineSha256,
      source,
      input,
      inputCanonicalValueSha256,
    });
  } catch {
    return err('bridge-report-schema');
  }

  // Step 1: all countable raw limits precede parsing and schema inspection.
  if (
    reportCopy.byteLength > MAX_ARTIFACT ||
    context.source.byteLength > MAX_CONTEXT ||
    context.input.byteLength > MAX_CONTEXT
  ) {
    return err('artifact-resource-limit');
  }

  // Step 2: bounded parse plus byte identity with csk.artifact-json/v0.
  let value: JsonValue;
  try {
    value = canonicalGate(reportCopy).value;
  } catch (error) {
    if (error instanceof ArtifactJsonError && error.kind === 'resource') {
      return err('artifact-resource-limit');
    }
    return err('non-canonical-artifact-json');
  }

  // Step 3 may inspect only the discriminator.
  const discriminator = discriminatorOf(value);
  if (typeof discriminator === 'string' && unsupportedVersion(discriminator)) {
    return err('unsupported-bridge-version');
  }

  // Step 4: exact nine-field schema and cross-field rules.
  const report = parseBridgeReport(value);
  if (!report) return err('bridge-report-schema');

  // Steps 5--9 consume only the immutable entry copies.
  if (report.profile !== context.profile) return err('bridge-profile-mismatch');
  if (report.engine_sha256 !== context.engineSha256)
    return err('bridge-engine-mismatch');
  const sourceSha256 = plainSha256(context.source);
  if (report.source_sha256 !== sourceSha256)
    return err('bridge-source-mismatch');
  const inputSha256 = plainSha256(context.input);
  if (report.input_sha256 !== inputSha256) return err('bridge-input-mismatch');
  if (
    report.input_canonical_value_sha256 !== context.inputCanonicalValueSha256
  ) {
    return err('bridge-input-canonical-value-mismatch');
  }

  return ok(
    mintBridgeEvidence({
      canonical_report_bytes: Object.freeze(Array.from(reportCopy)),
      report,
      profile: context.profile,
      engine_sha256: context.engineSha256,
      source_sha256: sourceSha256,
      input_sha256: inputSha256,
      input_canonical_value_sha256: context.inputCanonicalValueSha256,
    })
  );
}

function discriminatorOf(value: JsonValue): JsonValue | undefined {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    return undefined;
  }
  return value.bridge_report;
}

function parseBridgeReport(value: JsonValue): BridgeReport | undefined {
  const report = exactObject(value, [
    'bridge_report',
    'profile',
    'engine_sha256',
    'source_sha256',
    'input_sha256',
    'input_canonical_value_sha256',
    'comparison_status',
    'decision',
    'diagnostics',
  ]);
  if (
    !report ||
    report.bridge_report !== 'vouch.bridge-report/v0' ||
    typeof report.profile !== 'string' ||
    !PROFILE.test(report.profile) ||
    typeof report.engine_sha256 !== 'string' ||
    !ENGINE.test(report.engine_sha256) ||
    typeof report.source_sha256 !== 'string' ||
    !HEX64.test(report.source_sha256) ||
    typeof report.input_sha256 !== 'string' ||
    !HEX64.test(report.input_sha256) ||
    typeof report.input_canonical_value_sha256 !== 'string' ||
    !HEX64.test(report.input_canonical_value_sha256) ||
    !['agree', 'disagree', 'not-comparable'].includes(
      String(report.comparison_status)
    ) ||
    !decisionValid(report.comparison_status, report.decision) ||
    !diagnosticsValid(report.diagnostics)
  ) {
    return undefined;
  }
  return report;
}

function decisionValid(comparison: JsonValue, decision: JsonValue): boolean {
  if (comparison !== 'agree') return decision === null;
  return (
    decision === null ||
    ['approve', 'deny', 'review', 'invalid-input'].includes(String(decision))
  );
}

function diagnosticsValid(value: JsonValue): boolean {
  if (!Array.isArray(value)) return false;
  for (const item of value) {
    const diagnostic = exactObject(item, ['code', 'message']);
    if (
      !diagnostic ||
      typeof diagnostic.code !== 'string' ||
      typeof diagnostic.message !== 'string' ||
      SENSITIVE_DIAGNOSTIC.test(diagnostic.code) ||
      SENSITIVE_DIAGNOSTIC.test(diagnostic.message)
    ) {
      return false;
    }
  }
  return true;
}

function unsupportedVersion(value: string): boolean {
  const match = VERSION.exec(value);
  return Boolean(match && [...match[1]!].some((digit) => digit !== '0'));
}

function plainSha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}
