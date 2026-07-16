//! Authenticated native verifier boundary (Stage 5).

use vouch::artifact_json::{
    canonical_gate, write_canonical, JsonGateError, JsonValue, RawArtifactKind, MAX_ARTIFACT_BYTES,
};
use vouch::dsse::{
    decode_base64_canonical, ordinary_sha256, verify_envelope, Envelope, PayloadType,
    NATIVE_PAYLOAD_TYPE,
};
use vouch::policy::{parse_native_trust_policy, PolicyError};

use super::canonical_value::{domain_hash, CanonicalValue};
use super::checked_input::{CheckedInput, CheckedInputError, MAX_INPUT_BYTES};
use super::checked_profile::{prepare_checked_program, CHECKED_PROFILE_TAG, MAX_SOURCE_BYTES};
use super::receipt::{BuildVariant, ComparisonStatus, DifferentialReceipt};
use super::structural_verify::{verify_native_intrinsic, StructuralError};
use super::transcript::{Terminal, TranscriptEvent};

pub const NATIVE_VERIFY_REPORT_TAG: &str = "csk.native-verify-report/v0";
const SOURCE_HASH_DOMAIN: &str = "csk.v0.source";
const INPUT_HASH_DOMAIN: &str = "csk.v0.input";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeVerificationError {
    ArtifactResourceLimit,
    NonCanonicalArtifactJson,
    NativeTrustPolicyInvalid,
    MissingNativeAttestation,
    NativeEnvelopeSchema,
    NativePayloadType,
    NativeBase64Invalid,
    UntrustedNativeKey,
    NativeProfileDisallowed,
    NativePayloadTypeDisallowed,
    NativeSignatureInvalid,
    UnsupportedNativeVersion,
    NativeSchemaVersionBelowPolicy,
    NativeReceiptSchema,
    NativeReceiptInconsistent,
    NativeProfileMismatch,
    NativeEngineDisallowed,
    NativeSourceMismatch,
    NativeInputMismatch,
    NativeInputParseFailed,
    NativeInputProfileInvalid,
}

impl NativeVerificationError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ArtifactResourceLimit => "artifact-resource-limit",
            Self::NonCanonicalArtifactJson => "non-canonical-artifact-json",
            Self::NativeTrustPolicyInvalid => "native-trust-policy-invalid",
            Self::MissingNativeAttestation => "missing-native-attestation",
            Self::NativeEnvelopeSchema => "native-envelope-schema",
            Self::NativePayloadType => "native-payload-type",
            Self::NativeBase64Invalid => "native-base64-invalid",
            Self::UntrustedNativeKey => "untrusted-native-key",
            Self::NativeProfileDisallowed => "native-profile-disallowed",
            Self::NativePayloadTypeDisallowed => "native-payload-type-disallowed",
            Self::NativeSignatureInvalid => "native-signature-invalid",
            Self::UnsupportedNativeVersion => "unsupported-native-version",
            Self::NativeSchemaVersionBelowPolicy => "native-schema-version-below-policy",
            Self::NativeReceiptSchema => "native-receipt-schema",
            Self::NativeReceiptInconsistent => "native-receipt-inconsistent",
            Self::NativeProfileMismatch => "native-profile-mismatch",
            Self::NativeEngineDisallowed => "native-engine-disallowed",
            Self::NativeSourceMismatch => "native-source-mismatch",
            Self::NativeInputMismatch => "native-input-mismatch",
            Self::NativeInputParseFailed => "native-input-parse-failed",
            Self::NativeInputProfileInvalid => "native-input-profile-invalid",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromotionIneligibility {
    ComparisonNotAgree,
    TerminalNotCompleted,
    FinalValueNotDecision,
    DiagnosticsPresent,
    MutantBuild,
}

impl PromotionIneligibility {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::ComparisonNotAgree => "comparison-not-agree",
            Self::TerminalNotCompleted => "terminal-not-completed",
            Self::FinalValueNotDecision => "final-value-not-decision",
            Self::DiagnosticsPresent => "diagnostics-present",
            Self::MutantBuild => "mutant-build",
        }
    }
}

/// In-process authenticated evidence. Fields remain private so a serialized
/// report can never be reconstructed into this capability.
#[derive(Clone, Debug)]
pub struct AuthenticatedNativeEvidence {
    envelope_sha256: String,
    payload_sha256: String,
    payload: Vec<u8>,
    receipt: DifferentialReceipt,
    key_id: String,
    profile: String,
}

impl AuthenticatedNativeEvidence {
    pub fn promotion_ineligibility(&self) -> Option<PromotionIneligibility> {
        let receipt = &self.receipt;
        if receipt.comparison.status != ComparisonStatus::Agree {
            return Some(PromotionIneligibility::ComparisonNotAgree);
        }
        if !matches!(receipt.reference.transcript.terminal, Terminal::Completed)
            || !matches!(receipt.meaning_env.transcript.terminal, Terminal::Completed)
        {
            return Some(PromotionIneligibility::TerminalNotCompleted);
        }
        if !matches!(
            receipt.reference.transcript.events.last(),
            Some(TranscriptEvent::Value {
                value: CanonicalValue::Decision(_),
                ..
            })
        ) {
            return Some(PromotionIneligibility::FinalValueNotDecision);
        }
        if !receipt.diagnostics.is_empty() {
            return Some(PromotionIneligibility::DiagnosticsPresent);
        }
        if receipt.execution.build_variant != BuildVariant::Release
            || receipt.execution.mutant_id.is_some()
        {
            return Some(PromotionIneligibility::MutantBuild);
        }
        None
    }

    pub fn report(&self) -> NativeVerifyReport {
        NativeVerifyReport::authenticated(self)
    }

    pub fn canonical_payload_bytes(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeVerifyReport {
    value: JsonValue,
}

impl NativeVerifyReport {
    pub fn rejected(error: NativeVerificationError) -> Self {
        Self {
            value: JsonValue::object([
                (
                    "native_verify_report",
                    JsonValue::String(NATIVE_VERIFY_REPORT_TAG.to_string()),
                ),
                (
                    "authentication_status",
                    JsonValue::String("rejected".to_string()),
                ),
                ("comparison_status", JsonValue::Null),
                (
                    "decision_promotion",
                    JsonValue::String("not-evaluated".to_string()),
                ),
                ("primary_error", JsonValue::String(error.code().to_string())),
            ])
            .expect("native rejection report fields are unique"),
        }
    }

    pub fn authenticated(evidence: &AuthenticatedNativeEvidence) -> Self {
        let receipt = &evidence.receipt;
        let comparison = match receipt.comparison.status {
            ComparisonStatus::Agree => "agree",
            ComparisonStatus::Disagree => "disagree",
            ComparisonStatus::NotComparable => "not-comparable",
        };
        let decision_promotion = if evidence.promotion_ineligibility().is_none() {
            "eligible"
        } else {
            "ineligible"
        };
        Self {
            value: JsonValue::object([
                (
                    "native_verify_report",
                    JsonValue::String(NATIVE_VERIFY_REPORT_TAG.to_string()),
                ),
                (
                    "authentication_status",
                    JsonValue::String("authenticated".to_string()),
                ),
                (
                    "comparison_status",
                    JsonValue::String(comparison.to_string()),
                ),
                (
                    "decision_promotion",
                    JsonValue::String(decision_promotion.to_string()),
                ),
                ("primary_error", JsonValue::Null),
                (
                    "envelope_sha256",
                    JsonValue::String(evidence.envelope_sha256.clone()),
                ),
                (
                    "payload_sha256",
                    JsonValue::String(evidence.payload_sha256.clone()),
                ),
                ("key_id", JsonValue::String(evidence.key_id.clone())),
                ("profile", JsonValue::String(evidence.profile.clone())),
                (
                    "engine_sha256",
                    JsonValue::String(receipt.engine.executable_sha256.clone()),
                ),
                (
                    "source_sha256",
                    JsonValue::String(receipt.source.sha256.clone()),
                ),
                (
                    "input_sha256",
                    JsonValue::String(receipt.input.sha256.clone()),
                ),
                (
                    "input_canonical_value_sha256",
                    JsonValue::String(receipt.input.canonical_value_sha256.clone()),
                ),
            ])
            .expect("native authenticated report fields are unique"),
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        write_canonical(&self.value).expect("native report contains no integers")
    }
}

/// Verify one native envelope in the exact C-VN-06 primary-error order.
pub fn verify_native(
    envelope: &[u8],
    trust_policy: &[u8],
    expected_profile: &str,
    source: &[u8],
    input: &[u8],
) -> Result<AuthenticatedNativeEvidence, NativeVerificationError> {
    // Immutable entry copies; no later caller-buffer consultation is possible.
    let envelope = envelope.to_vec();
    let trust_policy = trust_policy.to_vec();
    let expected_profile = expected_profile.to_string();
    let source = source.to_vec();
    let input = input.to_vec();

    // 1. Consolidated raw resource limits.
    if envelope.len() > MAX_ARTIFACT_BYTES
        || trust_policy.len() > MAX_ARTIFACT_BYTES
        || source.len() > MAX_SOURCE_BYTES
        || input.len() > MAX_INPUT_BYTES
    {
        return Err(NativeVerificationError::ArtifactResourceLimit);
    }

    // 2. Policy canonical gate and complete closed schema.
    let policy = parse_native_trust_policy(&trust_policy).map_err(map_policy)?;

    // 3. Generic submitted-bytes canonical JSON gate.
    let canonical_envelope =
        canonical_gate(&envelope, RawArtifactKind::Envelope).map_err(map_gate)?;

    // 4. Canonical raw receipt and Bridge report classification.
    if is_raw_artifact(canonical_envelope.value()) {
        return Err(NativeVerificationError::MissingNativeAttestation);
    }

    // 5. Closed DSSE schema.
    let parsed_envelope = Envelope::from_canonical_json(&canonical_envelope)
        .map_err(|_| NativeVerificationError::NativeEnvelopeSchema)?;

    // 6. Exact payload type and canonical base64 for payload and signature.
    if parsed_envelope.payload_type() != NATIVE_PAYLOAD_TYPE {
        return Err(NativeVerificationError::NativePayloadType);
    }
    decode_base64_canonical(parsed_envelope.payload_base64())
        .map_err(|_| NativeVerificationError::NativeBase64Invalid)?;
    decode_base64_canonical(parsed_envelope.signatures()[0].signature_base64())
        .map_err(|_| NativeVerificationError::NativeBase64Invalid)?;

    // 7. Select exactly the key named by the envelope.
    let signature = &parsed_envelope.signatures()[0];
    let selected = policy
        .select_key(signature.key_id())
        .ok_or(NativeVerificationError::UntrustedNativeKey)?;

    // 8. Expected-profile authorization is selected-key local.
    if !selected.allows_profile(&expected_profile) {
        return Err(NativeVerificationError::NativeProfileDisallowed);
    }

    // 9. Payload authorization is selected-key local.
    if !selected.allows_payload_type(parsed_envelope.payload_type()) {
        return Err(NativeVerificationError::NativePayloadTypeDisallowed);
    }

    // 10. Signature verification completes before payload parsing.
    let payload = verify_envelope(
        &parsed_envelope,
        PayloadType::NativeReceipt,
        selected.public_key(),
    )
    .map_err(|_| NativeVerificationError::NativeSignatureInvalid)?;

    // 11. Payload canonical/version/schema/intrinsic consistency.
    let canonical_payload = canonical_gate(&payload, RawArtifactKind::Payload).map_err(map_gate)?;
    let version = receipt_version(canonical_payload.value())?;
    if version < policy.minimum_versions().native_receipt {
        return Err(NativeVerificationError::NativeSchemaVersionBelowPolicy);
    }
    let receipt = verify_native_intrinsic(canonical_payload.bytes()).map_err(map_structure)?;

    // 12. Authenticated receipt profile against the already-authorized expected profile.
    if expected_profile != CHECKED_PROFILE_TAG {
        return Err(NativeVerificationError::NativeProfileMismatch);
    }

    // 13a. Engine authorization precedes all source/input context checks.
    if !selected.allows_engine(&receipt.engine.executable_sha256) {
        return Err(NativeVerificationError::NativeEngineDisallowed);
    }

    // 13b. Source raw identity and deterministic normalization.
    if receipt.source.byte_length != source.len()
        || receipt.source.sha256 != domain_hash(SOURCE_HASH_DOMAIN, &source)
    {
        return Err(NativeVerificationError::NativeSourceMismatch);
    }
    let checked_source = prepare_checked_program(&source)
        .map_err(|_| NativeVerificationError::NativeSourceMismatch)?;
    if checked_source.normalized_bytes() != receipt.canonical.normalized_bytes {
        return Err(NativeVerificationError::NativeSourceMismatch);
    }

    // 13c. Input raw identity, parse/profile class, and canonical mapped value.
    if receipt.input.byte_length != input.len()
        || receipt.input.sha256 != domain_hash(INPUT_HASH_DOMAIN, &input)
    {
        return Err(NativeVerificationError::NativeInputMismatch);
    }
    let checked_input = CheckedInput::parse(&input).map_err(map_input)?;
    if checked_input.canonical_value_digest() != receipt.input.canonical_value_sha256 {
        return Err(NativeVerificationError::NativeInputMismatch);
    }

    Ok(AuthenticatedNativeEvidence {
        envelope_sha256: ordinary_sha256(&envelope),
        payload_sha256: ordinary_sha256(&payload),
        payload,
        receipt,
        key_id: selected.key_id().to_string(),
        profile: expected_profile,
    })
}

fn is_raw_artifact(value: &JsonValue) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object
        .get("differential_receipt")
        .and_then(JsonValue::as_str)
        == Some(super::receipt::DIFFERENTIAL_RECEIPT_TAG)
        || object.get("bridge_report").and_then(JsonValue::as_str) == Some("vouch.bridge-report/v0")
}

fn receipt_version(value: &JsonValue) -> Result<usize, NativeVerificationError> {
    let discriminator = value
        .as_object()
        .and_then(|object| object.get("differential_receipt"))
        .and_then(JsonValue::as_str)
        .ok_or(NativeVerificationError::NativeReceiptSchema)?;
    if discriminator == super::receipt::DIFFERENTIAL_RECEIPT_TAG {
        return Ok(0);
    }
    if discriminator.starts_with("csk.differential-receipt/v") {
        Err(NativeVerificationError::UnsupportedNativeVersion)
    } else {
        Err(NativeVerificationError::NativeReceiptSchema)
    }
}

fn map_gate(error: JsonGateError) -> NativeVerificationError {
    match error {
        JsonGateError::ResourceLimit(_) => NativeVerificationError::ArtifactResourceLimit,
        JsonGateError::NonCanonicalArtifactJson => {
            NativeVerificationError::NonCanonicalArtifactJson
        }
    }
}

fn map_policy(error: PolicyError) -> NativeVerificationError {
    match error {
        PolicyError::ResourceLimit => NativeVerificationError::ArtifactResourceLimit,
        PolicyError::NonCanonicalArtifactJson => NativeVerificationError::NonCanonicalArtifactJson,
        PolicyError::Invalid => NativeVerificationError::NativeTrustPolicyInvalid,
    }
}

fn map_structure(error: StructuralError) -> NativeVerificationError {
    match error {
        StructuralError::ResourceLimit(_) => NativeVerificationError::ArtifactResourceLimit,
        StructuralError::NonCanonicalArtifactJson => {
            NativeVerificationError::NonCanonicalArtifactJson
        }
        StructuralError::ReceiptSchema(_) => NativeVerificationError::NativeReceiptSchema,
        _ => NativeVerificationError::NativeReceiptInconsistent,
    }
}

fn map_input(error: CheckedInputError) -> NativeVerificationError {
    match error {
        CheckedInputError::ResourceLimit => NativeVerificationError::ArtifactResourceLimit,
        CheckedInputError::ParseFailed => NativeVerificationError::NativeInputParseFailed,
        CheckedInputError::ProfileInvalid => NativeVerificationError::NativeInputProfileInvalid,
    }
}
