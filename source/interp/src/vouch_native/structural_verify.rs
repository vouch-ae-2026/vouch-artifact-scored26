//! No-key structural verifier for `csk.differential-receipt/v0`.

use std::collections::BTreeMap;

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Zero};
use vouch::artifact_json::{
    canonical_gate, write_canonical, JsonGateError, JsonValue, RawArtifactKind, MAX_ARTIFACT_BYTES,
    MAX_SAFE_INTEGER,
};
use vouch::dsse::decode_base64_canonical;

use crate::value::{format_real, Decision};

use super::canonical_value::{domain_hash, CanonicalValue};
use super::checked_input::{CheckedInput, CheckedInputError, MAX_INPUT_BYTES};
use super::checked_profile::{
    parse_checked_normalized_program, prepare_checked_program, CHECKED_PROFILE_TAG,
    MAX_SOURCE_BYTES,
};
use super::graph::{
    contract_graph_bytes, lower_contract_graph, validate_contract_graph, ContractGraph,
    ContractNode, GraphError, CONTRACT_GRAPH_TAG, MAX_GRAPH_NODES,
};
use super::receipt::{
    BuildVariant, ByteIdentity, CanonicalProgramIdentity, Comparison, ComparisonStatus,
    DifferentialReceipt, EngineIdentity, ExecutionIdentity, GraphReceiptValue, InputIdentity,
    MeaningEnvReport, ReceiptDiagnostic, TraceReport, DIFFERENTIAL_RECEIPT_TAG,
    MEANING_ENV_REPORT_TAG,
};
use super::transcript::{
    EvaluationPhase, InfrastructureFailureCode, LanguageFaultCode, Terminal, Transcript,
    TranscriptEvent, TRANSCRIPT_TAG,
};

pub const VERIFY_REPORT_TAG: &str = "csk.verify-report/v0";
pub const STRUCTURAL_SUCCESS_STATUS: &str = "structurally-consistent";
pub const BOUNDARY_STATEMENT: &str = "This receipt records structural consistency only. It is not authentication, an independent witness, or evidence of freshness. Deterministic gates may veto a result. Only a human operator gives final approval.";

const SOURCE_HASH_DOMAIN: &str = "csk.v0.source";
const INPUT_HASH_DOMAIN: &str = "csk.v0.input";
const NORMALIZED_HASH_DOMAIN: &str = "csk.v0.canonical";
const GRAPH_HASH_DOMAIN: &str = "csk.v0.graph";
const REFERENCE_HASH_DOMAIN: &str = "csk.v0.reference";
const MEANING_HASH_DOMAIN: &str = "csk.v0.meaning_env";
const BOUNDARY_HASH_DOMAIN: &str = "csk.v0.boundary";
const CONTEXT_HASH_DOMAIN: &str = "csk.v0.execution-context";
const MAX_INTEGER_DIGITS: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StructuralError {
    ResourceLimit(&'static str),
    NonCanonicalArtifactJson,
    ReceiptSchema(String),
    ReceiptInconsistent(String),
    ProfileMismatch,
    SourceMismatch,
    InputMismatch,
    InputParseFailed,
    InputProfileInvalid,
}

impl StructuralError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ResourceLimit(_) => "artifact-resource-limit",
            Self::NonCanonicalArtifactJson => "non-canonical-artifact-json",
            Self::ReceiptSchema(_) => "native-receipt-schema",
            Self::ReceiptInconsistent(_) => "native-receipt-inconsistent",
            Self::ProfileMismatch => "native-profile-mismatch",
            Self::SourceMismatch => "native-source-mismatch",
            Self::InputMismatch => "native-input-mismatch",
            Self::InputParseFailed => "native-input-parse-failed",
            Self::InputProfileInvalid => "native-input-profile-invalid",
        }
    }

    pub const fn subject(&self) -> Option<&'static str> {
        match self {
            Self::ResourceLimit(subject) => Some(subject),
            _ => None,
        }
    }

    fn inconsistent(message: impl Into<String>) -> Self {
        Self::ReceiptInconsistent(message.into())
    }

    fn schema(message: impl Into<String>) -> Self {
        Self::ReceiptSchema(message.into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuralReport {
    pub status: &'static str,
    pub error: Option<&'static str>,
    pub resource_subject: Option<&'static str>,
}

impl StructuralReport {
    pub const fn success() -> Self {
        Self {
            status: STRUCTURAL_SUCCESS_STATUS,
            error: None,
            resource_subject: None,
        }
    }

    pub fn rejected(error: &StructuralError) -> Self {
        Self {
            status: "rejected",
            error: Some(error.code()),
            resource_subject: error.subject(),
        }
    }

    pub fn to_json(&self) -> JsonValue {
        let mut fields = vec![
            (
                "verify_report",
                JsonValue::String(VERIFY_REPORT_TAG.to_string()),
            ),
            ("status", JsonValue::String(self.status.to_string())),
        ];
        if let Some(error) = self.error {
            fields.push(("error", JsonValue::String(error.to_string())));
        }
        if let Some(subject) = self.resource_subject {
            fields.push(("resource_subject", JsonValue::String(subject.to_string())));
        }
        JsonValue::object(fields).expect("report fields are unique")
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        write_canonical(&self.to_json()).expect("structural report integers are bounded")
    }
}

pub struct StructuralContext<'a> {
    pub input: &'a [u8],
    pub source: Option<&'a [u8]>,
    pub expected_profile: Option<&'a str>,
    pub release_signed: bool,
}

struct ParsedReceipt {
    receipt: DifferentialReceipt,
    graph_node_count: usize,
    reference_terminal: Terminal,
    meaning_terminal: Terminal,
}

/// Verify receipt structure without an envelope, key, evaluator, or live token.
pub fn verify_structure(
    receipt_bytes: &[u8],
    context: StructuralContext<'_>,
) -> Result<StructuralReport, StructuralError> {
    // A-11 step 1: all raw resource ceilings win before canonical/schema work.
    if receipt_bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(StructuralError::ResourceLimit("payload-bytes"));
    }
    if context.input.len() > MAX_INPUT_BYTES {
        return Err(StructuralError::ResourceLimit("input-bytes"));
    }
    if context
        .source
        .is_some_and(|source| source.len() > MAX_SOURCE_BYTES)
    {
        return Err(StructuralError::ResourceLimit("source-bytes"));
    }

    // Steps 2-4: canonical bytes, exact version, complete closed schema.
    let canonical = canonical_gate(receipt_bytes, RawArtifactKind::Payload).map_err(map_gate)?;
    let parsed = parse_receipt(canonical.value())?;
    let receipt = &parsed.receipt;

    // Step 5: every receipt-carried preimage digest.
    require_equal(
        &receipt.graph.graph_sha256,
        &domain_hash(
            GRAPH_HASH_DOMAIN,
            &contract_graph_bytes(&receipt.graph.graph)
                .map_err(|_| StructuralError::inconsistent("graph serialization failed"))?,
        ),
        "graph digest mismatch",
    )?;
    let reference_bytes = receipt
        .reference
        .transcript
        .canonical_bytes()
        .map_err(|_| StructuralError::inconsistent("reference transcript serialization failed"))?;
    require_equal(
        &receipt.reference.transcript_sha256,
        &domain_hash(REFERENCE_HASH_DOMAIN, &reference_bytes),
        "reference transcript digest mismatch",
    )?;
    let meaning_bytes = receipt
        .meaning_env
        .transcript
        .canonical_bytes()
        .map_err(|_| StructuralError::inconsistent("meaning transcript serialization failed"))?;
    require_equal(
        &receipt.meaning_env.transcript_sha256,
        &domain_hash(MEANING_HASH_DOMAIN, &meaning_bytes),
        "meaning transcript digest mismatch",
    )?;
    require_equal(
        &receipt.canonical.normalized_sha256,
        &domain_hash(NORMALIZED_HASH_DOMAIN, &receipt.canonical.normalized_bytes),
        "normalized digest mismatch",
    )?;
    require_equal(
        &receipt.boundary_statement_sha256,
        &domain_hash(BOUNDARY_HASH_DOMAIN, BOUNDARY_STATEMENT.as_bytes()),
        "boundary digest mismatch",
    )?;

    // Step 6: repeated fields and deterministic context binding.
    require_equal(
        &receipt.engine.target_triple,
        &receipt.execution.target_triple,
        "target triple mismatch",
    )?;
    require_equal(
        &receipt.engine.executable_sha256,
        &receipt.execution.executable_sha256,
        "executable identity mismatch",
    )?;
    if parsed.graph_node_count != receipt.graph.graph.nodes.len()
        || receipt.meaning_env.node_count != parsed.graph_node_count
        || receipt.meaning_env.graph_sha256 != receipt.graph.graph_sha256
        || parsed.reference_terminal != receipt.reference.transcript.terminal
        || parsed.meaning_terminal != receipt.meaning_env.transcript.terminal
    {
        return Err(StructuralError::inconsistent(
            "repeated receipt field mismatch",
        ));
    }
    match (
        &receipt.execution.build_variant,
        &receipt.execution.mutant_id,
    ) {
        (BuildVariant::Release, None) => {}
        (BuildVariant::Mutant, Some(mutant_id)) if !mutant_id.is_empty() => {}
        (BuildVariant::Release, Some(_)) => {
            return Err(StructuralError::inconsistent(
                "release receipt has a mutant identifier",
            ))
        }
        (BuildVariant::Mutant, _) => {
            return Err(StructuralError::inconsistent(
                "mutant receipt requires a nonempty mutant identifier",
            ))
        }
    }
    require_equal(
        &receipt.execution.context_digest,
        &execution_context_digest(receipt)?,
        "execution context digest mismatch",
    )?;

    // Steps 7-8: parse Canonical Core and re-lower; never trust-and-hash.
    let normalized = parse_checked_normalized_program(&receipt.canonical.normalized_bytes)
        .map_err(|error| match error.code {
            super::checked_profile::ProfileErrorCode::ResourceLimit => {
                StructuralError::ResourceLimit("source-bytes")
            }
            _ => StructuralError::inconsistent("normalized Core cannot be re-parsed"),
        })?;
    let fresh_graph = lower_contract_graph(normalized.core()).map_err(map_graph)?;
    let fresh_graph_bytes = contract_graph_bytes(&fresh_graph)
        .map_err(|_| StructuralError::inconsistent("fresh graph serialization failed"))?;
    let submitted_graph_bytes = contract_graph_bytes(&receipt.graph.graph)
        .map_err(|_| StructuralError::inconsistent("submitted graph serialization failed"))?;
    if fresh_graph_bytes != submitted_graph_bytes {
        return Err(StructuralError::inconsistent(
            "normalized source does not reproduce graph bytes",
        ));
    }

    // Steps 9-11: mandatory immutable external input recheck and remapping.
    if receipt.input.byte_length != context.input.len()
        || receipt.input.sha256 != domain_hash(INPUT_HASH_DOMAIN, context.input)
    {
        return Err(StructuralError::InputMismatch);
    }
    let checked_input = CheckedInput::parse(context.input).map_err(map_input)?;
    if checked_input.canonical_value_digest() != receipt.input.canonical_value_sha256 {
        return Err(StructuralError::inconsistent(
            "external input does not reproduce canonical mapped value digest",
        ));
    }

    // Step 12: optional source context, from one retained external byte copy.
    if let Some(source) = context.source {
        if receipt.source.byte_length != source.len()
            || receipt.source.sha256 != domain_hash(SOURCE_HASH_DOMAIN, source)
        {
            return Err(StructuralError::SourceMismatch);
        }
        let program =
            prepare_checked_program(source).map_err(|_| StructuralError::SourceMismatch)?;
        if program.normalized_bytes() != receipt.canonical.normalized_bytes {
            return Err(StructuralError::SourceMismatch);
        }
    }
    if context
        .expected_profile
        .is_some_and(|profile| profile != CHECKED_PROFILE_TAG)
    {
        return Err(StructuralError::ProfileMismatch);
    }

    // Steps 13-14: graph canonicality and transcript completeness.
    validate_contract_graph(&receipt.graph.graph).map_err(map_graph)?;
    let root_count = receipt.graph.graph.roots.len();
    receipt
        .reference
        .transcript
        .validate(root_count)
        .map_err(|error| StructuralError::inconsistent(error.0))?;
    receipt
        .meaning_env
        .transcript
        .validate(root_count)
        .map_err(|error| StructuralError::inconsistent(error.0))?;

    // Steps 15-16: fresh comparison, including terminal sentinels and final values.
    let comparison = compare_transcripts(
        &receipt.reference.transcript,
        &receipt.meaning_env.transcript,
    )?;
    if comparison != receipt.comparison {
        return Err(StructuralError::inconsistent(
            "recorded comparison does not match fresh transcript comparison",
        ));
    }
    if receipt.comparison.status == ComparisonStatus::Agree
        && final_value(&receipt.reference.transcript)
            != final_value(&receipt.meaning_env.transcript)
    {
        return Err(StructuralError::inconsistent(
            "different final values recorded as agree",
        ));
    }

    // Step 18 is selected only by an authenticated verification caller.
    if context.release_signed
        && (receipt.execution.build_variant != BuildVariant::Release
            || receipt.execution.mutant_id.is_some()
            || !receipt.diagnostics.is_empty())
    {
        return Err(StructuralError::inconsistent(
            "release-signed receipt violates release fields",
        ));
    }

    Ok(StructuralReport::success())
}

/// Verify only receipt-intrinsic structure after native signature validation.
///
/// Native verification deliberately performs external profile, engine, source,
/// and input checks later, in the order fixed by C-VN-06. This entry therefore
/// reuses the Stage-3 parser and all intrinsic recomputations without consulting
/// caller context and without replaying either evaluator.
pub(super) fn verify_native_intrinsic(
    receipt_bytes: &[u8],
) -> Result<DifferentialReceipt, StructuralError> {
    if receipt_bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(StructuralError::ResourceLimit("payload-bytes"));
    }
    let canonical = canonical_gate(receipt_bytes, RawArtifactKind::Payload).map_err(map_gate)?;
    let parsed = parse_receipt(canonical.value())?;
    let receipt = &parsed.receipt;

    require_equal(
        &receipt.graph.graph_sha256,
        &domain_hash(
            GRAPH_HASH_DOMAIN,
            &contract_graph_bytes(&receipt.graph.graph)
                .map_err(|_| StructuralError::inconsistent("graph serialization failed"))?,
        ),
        "graph digest mismatch",
    )?;
    let reference_bytes = receipt
        .reference
        .transcript
        .canonical_bytes()
        .map_err(|_| StructuralError::inconsistent("reference transcript serialization failed"))?;
    require_equal(
        &receipt.reference.transcript_sha256,
        &domain_hash(REFERENCE_HASH_DOMAIN, &reference_bytes),
        "reference transcript digest mismatch",
    )?;
    let meaning_bytes = receipt
        .meaning_env
        .transcript
        .canonical_bytes()
        .map_err(|_| StructuralError::inconsistent("meaning transcript serialization failed"))?;
    require_equal(
        &receipt.meaning_env.transcript_sha256,
        &domain_hash(MEANING_HASH_DOMAIN, &meaning_bytes),
        "meaning transcript digest mismatch",
    )?;
    require_equal(
        &receipt.canonical.normalized_sha256,
        &domain_hash(NORMALIZED_HASH_DOMAIN, &receipt.canonical.normalized_bytes),
        "normalized digest mismatch",
    )?;
    require_equal(
        &receipt.boundary_statement_sha256,
        &domain_hash(BOUNDARY_HASH_DOMAIN, BOUNDARY_STATEMENT.as_bytes()),
        "boundary digest mismatch",
    )?;
    require_equal(
        &receipt.engine.target_triple,
        &receipt.execution.target_triple,
        "target triple mismatch",
    )?;
    require_equal(
        &receipt.engine.executable_sha256,
        &receipt.execution.executable_sha256,
        "executable identity mismatch",
    )?;
    if parsed.graph_node_count != receipt.graph.graph.nodes.len()
        || receipt.meaning_env.node_count != parsed.graph_node_count
        || receipt.meaning_env.graph_sha256 != receipt.graph.graph_sha256
        || parsed.reference_terminal != receipt.reference.transcript.terminal
        || parsed.meaning_terminal != receipt.meaning_env.transcript.terminal
    {
        return Err(StructuralError::inconsistent(
            "repeated receipt field mismatch",
        ));
    }
    match (
        &receipt.execution.build_variant,
        &receipt.execution.mutant_id,
    ) {
        (BuildVariant::Release, None) => {}
        (BuildVariant::Mutant, Some(mutant_id)) if !mutant_id.is_empty() => {}
        (BuildVariant::Release, Some(_)) => {
            return Err(StructuralError::inconsistent(
                "release receipt has a mutant identifier",
            ))
        }
        (BuildVariant::Mutant, _) => {
            return Err(StructuralError::inconsistent(
                "mutant receipt requires a nonempty mutant identifier",
            ))
        }
    }
    require_equal(
        &receipt.execution.context_digest,
        &execution_context_digest(receipt)?,
        "execution context digest mismatch",
    )?;

    let normalized = parse_checked_normalized_program(&receipt.canonical.normalized_bytes)
        .map_err(|error| match error.code {
            super::checked_profile::ProfileErrorCode::ResourceLimit => {
                StructuralError::ResourceLimit("source-bytes")
            }
            _ => StructuralError::inconsistent("normalized Core cannot be re-parsed"),
        })?;
    let fresh_graph = lower_contract_graph(normalized.core()).map_err(map_graph)?;
    let fresh_graph_bytes = contract_graph_bytes(&fresh_graph)
        .map_err(|_| StructuralError::inconsistent("fresh graph serialization failed"))?;
    let submitted_graph_bytes = contract_graph_bytes(&receipt.graph.graph)
        .map_err(|_| StructuralError::inconsistent("submitted graph serialization failed"))?;
    if fresh_graph_bytes != submitted_graph_bytes {
        return Err(StructuralError::inconsistent(
            "normalized source does not reproduce graph bytes",
        ));
    }

    validate_contract_graph(&receipt.graph.graph).map_err(map_graph)?;
    let root_count = receipt.graph.graph.roots.len();
    receipt
        .reference
        .transcript
        .validate(root_count)
        .map_err(|error| StructuralError::inconsistent(error.0))?;
    receipt
        .meaning_env
        .transcript
        .validate(root_count)
        .map_err(|error| StructuralError::inconsistent(error.0))?;
    let comparison = compare_transcripts(
        &receipt.reference.transcript,
        &receipt.meaning_env.transcript,
    )?;
    if comparison != receipt.comparison {
        return Err(StructuralError::inconsistent(
            "recorded comparison does not match fresh transcript comparison",
        ));
    }
    if receipt.comparison.status == ComparisonStatus::Agree
        && final_value(&receipt.reference.transcript)
            != final_value(&receipt.meaning_env.transcript)
    {
        return Err(StructuralError::inconsistent(
            "different final values recorded as agree",
        ));
    }

    Ok(parsed.receipt)
}

fn map_gate(error: JsonGateError) -> StructuralError {
    match error {
        JsonGateError::NonCanonicalArtifactJson => StructuralError::NonCanonicalArtifactJson,
        JsonGateError::ResourceLimit(subject) => StructuralError::ResourceLimit(subject),
    }
}

fn map_input(error: CheckedInputError) -> StructuralError {
    match error {
        CheckedInputError::ResourceLimit => StructuralError::ResourceLimit("input-value"),
        CheckedInputError::ParseFailed => StructuralError::InputParseFailed,
        CheckedInputError::ProfileInvalid => StructuralError::InputProfileInvalid,
    }
}

fn map_graph(error: GraphError) -> StructuralError {
    match error {
        GraphError::ResourceLimit => StructuralError::ResourceLimit("graph-nodes"),
        GraphError::ProfileEscape(message) | GraphError::Invalid(message) => {
            StructuralError::inconsistent(message)
        }
    }
}

fn require_equal<T: PartialEq>(left: &T, right: &T, message: &str) -> Result<(), StructuralError> {
    if left == right {
        Ok(())
    } else {
        Err(StructuralError::inconsistent(message))
    }
}

fn execution_context_digest(receipt: &DifferentialReceipt) -> Result<String, StructuralError> {
    let context = JsonValue::object([
        (
            "normalized_bytes_b64",
            JsonValue::String(vouch::dsse::encode_base64(
                &receipt.canonical.normalized_bytes,
            )),
        ),
        (
            "input_canonical_value_sha256",
            JsonValue::String(receipt.input.canonical_value_sha256.clone()),
        ),
        (
            "profile",
            JsonValue::String(CHECKED_PROFILE_TAG.to_string()),
        ),
        (
            "engine_executable_sha256",
            JsonValue::String(receipt.execution.executable_sha256.clone()),
        ),
    ])
    .expect("context fields are unique");
    let bytes = write_canonical(&context)
        .map_err(|_| StructuralError::inconsistent("execution context serialization failed"))?;
    Ok(domain_hash(CONTEXT_HASH_DOMAIN, &bytes))
}

fn compare_transcripts(
    reference: &Transcript,
    meaning: &Transcript,
) -> Result<Comparison, StructuralError> {
    let reference_infra = infrastructure_index(&reference.terminal);
    let meaning_infra = infrastructure_index(&meaning.terminal);
    if reference_infra.is_some() || meaning_infra.is_some() {
        return Ok(Comparison {
            status: ComparisonStatus::NotComparable,
            first_divergence_index: None,
            comparison_unavailable_at: reference_infra.into_iter().chain(meaning_infra).min(),
        });
    }
    let left = reference
        .canonical_bytes()
        .map_err(|_| StructuralError::inconsistent("reference transcript serialization failed"))?;
    let right = meaning
        .canonical_bytes()
        .map_err(|_| StructuralError::inconsistent("meaning transcript serialization failed"))?;
    if left == right {
        Ok(Comparison {
            status: ComparisonStatus::Agree,
            first_divergence_index: None,
            comparison_unavailable_at: None,
        })
    } else {
        Ok(Comparison {
            status: ComparisonStatus::Disagree,
            first_divergence_index: Some(first_divergence(reference, meaning)),
            comparison_unavailable_at: None,
        })
    }
}

fn infrastructure_index(terminal: &Terminal) -> Option<usize> {
    match terminal {
        Terminal::InfrastructureFailure {
            next_form_index, ..
        } => Some(*next_form_index),
        _ => None,
    }
}

fn first_divergence(left: &Transcript, right: &Transcript) -> usize {
    let shared = left.events.len().min(right.events.len());
    for index in 0..shared {
        if left.events[index] != right.events[index] {
            return index;
        }
    }
    if left.events.len() != right.events.len() {
        shared
    } else {
        left.events.len()
    }
}

fn final_value(transcript: &Transcript) -> Option<&CanonicalValue> {
    transcript.events.last().and_then(|event| match event {
        TranscriptEvent::Value { value, .. } => Some(value),
        TranscriptEvent::Output { .. } => None,
    })
}

fn parse_receipt(value: &JsonValue) -> Result<ParsedReceipt, StructuralError> {
    let object = exact_object(
        value,
        &[
            "differential_receipt",
            "engine",
            "execution",
            "source",
            "input",
            "canonical",
            "graph",
            "reference",
            "meaning_env",
            "comparison",
            "diagnostics",
            "boundary",
        ],
    )?;
    require_string(object, "differential_receipt", DIFFERENTIAL_RECEIPT_TAG)?;

    let engine_object = exact_object(
        field(object, "engine")?,
        &["executable_sha256", "target_triple"],
    )?;
    let engine = EngineIdentity {
        executable_sha256: executable_digest(field_string(engine_object, "executable_sha256")?)?,
        target_triple: field_string(engine_object, "target_triple")?.to_string(),
    };

    let execution_object = exact_object(
        field(object, "execution")?,
        &[
            "invocation",
            "context_digest",
            "profile",
            "lispex_version",
            "build_commit",
            "build_variant",
            "mutant_id",
            "target_triple",
            "executable_sha256",
        ],
    )?;
    require_string(execution_object, "invocation", "native-checked")?;
    require_string(execution_object, "profile", CHECKED_PROFILE_TAG)?;
    let build_variant = match field_string(execution_object, "build_variant")? {
        "release" => BuildVariant::Release,
        "mutant" => BuildVariant::Mutant,
        _ => return Err(StructuralError::schema("unknown build variant")),
    };
    let mutant_id = optional_string(field(execution_object, "mutant_id")?)?;
    let execution = ExecutionIdentity {
        context_digest: hex64(field_string(execution_object, "context_digest")?)?,
        lispex_version: field_string(execution_object, "lispex_version")?.to_string(),
        build_commit: hex40(field_string(execution_object, "build_commit")?)?,
        build_variant,
        mutant_id,
        target_triple: field_string(execution_object, "target_triple")?.to_string(),
        executable_sha256: executable_digest(field_string(execution_object, "executable_sha256")?)?,
    };

    let source = parse_byte_identity(field(object, "source")?)?;
    let input_object = exact_object(
        field(object, "input")?,
        &["sha256", "byte_length", "canonical_value_sha256"],
    )?;
    let input = InputIdentity {
        sha256: hex64(field_string(input_object, "sha256")?)?,
        byte_length: field_uint(input_object, "byte_length")?,
        canonical_value_sha256: hex64(field_string(input_object, "canonical_value_sha256")?)?,
    };

    let canonical_object = exact_object(
        field(object, "canonical")?,
        &["normalized_sha256", "normalized_bytes_b64"],
    )?;
    let normalized_bytes =
        decode_base64_canonical(field_string(canonical_object, "normalized_bytes_b64")?)
            .map_err(|_| StructuralError::schema("normalized bytes are not canonical base64"))?;
    let canonical = CanonicalProgramIdentity {
        normalized_sha256: hex64(field_string(canonical_object, "normalized_sha256")?)?,
        normalized_bytes,
    };

    let graph_object = exact_object(
        field(object, "graph")?,
        &["graph_sha256", "node_count", "value"],
    )?;
    let graph_node_count = field_uint(graph_object, "node_count")?;
    let graph = GraphReceiptValue {
        graph_sha256: hex64(field_string(graph_object, "graph_sha256")?)?,
        graph: parse_graph(field(graph_object, "value")?)?,
    };

    let reference_object = exact_object(
        field(object, "reference")?,
        &["transcript_sha256", "terminal", "transcript"],
    )?;
    let reference_terminal = parse_terminal(field(reference_object, "terminal")?)?;
    let reference = TraceReport {
        transcript_sha256: hex64(field_string(reference_object, "transcript_sha256")?)?,
        transcript: parse_transcript(field(reference_object, "transcript")?)?,
    };

    let meaning_object = exact_object(
        field(object, "meaning_env")?,
        &[
            "meaning_env",
            "graph_sha256",
            "transcript_sha256",
            "node_count",
            "terminal",
            "transcript",
        ],
    )?;
    require_string(meaning_object, "meaning_env", MEANING_ENV_REPORT_TAG)?;
    let meaning_terminal = parse_terminal(field(meaning_object, "terminal")?)?;
    let meaning_env = MeaningEnvReport {
        graph_sha256: hex64(field_string(meaning_object, "graph_sha256")?)?,
        transcript_sha256: hex64(field_string(meaning_object, "transcript_sha256")?)?,
        node_count: field_uint(meaning_object, "node_count")?,
        transcript: parse_transcript(field(meaning_object, "transcript")?)?,
    };

    let comparison_object = exact_object(
        field(object, "comparison")?,
        &[
            "status",
            "first_divergence_index",
            "comparison_unavailable_at",
        ],
    )?;
    let status = match field_string(comparison_object, "status")? {
        "agree" => ComparisonStatus::Agree,
        "disagree" => ComparisonStatus::Disagree,
        "not-comparable" => ComparisonStatus::NotComparable,
        _ => return Err(StructuralError::schema("unknown comparison status")),
    };
    let comparison = Comparison {
        status,
        first_divergence_index: optional_uint(field(comparison_object, "first_divergence_index")?)?,
        comparison_unavailable_at: optional_uint(field(
            comparison_object,
            "comparison_unavailable_at",
        )?)?,
    };

    let diagnostics = field(object, "diagnostics")?
        .as_array()
        .ok_or_else(|| StructuralError::schema("diagnostics is not an array"))?
        .iter()
        .map(|value| {
            let object = exact_object(value, &["code", "message"])?;
            Ok(ReceiptDiagnostic {
                code: field_string(object, "code")?.to_string(),
                message: field_string(object, "message")?.to_string(),
            })
        })
        .collect::<Result<Vec<_>, StructuralError>>()?;
    let boundary_object = exact_object(field(object, "boundary")?, &["statement_sha256"])?;
    let boundary_statement_sha256 = hex64(field_string(boundary_object, "statement_sha256")?)?;

    Ok(ParsedReceipt {
        receipt: DifferentialReceipt {
            engine,
            execution,
            source,
            input,
            canonical,
            graph,
            reference,
            meaning_env,
            comparison,
            diagnostics,
            boundary_statement_sha256,
        },
        graph_node_count,
        reference_terminal,
        meaning_terminal,
    })
}

fn parse_byte_identity(value: &JsonValue) -> Result<ByteIdentity, StructuralError> {
    let object = exact_object(value, &["sha256", "byte_length"])?;
    Ok(ByteIdentity {
        sha256: hex64(field_string(object, "sha256")?)?,
        byte_length: field_uint(object, "byte_length")?,
    })
}

fn parse_graph(value: &JsonValue) -> Result<ContractGraph, StructuralError> {
    let object = exact_object(value, &["graph", "roots", "nodes"])?;
    require_string(object, "graph", CONTRACT_GRAPH_TAG)?;
    let roots = uint_array(field(object, "roots")?)?;
    let node_values = field(object, "nodes")?
        .as_array()
        .ok_or_else(|| StructuralError::schema("graph nodes is not an array"))?;
    if node_values.len() > MAX_GRAPH_NODES {
        return Err(StructuralError::ResourceLimit("graph-nodes"));
    }
    let nodes = node_values
        .iter()
        .enumerate()
        .map(|(expected, value)| parse_node(expected, value))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ContractGraph { roots, nodes })
}

fn parse_node(expected_id: usize, value: &JsonValue) -> Result<ContractNode, StructuralError> {
    let base = value
        .as_object()
        .ok_or_else(|| StructuralError::schema("graph node is not an object"))?;
    if field_uint(base, "id")? != expected_id {
        return Err(StructuralError::inconsistent("graph node id mismatch"));
    }
    let op = field_string(base, "op")?;
    match op {
        "lit" => {
            let object = exact_object(value, &["id", "op", "value"])?;
            Ok(ContractNode::Lit {
                value: parse_canonical_value(field(object, "value")?)?,
            })
        }
        "var" => {
            let object = exact_object(value, &["id", "op", "name"])?;
            Ok(ContractNode::Var {
                name: field_string(object, "name")?.to_string(),
            })
        }
        "lambda" => {
            let object = exact_object(value, &["id", "op", "params", "body"])?;
            Ok(ContractNode::Lambda {
                params: string_array(field(object, "params")?)?,
                body: field_uint(object, "body")?,
            })
        }
        "app" => {
            let object = exact_object(value, &["id", "op", "operator", "arguments"])?;
            Ok(ContractNode::App {
                operator: field_uint(object, "operator")?,
                arguments: uint_array(field(object, "arguments")?)?,
            })
        }
        "if" => {
            let object = exact_object(value, &["id", "op", "test", "consequent", "alternate"])?;
            Ok(ContractNode::If {
                test: field_uint(object, "test")?,
                consequent: field_uint(object, "consequent")?,
                alternate: field_uint(object, "alternate")?,
            })
        }
        "begin" => {
            let object = exact_object(value, &["id", "op", "forms"])?;
            Ok(ContractNode::Begin {
                forms: uint_array(field(object, "forms")?)?,
            })
        }
        "let" => {
            let object = exact_object(value, &["id", "op", "names", "initializers", "body"])?;
            Ok(ContractNode::Let {
                names: string_array(field(object, "names")?)?,
                initializers: uint_array(field(object, "initializers")?)?,
                body: field_uint(object, "body")?,
            })
        }
        "define" => {
            let object = exact_object(value, &["id", "op", "name", "value"])?;
            Ok(ContractNode::Define {
                name: field_string(object, "name")?.to_string(),
                value: field_uint(object, "value")?,
            })
        }
        "prim" => {
            let object = exact_object(value, &["id", "op", "name"])?;
            Ok(ContractNode::Prim {
                name: field_string(object, "name")?.to_string(),
            })
        }
        _ => Err(StructuralError::schema("unknown graph operation")),
    }
}

fn parse_transcript(value: &JsonValue) -> Result<Transcript, StructuralError> {
    let object = exact_object(value, &["transcript", "events", "terminal"])?;
    require_string(object, "transcript", TRANSCRIPT_TAG)?;
    let events = field(object, "events")?
        .as_array()
        .ok_or_else(|| StructuralError::schema("transcript events is not an array"))?
        .iter()
        .map(parse_event)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Transcript {
        events,
        terminal: parse_terminal(field(object, "terminal")?)?,
    })
}

fn parse_event(value: &JsonValue) -> Result<TranscriptEvent, StructuralError> {
    let object = value
        .as_object()
        .ok_or_else(|| StructuralError::schema("transcript event is not an object"))?;
    match field_string(object, "kind")? {
        "output" => {
            let object = exact_object(value, &["kind", "form_index", "bytes_b64"])?;
            let bytes_b64 = field_string(object, "bytes_b64")?.to_string();
            decode_base64_canonical(&bytes_b64)
                .map_err(|_| StructuralError::schema("output event base64 is invalid"))?;
            Ok(TranscriptEvent::Output {
                form_index: field_uint(object, "form_index")?,
                bytes_b64,
            })
        }
        "value" => {
            let object = exact_object(value, &["kind", "form_index", "value"])?;
            Ok(TranscriptEvent::Value {
                form_index: field_uint(object, "form_index")?,
                value: parse_canonical_value(field(object, "value")?)?,
            })
        }
        _ => Err(StructuralError::schema("unknown transcript event kind")),
    }
}

fn parse_terminal(value: &JsonValue) -> Result<Terminal, StructuralError> {
    let object = value
        .as_object()
        .ok_or_else(|| StructuralError::schema("terminal is not an object"))?;
    match field_string(object, "kind")? {
        "completed" => {
            exact_object(value, &["kind"])?;
            Ok(Terminal::Completed)
        }
        "language-fault" => {
            let object = exact_object(value, &["kind", "code", "form_index"])?;
            let code = match field_string(object, "code")? {
                "arity-mismatch" => LanguageFaultCode::ArityMismatch,
                "type-error" => LanguageFaultCode::TypeError,
                "division-by-zero" => LanguageFaultCode::DivisionByZero,
                "numeric-domain-error" => LanguageFaultCode::NumericDomainError,
                "reference-budget-exhausted" => LanguageFaultCode::ReferenceBudgetExhausted,
                "meaning-env-budget-exhausted" => LanguageFaultCode::MeaningEnvBudgetExhausted,
                _ => return Err(StructuralError::schema("unknown language fault code")),
            };
            Ok(Terminal::LanguageFault {
                code,
                form_index: field_uint(object, "form_index")?,
            })
        }
        "infrastructure-failure" => {
            let object = exact_object(value, &["kind", "code", "phase", "next_form_index"])?;
            let code = match field_string(object, "code")? {
                "native-reference-execution-failed" => {
                    InfrastructureFailureCode::ReferenceExecutionFailed
                }
                "native-meaning-execution-failed" => {
                    InfrastructureFailureCode::MeaningExecutionFailed
                }
                _ => {
                    return Err(StructuralError::schema(
                        "unknown infrastructure failure code",
                    ))
                }
            };
            let phase = match field_string(object, "phase")? {
                "reference-evaluation" => EvaluationPhase::Reference,
                "meaning-evaluation" => EvaluationPhase::Meaning,
                _ => return Err(StructuralError::schema("unknown evaluation phase")),
            };
            if !matches!(
                (code, phase),
                (
                    InfrastructureFailureCode::ReferenceExecutionFailed,
                    EvaluationPhase::Reference
                ) | (
                    InfrastructureFailureCode::MeaningExecutionFailed,
                    EvaluationPhase::Meaning
                )
            ) {
                return Err(StructuralError::inconsistent(
                    "infrastructure failure code/phase mismatch",
                ));
            }
            Ok(Terminal::InfrastructureFailure {
                code,
                phase,
                next_form_index: field_uint(object, "next_form_index")?,
            })
        }
        _ => Err(StructuralError::schema("unknown terminal kind")),
    }
}

fn parse_canonical_value(value: &JsonValue) -> Result<CanonicalValue, StructuralError> {
    let object = value
        .as_object()
        .ok_or_else(|| StructuralError::schema("canonical value is not an object"))?;
    match field_string(object, "t")? {
        "int" => {
            let object = exact_object(value, &["t", "v"])?;
            let text = canonical_integer(field_string(object, "v")?, true)?;
            Ok(CanonicalValue::Integer(text))
        }
        "rat" => {
            let object = exact_object(value, &["t", "n", "d"])?;
            let numerator = canonical_integer(field_string(object, "n")?, true)?;
            let denominator = canonical_integer(field_string(object, "d")?, false)?;
            let n = numerator
                .parse::<BigInt>()
                .map_err(|_| StructuralError::schema("rational numerator invalid"))?;
            let d = denominator
                .parse::<BigInt>()
                .map_err(|_| StructuralError::schema("rational denominator invalid"))?;
            if d <= BigInt::zero()
                || n.gcd(&d) != BigInt::one()
                || (n.is_zero() && d != BigInt::one())
            {
                return Err(StructuralError::schema("rational is not canonical"));
            }
            Ok(CanonicalValue::Rational {
                numerator,
                denominator,
            })
        }
        "real" => {
            let object = exact_object(value, &["t", "v"])?;
            let text = field_string(object, "v")?;
            let parsed = text
                .parse::<f64>()
                .map_err(|_| StructuralError::schema("real is invalid"))?;
            if !parsed.is_finite() || format_real(parsed) != text {
                return Err(StructuralError::schema("real is not canonical"));
            }
            Ok(CanonicalValue::Real(text.to_string()))
        }
        "bool" => {
            let object = exact_object(value, &["t", "v"])?;
            let JsonValue::Bool(value) = field(object, "v")? else {
                return Err(StructuralError::schema("boolean value is invalid"));
            };
            Ok(CanonicalValue::Boolean(*value))
        }
        "nil" => {
            exact_object(value, &["t"])?;
            Ok(CanonicalValue::Nil)
        }
        "list" => {
            let object = exact_object(value, &["t", "items", "improper_tail"])?;
            let items = field(object, "items")?
                .as_array()
                .ok_or_else(|| StructuralError::schema("list items is not an array"))?
                .iter()
                .map(parse_canonical_value)
                .collect::<Result<Vec<_>, _>>()?;
            let improper_tail = match field(object, "improper_tail")? {
                JsonValue::Null => None,
                value => Some(Box::new(parse_canonical_value(value)?)),
            };
            Ok(CanonicalValue::List {
                items,
                improper_tail,
            })
        }
        "sym" => {
            let object = exact_object(value, &["t", "v"])?;
            Ok(CanonicalValue::Symbol(
                field_string(object, "v")?.to_string(),
            ))
        }
        "str" => {
            let object = exact_object(value, &["t", "v"])?;
            Ok(CanonicalValue::String(
                field_string(object, "v")?.to_string(),
            ))
        }
        "void" => {
            exact_object(value, &["t"])?;
            Ok(CanonicalValue::Void)
        }
        "decision" => {
            let object = exact_object(value, &["t", "v"])?;
            let decision = match field_string(object, "v")? {
                "approve" => Decision::Approve,
                "deny" => Decision::Deny,
                "review" => Decision::Review,
                "invalid-input" => Decision::InvalidInput,
                _ => return Err(StructuralError::schema("unknown decision value")),
            };
            Ok(CanonicalValue::Decision(decision))
        }
        _ => Err(StructuralError::schema("unknown canonical value tag")),
    }
}

fn canonical_integer(value: &str, allow_negative: bool) -> Result<String, StructuralError> {
    let digits = if let Some(rest) = value.strip_prefix('-') {
        if !allow_negative || rest == "0" {
            return Err(StructuralError::schema("canonical integer sign invalid"));
        }
        rest
    } else {
        value
    };
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return Err(StructuralError::schema("canonical integer invalid"));
    }
    if digits.len() > MAX_INTEGER_DIGITS {
        return Err(StructuralError::ResourceLimit("integer-digits"));
    }
    Ok(value.to_string())
}

fn exact_object<'a>(
    value: &'a JsonValue,
    expected: &[&str],
) -> Result<&'a BTreeMap<String, JsonValue>, StructuralError> {
    let object = value
        .as_object()
        .ok_or_else(|| StructuralError::schema("expected JSON object"))?;
    if object.len() != expected.len() || expected.iter().any(|name| !object.contains_key(*name)) {
        return Err(StructuralError::schema("closed schema member mismatch"));
    }
    Ok(object)
}

fn field<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a JsonValue, StructuralError> {
    object
        .get(name)
        .ok_or_else(|| StructuralError::schema(format!("missing field {name}")))
}

fn field_string<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a str, StructuralError> {
    field(object, name)?
        .as_str()
        .ok_or_else(|| StructuralError::schema(format!("field {name} is not a string")))
}

fn require_string(
    object: &BTreeMap<String, JsonValue>,
    name: &str,
    expected: &str,
) -> Result<(), StructuralError> {
    if field_string(object, name)? == expected {
        Ok(())
    } else {
        Err(StructuralError::schema(format!(
            "field {name} has the wrong tag"
        )))
    }
}

fn field_uint(object: &BTreeMap<String, JsonValue>, name: &str) -> Result<usize, StructuralError> {
    parse_uint(field(object, name)?)
}

fn parse_uint(value: &JsonValue) -> Result<usize, StructuralError> {
    let JsonValue::Integer(value) = value else {
        return Err(StructuralError::schema("uint is not an integer"));
    };
    if *value < 0 || *value > MAX_SAFE_INTEGER {
        return Err(StructuralError::schema("uint is outside safe range"));
    }
    usize::try_from(*value).map_err(|_| StructuralError::schema("uint is out of range"))
}

fn optional_uint(value: &JsonValue) -> Result<Option<usize>, StructuralError> {
    match value {
        JsonValue::Null => Ok(None),
        value => parse_uint(value).map(Some),
    }
}

fn optional_string(value: &JsonValue) -> Result<Option<String>, StructuralError> {
    match value {
        JsonValue::Null => Ok(None),
        JsonValue::String(value) => Ok(Some(value.clone())),
        _ => Err(StructuralError::schema(
            "optional string has the wrong type",
        )),
    }
}

fn uint_array(value: &JsonValue) -> Result<Vec<usize>, StructuralError> {
    value
        .as_array()
        .ok_or_else(|| StructuralError::schema("expected uint array"))?
        .iter()
        .map(parse_uint)
        .collect()
}

fn string_array(value: &JsonValue) -> Result<Vec<String>, StructuralError> {
    value
        .as_array()
        .ok_or_else(|| StructuralError::schema("expected string array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| StructuralError::schema("array member is not a string"))
        })
        .collect()
}

fn hex64(value: &str) -> Result<String, StructuralError> {
    if is_lower_hex(value, 64) {
        Ok(value.to_string())
    } else {
        Err(StructuralError::schema("digest is not lowercase hex64"))
    }
}

fn hex40(value: &str) -> Result<String, StructuralError> {
    if is_lower_hex(value, 40) {
        Ok(value.to_string())
    } else {
        Err(StructuralError::schema(
            "build commit is not lowercase hex40",
        ))
    }
}

fn executable_digest(value: &str) -> Result<String, StructuralError> {
    if value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_lower_hex(digest, 64))
    {
        Ok(value.to_string())
    } else {
        Err(StructuralError::schema(
            "executable digest representation is invalid",
        ))
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_report_has_no_authentication_language() {
        let bytes = StructuralReport::success().canonical_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("structurally-consistent"));
        assert!(!text.contains("authenticated"));
        assert!(!text.contains("trusted-native"));
        assert!(!text.contains("verified-native"));
    }

    #[test]
    fn canonical_integer_digit_limit_is_exact_and_precedes_bigint_work() {
        let exact = "9".repeat(MAX_INTEGER_DIGITS);
        assert_eq!(canonical_integer(&exact, true).unwrap(), exact);
        assert_eq!(
            canonical_integer(&"9".repeat(MAX_INTEGER_DIGITS + 1), true),
            Err(StructuralError::ResourceLimit("integer-digits"))
        );
        assert!(matches!(
            canonical_integer(&format!("-{}", "9".repeat(MAX_INTEGER_DIGITS + 1)), true),
            Err(StructuralError::ResourceLimit("integer-digits"))
        ));
    }
}
