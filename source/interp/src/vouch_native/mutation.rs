//! Internal, keyless SCORED mutation execution boundary.
//!
//! This module deliberately stops after canonical payload construction and
//! structural self-verification. It has no key handle, provider, signer, DSSE
//! envelope, release signability gate, or publication side effect.

use sha2::{Digest, Sha256};

use super::canonical_value::domain_hash;
use super::checked_input::CheckedInput;
use super::checked_profile::{
    parse_checked_source, prepare_parsed_checked_source, CHECKED_PROFILE_TAG,
};
use super::graph::{contract_graph_digest, lower_contract_graph};
use super::issue::{build_receipt, execution_context_digest, IssueBuildIdentity};
use super::structural_verify::{verify_structure, StructuralContext};
use super::tokens::{evaluate_and_bind, EvaluationBudgets, InvocationContext};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationPayload {
    bytes: Vec<u8>,
}

impl MutationPayload {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationRunError {
    Source(&'static str),
    Input(&'static str),
    Graph(&'static str),
    Evaluation(&'static str),
    ExecutableIdentity,
    Serialization,
    StructuralSelfVerification,
}

impl MutationRunError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Source(code) | Self::Input(code) | Self::Graph(code) => code,
            Self::Evaluation(code) => code,
            Self::ExecutableIdentity => "mutation-executable-identity",
            Self::Serialization => "mutation-payload-serialization",
            Self::StructuralSelfVerification => "mutation-structural-self-verification",
        }
    }

    pub const fn is_pre_graph_failure(self) -> bool {
        matches!(self, Self::Source(_) | Self::Input(_) | Self::Graph(_))
    }
}

/// Run both production evaluator paths and return one unsigned canonical receipt
/// payload. The immutable entry copies are the only byte authority after entry.
pub fn run_mutation_bytes(
    source_bytes: &[u8],
    input_bytes: &[u8],
) -> Result<MutationPayload, MutationRunError> {
    let source = source_bytes.to_vec();
    let input = input_bytes.to_vec();

    let parsed = parse_checked_source(&source)
        .map_err(|error| MutationRunError::Source(error.code.as_str()))?;
    let checked_input =
        CheckedInput::parse(&input).map_err(|error| MutationRunError::Input(error.code()))?;
    let program = prepare_parsed_checked_source(parsed)
        .map_err(|error| MutationRunError::Source(error.code.as_str()))?;
    let graph = lower_contract_graph(program.core())
        .map_err(|error| MutationRunError::Graph(error.code()))?;
    let graph_sha256 =
        contract_graph_digest(&graph).map_err(|_| MutationRunError::Serialization)?;
    let normalized_sha256 = domain_hash("csk.v0.canonical", program.normalized_bytes());
    let identity =
        IssueBuildIdentity::current().map_err(|_| MutationRunError::ExecutableIdentity)?;
    let context_digest = execution_context_digest(
        program.normalized_bytes(),
        checked_input.canonical_value_digest(),
        CHECKED_PROFILE_TAG,
        identity.executable_sha256(),
    )
    .map_err(|_| MutationRunError::Serialization)?;
    let context = InvocationContext::new(
        invocation_nonce(&source, &input),
        context_digest.clone(),
        normalized_sha256.clone(),
        graph_sha256.clone(),
        checked_input.canonical_value_digest().to_string(),
        CHECKED_PROFILE_TAG.to_string(),
        EvaluationBudgets::CONTRACT,
        graph.roots.len(),
    );
    let reports = evaluate_and_bind(&program, &graph, checked_input.mapped_value(), &context)
        .map_err(|error| match error {
            super::tokens::EvaluationPairError::ProfileEscape => {
                MutationRunError::Evaluation("profile-escape")
            }
            super::tokens::EvaluationPairError::InvocationMismatch
            | super::tokens::EvaluationPairError::TokenBinding => {
                MutationRunError::Evaluation("mutation-evaluation-infrastructure")
            }
        })?;
    let receipt = build_receipt(
        &source,
        &checked_input,
        &program,
        graph,
        reports,
        &identity,
        context_digest,
        normalized_sha256,
        graph_sha256,
    );
    let payload = receipt
        .canonical_bytes()
        .map_err(|_| MutationRunError::Serialization)?;
    verify_structure(
        &payload,
        StructuralContext {
            input: &input,
            source: Some(&source),
            expected_profile: Some(CHECKED_PROFILE_TAG),
            release_signed: false,
        },
    )
    .map_err(|_error| {
        #[cfg(test)]
        eprintln!("mutation structural self-verification failed: {_error:?}");
        MutationRunError::StructuralSelfVerification
    })?;
    Ok(MutationPayload { bytes: payload })
}

fn invocation_nonce(source: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"vouch/mutation-invocation/v0");
    hash.update([0]);
    hash.update(source);
    hash.update([0]);
    hash.update(input);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vouch::artifact_json::{canonical_gate, RawArtifactKind};

    const INPUT: &[u8] =
        b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": [\n    0\n  ]\n}\n";

    #[test]
    fn keyless_runner_emits_unsigned_structurally_valid_payload() {
        let payload = run_mutation_bytes(b"(+ 1 2)", INPUT).unwrap();
        let parsed = canonical_gate(payload.bytes(), RawArtifactKind::Payload).unwrap();
        let root = parsed.value().as_object().unwrap();
        assert_eq!(
            root.get("differential_receipt")
                .and_then(|value| value.as_str()),
            Some("csk.differential-receipt/v0")
        );
        assert!(!root.contains_key("payloadType"));
        assert!(!root.contains_key("signatures"));
    }

    #[test]
    fn malformed_input_fails_before_payload_construction() {
        assert_eq!(
            run_mutation_bytes(b"(+ 1 2)", b"{}\n").unwrap_err().code(),
            "native-input-profile-invalid"
        );
    }

    #[test]
    fn selected_mutant_has_the_required_activation_witness_class() {
        let selected = env!("CSK_SCORED_MUTANT");
        if selected.is_empty() {
            for (source, _) in activation_witnesses() {
                assert_eq!(comparison_status(source), "agree");
            }
            return;
        }
        let index = selected[1..].parse::<usize>().unwrap() - 1;
        let (source, expected) = activation_witnesses()[index];
        let payload = run_mutation_bytes(source, INPUT).unwrap();
        let parsed = canonical_gate(payload.bytes(), RawArtifactKind::Payload).unwrap();
        let root = parsed.value().as_object().unwrap();
        let comparison = root["comparison"].as_object().unwrap();
        assert_eq!(comparison["status"].as_str(), Some(expected));
        if expected == "agree" {
            let reference = root["reference"].as_object().unwrap();
            let meaning = root["meaning_env"].as_object().unwrap();
            assert_eq!(reference["transcript"], meaning["transcript"]);
        }
    }

    #[test]
    fn selected_mutant_activation_suite_self_verifies() {
        if env!("CSK_SCORED_MUTANT").is_empty() {
            return;
        }
        for (index, (source, _)) in activation_witnesses().into_iter().enumerate() {
            run_mutation_bytes(source, INPUT)
                .unwrap_or_else(|error| panic!("W-M{:02}: {error:?}", index + 1));
        }
    }

    fn comparison_status(source: &[u8]) -> String {
        let payload = run_mutation_bytes(source, INPUT).unwrap();
        let parsed = canonical_gate(payload.bytes(), RawArtifactKind::Payload).unwrap();
        parsed.value().as_object().unwrap()["comparison"]
            .as_object()
            .unwrap()["status"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn activation_witnesses() -> [(&'static [u8], &'static str); 12] {
        [
            (b"(and #f #t)\n", "disagree"),
            (b"(- 9 4)\n", "disagree"),
            (b"(if #t 1 2)\n", "disagree"),
            (b"(<= 1 1)\n", "disagree"),
            (b"(if #t 1 2)\n", "disagree"),
            (b"(- 9 4)\n", "disagree"),
            (b"(<= 1 1)\n", "agree"),
            (b"-1/2\n", "agree"),
            (b"(+ 1 2)\n", "disagree"),
            (b"\"line\nbreak\"\n", "disagree"),
            (b"(- 9 4)\n", "agree"),
            (b"#f\n", "agree"),
        ]
    }
}
