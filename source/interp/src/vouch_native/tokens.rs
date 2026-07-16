//! Live evaluator token boundary (Stage 4).
//!
//! The concrete token types live in their evaluator modules and expose no
//! public constructor or serialization surface.  This module is the only
//! receipt-construction boundary allowed to inspect both token types.  It
//! validates the current invocation binding and atomically consumes both
//! tokens before returning their transcripts.

use std::cell::Cell;

use super::meaning_trace::MeaningTraceToken;
use super::reference_trace::ReferenceTraceToken;
use super::transcript::Transcript;
use super::{
    canonical_value::domain_hash,
    checked_profile::CheckedProgram,
    graph::ContractGraph,
    meaning_trace::{mint_meaning_token, MeaningEvaluationError},
    receipt::{Comparison, ComparisonStatus, MeaningEnvReport, TraceReport},
    reference_trace::{mint_reference_token, ReferenceEvaluationError},
    transcript::{Terminal, TranscriptEvent},
};
use crate::Value;

pub const REFERENCE_STEP_BUDGET: usize = 1_000_000;
pub const REFERENCE_DEPTH_BUDGET: usize = 1_024;
pub const MEANING_ENV_STEP_BUDGET: usize = 1_000_000;
pub const MEANING_ENV_DEPTH_BUDGET: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluationBudgets {
    pub reference_steps: usize,
    pub reference_depth: usize,
    pub meaning_steps: usize,
    pub meaning_depth: usize,
}

impl EvaluationBudgets {
    pub const CONTRACT: Self = Self {
        reference_steps: REFERENCE_STEP_BUDGET,
        reference_depth: REFERENCE_DEPTH_BUDGET,
        meaning_steps: MEANING_ENV_STEP_BUDGET,
        meaning_depth: MEANING_ENV_DEPTH_BUDGET,
    };
}

/// Private state that binds two evaluator runs to one live issuer invocation.
/// The nonce is intentionally absent from every serialized artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InvocationContext {
    nonce: [u8; 32],
    context_digest: String,
    normalized_sha256: String,
    graph_sha256: String,
    input_canonical_value_sha256: String,
    profile: String,
    budgets: EvaluationBudgets,
    root_count: usize,
}

impl InvocationContext {
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub(super) fn new(
        nonce: [u8; 32],
        context_digest: String,
        normalized_sha256: String,
        graph_sha256: String,
        input_canonical_value_sha256: String,
        profile: String,
        budgets: EvaluationBudgets,
        root_count: usize,
    ) -> Self {
        Self {
            nonce,
            context_digest,
            normalized_sha256,
            graph_sha256,
            input_canonical_value_sha256,
            profile,
            budgets,
            root_count,
        }
    }

    pub(super) fn normalized_sha256(&self) -> &str {
        &self.normalized_sha256
    }

    pub(super) fn graph_sha256(&self) -> &str {
        &self.graph_sha256
    }

    pub(super) fn context_digest(&self) -> &str {
        &self.context_digest
    }

    pub(super) const fn budgets(&self) -> EvaluationBudgets {
        self.budgets
    }

    pub(super) const fn root_count(&self) -> usize {
        self.root_count
    }
}

/// Common private payload embedded in each evaluator-specific token.
/// `Cell` makes replay refusal observable without making the token clonable.
#[derive(Debug)]
pub(super) struct LiveTraceState {
    nonce: [u8; 32],
    context_digest: String,
    input_canonical_value_sha256: String,
    profile: String,
    budgets: EvaluationBudgets,
    transcript: Transcript,
    consumed: Cell<bool>,
}

impl LiveTraceState {
    pub(super) fn from_invocation(context: &InvocationContext, transcript: Transcript) -> Self {
        Self {
            nonce: context.nonce,
            context_digest: context.context_digest.clone(),
            input_canonical_value_sha256: context.input_canonical_value_sha256.clone(),
            profile: context.profile.clone(),
            budgets: context.budgets,
            transcript,
            consumed: Cell::new(false),
        }
    }

    fn matches_context(&self, context: &InvocationContext) -> bool {
        self.nonce == context.nonce
            && self.context_digest == context.context_digest
            && self.input_canonical_value_sha256 == context.input_canonical_value_sha256
            && self.profile == context.profile
            && self.budgets == context.budgets
    }

    fn matches_pair(&self, other: &Self) -> bool {
        self.nonce == other.nonce
            && self.context_digest == other.context_digest
            && self.input_canonical_value_sha256 == other.input_canonical_value_sha256
            && self.profile == other.profile
            && self.budgets == other.budgets
    }

    fn is_consumed(&self) -> bool {
        self.consumed.get()
    }

    fn consume(&self) {
        self.consumed.set(true);
    }

    fn transcript(&self) -> &Transcript {
        &self.transcript
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BoundTranscripts {
    pub(super) reference: Transcript,
    pub(super) meaning: Transcript,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TokenBindingError {
    Consumed,
    InvocationMismatch,
    DigestMismatch,
    InvalidTranscript,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EvaluationPairError {
    ProfileEscape,
    InvocationMismatch,
    TokenBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TokenBoundTraceReports {
    pub(super) reference: TraceReport,
    pub(super) meaning: MeaningEnvReport,
    pub(super) comparison: Comparison,
}

/// Stage-4 receipt-construction entry: mint both private tokens and consume
/// them through the only accepted token-bound transcript path.  PR7's issuer
/// calls this after parsing, normalization, lowering, and context derivation.
#[allow(dead_code)]
pub(super) fn evaluate_and_bind(
    program: &CheckedProgram,
    graph: &ContractGraph,
    input: &Value,
    context: &InvocationContext,
) -> Result<TokenBoundTraceReports, EvaluationPairError> {
    let reference = mint_reference_token(program, input, context).map_err(|error| match error {
        ReferenceEvaluationError::ProfileEscape => EvaluationPairError::ProfileEscape,
        ReferenceEvaluationError::InvocationMismatch => EvaluationPairError::InvocationMismatch,
    })?;
    let meaning = mint_meaning_token(graph, input, context).map_err(|error| match error {
        MeaningEvaluationError::ProfileEscape => EvaluationPairError::ProfileEscape,
        MeaningEvaluationError::InvocationMismatch => EvaluationPairError::InvocationMismatch,
    })?;
    let bound = bind_and_consume(context, &reference, &meaning)
        .map_err(|_| EvaluationPairError::TokenBinding)?;
    build_trace_reports(context, graph.nodes.len(), bound)
        .map_err(|_| EvaluationPairError::TokenBinding)
}

pub(super) fn build_trace_reports(
    context: &InvocationContext,
    node_count: usize,
    bound: BoundTranscripts,
) -> Result<TokenBoundTraceReports, vouch::artifact_json::JsonWriteError> {
    let reference_bytes = bound.reference.canonical_bytes()?;
    let meaning_bytes = bound.meaning.canonical_bytes()?;
    let comparison = compare_transcripts(
        &bound.reference,
        &bound.meaning,
        &reference_bytes,
        &meaning_bytes,
    );
    Ok(TokenBoundTraceReports {
        reference: TraceReport {
            transcript_sha256: domain_hash("csk.v0.reference", &reference_bytes),
            transcript: bound.reference,
        },
        meaning: MeaningEnvReport {
            graph_sha256: context.graph_sha256.clone(),
            transcript_sha256: domain_hash("csk.v0.meaning_env", &meaning_bytes),
            node_count,
            transcript: bound.meaning,
        },
        comparison,
    })
}

fn compare_transcripts(
    reference: &Transcript,
    meaning: &Transcript,
    reference_bytes: &[u8],
    meaning_bytes: &[u8],
) -> Comparison {
    let unavailable = [
        failure_index(&reference.terminal),
        failure_index(&meaning.terminal),
    ]
    .into_iter()
    .flatten()
    .min();
    if let Some(comparison_unavailable_at) = unavailable {
        return Comparison {
            status: ComparisonStatus::NotComparable,
            first_divergence_index: None,
            comparison_unavailable_at: Some(comparison_unavailable_at),
        };
    }
    if reference_bytes == meaning_bytes {
        Comparison {
            status: ComparisonStatus::Agree,
            first_divergence_index: None,
            comparison_unavailable_at: None,
        }
    } else {
        Comparison {
            status: ComparisonStatus::Disagree,
            first_divergence_index: Some(first_divergence(reference, meaning)),
            comparison_unavailable_at: None,
        }
    }
}

fn failure_index(terminal: &Terminal) -> Option<usize> {
    match terminal {
        Terminal::InfrastructureFailure {
            next_form_index, ..
        } => Some(*next_form_index),
        Terminal::Completed | Terminal::LanguageFault { .. } => None,
    }
}

fn first_divergence(reference: &Transcript, meaning: &Transcript) -> usize {
    for (index, (left, right)) in reference.events.iter().zip(&meaning.events).enumerate() {
        if !event_bytes_equal(left, right) {
            return index;
        }
    }
    if reference.events.len() != meaning.events.len() {
        return reference.events.len().min(meaning.events.len());
    }
    reference.events.len()
}

fn event_bytes_equal(left: &TranscriptEvent, right: &TranscriptEvent) -> bool {
    left == right
}

/// Accept exactly the two evaluator-minted token types, validate their live
/// invocation binding, and consume them as one atomic operation.
pub(super) fn bind_and_consume(
    context: &InvocationContext,
    reference: &ReferenceTraceToken,
    meaning: &MeaningTraceToken,
) -> Result<BoundTranscripts, TokenBindingError> {
    let reference_state = reference.state();
    let meaning_state = meaning.state();
    if reference_state.is_consumed() || meaning_state.is_consumed() {
        return Err(TokenBindingError::Consumed);
    }
    if !reference_state.matches_pair(meaning_state)
        || !reference_state.matches_context(context)
        || !meaning_state.matches_context(context)
    {
        return Err(TokenBindingError::InvocationMismatch);
    }
    if reference.normalized_sha256() != context.normalized_sha256()
        || meaning.graph_sha256() != context.graph_sha256()
    {
        return Err(TokenBindingError::DigestMismatch);
    }
    if reference_state
        .transcript()
        .validate(context.root_count())
        .is_err()
        || meaning_state
            .transcript()
            .validate(context.root_count())
            .is_err()
    {
        return Err(TokenBindingError::InvalidTranscript);
    }

    let bound = BoundTranscripts {
        reference: reference_state.transcript().clone(),
        meaning: meaning_state.transcript().clone(),
    };
    reference_state.consume();
    meaning_state.consume();
    Ok(bound)
}

/// Issuer-only second check over the exact consumed tokens used to construct
/// the receipt.  This does not replay either evaluator.  It proves that step 8
/// consumed this pair for the current invocation and that step 10 is checking
/// the same token-carried transcripts and derivation bindings.
pub(super) fn verify_consumed_binding(
    context: &InvocationContext,
    reference: &ReferenceTraceToken,
    meaning: &MeaningTraceToken,
    reports: &TokenBoundTraceReports,
) -> Result<(), TokenBindingError> {
    let reference_state = reference.state();
    let meaning_state = meaning.state();
    if !reference_state.is_consumed() || !meaning_state.is_consumed() {
        return Err(TokenBindingError::Consumed);
    }
    if !reference_state.matches_pair(meaning_state)
        || !reference_state.matches_context(context)
        || !meaning_state.matches_context(context)
    {
        return Err(TokenBindingError::InvocationMismatch);
    }
    if reference.normalized_sha256() != context.normalized_sha256()
        || meaning.graph_sha256() != context.graph_sha256()
    {
        return Err(TokenBindingError::DigestMismatch);
    }
    if reference_state.transcript() != &reports.reference.transcript
        || meaning_state.transcript() != &reports.meaning.transcript
        || reports.meaning.graph_sha256 != context.graph_sha256()
        || reports.meaning.node_count == 0
    {
        return Err(TokenBindingError::InvalidTranscript);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vouch_native::canonical_value::domain_hash;
    use crate::vouch_native::checked_input::CheckedInput;
    use crate::vouch_native::checked_profile::{
        prepare_checked_program, CheckedProgram, CHECKED_PROFILE_TAG,
    };
    use crate::vouch_native::graph::{contract_graph_digest, lower_contract_graph, ContractGraph};
    use crate::vouch_native::meaning_trace::{
        mint_meaning_token, MeaningEvaluationError, MeaningTraceToken,
    };
    use crate::vouch_native::reference_trace::{
        mint_reference_token, ReferenceEvaluationError, ReferenceTraceToken,
    };
    use crate::vouch_native::transcript::{LanguageFaultCode, Terminal};

    const INPUT_BYTES: &[u8] = b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": 5\n}\n";

    struct Prepared {
        program: CheckedProgram,
        graph: ContractGraph,
        input: CheckedInput,
        context: InvocationContext,
    }

    fn prepare_with(source: &[u8], nonce_byte: u8, budgets: EvaluationBudgets) -> Prepared {
        prepare_with_input(source, INPUT_BYTES, nonce_byte, budgets)
    }

    fn prepare_with_input(
        source: &[u8],
        input_bytes: &[u8],
        nonce_byte: u8,
        budgets: EvaluationBudgets,
    ) -> Prepared {
        let program = prepare_checked_program(source).unwrap();
        let graph = lower_contract_graph(program.core()).unwrap();
        let input = CheckedInput::parse(input_bytes).unwrap();
        let context = InvocationContext::new(
            [nonce_byte; 32],
            "c".repeat(64),
            domain_hash("csk.v0.canonical", program.normalized_bytes()),
            contract_graph_digest(&graph).unwrap(),
            input.canonical_value_digest().to_string(),
            CHECKED_PROFILE_TAG.to_string(),
            budgets,
            graph.roots.len(),
        );
        Prepared {
            program,
            graph,
            input,
            context,
        }
    }

    fn mint(prepared: &Prepared) -> (ReferenceTraceToken, MeaningTraceToken) {
        let reference = mint_reference_token(
            &prepared.program,
            prepared.input.mapped_value(),
            &prepared.context,
        )
        .unwrap();
        let meaning = mint_meaning_token(
            &prepared.graph,
            prepared.input.mapped_value(),
            &prepared.context,
        )
        .unwrap();
        (reference, meaning)
    }

    #[test]
    fn stage4_two_evaluators_emit_byte_identical_higher_order_transcripts() {
        let prepared = prepare_with(
            b"(define choose (lambda (x) (if (< x 10) (decision-approve) (decision-deny))))\n(choose input)",
            1,
            EvaluationBudgets::CONTRACT,
        );
        let reports = evaluate_and_bind(
            &prepared.program,
            &prepared.graph,
            prepared.input.mapped_value(),
            &prepared.context,
        )
        .unwrap();
        assert_eq!(
            reports.reference.transcript.canonical_bytes().unwrap(),
            reports.meaning.transcript.canonical_bytes().unwrap()
        );
        assert_eq!(reports.comparison.status, ComparisonStatus::Agree);
        assert_eq!(reports.reference.transcript.events.len(), 2);
    }

    #[test]
    fn stage4_language_faults_are_transcript_terminals_not_infrastructure_failures() {
        let prepared = prepare_with(b"(/ 1 0)", 2, EvaluationBudgets::CONTRACT);
        let (reference, meaning) = mint(&prepared);
        let bound = bind_and_consume(&prepared.context, &reference, &meaning).unwrap();
        assert_eq!(
            bound.reference.terminal,
            Terminal::LanguageFault {
                code: LanguageFaultCode::DivisionByZero,
                form_index: 0,
            }
        );
        assert_eq!(bound.reference.terminal, bound.meaning.terminal);
    }

    #[test]
    fn stage4_complete_covered_form_and_primitive_surface_agrees() {
        let sources: &[&[u8]] = &[
            b"(+ 1 2 3)",
            b"(- 9 2 3)",
            b"(* 2 3 4)",
            b"(/ 8 2)",
            b"(= 3 3)",
            b"(< 1 2)",
            b"(<= 2 2)",
            b"(> 3 2)",
            b"(>= 3 3)",
            b"(cons 1 2)",
            b"(car (cons 1 2))",
            b"(cdr (cons 1 2))",
            b"(null? (list))",
            b"(pair? (list 1))",
            b"(list 1 2 3)",
            b"(exact-integer? input)",
            b"((lambda (x) (+ x 1)) input)",
            b"(let ((x input) (y 2)) (if (< x 10) (+ x y) (- x y)))",
            b"(begin 1 2 3)",
            b"(and #t input)",
            b"(or #f input)",
            b"(cond ((< input 0) 0) (else input))",
            b"(define x 2)\n(+ x input)",
            b"(decision-approve)",
            b"(decision-deny)",
            b"(decision-review)",
            b"(decision-invalid-input)",
        ];
        for (index, source) in sources.iter().enumerate() {
            let prepared = prepare_with(source, index as u8 + 20, EvaluationBudgets::CONTRACT);
            let reports = evaluate_and_bind(
                &prepared.program,
                &prepared.graph,
                prepared.input.mapped_value(),
                &prepared.context,
            )
            .unwrap();
            assert_eq!(
                reports.comparison.status,
                ComparisonStatus::Agree,
                "{}",
                String::from_utf8_lossy(source)
            );
        }
    }

    #[test]
    fn stage4_exact_integer_predicate_is_total_on_checked_data_and_agrees() {
        let cases: &[(&[u8], bool)] = &[
            (INPUT_BYTES, true),
            (
                b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": true\n}\n",
                false,
            ),
            (
                b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": \"five\"\n}\n",
                false,
            ),
            (
                b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": []\n}\n",
                false,
            ),
            (
                b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": {\n    \"$rat\": {\n      \"d\": \"2\",\n      \"n\": \"1\"\n    }\n  }\n}\n",
                false,
            ),
            (
                b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": {\n    \"$real\": \"5.0\"\n  }\n}\n",
                false,
            ),
            (
                b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": {\n    \"$sym\": \"five\"\n  }\n}\n",
                false,
            ),
        ];
        for (index, (input_bytes, expected)) in cases.iter().enumerate() {
            let prepared = prepare_with_input(
                b"(exact-integer? input)",
                input_bytes,
                index as u8 + 120,
                EvaluationBudgets::CONTRACT,
            );
            let reports = evaluate_and_bind(
                &prepared.program,
                &prepared.graph,
                prepared.input.mapped_value(),
                &prepared.context,
            )
            .unwrap();
            assert_eq!(reports.comparison.status, ComparisonStatus::Agree);
            assert_eq!(
                reports.reference.transcript.canonical_bytes().unwrap(),
                reports.meaning.transcript.canonical_bytes().unwrap()
            );
            let expected_value =
                crate::vouch_native::canonical_value::CanonicalValue::Boolean(*expected);
            assert!(matches!(
                reports.reference.transcript.events.as_slice(),
                [crate::vouch_native::transcript::TranscriptEvent::Value { value, .. }]
                    if value == &expected_value
            ));
        }

        for (index, source) in [b"(exact-integer?)".as_slice(), b"(exact-integer? 1 2)"]
            .into_iter()
            .enumerate()
        {
            let prepared = prepare_with(source, index as u8 + 130, EvaluationBudgets::CONTRACT);
            let reports = evaluate_and_bind(
                &prepared.program,
                &prepared.graph,
                prepared.input.mapped_value(),
                &prepared.context,
            )
            .unwrap();
            assert_eq!(reports.comparison.status, ComparisonStatus::Agree);
            assert!(matches!(
                reports.reference.transcript.terminal,
                Terminal::LanguageFault {
                    code: LanguageFaultCode::ArityMismatch,
                    ..
                }
            ));
            assert_eq!(
                reports.reference.transcript.terminal,
                reports.meaning.transcript.terminal
            );
        }
    }

    #[test]
    fn stage4_typed_fault_surface_agrees() {
        for (index, source) in [
            b"(+ 1 #t)".as_slice(),
            b"(car 1)",
            b"(decision-approve 1)",
            b"(< 1)",
            b"((lambda (x) x))",
            b"(1 2)",
            b"(/ 1 0)",
            b"(* 1e308 1e308)",
        ]
        .into_iter()
        .enumerate()
        {
            let prepared = prepare_with(source, index as u8 + 60, EvaluationBudgets::CONTRACT);
            let reports = evaluate_and_bind(
                &prepared.program,
                &prepared.graph,
                prepared.input.mapped_value(),
                &prepared.context,
            )
            .unwrap();
            assert_eq!(
                reports.comparison.status,
                ComparisonStatus::Agree,
                "{}",
                String::from_utf8_lossy(source)
            );
            assert!(matches!(
                reports.reference.transcript.terminal,
                Terminal::LanguageFault { .. }
            ));
        }
    }

    #[test]
    fn stage4_infrastructure_terminal_forces_not_comparable() {
        use crate::vouch_native::transcript::{
            EvaluationPhase, InfrastructureFailureCode, TranscriptEvent,
        };

        let prepared = prepare_with(b"input", 90, EvaluationBudgets::CONTRACT);
        let reference = Transcript {
            events: vec![],
            terminal: Terminal::InfrastructureFailure {
                code: InfrastructureFailureCode::ReferenceExecutionFailed,
                phase: EvaluationPhase::Reference,
                next_form_index: 0,
            },
        };
        let meaning = Transcript {
            events: vec![TranscriptEvent::Value {
                form_index: 0,
                value: prepared.input.canonical_value().clone(),
            }],
            terminal: Terminal::Completed,
        };
        let reports = build_trace_reports(
            &prepared.context,
            prepared.graph.nodes.len(),
            BoundTranscripts { reference, meaning },
        )
        .unwrap();
        assert_eq!(reports.comparison.status, ComparisonStatus::NotComparable);
        assert_eq!(reports.comparison.comparison_unavailable_at, Some(0));
        assert_eq!(reports.comparison.first_divergence_index, None);
    }

    #[test]
    fn stage4_each_evaluator_has_its_own_bounded_terminal_code() {
        let budgets = EvaluationBudgets {
            reference_steps: 1,
            reference_depth: 32,
            meaning_steps: 1,
            meaning_depth: 32,
        };
        let prepared = prepare_with(b"(+ 1 2)", 3, budgets);
        let (reference, meaning) = mint(&prepared);
        let bound = bind_and_consume(&prepared.context, &reference, &meaning).unwrap();
        assert_eq!(
            bound.reference.terminal,
            Terminal::LanguageFault {
                code: LanguageFaultCode::ReferenceBudgetExhausted,
                form_index: 0,
            }
        );
        assert_eq!(
            bound.meaning.terminal,
            Terminal::LanguageFault {
                code: LanguageFaultCode::MeaningEnvBudgetExhausted,
                form_index: 0,
            }
        );
    }

    #[test]
    fn stage4_tokens_are_one_shot_and_replay_is_rejected() {
        let prepared = prepare_with(b"(+ input 1)", 4, EvaluationBudgets::CONTRACT);
        let (reference, meaning) = mint(&prepared);
        bind_and_consume(&prepared.context, &reference, &meaning).unwrap();
        assert_eq!(
            bind_and_consume(&prepared.context, &reference, &meaning),
            Err(TokenBindingError::Consumed)
        );
    }

    #[test]
    fn stage4_equal_root_count_prior_invocation_swap_is_rejected() {
        let first = prepare_with(b"(+ input 1)", 5, EvaluationBudgets::CONTRACT);
        let second = prepare_with(b"(- input 1)", 6, EvaluationBudgets::CONTRACT);
        assert_eq!(first.graph.roots.len(), second.graph.roots.len());
        let (reference, meaning) = mint(&second);
        assert_eq!(
            bind_and_consume(&first.context, &reference, &meaning),
            Err(TokenBindingError::InvocationMismatch)
        );
    }

    #[test]
    fn stage4_decision_before_final_root_is_a_dynamic_profile_escape() {
        let prepared = prepare_with(
            b"(decision-approve)\n(decision-deny)",
            7,
            EvaluationBudgets::CONTRACT,
        );
        assert!(matches!(
            mint_reference_token(
                &prepared.program,
                prepared.input.mapped_value(),
                &prepared.context,
            ),
            Err(ReferenceEvaluationError::ProfileEscape)
        ));
        assert!(matches!(
            mint_meaning_token(
                &prepared.graph,
                prepared.input.mapped_value(),
                &prepared.context,
            ),
            Err(MeaningEvaluationError::ProfileEscape)
        ));
    }

    #[test]
    fn stage4_decision_operand_is_rejected_by_both_live_paths() {
        let prepared = prepare_with(b"(+ (decision-approve) 1)", 91, EvaluationBudgets::CONTRACT);
        assert!(matches!(
            mint_reference_token(
                &prepared.program,
                prepared.input.mapped_value(),
                &prepared.context,
            ),
            Err(ReferenceEvaluationError::ProfileEscape)
        ));
        assert!(matches!(
            mint_meaning_token(
                &prepared.graph,
                prepared.input.mapped_value(),
                &prepared.context,
            ),
            Err(MeaningEvaluationError::ProfileEscape)
        ));
    }

    #[test]
    fn stage4_hidden_or_discarded_decision_is_not_a_final_decision() {
        for (index, source) in [
            b"(define hidden (decision-approve))\nhidden".as_slice(),
            b"(begin (decision-approve) (decision-deny))",
            b"(define hidden (decision-approve))",
        ]
        .into_iter()
        .enumerate()
        {
            let prepared = prepare_with(source, index as u8 + 100, EvaluationBudgets::CONTRACT);
            assert!(matches!(
                mint_reference_token(
                    &prepared.program,
                    prepared.input.mapped_value(),
                    &prepared.context,
                ),
                Err(ReferenceEvaluationError::ProfileEscape)
            ));
            assert!(matches!(
                mint_meaning_token(
                    &prepared.graph,
                    prepared.input.mapped_value(),
                    &prepared.context,
                ),
                Err(MeaningEvaluationError::ProfileEscape)
            ));
        }
    }
}
