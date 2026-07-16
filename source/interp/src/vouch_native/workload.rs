//! Closed Stage-8 workload outcome and coverage observation.

use std::collections::HashSet;

use super::canonical_value::{domain_hash, CanonicalValue};
use super::checked_input::CheckedInput;
use super::checked_profile::{prepare_checked_program, CHECKED_PROFILE_TAG};
use super::graph::{contract_graph_digest, lower_contract_graph, ContractNode};
use super::meaning_trace::{mint_meaning_token, MeaningEvaluationError};
use super::receipt::ComparisonStatus;
use super::reference_trace::{mint_reference_token, ReferenceEvaluationError};
use super::tokens::{bind_and_consume, build_trace_reports, EvaluationBudgets, InvocationContext};
use super::transcript::{Terminal, TranscriptEvent};
use crate::Decision;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseOutcome {
    Decision(Decision),
    ProfileEscape,
    NotComparable,
    PipelineFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadCoverage {
    pub graph_sha256: String,
    pub covered_nodes: Vec<usize>,
    pub total_nodes: Vec<usize>,
    pub covered_branches: Vec<(usize, bool)>,
    pub total_branches: Vec<(usize, bool)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadObservation {
    pub outcome: CaseOutcome,
    pub coverage: WorkloadCoverage,
}

impl WorkloadObservation {
    fn empty(outcome: CaseOutcome) -> Self {
        Self {
            outcome,
            coverage: WorkloadCoverage {
                graph_sha256: String::new(),
                covered_nodes: Vec::new(),
                total_nodes: Vec::new(),
                covered_branches: Vec::new(),
                total_branches: Vec::new(),
            },
        }
    }
}

/// Run both live evaluators and expose only the closed empirical outcome plus
/// Meaning-Graph instrumentation identifiers. No receipt or release capability
/// is constructed by this observation API.
pub fn evaluate_workload_case(source: &[u8], input_bytes: &[u8]) -> WorkloadObservation {
    let input = match CheckedInput::parse(input_bytes) {
        Ok(input) => input,
        Err(_) => return WorkloadObservation::empty(CaseOutcome::PipelineFailure),
    };
    let program = match prepare_checked_program(source) {
        Ok(program) => program,
        Err(error) => {
            return WorkloadObservation::empty(match error.code {
                super::checked_profile::ProfileErrorCode::ProfileEscape => {
                    CaseOutcome::ProfileEscape
                }
                _ => CaseOutcome::PipelineFailure,
            })
        }
    };
    let graph = match lower_contract_graph(program.core()) {
        Ok(graph) => graph,
        Err(super::graph::GraphError::ProfileEscape(_)) => {
            return WorkloadObservation::empty(CaseOutcome::ProfileEscape)
        }
        Err(_) => return WorkloadObservation::empty(CaseOutcome::PipelineFailure),
    };
    let graph_sha256 = match contract_graph_digest(&graph) {
        Ok(value) => value,
        Err(_) => return WorkloadObservation::empty(CaseOutcome::PipelineFailure),
    };
    let normalized_sha256 = domain_hash("csk.v0.canonical", program.normalized_bytes());
    let mut nonce = [0_u8; 32];
    if getrandom::getrandom(&mut nonce).is_err() {
        return WorkloadObservation::empty(CaseOutcome::PipelineFailure);
    }
    let mut context_preimage = Vec::with_capacity(source.len() + input_bytes.len() + 1);
    context_preimage.extend_from_slice(source);
    context_preimage.push(0);
    context_preimage.extend_from_slice(input_bytes);
    let context = InvocationContext::new(
        nonce,
        domain_hash("csk.v0.workload-context", &context_preimage),
        normalized_sha256,
        graph_sha256.clone(),
        input.canonical_value_digest().to_string(),
        CHECKED_PROFILE_TAG.to_string(),
        EvaluationBudgets::CONTRACT,
        graph.roots.len(),
    );
    let reference = match mint_reference_token(&program, input.mapped_value(), &context) {
        Ok(token) => token,
        Err(ReferenceEvaluationError::ProfileEscape) => {
            return WorkloadObservation::empty(CaseOutcome::ProfileEscape)
        }
        Err(ReferenceEvaluationError::InvocationMismatch) => {
            return WorkloadObservation::empty(CaseOutcome::PipelineFailure)
        }
    };
    let meaning = match mint_meaning_token(&graph, input.mapped_value(), &context) {
        Ok(token) => token,
        Err(MeaningEvaluationError::ProfileEscape) => {
            return WorkloadObservation::empty(CaseOutcome::ProfileEscape)
        }
        Err(MeaningEvaluationError::InvocationMismatch) => {
            return WorkloadObservation::empty(CaseOutcome::PipelineFailure)
        }
    };
    let covered_nodes = meaning.visited_nodes().to_vec();
    let covered_branches = meaning.visited_branches().to_vec();
    let bound = match bind_and_consume(&context, &reference, &meaning) {
        Ok(bound) => bound,
        Err(_) => return WorkloadObservation::empty(CaseOutcome::PipelineFailure),
    };
    let reports = match build_trace_reports(&context, graph.nodes.len(), bound) {
        Ok(reports) => reports,
        Err(_) => return WorkloadObservation::empty(CaseOutcome::PipelineFailure),
    };

    let total_nodes = (0..graph.nodes.len()).collect::<Vec<_>>();
    let total_branches = graph
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| matches!(node, ContractNode::If { .. }))
        .flat_map(|(id, _)| [(id, false), (id, true)])
        .collect::<Vec<_>>();
    let coverage = WorkloadCoverage {
        graph_sha256,
        covered_nodes,
        total_nodes,
        covered_branches,
        total_branches,
    };
    if reports.comparison.status != ComparisonStatus::Agree
        || !matches!(reports.reference.transcript.terminal, Terminal::Completed)
        || !matches!(reports.meaning.transcript.terminal, Terminal::Completed)
    {
        return WorkloadObservation {
            outcome: CaseOutcome::NotComparable,
            coverage,
        };
    }
    let reference_decision = final_decision(&reports.reference.transcript.events);
    let meaning_decision = final_decision(&reports.meaning.transcript.events);
    let outcome = match (reference_decision, meaning_decision) {
        (Some(left), Some(right)) if left == right => CaseOutcome::Decision(left),
        (Some(_), Some(_)) => CaseOutcome::NotComparable,
        _ => CaseOutcome::PipelineFailure,
    };
    WorkloadObservation { outcome, coverage }
}

fn final_decision(events: &[TranscriptEvent]) -> Option<Decision> {
    match events.last() {
        Some(TranscriptEvent::Value {
            value: CanonicalValue::Decision(decision),
            ..
        }) => Some(*decision),
        _ => None,
    }
}

pub fn stable_coverage_identifiers(
    rule_version: &str,
    coverage: &WorkloadCoverage,
) -> (
    HashSet<String>,
    HashSet<String>,
    HashSet<String>,
    HashSet<String>,
) {
    let node = |id: usize| format!("{rule_version}:node:{id:04}");
    let branch = |(id, direction): (usize, bool)| {
        format!(
            "{rule_version}:branch:{id:04}:{}",
            if direction { "consequent" } else { "alternate" }
        )
    };
    (
        coverage.covered_nodes.iter().copied().map(node).collect(),
        coverage.total_nodes.iter().copied().map(node).collect(),
        coverage
            .covered_branches
            .iter()
            .copied()
            .map(branch)
            .collect(),
        coverage
            .total_branches
            .iter()
            .copied()
            .map(branch)
            .collect(),
    )
}
