//! Metered checked-profile reference evaluator and live trace token.

use crate::eval::{Eval, Interp};
use crate::normalize::normalize_program;
use crate::reader::read_program;
use crate::{Outcome, RuntimeCode, Value};

use super::canonical_value::{domain_hash, CanonicalValue, ProfileEscape};
use super::checked_profile::CheckedProgram;
use super::eval_observer::{BudgetObserver, MeterSnapshot};
use super::tokens::{InvocationContext, LiveTraceState};
use super::transcript::{
    InfrastructureFailureCode, LanguageFaultCode, Terminal, Transcript, TranscriptEvent,
};

const NORMALIZED_HASH_DOMAIN: &str = "csk.v0.canonical";

/// Module-private and non-serializable by construction.  Only this evaluator
/// can mint a value, while the sibling token boundary can inspect it.
#[derive(Debug)]
pub(super) struct ReferenceTraceToken {
    state: LiveTraceState,
    normalized_sha256: String,
}

impl ReferenceTraceToken {
    pub(super) fn state(&self) -> &LiveTraceState {
        &self.state
    }

    pub(super) fn normalized_sha256(&self) -> &str {
        &self.normalized_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReferenceEvaluationError {
    ProfileEscape,
    InvocationMismatch,
}

/// Evaluate every checked Core root with the reference interpreter, record
/// observable values, and mint one live token bound to `context`.
pub(super) fn mint_reference_token(
    program: &CheckedProgram,
    input: &Value,
    context: &InvocationContext,
) -> Result<ReferenceTraceToken, ReferenceEvaluationError> {
    let normalized_sha256 = domain_hash(NORMALIZED_HASH_DOMAIN, program.normalized_bytes());
    if normalized_sha256 != context.normalized_sha256()
        || context.root_count() != program.core().len()
    {
        return Err(ReferenceEvaluationError::InvocationMismatch);
    }

    let budgets = context.budgets();
    let observer = BudgetObserver::new(budgets.reference_steps, budgets.reference_depth);
    let mut interp = Interp::new();
    interp.define_global("input", input.clone());
    interp.set_contract_observer(Box::new(observer));

    let root_count = program.core().len();
    let mut events = Vec::with_capacity(root_count);
    let mut terminal = Terminal::Completed;
    for (form_index, form) in program.core().iter().cloned().enumerate() {
        interp.begin_contract_root();
        let result = interp.eval_toplevel(form);
        let decisions_created = interp.contract_decisions_created();
        match result {
            Eval::Ok(outcome) => {
                let value = canonical_outcome(outcome)
                    .map_err(|_| ReferenceEvaluationError::ProfileEscape)?;
                // SCORED-MUTATION-SITE M10: reference-side canonical value before
                // the unchanged shared canonical writer.
                #[cfg(scored_mutant = "M10")]
                let value = {
                    let mut value = value;
                    mutate_reference_strings(&mut value);
                    value
                };
                if decisions_created > 0
                    && (decisions_created != 1
                        || form_index + 1 != root_count
                        || !matches!(value, CanonicalValue::Decision(_)))
                {
                    return Err(ReferenceEvaluationError::ProfileEscape);
                }
                if value.contains_decision()
                    && (!matches!(value, CanonicalValue::Decision(_))
                        || form_index + 1 != root_count)
                {
                    return Err(ReferenceEvaluationError::ProfileEscape);
                }
                events.push(TranscriptEvent::Value { form_index, value });
            }
            Eval::Error(error)
                if error.code == RuntimeCode::ProfileEscape || decisions_created > 0 =>
            {
                return Err(ReferenceEvaluationError::ProfileEscape)
            }
            Eval::Error(error) => {
                terminal = Terminal::LanguageFault {
                    code: language_fault(error.code),
                    form_index,
                };
                break;
            }
            Eval::Escape { .. } | Eval::TailApply { .. } => {
                terminal = Terminal::InfrastructureFailure {
                    code: InfrastructureFailureCode::ReferenceExecutionFailed,
                    phase: super::transcript::EvaluationPhase::Reference,
                    next_form_index: form_index,
                };
                break;
            }
        }
    }
    let transcript = Transcript { events, terminal };
    transcript
        .validate(root_count)
        .map_err(|_| ReferenceEvaluationError::InvocationMismatch)?;
    Ok(ReferenceTraceToken {
        state: LiveTraceState::from_invocation(context, transcript),
        normalized_sha256,
    })
}

fn canonical_outcome(outcome: Outcome) -> Result<CanonicalValue, ProfileEscape> {
    match outcome {
        Outcome::One(value) => CanonicalValue::from_value(&value),
        Outcome::Many(values) if values.is_empty() => Ok(CanonicalValue::Void),
        Outcome::Many(_) => Err(ProfileEscape),
    }
}

fn language_fault(code: RuntimeCode) -> LanguageFaultCode {
    match code {
        RuntimeCode::ReferenceBudgetExhausted | RuntimeCode::RecursionLimit => {
            LanguageFaultCode::ReferenceBudgetExhausted
        }
        RuntimeCode::E302 => LanguageFaultCode::ArityMismatch,
        RuntimeCode::E313 => LanguageFaultCode::DivisionByZero,
        RuntimeCode::E314 => LanguageFaultCode::NumericDomainError,
        RuntimeCode::E300
        | RuntimeCode::E301
        | RuntimeCode::E303
        | RuntimeCode::E310
        | RuntimeCode::E311
        | RuntimeCode::E312
        | RuntimeCode::E320
        | RuntimeCode::E321
        | RuntimeCode::E330
        | RuntimeCode::E331
        | RuntimeCode::E332
        | RuntimeCode::E340
        | RuntimeCode::ProfileEscape => LanguageFaultCode::TypeError,
    }
}

#[cfg(scored_mutant = "M10")]
fn mutate_reference_strings(value: &mut CanonicalValue) {
    match value {
        CanonicalValue::String(text) => *text = text.replace('\n', "\\n"),
        CanonicalValue::List {
            items,
            improper_tail,
        } => {
            for item in items {
                mutate_reference_strings(item);
            }
            if let Some(tail) = improper_tail {
                mutate_reference_strings(tail);
            }
        }
        _ => {}
    }
}

#[derive(Clone, Debug)]
pub struct ReferenceSpikeResult {
    pub terminal: Terminal,
    pub meter: MeterSnapshot,
}

/// Run the existing reference evaluator with contract accounting enabled.
/// Parsing and normalization errors are deliberately outside this spike: the
/// checked-profile lane classifies them before either evaluator is entered.
pub fn run_metering_spike(
    source: &str,
    step_limit: usize,
    depth_limit: usize,
) -> Result<ReferenceSpikeResult, String> {
    let program = read_program(source, "<contract-spike>").map_err(|e| e.to_string())?;
    let core = normalize_program(&program.datums, "<contract-spike>").map_err(|e| e.to_string())?;
    let observer = BudgetObserver::new(step_limit, depth_limit);
    let observer_handle = observer.clone();
    let mut interp = Interp::new();
    interp.set_contract_observer(Box::new(observer));

    let mut terminal = Terminal::Completed;
    for (form_index, form) in core.into_iter().enumerate() {
        match interp.eval_toplevel(form) {
            Eval::Ok(_) => {}
            Eval::Error(error) => {
                let code = match error.code {
                    crate::RuntimeCode::ReferenceBudgetExhausted => {
                        LanguageFaultCode::ReferenceBudgetExhausted
                    }
                    crate::RuntimeCode::E302 => LanguageFaultCode::ArityMismatch,
                    crate::RuntimeCode::E312 => LanguageFaultCode::TypeError,
                    crate::RuntimeCode::E313 => LanguageFaultCode::DivisionByZero,
                    crate::RuntimeCode::E314 => LanguageFaultCode::NumericDomainError,
                    _ => LanguageFaultCode::TypeError,
                };
                terminal = Terminal::LanguageFault { code, form_index };
                break;
            }
            Eval::Escape { .. } | Eval::TailApply { .. } => {
                terminal = Terminal::InfrastructureFailure {
                    code: InfrastructureFailureCode::ReferenceExecutionFailed,
                    phase: super::transcript::EvaluationPhase::Reference,
                    next_form_index: form_index,
                };
                break;
            }
        }
    }

    Ok(ReferenceSpikeResult {
        terminal,
        meter: observer_handle.snapshot(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vouch_native::eval_observer::{MeterEvent, MeterEventKind};
    use crate::{normalize_program, read_program, RuntimeCode};

    #[test]
    fn reference_trace_golden_counts_forms_and_primitive_invocation() {
        let result = run_metering_spike("(+ 1 2)", 10, 10).unwrap();
        assert_eq!(result.terminal, Terminal::Completed);
        assert_eq!(
            result.meter.trace,
            vec![
                MeterEvent {
                    kind: MeterEventKind::Form,
                    step: 1,
                    depth: 1,
                },
                MeterEvent {
                    kind: MeterEventKind::Form,
                    step: 2,
                    depth: 2,
                },
                MeterEvent {
                    kind: MeterEventKind::Form,
                    step: 3,
                    depth: 2,
                },
                MeterEvent {
                    kind: MeterEventKind::Form,
                    step: 4,
                    depth: 2,
                },
                MeterEvent {
                    kind: MeterEventKind::Primitive,
                    step: 5,
                    depth: 1,
                },
            ]
        );
    }

    #[test]
    fn reference_succeeds_at_exact_step_limit_and_faults_on_next_charge() {
        assert_eq!(
            run_metering_spike("(+ 1 2)", 5, 10).unwrap().terminal,
            Terminal::Completed
        );
        assert_eq!(
            run_metering_spike("(+ 1 2)", 4, 10).unwrap().terminal,
            Terminal::LanguageFault {
                code: LanguageFaultCode::ReferenceBudgetExhausted,
                form_index: 0,
            }
        );
    }

    #[test]
    fn tco_does_not_collapse_contract_frames() {
        let source =
            "(let ((loop (lambda (self n) (if (= n 0) 0 (self self (- n 1)))))) (loop loop 20))";
        let result = run_metering_spike(source, 10_000, 12).unwrap();
        assert_eq!(
            result.terminal,
            Terminal::LanguageFault {
                code: LanguageFaultCode::ReferenceBudgetExhausted,
                form_index: 0,
            }
        );
        assert_eq!(result.meter.maximum_depth, 12);
    }

    #[test]
    fn budget_fault_form_index_is_reproducible() {
        let source = "1\n(+ 1 2)\n3";
        let first = run_metering_spike(source, 5, 32).unwrap();
        let second = run_metering_spike(source, 5, 32).unwrap();
        assert_eq!(first.terminal, second.terminal);
        assert_eq!(
            first.terminal,
            Terminal::LanguageFault {
                code: LanguageFaultCode::ReferenceBudgetExhausted,
                form_index: 1,
            }
        );
    }

    #[test]
    fn decision_cannot_reach_comparison_list_or_other_primitive() {
        for source in [
            "(= (decision-approve) (decision-approve))",
            "(list (decision-approve))",
            "(+ (decision-approve) 1)",
            "((lambda (x) x) (decision-approve))",
        ] {
            let program = read_program(source, "<decision-escape>").unwrap();
            let core = normalize_program(&program.datums, "<decision-escape>").unwrap();
            let mut interp = Interp::new();
            interp.set_contract_observer(Box::new(BudgetObserver::new(100, 100)));
            let Eval::Error(error) = interp.eval_toplevel(core[0].clone()) else {
                panic!("decision operand unexpectedly reached primitive: {source}")
            };
            assert_eq!(error.code, RuntimeCode::ProfileEscape, "{source}");
        }
    }
}
