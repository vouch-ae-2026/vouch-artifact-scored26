//! Independent contract-graph evaluator and live Meaning trace token.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::meaning_env::eval_graph_contract_metering;
use crate::meaning_graph::MeaningGraph;
use crate::number::{self, AErr, CmpOp, Num};
use crate::value::Value;

use super::canonical_value::CanonicalValue;
use super::eval_observer::MeterSnapshot;
use super::eval_observer::{BudgetObserver, EvalObserver};
use super::graph::{contract_graph_digest, ContractGraph, ContractNode};
use super::tokens::{InvocationContext, LiveTraceState};
use super::transcript::{
    EvaluationPhase, InfrastructureFailureCode, LanguageFaultCode, Terminal, Transcript,
    TranscriptEvent,
};

/// Module-private and non-serializable by construction.  Only the graph
/// evaluator can mint a value, while the sibling token boundary may inspect it.
#[derive(Debug)]
pub(super) struct MeaningTraceToken {
    state: LiveTraceState,
    graph_sha256: String,
    visited_nodes: Vec<usize>,
    visited_branches: Vec<(usize, bool)>,
}

impl MeaningTraceToken {
    pub(super) fn state(&self) -> &LiveTraceState {
        &self.state
    }

    pub(super) fn graph_sha256(&self) -> &str {
        &self.graph_sha256
    }

    pub(super) fn visited_nodes(&self) -> &[usize] {
        &self.visited_nodes
    }

    pub(super) fn visited_branches(&self) -> &[(usize, bool)] {
        &self.visited_branches
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MeaningEvaluationError {
    ProfileEscape,
    InvocationMismatch,
}

#[derive(Clone)]
enum GraphValue {
    Data(Value),
    Closure(Rc<GraphClosure>),
    Primitive(String),
}

#[derive(Clone)]
struct GraphClosure {
    params: Vec<String>,
    body: usize,
    env: GraphEnv,
}

#[derive(Clone)]
struct GraphEnv(Rc<GraphFrame>);

struct GraphFrame {
    parent: Option<GraphEnv>,
    bindings: RefCell<HashMap<String, GraphValue>>,
}

impl GraphEnv {
    fn root(input: Value) -> Self {
        let env = Self(Rc::new(GraphFrame {
            parent: None,
            bindings: RefCell::new(HashMap::new()),
        }));
        env.define("input".to_string(), GraphValue::Data(input));
        env
    }

    fn child(&self, bindings: impl IntoIterator<Item = (String, GraphValue)>) -> Self {
        Self(Rc::new(GraphFrame {
            parent: Some(self.clone()),
            bindings: RefCell::new(bindings.into_iter().collect()),
        }))
    }

    fn define(&self, name: String, value: GraphValue) {
        self.0.bindings.borrow_mut().insert(name, value);
    }

    fn get(&self, name: &str) -> Option<GraphValue> {
        self.0
            .bindings
            .borrow()
            .get(name)
            .cloned()
            .or_else(|| self.0.parent.as_ref().and_then(|parent| parent.get(name)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MeaningSignal {
    Language(LanguageFaultCode),
    ProfileEscape,
    Infrastructure,
}

struct GraphEvaluator<'a> {
    graph: &'a ContractGraph,
    observer: BudgetObserver,
    decisions_created: usize,
    visited_nodes: HashSet<usize>,
    visited_branches: HashSet<(usize, bool)>,
}

impl GraphEvaluator<'_> {
    fn eval(&mut self, id: usize, env: &GraphEnv) -> Result<GraphValue, MeaningSignal> {
        let _frame = self
            .observer
            .enter_form()
            .map_err(|_| MeaningSignal::Language(LanguageFaultCode::MeaningEnvBudgetExhausted))?;
        let node = self
            .graph
            .nodes
            .get(id)
            .cloned()
            .ok_or(MeaningSignal::Infrastructure)?;
        self.visited_nodes.insert(id);
        match node {
            ContractNode::Lit { value } => canonical_to_value(&value)
                .map(GraphValue::Data)
                .ok_or(MeaningSignal::Infrastructure),
            ContractNode::Var { name } => env.get(&name).ok_or(MeaningSignal::Infrastructure),
            ContractNode::Prim { name } => Ok(GraphValue::Primitive(name)),
            ContractNode::Lambda { params, body } => {
                Ok(GraphValue::Closure(Rc::new(GraphClosure {
                    params,
                    body,
                    env: env.clone(),
                })))
            }
            ContractNode::App {
                operator,
                arguments,
            } => {
                let operator = self.eval(operator, env)?;
                let arguments = arguments
                    .into_iter()
                    .map(|argument| self.eval(argument, env))
                    .collect::<Result<Vec<_>, _>>()?;
                if is_decision(&operator) || arguments.iter().any(is_decision) {
                    return Err(MeaningSignal::ProfileEscape);
                }
                self.apply(operator, arguments)
            }
            ContractNode::If {
                test,
                consequent,
                alternate,
            } => {
                let test = self.eval(test, env)?;
                if is_false(&test) {
                    self.visited_branches.insert((id, false));
                    // SCORED-MUTATION-SITE M03: swap graph evaluator successors.
                    let selected = if cfg!(scored_mutant = "M03") {
                        consequent
                    } else {
                        alternate
                    };
                    self.eval(selected, env)
                } else {
                    self.visited_branches.insert((id, true));
                    let selected = if cfg!(scored_mutant = "M03") {
                        alternate
                    } else {
                        consequent
                    };
                    self.eval(selected, env)
                }
            }
            ContractNode::Begin { forms } => {
                let mut last = None;
                for form in forms {
                    last = Some(self.eval(form, env)?);
                }
                last.ok_or(MeaningSignal::Infrastructure)
            }
            ContractNode::Let {
                names,
                initializers,
                body,
            } => {
                let values = initializers
                    .into_iter()
                    .map(|initializer| self.eval(initializer, env))
                    .collect::<Result<Vec<_>, _>>()?;
                let child = env.child(names.into_iter().zip(values));
                self.eval(body, &child)
            }
            ContractNode::Define { name, value } => {
                let value = self.eval(value, env)?;
                env.define(name, value);
                Ok(GraphValue::Data(Value::Nil))
            }
        }
    }

    fn apply(
        &mut self,
        operator: GraphValue,
        arguments: Vec<GraphValue>,
    ) -> Result<GraphValue, MeaningSignal> {
        match operator {
            GraphValue::Closure(closure) => {
                if closure.params.len() != arguments.len() {
                    return Err(MeaningSignal::Language(LanguageFaultCode::ArityMismatch));
                }
                let env = closure
                    .env
                    .child(closure.params.iter().cloned().zip(arguments));
                self.eval(closure.body, &env)
            }
            GraphValue::Primitive(name) => {
                self.observer.primitive_call().map_err(|_| {
                    MeaningSignal::Language(LanguageFaultCode::MeaningEnvBudgetExhausted)
                })?;
                let arguments = arguments
                    .into_iter()
                    .map(|value| match value {
                        GraphValue::Data(value) => Ok(value),
                        GraphValue::Closure(_) | GraphValue::Primitive(_) => {
                            Err(MeaningSignal::Language(LanguageFaultCode::TypeError))
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let value = apply_primitive(&name, &arguments)?;
                if matches!(value, Value::Decision(_)) {
                    self.decisions_created += 1;
                }
                Ok(GraphValue::Data(value))
            }
            GraphValue::Data(_) => Err(MeaningSignal::Language(LanguageFaultCode::TypeError)),
        }
    }
}

/// Evaluate the canonical forest without calling the interpreter evaluator for
/// graph traversal, environment handling, application, or primitive dispatch.
pub(super) fn mint_meaning_token(
    graph: &ContractGraph,
    input: &Value,
    context: &InvocationContext,
) -> Result<MeaningTraceToken, MeaningEvaluationError> {
    let graph_sha256 =
        contract_graph_digest(graph).map_err(|_| MeaningEvaluationError::InvocationMismatch)?;
    if graph_sha256 != context.graph_sha256() || graph.roots.len() != context.root_count() {
        return Err(MeaningEvaluationError::InvocationMismatch);
    }
    let budgets = context.budgets();
    let mut evaluator = GraphEvaluator {
        graph,
        observer: BudgetObserver::new(budgets.meaning_steps, budgets.meaning_depth),
        decisions_created: 0,
        visited_nodes: HashSet::new(),
        visited_branches: HashSet::new(),
    };
    let env = GraphEnv::root(input.clone());
    let root_count = graph.roots.len();
    let mut events = Vec::with_capacity(root_count);
    let mut terminal = Terminal::Completed;
    for (form_index, root) in graph.roots.iter().copied().enumerate() {
        evaluator.decisions_created = 0;
        let result = evaluator.eval(root, &env);
        let decisions_created = evaluator.decisions_created;
        if decisions_created > 0
            && !matches!(
                &result,
                Ok(GraphValue::Data(Value::Decision(_)))
                    if decisions_created == 1 && form_index + 1 == root_count
            )
        {
            return Err(MeaningEvaluationError::ProfileEscape);
        }
        match result {
            Ok(GraphValue::Data(value)) => {
                let value = if matches!(graph.nodes[root], ContractNode::Define { .. }) {
                    CanonicalValue::Void
                } else {
                    CanonicalValue::from_value(&value)
                        .map_err(|_| MeaningEvaluationError::ProfileEscape)?
                };
                if value.contains_decision()
                    && (!matches!(value, CanonicalValue::Decision(_))
                        || form_index + 1 != root_count)
                {
                    return Err(MeaningEvaluationError::ProfileEscape);
                }
                events.push(TranscriptEvent::Value { form_index, value });
            }
            Ok(GraphValue::Closure(_) | GraphValue::Primitive(_))
            | Err(MeaningSignal::ProfileEscape) => {
                return Err(MeaningEvaluationError::ProfileEscape)
            }
            Err(MeaningSignal::Language(code)) => {
                terminal = Terminal::LanguageFault { code, form_index };
                break;
            }
            Err(MeaningSignal::Infrastructure) => {
                terminal = Terminal::InfrastructureFailure {
                    code: InfrastructureFailureCode::MeaningExecutionFailed,
                    phase: EvaluationPhase::Meaning,
                    next_form_index: form_index,
                };
                break;
            }
        }
    }
    // SCORED-MUTATION-SITE M09: graph-side final-value serialization.
    #[cfg(scored_mutant = "M09")]
    mutate_final_graph_value(&mut events);
    let transcript = Transcript { events, terminal };
    transcript
        .validate(root_count)
        .map_err(|_| MeaningEvaluationError::InvocationMismatch)?;
    let mut visited_nodes = evaluator.visited_nodes.into_iter().collect::<Vec<_>>();
    visited_nodes.sort_unstable();
    let mut visited_branches = evaluator.visited_branches.into_iter().collect::<Vec<_>>();
    visited_branches.sort_unstable();
    Ok(MeaningTraceToken {
        state: LiveTraceState::from_invocation(context, transcript),
        graph_sha256,
        visited_nodes,
        visited_branches,
    })
}

fn apply_primitive(name: &str, args: &[Value]) -> Result<Value, MeaningSignal> {
    match name {
        "+" => number::add(&numeric_args(args)?).map_err(arithmetic_fault),
        "*" => number::mul(&numeric_args(args)?).map_err(arithmetic_fault),
        "-" => {
            require_min_arity(args, 1)?;
            number::sub(&numeric_args(args)?).map_err(arithmetic_fault)
        }
        "/" => {
            require_min_arity(args, 1)?;
            number::div(&numeric_args(args)?).map_err(arithmetic_fault)
        }
        "=" | "<" | "<=" | ">" | ">=" => {
            require_min_arity(args, 2)?;
            let operation = match name {
                "=" => CmpOp::Eq,
                "<" => CmpOp::Lt,
                // SCORED-MUTATION-SITE M04: graph-side inclusive comparison is
                // strict while the reference evaluator remains unchanged.
                "<=" if cfg!(scored_mutant = "M04") => CmpOp::Lt,
                "<=" => CmpOp::Le,
                ">" => CmpOp::Gt,
                ">=" => CmpOp::Ge,
                _ => unreachable!(),
            };
            Ok(Value::Bool(number::compare(
                &numeric_args(args)?,
                operation,
            )))
        }
        "cons" => {
            require_arity(args, 2)?;
            Ok(Value::list_with_tail(
                std::iter::once(args[0].clone()),
                args[1].clone(),
            ))
        }
        "car" => {
            require_arity(args, 1)?;
            match &args[0] {
                Value::Pair(pair) => Ok(pair.car.clone()),
                _ => Err(MeaningSignal::Language(LanguageFaultCode::TypeError)),
            }
        }
        "cdr" => {
            require_arity(args, 1)?;
            match &args[0] {
                Value::Pair(pair) => Ok(pair.cdr.clone()),
                _ => Err(MeaningSignal::Language(LanguageFaultCode::TypeError)),
            }
        }
        "null?" => {
            require_arity(args, 1)?;
            Ok(Value::Bool(matches!(args[0], Value::Nil)))
        }
        "pair?" => {
            require_arity(args, 1)?;
            Ok(Value::Bool(matches!(args[0], Value::Pair(_))))
        }
        "list" => Ok(Value::list(args.iter().cloned())),
        "exact-integer?" => {
            require_arity(args, 1)?;
            Ok(Value::Bool(matches!(args[0], Value::Int(_))))
        }
        "decision-approve" => decision(args, crate::Decision::Approve),
        "decision-deny" => decision(args, crate::Decision::Deny),
        "decision-review" => decision(args, crate::Decision::Review),
        "decision-invalid-input" => decision(args, crate::Decision::InvalidInput),
        _ => Err(MeaningSignal::Infrastructure),
    }
}

fn numeric_args(args: &[Value]) -> Result<Vec<Num>, MeaningSignal> {
    args.iter()
        .map(|value| {
            number::num_of(value).ok_or(MeaningSignal::Language(LanguageFaultCode::TypeError))
        })
        .collect()
}

fn arithmetic_fault(error: AErr) -> MeaningSignal {
    MeaningSignal::Language(match error {
        AErr::DivZero => LanguageFaultCode::DivisionByZero,
        AErr::NotFinite => LanguageFaultCode::NumericDomainError,
        AErr::NotInteger => LanguageFaultCode::TypeError,
    })
}

fn require_arity(args: &[Value], expected: usize) -> Result<(), MeaningSignal> {
    if args.len() == expected {
        Ok(())
    } else {
        Err(MeaningSignal::Language(LanguageFaultCode::ArityMismatch))
    }
}

fn require_min_arity(args: &[Value], minimum: usize) -> Result<(), MeaningSignal> {
    if args.len() >= minimum {
        Ok(())
    } else {
        Err(MeaningSignal::Language(LanguageFaultCode::ArityMismatch))
    }
}

fn decision(args: &[Value], value: crate::Decision) -> Result<Value, MeaningSignal> {
    require_arity(args, 0)?;
    Ok(Value::Decision(value))
}

fn is_false(value: &GraphValue) -> bool {
    matches!(value, GraphValue::Data(Value::Bool(false)))
}

fn is_decision(value: &GraphValue) -> bool {
    matches!(value, GraphValue::Data(Value::Decision(_)))
}

fn canonical_to_value(value: &CanonicalValue) -> Option<Value> {
    match value {
        CanonicalValue::Integer(value) => value.parse().ok().map(Value::Int),
        CanonicalValue::Rational {
            numerator,
            denominator,
        } => Some(Value::ratio(
            numerator.parse().ok()?,
            denominator.parse().ok()?,
        )),
        CanonicalValue::Real(value) => Value::real(value.parse().ok()?),
        CanonicalValue::Boolean(value) => Some(Value::Bool(*value)),
        CanonicalValue::Nil => Some(Value::Nil),
        CanonicalValue::List {
            items,
            improper_tail,
        } => {
            let items = items
                .iter()
                .map(canonical_to_value)
                .collect::<Option<Vec<_>>>()?;
            let tail = match improper_tail.as_deref() {
                Some(value) => canonical_to_value(value)?,
                None => Value::Nil,
            };
            Some(Value::list_with_tail(items.into_iter(), tail))
        }
        CanonicalValue::Symbol(value) => Some(Value::Sym(value.as_str().into())),
        CanonicalValue::String(value) => Some(Value::Str(value.as_str().into())),
        CanonicalValue::Void | CanonicalValue::Decision(_) => None,
    }
}

#[cfg(scored_mutant = "M09")]
fn mutate_final_graph_value(events: &mut [TranscriptEvent]) {
    let Some(TranscriptEvent::Value { value, .. }) = events.last_mut() else {
        return;
    };
    *value = match value {
        CanonicalValue::Boolean(false) => CanonicalValue::Boolean(true),
        _ => CanonicalValue::Boolean(false),
    };
}

#[derive(Clone, Debug)]
pub struct MeaningSpikeResult {
    pub terminal: Terminal,
    pub meter: MeterSnapshot,
}

/// Exercise the contract observer over the existing Meaning Graph traversal.
/// This spike intentionally does not change or extend that graph schema; PR3's
/// contract graph remains a separate type.
pub fn run_metering_spike(
    graph: &MeaningGraph,
    step_limit: usize,
    depth_limit: usize,
) -> MeaningSpikeResult {
    let (result, meter) = eval_graph_contract_metering(graph, None, step_limit, depth_limit);
    MeaningSpikeResult {
        terminal: if result.is_ok() {
            Terminal::Completed
        } else {
            Terminal::LanguageFault {
                code: LanguageFaultCode::MeaningEnvBudgetExhausted,
                form_index: 0,
            }
        },
        meter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vouch_native::eval_observer::{MeterEvent, MeterEventKind};
    use crate::{lower_meaning_graph_program, normalize_program, read_program};

    fn graph(source: &str) -> MeaningGraph {
        let program = read_program(source, "<meaning-spike>").unwrap();
        let core = normalize_program(&program.datums, "<meaning-spike>").unwrap();
        lower_meaning_graph_program(&core).unwrap()
    }

    #[test]
    fn meaning_trace_is_deterministic_and_budget_terminal_has_schema_code() {
        let graph = graph("(+ 1 2)");
        let first = run_metering_spike(&graph, 5, 32);
        let second = run_metering_spike(&graph, 5, 32);
        assert_eq!(first.terminal, second.terminal);
        assert_eq!(first.meter.trace, second.meter.trace);
        assert_eq!(
            run_metering_spike(&graph, 6, 32).meter.trace,
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
                    depth: 3,
                },
                MeterEvent {
                    kind: MeterEventKind::Form,
                    step: 4,
                    depth: 3,
                },
                MeterEvent {
                    kind: MeterEventKind::Form,
                    step: 5,
                    depth: 3,
                },
                MeterEvent {
                    kind: MeterEventKind::Primitive,
                    step: 6,
                    depth: 2,
                },
            ]
        );
        assert_eq!(
            first.terminal,
            Terminal::LanguageFault {
                code: LanguageFaultCode::MeaningEnvBudgetExhausted,
                form_index: 0,
            }
        );
    }

    #[test]
    fn meaning_succeeds_at_exact_limit_and_faults_on_next_charge() {
        let graph = graph("(+ 1 2)");
        assert_eq!(
            run_metering_spike(&graph, 6, 32).terminal,
            Terminal::Completed
        );
        assert_eq!(
            run_metering_spike(&graph, 5, 32).terminal,
            Terminal::LanguageFault {
                code: LanguageFaultCode::MeaningEnvBudgetExhausted,
                form_index: 0,
            }
        );
    }
}
