//! Meaning Environment v0 evaluator (CSK-MEANING-ENVIRONMENT.md).
//!
//! This module evaluates canonical Meaning Graph v0 JSON bytes. It is deliberately
//! separate from `eval.rs`: the reference interpreter remains the authority, while
//! this evaluator provides the second internal path that v1.2.8 can compare.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::process::Command;
use std::rc::Rc;

use serde_json::{json, Value as JsonValue};

use crate::canonical::{
    canonical_datum_parse, canonical_datum_string, profile_input_hash_hex,
    PROFILE_INPUT_HASH_DOMAIN,
};
use crate::core::Intrinsic;
use crate::meaning_graph::{
    graph_from_json_value, graph_hash_hex, graph_json_bytes, validate_graph_value, Anchor,
    GraphLawError, GraphName, GraphNode, MeaningGraph, MEANING_GRAPH_HASH_DOMAIN,
};
use crate::number::{self, AErr, CmpOp, Num};
use crate::value::Value;

pub const MEANING_ENV_REPORT_TAG: &str = "csk.meaning-env-report/v0";
pub const MEANING_ENV_REPORT_HASH_DOMAIN: &str = "csk/meaning-env-report-hash/v0";
pub const MEANING_ENV_DEFAULT_STEP_LIMIT: usize = 65_536;

#[cfg(not(target_arch = "wasm32"))]
const MEANING_ENV_STACK_RED_ZONE: usize = 64 * 1024;
#[cfg(not(target_arch = "wasm32"))]
const MEANING_ENV_STACK_GROW_SIZE: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeaningEnvOutput {
    pub report: Vec<u8>,
    pub ok: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeaningEnvReceiptProjection {
    pub status: &'static str,
    pub transcript: Vec<String>,
    pub steps_used: usize,
    pub step_limit: usize,
    pub fault: JsonValue,
    pub ok: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeaningEnvInputError {
    message: String,
}

impl MeaningEnvInputError {
    fn new(message: impl Into<String>) -> MeaningEnvInputError {
        MeaningEnvInputError {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MeaningEnvInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MeaningEnvInputError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeaningEnvFault {
    kind: &'static str,
    message: String,
    node: Option<usize>,
    anchor: Option<Anchor>,
}

impl MeaningEnvFault {
    fn new(
        kind: &'static str,
        message: impl Into<String>,
        node: Option<usize>,
        anchor: Option<Anchor>,
    ) -> MeaningEnvFault {
        MeaningEnvFault {
            kind,
            message: message.into(),
            node,
            anchor,
        }
    }

    pub fn kind(&self) -> &'static str {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

pub fn eval_graph_json_report(
    bytes: &[u8],
    step_limit: usize,
) -> Result<MeaningEnvOutput, MeaningEnvInputError> {
    eval_graph_json_report_with_input(bytes, step_limit, None)
}

pub fn eval_graph_json_report_with_input(
    bytes: &[u8],
    step_limit: usize,
    profile_input: Option<Value>,
) -> Result<MeaningEnvOutput, MeaningEnvInputError> {
    if std::str::from_utf8(bytes).is_err() {
        return Err(MeaningEnvInputError::new(
            "lispex eval-graph: graph JSON is not valid UTF-8",
        ));
    }

    let input_report = match profile_input.as_ref() {
        Some(value) => Some(InputReport::from_value(value).map_err(|e| {
            MeaningEnvInputError::new(format!("lispex eval-graph: input datum failed: {e}"))
        })?),
        None => None,
    };

    let graph_hash = graph_hash_hex(bytes);
    let json: JsonValue = serde_json::from_slice(bytes).map_err(|e| {
        MeaningEnvInputError::new(format!("lispex eval-graph: graph JSON parse failed: {e}"))
    })?;

    let law_errors = validate_graph_value(&json);
    if !law_errors.is_empty() {
        let report = Report::law_error(
            bytes.len(),
            graph_hash,
            step_limit,
            input_report,
            law_errors,
        );
        return Ok(MeaningEnvOutput {
            report: report_json_bytes(&report),
            ok: false,
        });
    }

    let graph = graph_from_json_value(&json).expect("law-valid graph should build");
    let rendered = graph_json_bytes(&graph);
    if rendered != bytes {
        let report = Report::fault(
            bytes.len(),
            graph_hash,
            step_limit,
            input_report,
            0,
            Vec::new(),
            Vec::new(),
            MeaningEnvFault::new(
                "non-canonical-graph",
                "graph JSON bytes are law-legal but not canonical Meaning Graph writer bytes",
                None,
                None,
            ),
        );
        return Ok(MeaningEnvOutput {
            report: report_json_bytes(&report),
            ok: false,
        });
    }

    if let Some(fault) = shared_node_fault(&graph) {
        let report = Report::fault(
            bytes.len(),
            graph_hash,
            step_limit,
            input_report,
            0,
            Vec::new(),
            Vec::new(),
            fault,
        );
        return Ok(MeaningEnvOutput {
            report: report_json_bytes(&report),
            ok: false,
        });
    }

    match Evaluator::new(&graph, step_limit, profile_input).eval_roots() {
        Ok(result) => {
            let report = Report::ok(
                bytes.len(),
                graph_hash,
                step_limit,
                input_report,
                result.steps_used,
                result.trace,
                result.transcript,
                result.values,
            );
            Ok(MeaningEnvOutput {
                report: report_json_bytes(&report),
                ok: true,
            })
        }
        Err(result) => {
            let result = *result;
            let report = Report::fault(
                bytes.len(),
                graph_hash,
                step_limit,
                input_report,
                result.steps_used,
                result.trace,
                result.transcript,
                result.fault,
            );
            Ok(MeaningEnvOutput {
                report: report_json_bytes(&report),
                ok: false,
            })
        }
    }
}

pub fn eval_graph_json_receipt_projection_with_input(
    bytes: &[u8],
    step_limit: usize,
    profile_input: Option<Value>,
) -> Result<MeaningEnvReceiptProjection, MeaningEnvInputError> {
    if std::str::from_utf8(bytes).is_err() {
        return Err(MeaningEnvInputError::new(
            "lispex eval-graph: graph JSON is not valid UTF-8",
        ));
    }

    if let Some(value) = profile_input.as_ref() {
        InputReport::from_value(value).map_err(|e| {
            MeaningEnvInputError::new(format!("lispex eval-graph: input datum failed: {e}"))
        })?;
    }

    let json: JsonValue = serde_json::from_slice(bytes).map_err(|e| {
        MeaningEnvInputError::new(format!("lispex eval-graph: graph JSON parse failed: {e}"))
    })?;

    let law_errors = validate_graph_value(&json);
    if !law_errors.is_empty() {
        return Ok(MeaningEnvReceiptProjection {
            status: "law-error",
            transcript: Vec::new(),
            steps_used: 0,
            step_limit,
            fault: JsonValue::Null,
            ok: false,
        });
    }

    let graph = graph_from_json_value(&json).expect("law-valid graph should build");
    let rendered = graph_json_bytes(&graph);
    if rendered != bytes {
        let fault = MeaningEnvFault::new(
            "non-canonical-graph",
            "graph JSON bytes are law-legal but not canonical Meaning Graph writer bytes",
            None,
            None,
        );
        return Ok(MeaningEnvReceiptProjection {
            status: "fault",
            transcript: Vec::new(),
            steps_used: 0,
            step_limit,
            fault: fault_json(Some(&fault)),
            ok: false,
        });
    }

    if let Some(fault) = shared_node_fault(&graph) {
        return Ok(MeaningEnvReceiptProjection {
            status: "fault",
            transcript: Vec::new(),
            steps_used: 0,
            step_limit,
            fault: fault_json(Some(&fault)),
            ok: false,
        });
    }

    match Evaluator::new_with_trace_mode(&graph, step_limit, profile_input, TraceMode::Suppressed)
        .eval_roots()
    {
        Ok(result) => Ok(MeaningEnvReceiptProjection {
            status: "ok",
            transcript: result.transcript,
            steps_used: result.steps_used,
            step_limit,
            fault: JsonValue::Null,
            ok: true,
        }),
        Err(result) => {
            let result = *result;
            Ok(MeaningEnvReceiptProjection {
                status: "fault",
                transcript: result.transcript,
                steps_used: result.steps_used,
                step_limit,
                fault: fault_json(Some(&result.fault)),
                ok: false,
            })
        }
    }
}

/// Stage 2.5 contract-only metering entry over the existing Meaning evaluator.
/// It is intentionally not used by normal `eval-graph` or `diff-receipt`.
#[cfg(feature = "scored-native-contract")]
pub fn eval_graph_contract_metering(
    graph: &MeaningGraph,
    profile_input: Option<Value>,
    step_limit: usize,
    depth_limit: usize,
) -> (
    Result<(), MeaningEnvFault>,
    crate::vouch_native::eval_observer::MeterSnapshot,
) {
    let observer = crate::vouch_native::eval_observer::BudgetObserver::new(step_limit, depth_limit);
    let handle = observer.clone();
    let result = Evaluator::new_contract_metered(graph, profile_input, observer)
        .eval_roots()
        .map(|_| ())
        .map_err(|failure| failure.fault);
    (result, handle.snapshot())
}

#[derive(Clone)]
struct EvalSuccess {
    values: Vec<String>,
    trace: Vec<TraceEvent>,
    transcript: Vec<String>,
    steps_used: usize,
}

#[derive(Clone)]
struct EvalFailure {
    fault: MeaningEnvFault,
    trace: Vec<TraceEvent>,
    transcript: Vec<String>,
    steps_used: usize,
}

type Cell = Rc<RefCell<Option<EnvValue>>>;

#[derive(Clone)]
struct Env(Rc<Frame>);

struct Frame {
    vars: RefCell<BTreeMap<String, Cell>>,
    parent: Option<Env>,
}

impl Env {
    fn root() -> Env {
        Env(Rc::new(Frame {
            vars: RefCell::new(BTreeMap::new()),
            parent: None,
        }))
    }

    fn child(&self) -> Env {
        Env(Rc::new(Frame {
            vars: RefCell::new(BTreeMap::new()),
            parent: Some(self.clone()),
        }))
    }

    fn lookup(&self, key: &str) -> Option<Cell> {
        if let Some(cell) = self.0.vars.borrow().get(key).cloned() {
            return Some(cell);
        }
        self.0.parent.as_ref().and_then(|parent| parent.lookup(key))
    }

    fn prebind_local(&self, key: String) {
        self.0
            .vars
            .borrow_mut()
            .entry(key)
            .or_insert_with(|| Rc::new(RefCell::new(None)));
    }

    fn bind_value_local(&self, key: String, value: EnvValue) {
        self.0
            .vars
            .borrow_mut()
            .insert(key, Rc::new(RefCell::new(Some(value))));
    }

    fn assign_local_or_bind(&self, key: String, value: EnvValue) {
        if let Some(cell) = self.0.vars.borrow().get(&key).cloned() {
            *cell.borrow_mut() = Some(value);
        } else {
            self.bind_value_local(key, value);
        }
    }
}

#[derive(Clone)]
struct Evaluator<'a> {
    graph: &'a MeaningGraph,
    env: Env,
    trace: Vec<TraceEvent>,
    transcript: Vec<String>,
    steps: usize,
    step_limit: usize,
    trace_mode: TraceMode,
    #[cfg(feature = "scored-native-contract")]
    contract_observer: Option<crate::vouch_native::eval_observer::BudgetObserver>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceMode {
    Full,
    Suppressed,
}

impl<'a> Evaluator<'a> {
    fn new(
        graph: &'a MeaningGraph,
        step_limit: usize,
        profile_input: Option<Value>,
    ) -> Evaluator<'a> {
        Self::new_with_trace_mode(graph, step_limit, profile_input, TraceMode::Full)
    }

    fn new_with_trace_mode(
        graph: &'a MeaningGraph,
        step_limit: usize,
        profile_input: Option<Value>,
        trace_mode: TraceMode,
    ) -> Evaluator<'a> {
        let env = Env::root();
        if let Some(input) = profile_input {
            env.bind_value_local("user:input".to_string(), EnvValue::Datum(input));
        }
        Evaluator {
            graph,
            env,
            trace: Vec::new(),
            transcript: Vec::new(),
            steps: 0,
            step_limit,
            trace_mode,
            #[cfg(feature = "scored-native-contract")]
            contract_observer: None,
        }
    }

    #[cfg(feature = "scored-native-contract")]
    fn new_contract_metered(
        graph: &'a MeaningGraph,
        profile_input: Option<Value>,
        observer: crate::vouch_native::eval_observer::BudgetObserver,
    ) -> Evaluator<'a> {
        let mut evaluator =
            Self::new_with_trace_mode(graph, usize::MAX, profile_input, TraceMode::Suppressed);
        evaluator.contract_observer = Some(observer);
        evaluator
    }

    fn eval_roots(mut self) -> Result<EvalSuccess, Box<EvalFailure>> {
        let mut last = Vec::new();
        for &root in &self.graph.roots {
            match self.eval_node(
                root,
                matches!(self.graph.nodes[root], GraphNode::Block { .. }),
            ) {
                Ok(values) => {
                    if !matches!(self.graph.nodes[root], GraphNode::Block { .. }) {
                        self.extend_transcript(&values);
                    }
                    last = values;
                }
                Err(fault) => return Err(self.failure(fault)),
            }
        }
        Ok(EvalSuccess {
            values: render_values(&last),
            trace: self.trace,
            transcript: self.transcript,
            steps_used: self.steps,
        })
    }

    fn eval_node(
        &mut self,
        index: usize,
        root_transcript: bool,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        self.eval_node_step(index, root_transcript)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn eval_node_step(
        &mut self,
        index: usize,
        root_transcript: bool,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        let me = &mut *self;
        stacker::maybe_grow(
            MEANING_ENV_STACK_RED_ZONE,
            MEANING_ENV_STACK_GROW_SIZE,
            move || me.eval_node_inner(index, root_transcript),
        )
    }

    #[cfg(target_arch = "wasm32")]
    fn eval_node_step(
        &mut self,
        index: usize,
        root_transcript: bool,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        self.eval_node_inner(index, root_transcript)
    }

    fn eval_node_inner(
        &mut self,
        index: usize,
        root_transcript: bool,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        #[cfg(feature = "scored-native-contract")]
        let _contract_frame = if let Some(observer) = self.contract_observer.as_mut() {
            use crate::vouch_native::eval_observer::EvalObserver;
            match observer.enter_form() {
                Ok(frame) => Some(frame),
                Err(_) => {
                    return Err(self.fault(
                        "meaning-env-budget-exhausted",
                        "contract Meaning evaluator budget exhausted",
                        index,
                    ))
                }
            }
        } else {
            None
        };
        if self.steps >= self.step_limit {
            return Err(self.fault(
                "step-limit",
                "Meaning Environment v0 step limit exceeded",
                index,
            ));
        }
        self.steps += 1;
        let node = &self.graph.nodes[index];
        let values = match node {
            GraphNode::Lit { datum, .. } => vec![EnvValue::Datum(
                canonical_datum_parse(datum).map_err(|_| {
                    self.fault(
                        "datum-text",
                        "literal datum is not canonical Canonical Core v0 text",
                        index,
                    )
                })?,
            )],
            GraphNode::Ref { name, .. } => match name {
                GraphName::Intrinsic(intrinsic) => vec![EnvValue::Intrinsic(*intrinsic)],
                GraphName::User(_) | GraphName::Temp(_) => {
                    let key = env_key(name).expect("non-intrinsic name has an env key");
                    let Some(cell) = self.env.lookup(&key) else {
                        return Err(self.fault("unbound-ref", "reference is unbound", index));
                    };
                    let Some(value) = cell.borrow().clone() else {
                        return Err(self.fault(
                            "uninitialized-ref",
                            "reference points to an uninitialized binding",
                            index,
                        ));
                    };
                    vec![value]
                }
            },
            GraphNode::Call { op, args, .. } => {
                let op_values = self.eval_node(*op, false)?;
                let callable = match op_values.as_slice() {
                    [value] => value.clone(),
                    _ => {
                        return Err(self.fault(
                            "non-callable",
                            "call operator did not evaluate to one callable value",
                            index,
                        ))
                    }
                };
                let mut arg_values = Vec::with_capacity(args.len());
                for &arg in args {
                    let values = self.eval_node(arg, false)?;
                    match values.as_slice() {
                        [value] => arg_values.push(value.clone()),
                        _ => {
                            return Err(self.fault(
                                "intrinsic-domain",
                                "call argument did not evaluate to one value",
                                index,
                            ))
                        }
                    }
                }
                self.apply_callable(callable, &arg_values, index)?
            }
            GraphNode::If {
                test,
                then_branch,
                else_branch,
                ..
            } => {
                let test_values = self.eval_node(*test, false)?;
                let [EnvValue::Datum(test_value)] = test_values.as_slice() else {
                    return Err(self.fault(
                        "intrinsic-domain",
                        "if test did not evaluate to one datum",
                        index,
                    ));
                };
                let branch = if truthy(test_value) {
                    *then_branch
                } else {
                    *else_branch
                };
                self.eval_node(branch, false)?
            }
            GraphNode::Lambda { formals, body, .. } => {
                vec![EnvValue::Closure(Rc::new(ClosureValue {
                    formals: formals.clone(),
                    body: *body,
                    env: self.env.clone(),
                }))]
            }
            GraphNode::Let { bindings, body, .. } => {
                let mut values = Vec::with_capacity(bindings.len());
                for binding in bindings {
                    let binding_values = self.eval_node(binding.value, false)?;
                    let [value] = binding_values.as_slice() else {
                        return Err(self.fault(
                            "intrinsic-domain",
                            "let initializer did not evaluate to one value",
                            index,
                        ));
                    };
                    let key =
                        env_key(&binding.name).expect("Meaning Law excludes intrinsic let names");
                    values.push((key, value.clone()));
                }
                let child = self.env.child();
                for (key, value) in values {
                    child.bind_value_local(key, value);
                }
                self.with_env(child, |this| this.eval_node(*body, false))?
            }
            GraphNode::Block { body, .. } => {
                self.prebind_block_body(body);
                let mut last = Vec::new();
                for &child in body {
                    last = self.eval_node(child, false)?;
                    if root_transcript {
                        self.extend_transcript(&last);
                    }
                }
                last
            }
            GraphNode::Bind { name, value, .. } => {
                let values = self.eval_node(*value, false)?;
                let [value] = values.as_slice() else {
                    return Err(self.fault(
                        "intrinsic-domain",
                        "binding value did not evaluate to one value",
                        index,
                    ));
                };
                let key = env_key(name).expect("Meaning Law excludes intrinsic bind names");
                self.env.assign_local_or_bind(key, value.clone());
                Vec::new()
            }
        };
        if self.trace_mode == TraceMode::Full {
            let step = self.trace.len() + 1;
            self.trace.push(TraceEvent {
                step,
                node: index,
                kind: node_kind(node),
                values: render_values(&values),
            });
        }
        Ok(values)
    }

    fn prebind_block_body(&mut self, body: &[usize]) {
        for &child in body {
            if let GraphNode::Bind { name, .. } = &self.graph.nodes[child] {
                let key = env_key(name).expect("Meaning Law excludes intrinsic bind names");
                self.env.prebind_local(key);
            }
        }
    }

    fn with_env<T>(
        &mut self,
        env: Env,
        f: impl FnOnce(&mut Self) -> Result<T, MeaningEnvFault>,
    ) -> Result<T, MeaningEnvFault> {
        let previous = std::mem::replace(&mut self.env, env);
        let result = f(self);
        self.env = previous;
        result
    }

    fn apply_callable(
        &mut self,
        callable: EnvValue,
        args: &[EnvValue],
        index: usize,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        match callable {
            EnvValue::Intrinsic(intrinsic) => self.apply_intrinsic(intrinsic, args, index),
            EnvValue::Closure(closure) => {
                if args.len() != closure.formals.len() {
                    return Err(self.fault("arity", "closure arity mismatch", index));
                }
                let child = closure.env.child();
                for (formal, arg) in closure.formals.iter().zip(args) {
                    let key = env_key(formal).expect("Meaning Law excludes intrinsic formals");
                    child.bind_value_local(key, arg.clone());
                }
                self.with_env(child, |this| this.eval_node(closure.body, false))
            }
            EnvValue::Datum(_) => Err(self.fault(
                "non-callable",
                "call operator did not evaluate to a callable value",
                index,
            )),
        }
    }

    fn apply_intrinsic(
        &mut self,
        intrinsic: Intrinsic,
        args: &[EnvValue],
        index: usize,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        #[cfg(feature = "scored-native-contract")]
        if let Some(observer) = self.contract_observer.as_mut() {
            use crate::vouch_native::eval_observer::EvalObserver;
            if observer.primitive_call().is_err() {
                return Err(self.fault(
                    "meaning-env-budget-exhausted",
                    "contract Meaning evaluator budget exhausted",
                    index,
                ));
            }
        }
        match intrinsic {
            Intrinsic::Map => self.prim_map(args, index),
            Intrinsic::Filter => self.prim_filter(args, index),
            Intrinsic::AnyP => self.prim_any_p(args, index),
            Intrinsic::AllP => self.prim_all_p(args, index),
            Intrinsic::Reduce | Intrinsic::FoldLeft => self.prim_reduce(args, index),
            Intrinsic::FoldRight => self.prim_fold_right(args, index),
            Intrinsic::Apply => self.prim_apply(args, index),
            Intrinsic::Values => Ok(args.to_vec()),
            Intrinsic::CallWithValues => self.prim_call_with_values(args, index),
            _ => {
                let args = self.datum_args(args, index)?;
                let value = apply_datum_intrinsic(
                    intrinsic,
                    &args,
                    || self.fault("arity", "intrinsic arity mismatch", index),
                    || self.fault("intrinsic-domain", "intrinsic domain mismatch", index),
                    || self.fault("division-by-zero", "intrinsic division by zero", index),
                )?;
                Ok(vec![EnvValue::Datum(value)])
            }
        }
    }

    fn prim_map(
        &mut self,
        args: &[EnvValue],
        index: usize,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        if args.len() != 2 {
            return Err(self.fault("arity", "intrinsic arity mismatch", index));
        }
        let callable = args[0].clone();
        let elems = self.proper_list_arg(&args[1], index)?;
        let mut out = Vec::with_capacity(elems.len());
        for elem in elems {
            out.push(self.call_single_datum(
                callable.clone(),
                vec![EnvValue::Datum(elem)],
                index,
            )?);
        }
        Ok(vec![EnvValue::Datum(Value::list(out.into_iter()))])
    }

    fn prim_filter(
        &mut self,
        args: &[EnvValue],
        index: usize,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        if args.len() != 2 {
            return Err(self.fault("arity", "intrinsic arity mismatch", index));
        }
        let callable = args[0].clone();
        let elems = self.proper_list_arg(&args[1], index)?;
        let mut out = Vec::new();
        for elem in elems {
            let keep = self.call_single_datum(
                callable.clone(),
                vec![EnvValue::Datum(elem.clone())],
                index,
            )?;
            if truthy(&keep) {
                out.push(elem);
            }
        }
        Ok(vec![EnvValue::Datum(Value::list(out.into_iter()))])
    }

    fn prim_any_p(
        &mut self,
        args: &[EnvValue],
        index: usize,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        if args.len() != 2 {
            return Err(self.fault("arity", "intrinsic arity mismatch", index));
        }
        let callable = args[0].clone();
        let elems = self.proper_list_arg(&args[1], index)?;
        for elem in elems {
            let result =
                self.call_single_datum(callable.clone(), vec![EnvValue::Datum(elem)], index)?;
            match result {
                Value::Bool(true) => return Ok(vec![EnvValue::Datum(Value::Bool(true))]),
                Value::Bool(false) => {}
                _ => {
                    return Err(self.fault("intrinsic-domain", "intrinsic domain mismatch", index))
                }
            }
        }
        Ok(vec![EnvValue::Datum(Value::Bool(false))])
    }

    fn prim_all_p(
        &mut self,
        args: &[EnvValue],
        index: usize,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        if args.len() != 2 {
            return Err(self.fault("arity", "intrinsic arity mismatch", index));
        }
        let callable = args[0].clone();
        let elems = self.proper_list_arg(&args[1], index)?;
        for elem in elems {
            let result =
                self.call_single_datum(callable.clone(), vec![EnvValue::Datum(elem)], index)?;
            match result {
                Value::Bool(false) => return Ok(vec![EnvValue::Datum(Value::Bool(false))]),
                Value::Bool(true) => {}
                _ => {
                    return Err(self.fault("intrinsic-domain", "intrinsic domain mismatch", index))
                }
            }
        }
        Ok(vec![EnvValue::Datum(Value::Bool(true))])
    }

    fn prim_reduce(
        &mut self,
        args: &[EnvValue],
        index: usize,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        if args.len() != 3 {
            return Err(self.fault("arity", "intrinsic arity mismatch", index));
        }
        let callable = args[0].clone();
        let mut acc = self.datum_arg(&args[1], index)?;
        let elems = self.proper_list_arg(&args[2], index)?;
        for elem in elems {
            acc = self.call_single_datum(
                callable.clone(),
                vec![EnvValue::Datum(acc), EnvValue::Datum(elem)],
                index,
            )?;
        }
        Ok(vec![EnvValue::Datum(acc)])
    }

    fn prim_fold_right(
        &mut self,
        args: &[EnvValue],
        index: usize,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        if args.len() != 3 {
            return Err(self.fault("arity", "intrinsic arity mismatch", index));
        }
        let callable = args[0].clone();
        let mut acc = self.datum_arg(&args[1], index)?;
        let elems = self.proper_list_arg(&args[2], index)?;
        for elem in elems.into_iter().rev() {
            acc = self.call_single_datum(
                callable.clone(),
                vec![EnvValue::Datum(elem), EnvValue::Datum(acc)],
                index,
            )?;
        }
        Ok(vec![EnvValue::Datum(acc)])
    }

    fn prim_apply(
        &mut self,
        args: &[EnvValue],
        index: usize,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        if args.len() < 2 {
            return Err(self.fault("arity", "intrinsic arity mismatch", index));
        }
        let callable = args[0].clone();
        let mut call_args = args[1..args.len() - 1].to_vec();
        for elem in self.proper_list_arg(&args[args.len() - 1], index)? {
            call_args.push(EnvValue::Datum(elem));
        }
        self.apply_callable(callable, &call_args, index)
    }

    fn prim_call_with_values(
        &mut self,
        args: &[EnvValue],
        index: usize,
    ) -> Result<Vec<EnvValue>, MeaningEnvFault> {
        let [producer, consumer] = args else {
            return Err(self.fault("arity", "intrinsic arity mismatch", index));
        };
        let produced = self.apply_callable(producer.clone(), &[], index)?;
        self.apply_callable(consumer.clone(), &produced, index)
    }

    fn datum_args(&self, args: &[EnvValue], index: usize) -> Result<Vec<Value>, MeaningEnvFault> {
        args.iter().map(|arg| self.datum_arg(arg, index)).collect()
    }

    fn datum_arg(&self, arg: &EnvValue, index: usize) -> Result<Value, MeaningEnvFault> {
        match arg {
            EnvValue::Datum(value) => Ok(value.clone()),
            EnvValue::Intrinsic(_) | EnvValue::Closure(_) => Err(self.fault(
                "intrinsic-domain",
                "intrinsic argument did not evaluate to one datum",
                index,
            )),
        }
    }

    fn proper_list_arg(&self, arg: &EnvValue, index: usize) -> Result<Vec<Value>, MeaningEnvFault> {
        let value = self.datum_arg(arg, index)?;
        proper_list_elems(&value)
            .ok_or_else(|| self.fault("intrinsic-domain", "intrinsic domain mismatch", index))
    }

    fn call_single_datum(
        &mut self,
        callable: EnvValue,
        args: Vec<EnvValue>,
        index: usize,
    ) -> Result<Value, MeaningEnvFault> {
        let values = self.apply_callable(callable, &args, index)?;
        let [EnvValue::Datum(value)] = values.as_slice() else {
            return Err(self.fault(
                "intrinsic-domain",
                "higher-order intrinsic callback did not return one datum",
                index,
            ));
        };
        Ok(value.clone())
    }

    fn extend_transcript(&mut self, values: &[EnvValue]) {
        self.transcript.extend(render_values(values));
    }

    fn failure(self, fault: MeaningEnvFault) -> Box<EvalFailure> {
        Box::new(EvalFailure {
            fault,
            trace: self.trace,
            transcript: self.transcript,
            steps_used: self.steps,
        })
    }

    fn fault(
        &self,
        kind: &'static str,
        message: impl Into<String>,
        node: usize,
    ) -> MeaningEnvFault {
        MeaningEnvFault::new(kind, message, Some(node), node_anchor(self.graph, node))
    }
}

#[derive(Clone)]
enum EnvValue {
    Datum(Value),
    Intrinsic(Intrinsic),
    Closure(Rc<ClosureValue>),
}

#[derive(Clone)]
struct ClosureValue {
    formals: Vec<GraphName>,
    body: usize,
    env: Env,
}

fn render_values(values: &[EnvValue]) -> Vec<String> {
    values.iter().map(EnvValue::render).collect()
}

impl EnvValue {
    fn render(&self) -> String {
        match self {
            EnvValue::Datum(value) => {
                canonical_datum_string(value).expect("Meaning Environment datum is canonical")
            }
            EnvValue::Intrinsic(intrinsic) => format!("#<intrinsic:{}>", intrinsic.name()),
            EnvValue::Closure(_) => "#<procedure>".to_string(),
        }
    }
}

fn env_key(name: &GraphName) -> Option<String> {
    match name {
        GraphName::User(text) => Some(format!("user:{text}")),
        GraphName::Temp(index) => Some(format!("temp:{index}")),
        GraphName::Intrinsic(_) => None,
    }
}

fn apply_datum_intrinsic(
    intrinsic: Intrinsic,
    args: &[Value],
    arity_fault: impl Fn() -> MeaningEnvFault,
    domain_fault: impl Fn() -> MeaningEnvFault,
    div_zero_fault: impl Fn() -> MeaningEnvFault,
) -> Result<Value, MeaningEnvFault> {
    match intrinsic {
        Intrinsic::Cons => {
            if args.len() != 2 {
                return Err(arity_fault());
            }
            Ok(Value::cons(args[0].clone(), args[1].clone()))
        }
        Intrinsic::Append => {
            if args.is_empty() {
                return Ok(Value::Nil);
            }
            let mut acc = args[args.len() - 1].clone();
            for arg in args[..args.len() - 1].iter().rev() {
                let elems = proper_list_elems(arg).ok_or_else(&domain_fault)?;
                for elem in elems.into_iter().rev() {
                    acc = Value::cons(elem, acc);
                }
            }
            Ok(acc)
        }
        Intrinsic::ListToVector => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            let elems = proper_list_elems(&args[0]).ok_or_else(domain_fault)?;
            Ok(Value::vector(elems))
        }
        Intrinsic::Eqv => {
            if args.len() != 2 {
                return Err(arity_fault());
            }
            Ok(Value::Bool(eqv(&args[0], &args[1])))
        }
        Intrinsic::Add => {
            let nums = exact_nums(args, &domain_fault)?;
            number::add(&nums).map_err(|e| arithmetic_fault(e, &domain_fault, &div_zero_fault))
        }
        Intrinsic::Sub => {
            if args.is_empty() {
                return Err(arity_fault());
            }
            let nums = exact_nums(args, &domain_fault)?;
            number::sub(&nums).map_err(|e| arithmetic_fault(e, &domain_fault, &div_zero_fault))
        }
        Intrinsic::Mul => {
            let nums = exact_nums(args, &domain_fault)?;
            number::mul(&nums).map_err(|e| arithmetic_fault(e, &domain_fault, &div_zero_fault))
        }
        Intrinsic::Div => {
            if args.is_empty() {
                return Err(arity_fault());
            }
            let nums = exact_nums(args, &domain_fault)?;
            number::div(&nums).map_err(|e| arithmetic_fault(e, &domain_fault, &div_zero_fault))
        }
        Intrinsic::Modulo => {
            if args.len() != 2 {
                return Err(arity_fault());
            }
            let nums = exact_nums(args, &domain_fault)?;
            number::modulo(&nums[0], &nums[1])
                .map_err(|e| arithmetic_fault(e, &domain_fault, &div_zero_fault))
        }
        Intrinsic::NumEq | Intrinsic::Lt | Intrinsic::Gt | Intrinsic::Le | Intrinsic::Ge => {
            if args.len() < 2 {
                return Err(arity_fault());
            }
            let nums = exact_nums(args, &domain_fault)?;
            let op = match intrinsic {
                Intrinsic::NumEq => CmpOp::Eq,
                Intrinsic::Lt => CmpOp::Lt,
                Intrinsic::Gt => CmpOp::Gt,
                Intrinsic::Le => CmpOp::Le,
                Intrinsic::Ge => CmpOp::Ge,
                _ => unreachable!("matched comparison intrinsic"),
            };
            Ok(Value::Bool(number::compare(&nums, op)))
        }
        Intrinsic::Equal => {
            if args.len() != 2 {
                return Err(arity_fault());
            }
            Ok(Value::Bool(equal(&args[0], &args[1])))
        }
        Intrinsic::Assoc | Intrinsic::Assv => {
            if args.len() != 2 {
                return Err(arity_fault());
            }
            let cmp = match intrinsic {
                Intrinsic::Assoc => equal,
                Intrinsic::Assv => eqv,
                _ => unreachable!("matched assoc intrinsic"),
            };
            assoc_value(&args[0], &args[1], cmp).ok_or_else(domain_fault)
        }
        Intrinsic::Member | Intrinsic::Memv => {
            if args.len() != 2 {
                return Err(arity_fault());
            }
            let cmp = match intrinsic {
                Intrinsic::Member => equal,
                Intrinsic::Memv => eqv,
                _ => unreachable!("matched member intrinsic"),
            };
            member_value(&args[0], &args[1], cmp).ok_or_else(domain_fault)
        }
        Intrinsic::Not => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            Ok(Value::Bool(!truthy(&args[0])))
        }
        Intrinsic::StringEq | Intrinsic::StringLt => {
            if args.len() < 2 {
                return Err(arity_fault());
            }
            let strings = strings(args).ok_or_else(&domain_fault)?;
            let ok = strings.windows(2).all(|pair| match intrinsic {
                Intrinsic::StringEq => pair[0] == pair[1],
                Intrinsic::StringLt => pair[0] < pair[1],
                _ => unreachable!("matched string intrinsic"),
            });
            Ok(Value::Bool(ok))
        }
        Intrinsic::StringAppend => {
            let strings = strings(args).ok_or_else(&domain_fault)?;
            let mut out = String::new();
            for text in strings {
                out.push_str(&text);
            }
            Ok(Value::Str(Rc::from(out.as_str())))
        }
        Intrinsic::NumberToString => {
            if args.is_empty() || args.len() > 2 {
                return Err(arity_fault());
            }
            let radix = radix_arg(args.get(1), &domain_fault)?;
            let out = if radix == 10 {
                match &args[0] {
                    Value::Int(i) => i.to_string(),
                    Value::Rational(r) => format!("{}/{}", r.numer(), r.denom()),
                    Value::Real(f) => crate::value::format_real(f.get()),
                    _ => return Err(domain_fault()),
                }
            } else {
                match &args[0] {
                    Value::Int(i) => i.to_str_radix(radix),
                    _ => return Err(domain_fault()),
                }
            };
            Ok(Value::Str(Rc::from(out.as_str())))
        }
        Intrinsic::NullP => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            Ok(Value::Bool(matches!(args[0], Value::Nil)))
        }
        Intrinsic::PairP => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            Ok(Value::Bool(matches!(args[0], Value::Pair(_))))
        }
        Intrinsic::Car => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            match &args[0] {
                Value::Pair(pair) => Ok(pair.car.clone()),
                _ => Err(domain_fault()),
            }
        }
        Intrinsic::Cdr => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            match &args[0] {
                Value::Pair(pair) => Ok(pair.cdr.clone()),
                _ => Err(domain_fault()),
            }
        }
        Intrinsic::List => Ok(Value::list(args.iter().cloned())),
        Intrinsic::Length => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            let elems = proper_list_elems(&args[0]).ok_or_else(domain_fault)?;
            Ok(Value::int(elems.len()))
        }
        Intrinsic::ListP => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            Ok(Value::Bool(proper_list_elems(&args[0]).is_some()))
        }
        Intrinsic::StringP => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            Ok(Value::Bool(matches!(args[0], Value::Str(_))))
        }
        Intrinsic::NumberP => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            Ok(Value::Bool(matches!(
                args[0],
                Value::Int(_) | Value::Rational(_) | Value::Real(_)
            )))
        }
        Intrinsic::BooleanP => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            Ok(Value::Bool(matches!(args[0], Value::Bool(_))))
        }
        Intrinsic::SymbolP => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            Ok(Value::Bool(matches!(args[0], Value::Sym(_))))
        }
        Intrinsic::Min | Intrinsic::Max => {
            if args.is_empty() {
                return Err(arity_fault());
            }
            let nums = exact_nums(args, &domain_fault)?;
            number::minmax(&nums, matches!(intrinsic, Intrinsic::Max))
                .map_err(|e| arithmetic_fault(e, &domain_fault, &div_zero_fault))
        }
        Intrinsic::Abs => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            let nums = exact_nums(args, &domain_fault)?;
            number::abs(&nums[0]).map_err(|e| arithmetic_fault(e, &domain_fault, &div_zero_fault))
        }
        Intrinsic::Quotient | Intrinsic::Remainder => {
            if args.len() != 2 {
                return Err(arity_fault());
            }
            let nums = exact_nums(args, &domain_fault)?;
            let result = match intrinsic {
                Intrinsic::Quotient => number::quotient(&nums[0], &nums[1]),
                Intrinsic::Remainder => number::remainder(&nums[0], &nums[1]),
                _ => unreachable!("matched integer division intrinsic"),
            };
            result.map_err(|e| arithmetic_fault(e, &domain_fault, &div_zero_fault))
        }
        Intrinsic::Floor | Intrinsic::Ceiling | Intrinsic::Round | Intrinsic::Truncate => {
            if args.len() != 1 {
                return Err(arity_fault());
            }
            let nums = exact_nums(args, &domain_fault)?;
            let result = match intrinsic {
                Intrinsic::Floor => number::floor(&nums[0]),
                Intrinsic::Ceiling => number::ceiling(&nums[0]),
                Intrinsic::Round => number::round(&nums[0]),
                Intrinsic::Truncate => number::truncate(&nums[0]),
                _ => unreachable!("matched rounding intrinsic"),
            };
            result.map_err(|e| arithmetic_fault(e, &domain_fault, &div_zero_fault))
        }
        Intrinsic::Map
        | Intrinsic::Filter
        | Intrinsic::AnyP
        | Intrinsic::AllP
        | Intrinsic::Reduce
        | Intrinsic::FoldLeft
        | Intrinsic::FoldRight
        | Intrinsic::Apply
        | Intrinsic::Values
        | Intrinsic::CallWithValues => {
            unreachable!("higher-order intrinsic handled by evaluator")
        }
    }
}

fn member_value(obj: &Value, list: &Value, cmp: fn(&Value, &Value) -> bool) -> Option<Value> {
    let mut cur = list.clone();
    loop {
        match cur {
            Value::Nil => return Some(Value::Bool(false)),
            Value::Pair(pair) => {
                if cmp(obj, &pair.car) {
                    return Some(Value::Pair(pair));
                }
                cur = pair.cdr.clone();
            }
            _ => return None,
        }
    }
}

fn assoc_value(obj: &Value, alist: &Value, cmp: fn(&Value, &Value) -> bool) -> Option<Value> {
    let mut cur = alist.clone();
    loop {
        match cur {
            Value::Nil => return Some(Value::Bool(false)),
            Value::Pair(pair) => {
                let entry = pair.car.clone();
                let Value::Pair(entry_pair) = entry else {
                    return None;
                };
                if cmp(obj, &entry_pair.car) {
                    return Some(Value::Pair(entry_pair));
                }
                cur = pair.cdr.clone();
            }
            _ => return None,
        }
    }
}

fn exact_nums(
    args: &[Value],
    domain_fault: &impl Fn() -> MeaningEnvFault,
) -> Result<Vec<Num>, MeaningEnvFault> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        match number::num_of(arg) {
            Some(num @ (Num::Int(_) | Num::Rat(_))) => out.push(num),
            Some(Num::Real(_)) | None => return Err(domain_fault()),
        }
    }
    Ok(out)
}

fn arithmetic_fault(
    fault: AErr,
    domain_fault: &impl Fn() -> MeaningEnvFault,
    div_zero_fault: &impl Fn() -> MeaningEnvFault,
) -> MeaningEnvFault {
    match fault {
        AErr::DivZero => div_zero_fault(),
        AErr::NotFinite | AErr::NotInteger => domain_fault(),
    }
}

fn strings(args: &[Value]) -> Option<Vec<Rc<str>>> {
    args.iter()
        .map(|arg| match arg {
            Value::Str(text) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

fn radix_arg(
    arg: Option<&Value>,
    domain_fault: &impl Fn() -> MeaningEnvFault,
) -> Result<u32, MeaningEnvFault> {
    let Some(arg) = arg else {
        return Ok(10);
    };
    let Value::Int(radix) = arg else {
        return Err(domain_fault());
    };
    use num_traits::ToPrimitive;
    match radix.to_u32() {
        Some(value @ (2 | 8 | 10 | 16)) => Ok(value),
        _ => Err(domain_fault()),
    }
}

fn truthy(value: &Value) -> bool {
    !matches!(value, Value::Bool(false))
}

fn equal(a: &Value, b: &Value) -> bool {
    use Value::*;
    match (a, b) {
        (Bool(x), Bool(y)) => x == y,
        (Int(x), Int(y)) => x == y,
        (Rational(x), Rational(y)) => x == y,
        (Real(x), Real(y)) => x == y,
        (Char(x), Char(y)) => x == y,
        (Sym(x), Sym(y)) => x == y,
        (Str(x), Str(y)) => x == y,
        (Nil, Nil) => true,
        (Pair(x), Pair(y)) => equal(&x.car, &y.car) && equal(&x.cdr, &y.cdr),
        (Vector(x), Vector(y)) => {
            let x_items = x.items.borrow();
            let y_items = y.items.borrow();
            x_items.len() == y_items.len()
                && x_items
                    .iter()
                    .zip(y_items.iter())
                    .all(|(left, right)| equal(left, right))
        }
        (Bytevector(x), Bytevector(y)) => x == y,
        (Closure(x), Closure(y)) => Rc::ptr_eq(x, y),
        (Primitive(x), Primitive(y)) => x.ptr_eq(y),
        (Cont(x), Cont(y)) => Rc::ptr_eq(x, y),
        (ErrorObject(x), ErrorObject(y)) => Rc::ptr_eq(x, y),
        _ => false,
    }
}

fn proper_list_elems(value: &Value) -> Option<Vec<Value>> {
    let mut elems = Vec::new();
    let mut cur = value.clone();
    loop {
        match cur {
            Value::Nil => return Some(elems),
            Value::Pair(pair) => {
                elems.push(pair.car.clone());
                cur = pair.cdr.clone();
            }
            _ => return None,
        }
    }
}

fn eqv(a: &Value, b: &Value) -> bool {
    use Value::*;
    match (a, b) {
        (Bool(x), Bool(y)) => x == y,
        (Int(x), Int(y)) => x == y,
        (Rational(x), Rational(y)) => x == y,
        (Real(x), Real(y)) => x == y,
        (Char(x), Char(y)) => x == y,
        (Sym(x), Sym(y)) => x == y,
        (Nil, Nil) => true,
        (Str(x), Str(y)) => Rc::ptr_eq(x, y),
        (Pair(x), Pair(y)) => Rc::ptr_eq(x, y),
        (Vector(x), Vector(y)) => Rc::ptr_eq(x, y),
        (Bytevector(x), Bytevector(y)) => Rc::ptr_eq(x, y),
        (Closure(x), Closure(y)) => Rc::ptr_eq(x, y),
        (Primitive(x), Primitive(y)) => x.ptr_eq(y),
        (Cont(x), Cont(y)) => Rc::ptr_eq(x, y),
        (ErrorObject(x), ErrorObject(y)) => Rc::ptr_eq(x, y),
        _ => false,
    }
}

fn shared_node_fault(graph: &MeaningGraph) -> Option<MeaningEnvFault> {
    let mut incoming = vec![0usize; graph.nodes.len()];
    for &root in &graph.roots {
        incoming[root] += 1;
    }
    for node in &graph.nodes {
        for child in child_indices(node) {
            incoming[child] += 1;
        }
    }
    incoming.iter().position(|count| *count > 1).map(|node| {
        MeaningEnvFault::new(
            "shared-node",
            "Meaning Environment v0 requires tree-shaped graph use",
            Some(node),
            node_anchor(graph, node),
        )
    })
}

fn child_indices(node: &GraphNode) -> Vec<usize> {
    match node {
        GraphNode::Lit { .. } | GraphNode::Ref { .. } => Vec::new(),
        GraphNode::Call { op, args, .. } => {
            let mut children = Vec::with_capacity(args.len() + 1);
            children.push(*op);
            children.extend(args.iter().copied());
            children
        }
        GraphNode::If {
            test,
            then_branch,
            else_branch,
            ..
        } => vec![*test, *then_branch, *else_branch],
        GraphNode::Lambda { body, .. } => vec![*body],
        GraphNode::Let { bindings, body, .. } => {
            let mut children = Vec::with_capacity(bindings.len() + 1);
            children.extend(bindings.iter().map(|binding| binding.value));
            children.push(*body);
            children
        }
        GraphNode::Block { body, .. } => body.clone(),
        GraphNode::Bind { value, .. } => vec![*value],
    }
}

fn node_anchor(graph: &MeaningGraph, index: usize) -> Option<Anchor> {
    match &graph.nodes[index] {
        GraphNode::Lit { anchor, .. }
        | GraphNode::Ref { anchor, .. }
        | GraphNode::Call { anchor, .. }
        | GraphNode::If { anchor, .. }
        | GraphNode::Lambda { anchor, .. }
        | GraphNode::Let { anchor, .. }
        | GraphNode::Bind { anchor, .. } => Some(anchor.clone()),
        GraphNode::Block { anchor, .. } => anchor.clone(),
    }
}

fn node_kind(node: &GraphNode) -> &'static str {
    match node {
        GraphNode::Lit { .. } => "lit",
        GraphNode::Ref { .. } => "ref",
        GraphNode::Call { .. } => "call",
        GraphNode::If { .. } => "if",
        GraphNode::Lambda { .. } => "lambda",
        GraphNode::Let { .. } => "let",
        GraphNode::Block { .. } => "block",
        GraphNode::Bind { .. } => "bind",
    }
}

fn fault_json(fault: Option<&MeaningEnvFault>) -> JsonValue {
    let Some(fault) = fault else {
        return JsonValue::Null;
    };
    let mut value = json!({
        "kind": fault.kind,
        "message": fault.message,
    });
    if let Some(node) = fault.node {
        value["node"] = json!(node);
    }
    if let Some(anchor) = &fault.anchor {
        let mut anchor_value = json!({
            "line": anchor.line,
            "col": anchor.col,
        });
        if let Some(file) = &anchor.file {
            anchor_value["file"] = json!(file.as_ref());
        }
        value["anchor"] = anchor_value;
    }
    value
}

#[derive(Clone)]
struct TraceEvent {
    step: usize,
    node: usize,
    kind: &'static str,
    values: Vec<String>,
}

#[derive(Clone)]
struct InputReport {
    name: &'static str,
    datum: String,
    byte_len: usize,
    hash_hex: String,
}

impl InputReport {
    fn from_value(value: &Value) -> Result<InputReport, crate::canonical::CanonFault> {
        let datum = canonical_datum_string(value)?;
        Ok(InputReport {
            name: "input",
            byte_len: datum.len(),
            hash_hex: profile_input_hash_hex(datum.as_bytes()),
            datum,
        })
    }
}

#[derive(Clone)]
struct Report {
    byte_len: usize,
    graph_hash: String,
    input: Option<InputReport>,
    status: &'static str,
    law_errors: Vec<GraphLawError>,
    trace: Vec<TraceEvent>,
    transcript: Vec<String>,
    result: Option<Vec<String>>,
    fault: Option<MeaningEnvFault>,
    steps_used: usize,
    step_limit: usize,
}

impl Report {
    #[allow(clippy::too_many_arguments)]
    fn ok(
        byte_len: usize,
        graph_hash: String,
        step_limit: usize,
        input: Option<InputReport>,
        steps_used: usize,
        trace: Vec<TraceEvent>,
        transcript: Vec<String>,
        result: Vec<String>,
    ) -> Report {
        Report {
            byte_len,
            graph_hash,
            input,
            status: "ok",
            law_errors: Vec::new(),
            trace,
            transcript,
            result: Some(result),
            fault: None,
            steps_used,
            step_limit,
        }
    }

    fn law_error(
        byte_len: usize,
        graph_hash: String,
        step_limit: usize,
        input: Option<InputReport>,
        law_errors: Vec<GraphLawError>,
    ) -> Report {
        Report {
            byte_len,
            graph_hash,
            input,
            status: "law-error",
            law_errors,
            trace: Vec::new(),
            transcript: Vec::new(),
            result: None,
            fault: None,
            steps_used: 0,
            step_limit,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn fault(
        byte_len: usize,
        graph_hash: String,
        step_limit: usize,
        input: Option<InputReport>,
        steps_used: usize,
        trace: Vec<TraceEvent>,
        transcript: Vec<String>,
        fault: MeaningEnvFault,
    ) -> Report {
        Report {
            byte_len,
            graph_hash,
            input,
            status: "fault",
            law_errors: Vec::new(),
            trace,
            transcript,
            result: None,
            fault: Some(fault),
            steps_used,
            step_limit,
        }
    }
}

fn report_json_bytes(report: &Report) -> Vec<u8> {
    let mut out = String::new();
    write_report(report, &mut out);
    out.into_bytes()
}

fn write_report(report: &Report, out: &mut String) {
    out.push_str("{\n");
    write_field_string("meaning_env_report", MEANING_ENV_REPORT_TAG, 1, true, out);
    write_engine(1, out);
    out.push_str(",\n");
    write_graph_binding(report, 1, out);
    if report.input.is_some() {
        out.push_str(",\n");
        write_input_binding(report.input.as_ref(), 1, out);
    }
    out.push_str(",\n");
    write_field_string("status", report.status, 1, true, out);
    write_law_errors(&report.law_errors, 1, out);
    out.push_str(",\n");
    write_trace(&report.trace, 1, out);
    out.push_str(",\n");
    write_string_array_field("transcript", &report.transcript, 1, true, out);
    write_result(report.result.as_deref(), 1, out);
    out.push_str(",\n");
    write_fault(report.fault.as_ref(), 1, out);
    out.push_str(",\n");
    write_steps(report.steps_used, report.step_limit, 1, out);
    out.push_str(",\n");
    write_boundary(1, out);
    out.push('\n');
    out.push_str("}\n");
}

fn write_engine(indent_level: usize, out: &mut String) {
    indent(indent_level, out);
    out.push_str("\"engine\": {\n");
    write_field_string("name", "lispex-rust-reference", indent_level + 1, true, out);
    write_field_string(
        "version",
        env!("CARGO_PKG_VERSION"),
        indent_level + 1,
        true,
        out,
    );
    write_commit(indent_level + 1, out);
    indent(indent_level, out);
    out.push('}');
}

fn write_commit(indent_level: usize, out: &mut String) {
    let commit = artifact_commit();
    indent(indent_level, out);
    out.push_str("\"commit\": {\n");
    write_field_string("vcs", "git", indent_level + 1, true, out);
    write_field_string("hex", &commit.hex, indent_level + 1, true, out);
    write_field_bool("dirty", commit.dirty, indent_level + 1, false, out);
    indent(indent_level, out);
    out.push_str("}\n");
}

struct ArtifactCommit {
    hex: String,
    dirty: bool,
}

fn artifact_commit() -> ArtifactCommit {
    let env_hex = std::env::var("LISPEX_ARTIFACT_COMMIT_HEX")
        .ok()
        .filter(|hex| is_git_hex(hex));
    let hex = env_hex
        .or_else(|| git_output(&["rev-parse", "HEAD"]).filter(|hex| is_git_hex(hex)))
        .unwrap_or_else(|| "0000000000000000000000000000000000000000".to_string());
    let dirty = std::env::var("LISPEX_ARTIFACT_COMMIT_DIRTY")
        .ok()
        .and_then(|value| match value.as_str() {
            "false" | "0" => Some(false),
            "true" | "1" => Some(true),
            _ => None,
        })
        .unwrap_or_else(git_dirty);
    ArtifactCommit { hex, dirty }
}

fn is_git_hex(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    Some(value)
}

fn git_dirty() -> bool {
    let Some(output) = git_output(&["status", "--porcelain"]) else {
        return true;
    };
    !output.is_empty()
}

fn write_graph_binding(report: &Report, indent_level: usize, out: &mut String) {
    indent(indent_level, out);
    out.push_str("\"graph\": {\n");
    write_field_usize("byte_len", report.byte_len, indent_level + 1, true, out);
    indent(indent_level + 1, out);
    out.push_str("\"hash\": {\n");
    write_field_string(
        "domain",
        MEANING_GRAPH_HASH_DOMAIN,
        indent_level + 2,
        true,
        out,
    );
    write_field_string("algo", "sha-256", indent_level + 2, true, out);
    write_field_string("hex", &report.graph_hash, indent_level + 2, false, out);
    indent(indent_level + 1, out);
    out.push_str("}\n");
    indent(indent_level, out);
    out.push('}');
}

fn write_input_binding(input: Option<&InputReport>, indent_level: usize, out: &mut String) {
    indent(indent_level, out);
    out.push_str("\"input\": ");
    let Some(input) = input else {
        out.push_str("null");
        return;
    };
    out.push_str("{\n");
    write_field_string("status", "bound", indent_level + 1, true, out);
    write_field_string("name", input.name, indent_level + 1, true, out);
    write_field_string("datum", &input.datum, indent_level + 1, true, out);
    write_field_usize("byte_len", input.byte_len, indent_level + 1, true, out);
    indent(indent_level + 1, out);
    out.push_str("\"hash\": {\n");
    write_field_string(
        "domain",
        PROFILE_INPUT_HASH_DOMAIN,
        indent_level + 2,
        true,
        out,
    );
    write_field_string("algo", "sha-256", indent_level + 2, true, out);
    write_field_string("hex", &input.hash_hex, indent_level + 2, false, out);
    indent(indent_level + 1, out);
    out.push_str("}\n");
    indent(indent_level, out);
    out.push('}');
}

fn write_law_errors(errors: &[GraphLawError], indent_level: usize, out: &mut String) {
    indent(indent_level, out);
    out.push_str("\"law_errors\": ");
    if errors.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, error) in errors.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        indent(indent_level + 1, out);
        out.push_str("{\n");
        write_field_string("rule", error.rule(), indent_level + 2, true, out);
        write_field_string("message", error.message(), indent_level + 2, false, out);
        indent(indent_level + 1, out);
        out.push('}');
    }
    out.push('\n');
    indent(indent_level, out);
    out.push(']');
}

fn write_trace(trace: &[TraceEvent], indent_level: usize, out: &mut String) {
    indent(indent_level, out);
    out.push_str("\"trace\": ");
    if trace.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, event) in trace.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        indent(indent_level + 1, out);
        out.push_str("{\n");
        write_field_usize("step", event.step, indent_level + 2, true, out);
        write_field_usize("node", event.node, indent_level + 2, true, out);
        write_field_string("kind", event.kind, indent_level + 2, true, out);
        write_string_array_field("values", &event.values, indent_level + 2, false, out);
        indent(indent_level + 1, out);
        out.push('}');
    }
    out.push('\n');
    indent(indent_level, out);
    out.push(']');
}

fn write_result(result: Option<&[String]>, indent_level: usize, out: &mut String) {
    indent(indent_level, out);
    out.push_str("\"result\": ");
    match result {
        Some(values) => {
            out.push_str("{\n");
            write_string_array_field("values", values, indent_level + 1, false, out);
            indent(indent_level, out);
            out.push('}');
        }
        None => out.push_str("null"),
    }
}

fn write_fault(fault: Option<&MeaningEnvFault>, indent_level: usize, out: &mut String) {
    indent(indent_level, out);
    out.push_str("\"fault\": ");
    let Some(fault) = fault else {
        out.push_str("null");
        return;
    };
    out.push_str("{\n");
    write_field_string("kind", fault.kind, indent_level + 1, true, out);
    write_field_string(
        "message",
        &fault.message,
        indent_level + 1,
        fault.node.is_some() || fault.anchor.is_some(),
        out,
    );
    if let Some(node) = fault.node {
        write_field_usize("node", node, indent_level + 1, fault.anchor.is_some(), out);
    }
    if let Some(anchor) = &fault.anchor {
        write_anchor_field(anchor, indent_level + 1, false, out);
    }
    indent(indent_level, out);
    out.push('}');
}

fn write_steps(used: usize, limit: usize, indent_level: usize, out: &mut String) {
    indent(indent_level, out);
    out.push_str("\"steps\": {\n");
    write_field_usize("used", used, indent_level + 1, true, out);
    write_field_usize("limit", limit, indent_level + 1, false, out);
    indent(indent_level, out);
    out.push('}');
}

fn write_boundary(indent_level: usize, out: &mut String) {
    const ATTESTS: &[&str] = &[
        "meaning-law-v0-validation-rust",
        "bounded-deterministic-v0-subset-evaluation",
        "lexical-closure-v0-evaluation",
        "higher-order-traversal-v0-evaluation",
        "profile-input-binding-when-supplied",
        "transcript-bytes",
        "graph-hash-binding",
    ];
    const EXCLUDES: &[&str] = &[
        "semantic-equivalence",
        "differential-receipt",
        "independent-witness",
        "external-backend-reporting",
        "lispex-source-lowering",
        "target-code-generation",
        "full-cskernel-coverage",
        "private-implementation-detail",
    ];
    indent(indent_level, out);
    out.push_str("\"boundary\": {\n");
    write_str_slice_array_field("attests", ATTESTS, indent_level + 1, true, out);
    write_str_slice_array_field("excludes", EXCLUDES, indent_level + 1, false, out);
    indent(indent_level, out);
    out.push('}');
}

fn write_anchor_field(anchor: &Anchor, indent_level: usize, comma: bool, out: &mut String) {
    indent(indent_level, out);
    out.push_str("\"anchor\": {\n");
    if let Some(file) = &anchor.file {
        write_field_string("file", file, indent_level + 1, true, out);
    }
    write_field_usize("line", anchor.line, indent_level + 1, true, out);
    write_field_usize("col", anchor.col, indent_level + 1, false, out);
    indent(indent_level, out);
    out.push('}');
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn write_field_string(key: &str, value: &str, indent_level: usize, comma: bool, out: &mut String) {
    indent(indent_level, out);
    write_json_string(key, out);
    out.push_str(": ");
    write_json_string(value, out);
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn write_field_usize(key: &str, value: usize, indent_level: usize, comma: bool, out: &mut String) {
    indent(indent_level, out);
    write_json_string(key, out);
    out.push_str(": ");
    out.push_str(&value.to_string());
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn write_field_bool(key: &str, value: bool, indent_level: usize, comma: bool, out: &mut String) {
    indent(indent_level, out);
    write_json_string(key, out);
    out.push_str(": ");
    out.push_str(if value { "true" } else { "false" });
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn write_string_array_field(
    key: &str,
    values: &[String],
    indent_level: usize,
    comma: bool,
    out: &mut String,
) {
    indent(indent_level, out);
    write_json_string(key, out);
    out.push_str(": ");
    write_string_array(values.iter().map(String::as_str), indent_level, out);
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn write_str_slice_array_field(
    key: &str,
    values: &[&str],
    indent_level: usize,
    comma: bool,
    out: &mut String,
) {
    indent(indent_level, out);
    write_json_string(key, out);
    out.push_str(": ");
    write_string_array(values.iter().copied(), indent_level, out);
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn write_string_array<'a>(
    values: impl Iterator<Item = &'a str>,
    indent_level: usize,
    out: &mut String,
) {
    let values: Vec<&str> = values.collect();
    if values.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        indent(indent_level + 1, out);
        write_json_string(value, out);
    }
    out.push('\n');
    indent(indent_level, out);
    out.push(']');
}

fn write_json_string(value: &str, out: &mut String) {
    out.push_str(&serde_json::to_string(value).expect("string encoding cannot fail"));
}

fn indent(level: usize, out: &mut String) {
    for _ in 0..level {
        out.push_str("  ");
    }
}
