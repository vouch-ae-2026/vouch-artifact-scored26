//! Separate canonical `csk.graph/v0` forest.
//!
//! This type intentionally shares only the interpreter Core input. It does not
//! extend or serialize through the existing Meaning Graph schema.

use std::collections::HashSet;

use vouch::artifact_json::{write_canonical, JsonValue, JsonWriteError};

use crate::core::{CoreExpr, CoreKind, Ident};
use crate::value::Value;

use super::canonical_value::{domain_hash, CanonicalValue};
use super::checked_profile::{validate_core, COVERED_PRIMITIVES};

pub const CONTRACT_GRAPH_TAG: &str = "csk.graph/v0";
pub const GRAPH_HASH_DOMAIN: &str = "csk.v0.graph";
pub const MAX_GRAPH_NODES: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractNode {
    Lit {
        value: CanonicalValue,
    },
    Var {
        name: String,
    },
    Lambda {
        params: Vec<String>,
        body: usize,
    },
    App {
        operator: usize,
        arguments: Vec<usize>,
    },
    If {
        test: usize,
        consequent: usize,
        alternate: usize,
    },
    Begin {
        forms: Vec<usize>,
    },
    Let {
        names: Vec<String>,
        initializers: Vec<usize>,
        body: usize,
    },
    Define {
        name: String,
        value: usize,
    },
    Prim {
        name: String,
    },
}

impl ContractNode {
    fn children(&self) -> Vec<usize> {
        match self {
            Self::Lit { .. } | Self::Var { .. } | Self::Prim { .. } => Vec::new(),
            Self::Lambda { body, .. } | Self::Define { value: body, .. } => vec![*body],
            Self::App {
                operator,
                arguments,
            } => std::iter::once(*operator)
                .chain(arguments.iter().copied())
                .collect(),
            Self::If {
                test,
                consequent,
                alternate,
            } => vec![*test, *consequent, *alternate],
            Self::Begin { forms } => forms.clone(),
            Self::Let {
                initializers, body, ..
            } => initializers
                .iter()
                .copied()
                .chain(std::iter::once(*body))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractGraph {
    pub roots: Vec<usize>,
    pub nodes: Vec<ContractNode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphError {
    ResourceLimit,
    ProfileEscape(String),
    Invalid(String),
}

impl GraphError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ResourceLimit => "artifact-resource-limit",
            Self::ProfileEscape(_) => "profile-escape",
            Self::Invalid(_) => "native-receipt-inconsistent",
        }
    }
}

pub fn lower_contract_graph(core: &[CoreExpr]) -> Result<ContractGraph, GraphError> {
    validate_core(core).map_err(|error| GraphError::ProfileEscape(error.message))?;
    let mut lowerer = Lowerer::default();
    let mut roots = Vec::with_capacity(core.len());
    let mut top = HashSet::new();
    for form in core {
        roots.push(lowerer.lower(form, &top, true)?);
        if let CoreKind::Define { name, .. } = &form.kind {
            top.insert(name.clone());
        }
    }
    let graph = ContractGraph {
        roots,
        nodes: lowerer
            .nodes
            .into_iter()
            .map(|node| node.expect("lowerer fills every preorder reservation"))
            .collect(),
    };
    validate_contract_graph(&graph)?;
    Ok(graph)
}

#[derive(Default)]
struct Lowerer {
    nodes: Vec<Option<ContractNode>>,
}

impl Lowerer {
    fn lower(
        &mut self,
        expr: &CoreExpr,
        lexical: &HashSet<Ident>,
        root: bool,
    ) -> Result<usize, GraphError> {
        if self.nodes.len() >= MAX_GRAPH_NODES {
            return Err(GraphError::ResourceLimit);
        }
        let id = self.nodes.len();
        self.nodes.push(None);
        let node = match &expr.kind {
            CoreKind::Quote(value) => ContractNode::Lit {
                value: CanonicalValue::from_value(value)
                    .map_err(|_| GraphError::ProfileEscape("unencodable literal".to_string()))?,
            },
            CoreKind::Var(name) => {
                let name_text = graph_name(name);
                if !lexical.contains(name) && COVERED_PRIMITIVES.contains(&name_text.as_str()) {
                    ContractNode::Prim { name: name_text }
                } else {
                    ContractNode::Var { name: name_text }
                }
            }
            CoreKind::Lambda { formals, body } => {
                let mut child_scope = lexical.clone();
                child_scope.extend(formals.fixed.iter().cloned());
                ContractNode::Lambda {
                    params: formals.fixed.iter().map(graph_name).collect(),
                    body: self.lower(body, &child_scope, false)?,
                }
            }
            CoreKind::App { op, args } => {
                let mut arguments = args.iter().collect::<Vec<_>>();
                // SCORED-MUTATION-SITE M02: reverse graph-side subtraction
                // arguments during lowering, leaving the reference Core intact.
                if cfg!(scored_mutant = "M02") && is_subtraction_operator(op) {
                    arguments.reverse();
                }
                ContractNode::App {
                    operator: self.lower(op, lexical, false)?,
                    arguments: arguments
                        .into_iter()
                        .map(|arg| self.lower(arg, lexical, false))
                        .collect::<Result<_, _>>()?,
                }
            }
            CoreKind::If(test, consequent, alternate) => {
                let test_node = self.lower(test, lexical, false)?;
                // SCORED-MUTATION-SITE M01: a checked-profile `and` lowers to an
                // `if` whose synthesized false literal shares the form span.
                // Mutate only that graph lowering into Boolean `or` semantics.
                if cfg!(scored_mutant = "M01") && is_lowered_and_shape(alternate) {
                    let truth = CoreExpr::new(CoreKind::Quote(Value::Bool(true)), expr.span);
                    ContractNode::If {
                        test: test_node,
                        consequent: self.lower(&truth, lexical, false)?,
                        alternate: self.lower(consequent, lexical, false)?,
                    }
                } else {
                    ContractNode::If {
                        test: test_node,
                        consequent: self.lower(consequent, lexical, false)?,
                        alternate: self.lower(alternate, lexical, false)?,
                    }
                }
            }
            CoreKind::Begin(forms) => ContractNode::Begin {
                forms: forms
                    .iter()
                    .map(|form| self.lower(form, lexical, false))
                    .collect::<Result<_, _>>()?,
            },
            CoreKind::Let { bindings, body } => {
                let initializers = bindings
                    .iter()
                    .map(|binding| self.lower(&binding.init, lexical, false))
                    .collect::<Result<_, _>>()?;
                let mut child_scope = lexical.clone();
                child_scope.extend(bindings.iter().map(|binding| binding.name.clone()));
                ContractNode::Let {
                    names: bindings
                        .iter()
                        .map(|binding| graph_name(&binding.name))
                        .collect(),
                    initializers,
                    body: self.lower(body, &child_scope, false)?,
                }
            }
            CoreKind::Define { name, value } if root => ContractNode::Define {
                name: graph_name(name),
                value: self.lower(value, lexical, false)?,
            },
            _ => {
                return Err(GraphError::ProfileEscape(
                    "Core form outside csk.graph/v0".to_string(),
                ))
            }
        };
        self.nodes[id] = Some(node);
        Ok(id)
    }
}

fn is_subtraction_operator(expression: &CoreExpr) -> bool {
    matches!(
        &expression.kind,
        CoreKind::Var(name) if graph_name(name) == "-"
    )
}

fn is_lowered_and_shape(alternate: &CoreExpr) -> bool {
    // Canonical checked Core intentionally erases surface-form provenance. The
    // stable `and` lowering shape is therefore identified by its false branch,
    // so the submitted graph and the verifier's normalized-Core re-lowering
    // select the same compile-time mutation.
    matches!(&alternate.kind, CoreKind::Quote(Value::Bool(false)))
}

pub fn contract_graph_bytes(graph: &ContractGraph) -> Result<Vec<u8>, JsonWriteError> {
    write_canonical(&graph_to_json(graph))
}

pub fn contract_graph_digest(graph: &ContractGraph) -> Result<String, JsonWriteError> {
    Ok(domain_hash(
        GRAPH_HASH_DOMAIN,
        &contract_graph_bytes(graph)?,
    ))
}

pub fn graph_to_json(graph: &ContractGraph) -> JsonValue {
    JsonValue::object([
        ("graph", JsonValue::String(CONTRACT_GRAPH_TAG.to_string())),
        (
            "roots",
            JsonValue::Array(
                graph
                    .roots
                    .iter()
                    .map(|id| JsonValue::Integer(*id as i64))
                    .collect(),
            ),
        ),
        (
            "nodes",
            JsonValue::Array(
                graph
                    .nodes
                    .iter()
                    .enumerate()
                    .map(|(id, node)| node_to_json(id, node))
                    .collect(),
            ),
        ),
    ])
    .expect("graph fields are unique")
}

fn node_to_json(id: usize, node: &ContractNode) -> JsonValue {
    let id_value = JsonValue::Integer(id as i64);
    let string = |value: &str| JsonValue::String(value.to_string());
    let ids = |values: &[usize]| {
        JsonValue::Array(
            values
                .iter()
                .map(|value| JsonValue::Integer(*value as i64))
                .collect(),
        )
    };
    match node {
        ContractNode::Lit { value } => JsonValue::object([
            ("id", id_value),
            ("op", string("lit")),
            ("value", value.to_json()),
        ]),
        ContractNode::Var { name } => JsonValue::object([
            ("id", id_value),
            ("op", string("var")),
            ("name", string(name)),
        ]),
        ContractNode::Lambda { params, body } => JsonValue::object([
            ("id", id_value),
            ("op", string("lambda")),
            (
                "params",
                JsonValue::Array(params.iter().map(|name| string(name)).collect()),
            ),
            ("body", JsonValue::Integer(*body as i64)),
        ]),
        ContractNode::App {
            operator,
            arguments,
        } => JsonValue::object([
            ("id", id_value),
            ("op", string("app")),
            ("operator", JsonValue::Integer(*operator as i64)),
            ("arguments", ids(arguments)),
        ]),
        ContractNode::If {
            test,
            consequent,
            alternate,
        } => JsonValue::object([
            ("id", id_value),
            ("op", string("if")),
            ("test", JsonValue::Integer(*test as i64)),
            ("consequent", JsonValue::Integer(*consequent as i64)),
            ("alternate", JsonValue::Integer(*alternate as i64)),
        ]),
        ContractNode::Begin { forms } => JsonValue::object([
            ("id", id_value),
            ("op", string("begin")),
            ("forms", ids(forms)),
        ]),
        ContractNode::Let {
            names,
            initializers,
            body,
        } => JsonValue::object([
            ("id", id_value),
            ("op", string("let")),
            (
                "names",
                JsonValue::Array(names.iter().map(|name| string(name)).collect()),
            ),
            ("initializers", ids(initializers)),
            ("body", JsonValue::Integer(*body as i64)),
        ]),
        ContractNode::Define { name, value } => JsonValue::object([
            ("id", id_value),
            ("op", string("define")),
            ("name", string(name)),
            ("value", JsonValue::Integer(*value as i64)),
        ]),
        ContractNode::Prim { name } => JsonValue::object([
            ("id", id_value),
            ("op", string("prim")),
            ("name", string(name)),
        ]),
    }
    .expect("node fields are unique")
}

pub fn validate_contract_graph(graph: &ContractGraph) -> Result<(), GraphError> {
    if graph.nodes.len() > MAX_GRAPH_NODES {
        return Err(GraphError::ResourceLimit);
    }
    if graph.roots.is_empty() {
        return invalid("graph requires at least one root");
    }
    let count = graph.nodes.len();
    if graph.roots.iter().any(|root| *root >= count) {
        return invalid("root references missing node");
    }
    let mut incoming = vec![0usize; count];
    for (id, node) in graph.nodes.iter().enumerate() {
        for child in node.children() {
            if child >= count {
                return invalid("child references missing node");
            }
            if child <= id {
                return invalid("preorder graph edge is cyclic or backward");
            }
            incoming[child] += 1;
        }
        validate_node_shape(node)?;
    }
    let root_set: HashSet<_> = graph.roots.iter().copied().collect();
    if root_set.len() != graph.roots.len() {
        return invalid("duplicate root");
    }
    for (id, actual) in incoming.iter().enumerate() {
        let expected = usize::from(!root_set.contains(&id));
        if *actual != expected {
            return invalid("graph is shared or unreachable");
        }
    }
    let mut expected_id = 0;
    for root in &graph.roots {
        validate_preorder(graph, *root, &mut expected_id)?;
    }
    if expected_id != count {
        return invalid("graph has unreachable nodes");
    }
    validate_lexical_graph(graph)
}

fn validate_preorder(
    graph: &ContractGraph,
    id: usize,
    expected: &mut usize,
) -> Result<(), GraphError> {
    if id != *expected {
        return invalid("node ids are not canonical preorder");
    }
    *expected += 1;
    for child in graph.nodes[id].children() {
        validate_preorder(graph, child, expected)?;
    }
    Ok(())
}

fn validate_node_shape(node: &ContractNode) -> Result<(), GraphError> {
    match node {
        ContractNode::Begin { forms } if forms.is_empty() => invalid("empty begin"),
        ContractNode::Let {
            names,
            initializers,
            ..
        } if names.len() != initializers.len() => invalid("let arity mismatch"),
        ContractNode::Lambda { params, .. } => unique_names(params),
        ContractNode::Let { names, .. } => unique_names(names),
        ContractNode::Prim { name } if !COVERED_PRIMITIVES.contains(&name.as_str()) => {
            invalid("unknown primitive")
        }
        ContractNode::Lit {
            value: CanonicalValue::Void | CanonicalValue::Decision(_),
        } => invalid("execution-only value in literal"),
        _ => Ok(()),
    }
}

fn unique_names(names: &[String]) -> Result<(), GraphError> {
    let mut seen = HashSet::new();
    if names.iter().any(|name| !seen.insert(name)) {
        invalid("duplicate binding names")
    } else if names.iter().any(|name| name == "input") {
        invalid("reserved input binding")
    } else {
        Ok(())
    }
}

fn validate_lexical_graph(graph: &ContractGraph) -> Result<(), GraphError> {
    let mut top: HashSet<String> = COVERED_PRIMITIVES
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    top.insert("input".to_string());
    let mut definitions = HashSet::new();
    for root in &graph.roots {
        match &graph.nodes[*root] {
            ContractNode::Define { name, value } => {
                if name == "input"
                    || COVERED_PRIMITIVES.contains(&name.as_str())
                    || !definitions.insert(name.clone())
                {
                    return invalid("illegal top-level definition");
                }
                validate_scope(graph, *value, &top)?;
                top.insert(name.clone());
            }
            _ => validate_scope(graph, *root, &top)?,
        }
    }
    Ok(())
}

fn validate_scope(
    graph: &ContractGraph,
    id: usize,
    scope: &HashSet<String>,
) -> Result<(), GraphError> {
    match &graph.nodes[id] {
        ContractNode::Var { name } if !scope.contains(name) => invalid("unbound variable"),
        ContractNode::Lambda { params, body } => {
            let mut child = scope.clone();
            child.extend(params.iter().cloned());
            validate_scope(graph, *body, &child)
        }
        ContractNode::Let {
            names,
            initializers,
            body,
        } => {
            for init in initializers {
                validate_scope(graph, *init, scope)?;
            }
            let mut child = scope.clone();
            child.extend(names.iter().cloned());
            validate_scope(graph, *body, &child)
        }
        ContractNode::Define { .. } => invalid("define may appear only as root"),
        node => {
            for child in node.children() {
                validate_scope(graph, child, scope)?;
            }
            Ok(())
        }
    }
}

fn graph_name(name: &Ident) -> String {
    match name {
        Ident::User(name) => name.to_string(),
        Ident::Temp(id) => format!("#:t{id}"),
    }
}

fn invalid<T>(message: &str) -> Result<T, GraphError> {
    Err(GraphError::Invalid(message.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vouch_native::checked_profile::prepare_checked_program;

    #[test]
    fn graph_is_separate_canonical_and_reproducible() {
        let source =
            b"(define threshold 10)\n(if (< input threshold) (decision-approve) (decision-deny))";
        let first_program = prepare_checked_program(source).unwrap();
        let second_program = prepare_checked_program(source).unwrap();
        let first = lower_contract_graph(first_program.core()).unwrap();
        let second = lower_contract_graph(second_program.core()).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            contract_graph_bytes(&first).unwrap(),
            contract_graph_bytes(&second).unwrap()
        );
        assert_eq!(
            contract_graph_digest(&first).unwrap(),
            contract_graph_digest(&second).unwrap()
        );
        assert_eq!(
            graph_to_json(&first)
                .as_object()
                .unwrap()
                .get("graph")
                .unwrap()
                .as_str(),
            Some(CONTRACT_GRAPH_TAG)
        );
    }

    #[test]
    fn validator_rejects_sharing_and_empty_begin() {
        let shared = ContractGraph {
            roots: vec![0, 1],
            nodes: vec![
                ContractNode::Var {
                    name: "input".to_string(),
                },
                ContractNode::Begin { forms: vec![0] },
            ],
        };
        assert!(validate_contract_graph(&shared).is_err());
        let empty = ContractGraph {
            roots: vec![0],
            nodes: vec![ContractNode::Begin { forms: vec![] }],
        };
        assert!(validate_contract_graph(&empty).is_err());
    }

    #[test]
    fn graph_node_limit_is_exact_and_lowering_checks_before_reservation() {
        let mut graph = ContractGraph {
            roots: (0..MAX_GRAPH_NODES).step_by(10).collect(),
            nodes: (0..MAX_GRAPH_NODES)
                .map(|id| {
                    if id % 10 == 9 {
                        ContractNode::Lit {
                            value: CanonicalValue::Boolean(false),
                        }
                    } else {
                        ContractNode::Begin {
                            forms: vec![id + 1],
                        }
                    }
                })
                .collect(),
        };
        assert!(validate_contract_graph(&graph).is_ok());
        graph.nodes.push(ContractNode::Lit {
            value: CanonicalValue::Boolean(false),
        });
        assert_eq!(
            validate_contract_graph(&graph),
            Err(GraphError::ResourceLimit)
        );

        let program = prepare_checked_program(b"#f").unwrap();
        let mut lowerer = Lowerer {
            nodes: vec![None; MAX_GRAPH_NODES],
        };
        assert_eq!(
            lowerer.lower(&program.core()[0], &HashSet::new(), true),
            Err(GraphError::ResourceLimit)
        );
        assert_eq!(lowerer.nodes.len(), MAX_GRAPH_NODES);
    }
}
