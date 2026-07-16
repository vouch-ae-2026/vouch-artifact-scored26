//! Meaning Graph v0 lowering spike (CSK-MEANING-LOWERING.md).
//!
//! This is a structural, one-way lowering for the v0 graph subset only. It does
//! not evaluate a graph and does not claim semantic equivalence.

use std::collections::HashSet;
use std::fmt;
use std::rc::Rc;

use serde_json::Value as JsonValue;

use crate::canonical::{
    canonical_datum_parse, canonical_datum_string, hash_with_domain_hex, CanonFault,
};
use crate::core::{CoreExpr, CoreKind, Ident, Intrinsic};
use crate::reader::Span;

pub const MEANING_GRAPH_TAG: &str = "csk.meaning-graph/v0";
pub const MEANING_GRAPH_HASH_DOMAIN: &str = "csk/meaning-graph-hash/v0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeaningGraph {
    pub(crate) nodes: Vec<GraphNode>,
    pub(crate) roots: Vec<usize>,
}

impl MeaningGraph {
    pub fn nodes(&self) -> &[GraphNode] {
        &self.nodes
    }

    pub fn roots(&self) -> &[usize] {
        &self.roots
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphNode {
    Lit {
        datum: String,
        anchor: Anchor,
    },
    Ref {
        name: GraphName,
        anchor: Anchor,
    },
    Call {
        op: usize,
        args: Vec<usize>,
        anchor: Anchor,
    },
    If {
        test: usize,
        then_branch: usize,
        else_branch: usize,
        anchor: Anchor,
    },
    Lambda {
        formals: Vec<GraphName>,
        body: usize,
        anchor: Anchor,
    },
    Let {
        bindings: Vec<GraphBinding>,
        body: usize,
        anchor: Anchor,
    },
    Block {
        body: Vec<usize>,
        anchor: Option<Anchor>,
    },
    Bind {
        name: GraphName,
        value: usize,
        anchor: Anchor,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphBinding {
    pub name: GraphName,
    pub value: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphName {
    User(Rc<str>),
    Temp(u32),
    Intrinsic(Intrinsic),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub file: Option<Rc<str>>,
    pub line: usize,
    pub col: usize,
}

impl From<Span> for Anchor {
    fn from(span: Span) -> Anchor {
        Anchor {
            file: None,
            line: span.line,
            col: span.col,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphLawError {
    rule: &'static str,
    message: String,
}

impl GraphLawError {
    fn new(rule: &'static str, message: impl Into<String>) -> GraphLawError {
        GraphLawError {
            rule,
            message: message.into(),
        }
    }

    pub fn rule(&self) -> &'static str {
        self.rule
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LowerFault {
    kind: &'static str,
    message: String,
    span: Span,
}

impl LowerFault {
    fn new(kind: &'static str, span: Span, message: impl Into<String>) -> LowerFault {
        LowerFault {
            kind,
            message: message.into(),
            span,
        }
    }

    pub fn kind(&self) -> &'static str {
        self.kind
    }

    pub fn span(&self) -> Span {
        self.span
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn display(&self, file: &str) -> String {
        format!(
            "E-MG-LOWER {file}:{}:{} {}",
            self.span.line, self.span.col, self.message
        )
    }
}

impl fmt::Display for LowerFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LowerFault {}

pub fn lower_program(core: &[CoreExpr]) -> Result<MeaningGraph, LowerFault> {
    if core.is_empty() {
        return Err(LowerFault::new(
            "empty-program",
            Span { line: 1, col: 1 },
            "Meaning Graph v0 lowering requires at least one Core expression",
        ));
    }

    let mut lower = Lowerer::default();
    let mut body = Vec::with_capacity(core.len());
    for expr in core {
        body.push(lower.lower_expr(expr, Context::BlockBody)?);
    }
    let root = lower.push(GraphNode::Block { body, anchor: None });
    Ok(MeaningGraph {
        nodes: lower.nodes,
        roots: vec![root],
    })
}

pub fn graph_json_bytes(graph: &MeaningGraph) -> Vec<u8> {
    let mut out = String::new();
    write_graph(graph, &mut out);
    out.into_bytes()
}

pub fn graph_hash_hex(graph_bytes: &[u8]) -> String {
    hash_with_domain_hex(MEANING_GRAPH_HASH_DOMAIN, graph_bytes)
}

pub fn validate_graph_value(graph: &JsonValue) -> Vec<GraphLawError> {
    let mut errors = Vec::new();
    let mut edges = Vec::new();

    let Some(object) = graph.as_object() else {
        add(&mut errors, "top-level-fields", "graph must be an object");
        return errors;
    };
    if !same_fields(object, &["meaning_graph", "nodes", "roots"]) {
        add(
            &mut errors,
            "top-level-fields",
            "graph has illegal top-level fields",
        );
    }
    if graph.get("meaning_graph").and_then(JsonValue::as_str) != Some(MEANING_GRAPH_TAG) {
        add(&mut errors, "graph-tag", "graph tag mismatch");
    }

    let Some(nodes) = graph.get("nodes").and_then(JsonValue::as_array) else {
        add(&mut errors, "top-level-fields", "nodes must be an array");
        return errors;
    };
    let roots = graph.get("roots").and_then(JsonValue::as_array);
    if roots.is_none_or(Vec::is_empty) {
        add(
            &mut errors,
            "roots-non-empty",
            "roots must be a non-empty array",
        );
    }

    for (index, node) in nodes.iter().enumerate() {
        let Some(node_object) = node.as_object() else {
            add(
                &mut errors,
                "node-kind",
                format!("node {index} must be an object"),
            );
            continue;
        };
        if let Some(anchor) = node_object.get("anchor") {
            validate_anchor(anchor, &mut errors);
        }
        match node_object.get("kind").and_then(JsonValue::as_str) {
            Some("lit") => {
                if !same_fields(
                    node_object,
                    &optional_anchor_fields(&["kind", "datum"], node),
                ) {
                    add(
                        &mut errors,
                        "fields",
                        format!("lit node {index} has illegal fields"),
                    );
                }
                check_datum(node_object.get("datum"), &mut errors);
            }
            Some("ref") => {
                if !same_fields(
                    node_object,
                    &optional_anchor_fields(&["kind", "name"], node),
                ) {
                    add(
                        &mut errors,
                        "fields",
                        format!("ref node {index} has illegal fields"),
                    );
                }
                validate_name(node_object.get("name"), &mut errors, "name");
            }
            Some("call") => {
                if !same_fields(
                    node_object,
                    &optional_anchor_fields(&["kind", "op", "args"], node),
                ) {
                    add(
                        &mut errors,
                        "fields",
                        format!("call node {index} has illegal fields"),
                    );
                }
                check_index(
                    node_object.get("op"),
                    nodes.len(),
                    index,
                    "call.op",
                    &mut errors,
                    &mut edges,
                );
                match node_object.get("args").and_then(JsonValue::as_array) {
                    Some(args) => {
                        for (arg_index, arg) in args.iter().enumerate() {
                            check_index(
                                Some(arg),
                                nodes.len(),
                                index,
                                &format!("call.args[{arg_index}]"),
                                &mut errors,
                                &mut edges,
                            );
                        }
                    }
                    None => add(
                        &mut errors,
                        "fields",
                        format!("call node {index} args must be an array"),
                    ),
                }
            }
            Some("if") => {
                if !same_fields(
                    node_object,
                    &optional_anchor_fields(&["kind", "test", "then", "else"], node),
                ) {
                    add(
                        &mut errors,
                        "fields",
                        format!("if node {index} has illegal fields"),
                    );
                }
                check_index(
                    node_object.get("test"),
                    nodes.len(),
                    index,
                    "if.test",
                    &mut errors,
                    &mut edges,
                );
                check_index(
                    node_object.get("then"),
                    nodes.len(),
                    index,
                    "if.then",
                    &mut errors,
                    &mut edges,
                );
                check_index(
                    node_object.get("else"),
                    nodes.len(),
                    index,
                    "if.else",
                    &mut errors,
                    &mut edges,
                );
            }
            Some("lambda") => {
                if !same_fields(
                    node_object,
                    &optional_anchor_fields(&["kind", "formals", "body"], node),
                ) {
                    add(
                        &mut errors,
                        "fields",
                        format!("lambda node {index} has illegal fields"),
                    );
                }
                match node_object.get("formals").and_then(JsonValue::as_array) {
                    Some(formals) => {
                        let mut seen = HashSet::new();
                        for (formal_index, formal) in formals.iter().enumerate() {
                            let space = validate_name(Some(formal), &mut errors, "lambda-formals");
                            if space == Some("intrinsic") {
                                add(
                                    &mut errors,
                                    "lambda-formals",
                                    "lambda formal cannot be intrinsic",
                                );
                            }
                            if let Some(key) = law_name_key(formal) {
                                if !seen.insert(key) {
                                    add(
                                        &mut errors,
                                        "lambda-formals",
                                        format!(
                                            "lambda formal {formal_index} duplicates an earlier formal"
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    None => add(
                        &mut errors,
                        "fields",
                        format!("lambda node {index} formals must be an array"),
                    ),
                }
                check_index(
                    node_object.get("body"),
                    nodes.len(),
                    index,
                    "lambda.body",
                    &mut errors,
                    &mut edges,
                );
            }
            Some("let") => {
                if !same_fields(
                    node_object,
                    &optional_anchor_fields(&["kind", "bindings", "body"], node),
                ) {
                    add(
                        &mut errors,
                        "fields",
                        format!("let node {index} has illegal fields"),
                    );
                }
                match node_object.get("bindings").and_then(JsonValue::as_array) {
                    Some(bindings) => {
                        let mut seen = HashSet::new();
                        for (binding_index, binding) in bindings.iter().enumerate() {
                            let Some(binding_object) = binding.as_object() else {
                                add(
                                    &mut errors,
                                    "let-bindings",
                                    format!("let binding {binding_index} must be an object"),
                                );
                                continue;
                            };
                            if !same_fields(binding_object, &["name", "value"]) {
                                add(
                                    &mut errors,
                                    "fields",
                                    format!("let binding {binding_index} has illegal fields"),
                                );
                            }
                            let name = binding_object.get("name");
                            let space = validate_name(name, &mut errors, "let-bindings");
                            if space == Some("intrinsic") {
                                add(
                                    &mut errors,
                                    "let-bindings",
                                    "let binding name cannot be intrinsic",
                                );
                            }
                            if let Some(key) = name.and_then(law_name_key) {
                                if !seen.insert(key) {
                                    add(
                                        &mut errors,
                                        "let-bindings",
                                        format!(
                                            "let binding {binding_index} duplicates an earlier binding"
                                        ),
                                    );
                                }
                            }
                            check_index(
                                binding_object.get("value"),
                                nodes.len(),
                                index,
                                &format!("let.bindings[{binding_index}].value"),
                                &mut errors,
                                &mut edges,
                            );
                        }
                    }
                    None => add(
                        &mut errors,
                        "fields",
                        format!("let node {index} bindings must be an array"),
                    ),
                }
                check_index(
                    node_object.get("body"),
                    nodes.len(),
                    index,
                    "let.body",
                    &mut errors,
                    &mut edges,
                );
            }
            Some("block") => {
                if !same_fields(
                    node_object,
                    &optional_anchor_fields(&["kind", "body"], node),
                ) {
                    add(
                        &mut errors,
                        "fields",
                        format!("block node {index} has illegal fields"),
                    );
                }
                match node_object.get("body").and_then(JsonValue::as_array) {
                    Some(body) if !body.is_empty() => {
                        for (body_index, child) in body.iter().enumerate() {
                            check_index(
                                Some(child),
                                nodes.len(),
                                index,
                                &format!("block.body[{body_index}]"),
                                &mut errors,
                                &mut edges,
                            );
                        }
                    }
                    _ => add(
                        &mut errors,
                        "block-body-non-empty",
                        format!("block node {index} body is empty"),
                    ),
                }
            }
            Some("bind") => {
                if !same_fields(
                    node_object,
                    &optional_anchor_fields(&["kind", "name", "value"], node),
                ) {
                    add(
                        &mut errors,
                        "fields",
                        format!("bind node {index} has illegal fields"),
                    );
                }
                let space = validate_name(node_object.get("name"), &mut errors, "name");
                if space == Some("intrinsic") {
                    add(
                        &mut errors,
                        "bind-name-space",
                        "bind name cannot be intrinsic",
                    );
                }
                check_index(
                    node_object.get("value"),
                    nodes.len(),
                    index,
                    "bind.value",
                    &mut errors,
                    &mut edges,
                );
            }
            _ => add(
                &mut errors,
                "node-kind",
                format!("node {index} kind is illegal"),
            ),
        }
    }

    if let Some(roots) = roots {
        for (root_index, root) in roots.iter().enumerate() {
            match json_usize(root) {
                Some(index) if index < nodes.len() => {
                    if nodes[index].get("kind").and_then(JsonValue::as_str) == Some("bind") {
                        add(&mut errors, "bind-position", "bind node cannot be a root");
                    }
                }
                _ => add(
                    &mut errors,
                    "index-in-range",
                    format!("roots[{root_index}] is out of range"),
                ),
            }
        }
    }

    for edge in &edges {
        if nodes
            .get(edge.child)
            .and_then(|node| node.get("kind"))
            .and_then(JsonValue::as_str)
            == Some("bind")
            && !edge.context.starts_with("block.body")
        {
            add(
                &mut errors,
                "bind-position",
                "bind node must be referenced only by block.body",
            );
        }
    }

    let mut reachable = HashSet::new();
    if let Some(roots) = roots {
        for root in roots {
            if let Some(index) = json_usize(root).filter(|index| *index < nodes.len()) {
                visit(index, &edges, &mut reachable);
            }
        }
    }
    for index in 0..nodes.len() {
        if !reachable.contains(&index) {
            add(
                &mut errors,
                "reachability",
                format!("node {index} is unreachable"),
            );
        }
    }

    errors
}

pub fn graph_from_json_value(graph: &JsonValue) -> Result<MeaningGraph, Vec<GraphLawError>> {
    let errors = validate_graph_value(graph);
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(build_graph(graph))
}

pub fn graph_from_json_bytes(
    bytes: &[u8],
) -> Result<Result<MeaningGraph, Vec<GraphLawError>>, serde_json::Error> {
    let json: JsonValue = serde_json::from_slice(bytes)?;
    Ok(graph_from_json_value(&json))
}

#[derive(Clone, Debug)]
struct Edge {
    parent: usize,
    child: usize,
    context: String,
}

fn add(errors: &mut Vec<GraphLawError>, rule: &'static str, message: impl Into<String>) {
    errors.push(GraphLawError::new(rule, message));
}

fn same_fields(object: &serde_json::Map<String, JsonValue>, fields: &[&str]) -> bool {
    if object.len() != fields.len() {
        return false;
    }
    fields.iter().all(|field| object.contains_key(*field))
}

fn optional_anchor_fields<'a>(fields: &[&'a str], node: &JsonValue) -> Vec<&'a str> {
    let mut expected = fields.to_vec();
    if node.get("anchor").is_some() {
        expected.push("anchor");
    }
    expected
}

fn validate_anchor(anchor: &JsonValue, errors: &mut Vec<GraphLawError>) {
    let Some(object) = anchor.as_object() else {
        add(errors, "anchor-positive", "anchor must be an object");
        return;
    };
    if !object
        .keys()
        .all(|field| matches!(field.as_str(), "file" | "line" | "col"))
    {
        add(errors, "fields", "anchor has an unknown field");
    }
    let line = anchor.get("line").and_then(json_usize);
    let col = anchor.get("col").and_then(json_usize);
    if line.is_none_or(|line| line == 0) || col.is_none_or(|col| col == 0) {
        add(
            errors,
            "anchor-positive",
            "anchor line/col must be positive integers",
        );
    }
    if let Some(file) = anchor.get("file") {
        match file.as_str() {
            Some(path) if !path.starts_with('/') && !path.contains('\\') => {}
            _ => add(
                errors,
                "anchor-positive",
                "anchor file must be repo-relative",
            ),
        }
    }
}

fn validate_name(
    name: Option<&JsonValue>,
    errors: &mut Vec<GraphLawError>,
    rule: &'static str,
) -> Option<&'static str> {
    let Some(name) = name else {
        add(errors, rule, "name must be an object");
        return None;
    };
    let Some(object) = name.as_object() else {
        add(errors, rule, "name must be an object");
        return None;
    };
    match name.get("space").and_then(JsonValue::as_str) {
        Some("user") => {
            if !same_fields(object, &["space", "text"]) {
                add(errors, "fields", "user name has illegal fields");
            }
            if name
                .get("text")
                .and_then(JsonValue::as_str)
                .is_none_or(str::is_empty)
            {
                add(errors, rule, "user name text must be non-empty");
            }
            Some("user")
        }
        Some("temp") => {
            if !same_fields(object, &["space", "index"]) {
                add(errors, "fields", "temp name has illegal fields");
            }
            match name.get("index").and_then(json_usize) {
                Some(index) if index <= u32::MAX as usize => {}
                _ => add(
                    errors,
                    rule,
                    "temp name index must be a non-negative integer",
                ),
            }
            Some("temp")
        }
        Some("intrinsic") => {
            if !same_fields(object, &["space", "name"]) {
                add(errors, "fields", "intrinsic name has illegal fields");
            }
            let valid = name
                .get("name")
                .and_then(JsonValue::as_str)
                .and_then(intrinsic_by_name)
                .is_some();
            if !valid {
                add(
                    errors,
                    "intrinsic-name",
                    "intrinsic name is outside the closed set",
                );
            }
            Some("intrinsic")
        }
        _ => {
            add(errors, rule, "name space is illegal");
            None
        }
    }
}

fn law_name_key(name: &JsonValue) -> Option<String> {
    match name.get("space").and_then(JsonValue::as_str) {
        Some("user") => name
            .get("text")
            .and_then(JsonValue::as_str)
            .map(|text| format!("user:{text}")),
        Some("temp") => name
            .get("index")
            .and_then(json_usize)
            .map(|index| format!("temp:{index}")),
        Some("intrinsic") => name
            .get("name")
            .and_then(JsonValue::as_str)
            .map(|text| format!("intrinsic:{text}")),
        _ => None,
    }
}

fn check_datum(datum: Option<&JsonValue>, errors: &mut Vec<GraphLawError>) {
    let Some(text) = datum.and_then(JsonValue::as_str) else {
        add(errors, "datum-text", "datum must be non-empty text");
        return;
    };
    if text.is_empty() || canonical_datum_parse(text).is_err() {
        add(
            errors,
            "datum-text",
            "datum must be canonical Canonical Core v0 datum text",
        );
    }
}

fn check_index(
    value: Option<&JsonValue>,
    node_count: usize,
    parent: usize,
    context: &str,
    errors: &mut Vec<GraphLawError>,
    edges: &mut Vec<Edge>,
) {
    let Some(index) = value.and_then(json_usize) else {
        add(
            errors,
            "index-in-range",
            format!("{context} index is out of range"),
        );
        return;
    };
    if index >= node_count {
        add(
            errors,
            "index-in-range",
            format!("{context} index is out of range"),
        );
        return;
    }
    if index >= parent {
        add(
            errors,
            "child-order",
            format!("{context} must reference a lower node index"),
        );
    }
    edges.push(Edge {
        parent,
        child: index,
        context: context.to_string(),
    });
}

fn visit(index: usize, edges: &[Edge], reachable: &mut HashSet<usize>) {
    if !reachable.insert(index) {
        return;
    }
    for edge in edges.iter().filter(|edge| edge.parent == index) {
        visit(edge.child, edges, reachable);
    }
}

fn json_usize(value: &JsonValue) -> Option<usize> {
    value.as_u64().and_then(|n| usize::try_from(n).ok())
}

fn build_graph(graph: &JsonValue) -> MeaningGraph {
    let nodes = graph["nodes"]
        .as_array()
        .expect("validated nodes array")
        .iter()
        .map(build_node)
        .collect();
    let roots = graph["roots"]
        .as_array()
        .expect("validated roots array")
        .iter()
        .map(|root| json_usize(root).expect("validated root index"))
        .collect();
    MeaningGraph { nodes, roots }
}

fn build_node(node: &JsonValue) -> GraphNode {
    match node["kind"].as_str().expect("validated node kind") {
        "lit" => GraphNode::Lit {
            datum: node["datum"].as_str().expect("validated datum").to_string(),
            anchor: build_required_anchor(node),
        },
        "ref" => GraphNode::Ref {
            name: build_name(&node["name"]),
            anchor: build_required_anchor(node),
        },
        "call" => GraphNode::Call {
            op: json_usize(&node["op"]).expect("validated op"),
            args: node["args"]
                .as_array()
                .expect("validated args")
                .iter()
                .map(|arg| json_usize(arg).expect("validated arg"))
                .collect(),
            anchor: build_required_anchor(node),
        },
        "if" => GraphNode::If {
            test: json_usize(&node["test"]).expect("validated test"),
            then_branch: json_usize(&node["then"]).expect("validated then"),
            else_branch: json_usize(&node["else"]).expect("validated else"),
            anchor: build_required_anchor(node),
        },
        "lambda" => GraphNode::Lambda {
            formals: node["formals"]
                .as_array()
                .expect("validated formals")
                .iter()
                .map(build_name)
                .collect(),
            body: json_usize(&node["body"]).expect("validated body"),
            anchor: build_required_anchor(node),
        },
        "let" => GraphNode::Let {
            bindings: node["bindings"]
                .as_array()
                .expect("validated bindings")
                .iter()
                .map(build_binding)
                .collect(),
            body: json_usize(&node["body"]).expect("validated body"),
            anchor: build_required_anchor(node),
        },
        "block" => GraphNode::Block {
            body: node["body"]
                .as_array()
                .expect("validated body")
                .iter()
                .map(|child| json_usize(child).expect("validated body child"))
                .collect(),
            anchor: node.get("anchor").map(build_anchor),
        },
        "bind" => GraphNode::Bind {
            name: build_name(&node["name"]),
            value: json_usize(&node["value"]).expect("validated value"),
            anchor: build_required_anchor(node),
        },
        _ => unreachable!("validated node kind"),
    }
}

fn build_binding(binding: &JsonValue) -> GraphBinding {
    GraphBinding {
        name: build_name(&binding["name"]),
        value: json_usize(&binding["value"]).expect("validated binding value"),
    }
}

fn build_required_anchor(node: &JsonValue) -> Anchor {
    node.get("anchor").map(build_anchor).unwrap_or(Anchor {
        file: None,
        line: 1,
        col: 1,
    })
}

fn build_anchor(anchor: &JsonValue) -> Anchor {
    Anchor {
        file: anchor.get("file").and_then(JsonValue::as_str).map(Rc::from),
        line: anchor
            .get("line")
            .and_then(json_usize)
            .expect("validated anchor line"),
        col: anchor
            .get("col")
            .and_then(json_usize)
            .expect("validated anchor col"),
    }
}

fn build_name(name: &JsonValue) -> GraphName {
    match name["space"].as_str().expect("validated name space") {
        "user" => GraphName::User(Rc::from(
            name["text"].as_str().expect("validated user text"),
        )),
        "temp" => GraphName::Temp(json_usize(&name["index"]).expect("validated temp") as u32),
        "intrinsic" => GraphName::Intrinsic(
            intrinsic_by_name(name["name"].as_str().expect("validated intrinsic"))
                .expect("validated intrinsic name"),
        ),
        _ => unreachable!("validated name space"),
    }
}

fn intrinsic_by_name(name: &str) -> Option<Intrinsic> {
    Intrinsic::by_name(name)
}

#[derive(Clone, Copy)]
enum Context {
    BlockBody,
    Expr,
}

#[derive(Default)]
struct Lowerer {
    nodes: Vec<GraphNode>,
}

impl Lowerer {
    fn push(&mut self, node: GraphNode) -> usize {
        let index = self.nodes.len();
        self.nodes.push(node);
        index
    }

    fn lower_expr(&mut self, expr: &CoreExpr, context: Context) -> Result<usize, LowerFault> {
        match &expr.kind {
            CoreKind::Quote(value) => {
                let datum = canonical_datum_string(value).map_err(|e| canon_fault(expr.span, e))?;
                Ok(self.push(GraphNode::Lit {
                    datum,
                    anchor: expr.span.into(),
                }))
            }
            CoreKind::Var(name) => Ok(self.push(GraphNode::Ref {
                name: graph_ref_name(name),
                anchor: expr.span.into(),
            })),
            CoreKind::Intrinsic(intrinsic) => Ok(self.push(GraphNode::Ref {
                name: GraphName::Intrinsic(*intrinsic),
                anchor: expr.span.into(),
            })),
            CoreKind::App { op, args } => {
                let op = self.lower_expr(op, Context::Expr)?;
                let mut lowered_args = Vec::with_capacity(args.len());
                for arg in args {
                    lowered_args.push(self.lower_expr(arg, Context::Expr)?);
                }
                Ok(self.push(GraphNode::Call {
                    op,
                    args: lowered_args,
                    anchor: expr.span.into(),
                }))
            }
            CoreKind::If(test, then_branch, else_branch) => {
                let test = self.lower_expr(test, Context::Expr)?;
                let then_branch = self.lower_expr(then_branch, Context::Expr)?;
                let else_branch = self.lower_expr(else_branch, Context::Expr)?;
                Ok(self.push(GraphNode::If {
                    test,
                    then_branch,
                    else_branch,
                    anchor: expr.span.into(),
                }))
            }
            CoreKind::Values(exprs) => {
                let op = self.push(GraphNode::Ref {
                    name: GraphName::Intrinsic(Intrinsic::Values),
                    anchor: expr.span.into(),
                });
                let mut args = Vec::with_capacity(exprs.len());
                for value in exprs {
                    args.push(self.lower_expr(value, Context::Expr)?);
                }
                Ok(self.push(GraphNode::Call {
                    op,
                    args,
                    anchor: expr.span.into(),
                }))
            }
            CoreKind::Begin(exprs) => {
                if exprs.is_empty() {
                    return Err(LowerFault::new(
                        "empty-block",
                        expr.span,
                        "Meaning Graph v0 block nodes require at least one body item",
                    ));
                }
                let mut body = Vec::with_capacity(exprs.len());
                for item in exprs {
                    body.push(self.lower_expr(item, Context::BlockBody)?);
                }
                Ok(self.push(GraphNode::Block {
                    body,
                    anchor: Some(expr.span.into()),
                }))
            }
            CoreKind::Define { name, value } => {
                match context {
                    Context::BlockBody => {
                        if let Some(reserved) = profile_reserved_name(name) {
                            return Err(LowerFault::new(
                            "profile-escape",
                            expr.span,
                            format!("`define` cannot bind reserved checked profile name `{reserved}`"),
                        ));
                        }
                        let value = self.lower_expr(value, Context::Expr)?;
                        Ok(self.push(GraphNode::Bind {
                            name: graph_name(name),
                            value,
                            anchor: expr.span.into(),
                        }))
                    }
                    Context::Expr => Err(LowerFault::new(
                        "bind-position",
                        expr.span,
                        "`define` can lower only as a direct block body item in Meaning Graph v0",
                    )),
                }
            }
            CoreKind::Lambda { formals, body } => {
                if formals.rest.is_some() {
                    return Err(LowerFault::new(
                        "profile-escape",
                        expr.span,
                        "Meaning Graph v0 lowers only fixed-arity checked profile lambdas",
                    ));
                }
                let mut seen = HashSet::new();
                let mut lowered_formals = Vec::with_capacity(formals.fixed.len());
                for formal in &formals.fixed {
                    let name = checked_binder_name(formal, expr.span, "lambda formal", &mut seen)?;
                    lowered_formals.push(name);
                }
                let body = self.lower_expr(body, Context::Expr)?;
                Ok(self.push(GraphNode::Lambda {
                    formals: lowered_formals,
                    body,
                    anchor: expr.span.into(),
                }))
            }
            CoreKind::Let { bindings, body } => {
                let mut seen = HashSet::new();
                let mut lowered_bindings = Vec::with_capacity(bindings.len());
                for binding in bindings {
                    let name =
                        checked_binder_name(&binding.name, expr.span, "let binding", &mut seen)?;
                    let value = self.lower_expr(&binding.init, Context::Expr)?;
                    lowered_bindings.push(GraphBinding { name, value });
                }
                let body = self.lower_expr(body, Context::Expr)?;
                Ok(self.push(GraphNode::Let {
                    bindings: lowered_bindings,
                    body,
                    anchor: expr.span.into(),
                }))
            }
            CoreKind::Letrec { .. } => unsupported("letrec", expr.span),
            CoreKind::Set { .. } => unsupported("set!", expr.span),
            CoreKind::Guard { .. } => unsupported("guard", expr.span),
        }
    }
}

fn graph_ref_name(name: &Ident) -> GraphName {
    match name {
        Ident::User(name) => Intrinsic::profile_by_name(name)
            .map(GraphName::Intrinsic)
            .unwrap_or_else(|| GraphName::User(name.clone())),
        Ident::Temp(index) => GraphName::Temp(*index),
    }
}

fn graph_name(name: &Ident) -> GraphName {
    match name {
        Ident::User(name) => GraphName::User(name.clone()),
        Ident::Temp(index) => GraphName::Temp(*index),
    }
}

fn checked_binder_name(
    name: &Ident,
    span: Span,
    label: &'static str,
    seen: &mut HashSet<String>,
) -> Result<GraphName, LowerFault> {
    if let Some(reserved) = profile_reserved_name(name) {
        return Err(LowerFault::new(
            "profile-escape",
            span,
            format!("{label} cannot bind reserved checked profile name `{reserved}`"),
        ));
    }
    let key = match name {
        Ident::User(name) => format!("user:{name}"),
        Ident::Temp(index) => format!("temp:{index}"),
    };
    if !seen.insert(key) {
        return Err(LowerFault::new(
            "profile-escape",
            span,
            format!("{label} duplicates an earlier binder"),
        ));
    }
    Ok(graph_name(name))
}

fn profile_reserved_name(name: &Ident) -> Option<&str> {
    match name {
        Ident::User(name) if name.as_ref() == "input" => Some("input"),
        Ident::User(name) if Intrinsic::profile_by_name(name).is_some() => Some(name.as_ref()),
        _ => None,
    }
}

fn unsupported(form: &'static str, span: Span) -> Result<usize, LowerFault> {
    Err(LowerFault::new(
        "unsupported-core",
        span,
        format!("Core form `{form}` is outside Meaning Graph v0 lowering"),
    ))
}

fn canon_fault(span: Span, fault: CanonFault) -> LowerFault {
    LowerFault::new(
        "datum-text",
        span,
        format!("literal is not valid Meaning Graph v0 datum text: {fault}"),
    )
}

fn write_graph(graph: &MeaningGraph, out: &mut String) {
    out.push_str("{\n");
    out.push_str("  \"meaning_graph\": ");
    write_json_string(MEANING_GRAPH_TAG, out);
    out.push_str(",\n");
    out.push_str("  \"nodes\": [\n");
    for (index, node) in graph.nodes.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        write_node(node, 2, out);
    }
    out.push_str("\n  ],\n");
    out.push_str("  \"roots\": ");
    write_usize_array(&graph.roots, 1, out);
    out.push('\n');
    out.push_str("}\n");
}

fn write_node(node: &GraphNode, indent_level: usize, out: &mut String) {
    indent(indent_level, out);
    out.push_str("{\n");
    match node {
        GraphNode::Lit { datum, anchor } => {
            write_field_string("kind", "lit", indent_level + 1, true, out);
            write_field_string("datum", datum, indent_level + 1, true, out);
            write_anchor_field(anchor, indent_level + 1, false, out);
        }
        GraphNode::Ref { name, anchor } => {
            write_field_string("kind", "ref", indent_level + 1, true, out);
            write_name_field(name, indent_level + 1, true, out);
            write_anchor_field(anchor, indent_level + 1, false, out);
        }
        GraphNode::Call { op, args, anchor } => {
            write_field_string("kind", "call", indent_level + 1, true, out);
            write_field_usize("op", *op, indent_level + 1, true, out);
            write_array_field("args", args, indent_level + 1, true, out);
            write_anchor_field(anchor, indent_level + 1, false, out);
        }
        GraphNode::If {
            test,
            then_branch,
            else_branch,
            anchor,
        } => {
            write_field_string("kind", "if", indent_level + 1, true, out);
            write_field_usize("test", *test, indent_level + 1, true, out);
            write_field_usize("then", *then_branch, indent_level + 1, true, out);
            write_field_usize("else", *else_branch, indent_level + 1, true, out);
            write_anchor_field(anchor, indent_level + 1, false, out);
        }
        GraphNode::Lambda {
            formals,
            body,
            anchor,
        } => {
            write_field_string("kind", "lambda", indent_level + 1, true, out);
            write_name_array_field("formals", formals, indent_level + 1, true, out);
            write_field_usize("body", *body, indent_level + 1, true, out);
            write_anchor_field(anchor, indent_level + 1, false, out);
        }
        GraphNode::Let {
            bindings,
            body,
            anchor,
        } => {
            write_field_string("kind", "let", indent_level + 1, true, out);
            write_binding_array_field("bindings", bindings, indent_level + 1, true, out);
            write_field_usize("body", *body, indent_level + 1, true, out);
            write_anchor_field(anchor, indent_level + 1, false, out);
        }
        GraphNode::Block { body, anchor } => {
            write_field_string("kind", "block", indent_level + 1, true, out);
            write_array_field("body", body, indent_level + 1, anchor.is_some(), out);
            if let Some(anchor) = anchor {
                write_anchor_field(anchor, indent_level + 1, false, out);
            }
        }
        GraphNode::Bind {
            name,
            value,
            anchor,
        } => {
            write_field_string("kind", "bind", indent_level + 1, true, out);
            write_name_field(name, indent_level + 1, true, out);
            write_field_usize("value", *value, indent_level + 1, true, out);
            write_anchor_field(anchor, indent_level + 1, false, out);
        }
    }
    indent(indent_level, out);
    out.push('}');
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

fn write_name_array_field(
    key: &str,
    names: &[GraphName],
    indent_level: usize,
    comma: bool,
    out: &mut String,
) {
    indent(indent_level, out);
    write_json_string(key, out);
    out.push_str(": ");
    write_name_array(names, indent_level, out);
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn write_name_array(names: &[GraphName], indent_level: usize, out: &mut String) {
    if names.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        indent(indent_level + 1, out);
        write_name_object(name, indent_level + 1, out);
    }
    out.push('\n');
    indent(indent_level, out);
    out.push(']');
}

fn write_binding_array_field(
    key: &str,
    bindings: &[GraphBinding],
    indent_level: usize,
    comma: bool,
    out: &mut String,
) {
    indent(indent_level, out);
    write_json_string(key, out);
    out.push_str(": ");
    if bindings.is_empty() {
        out.push_str("[]");
    } else {
        out.push_str("[\n");
        for (index, binding) in bindings.iter().enumerate() {
            if index > 0 {
                out.push_str(",\n");
            }
            indent(indent_level + 1, out);
            out.push_str("{\n");
            write_named_name_field("name", &binding.name, indent_level + 2, true, out);
            write_field_usize("value", binding.value, indent_level + 2, false, out);
            indent(indent_level + 1, out);
            out.push('}');
        }
        out.push('\n');
        indent(indent_level, out);
        out.push(']');
    }
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn write_name_field(name: &GraphName, indent_level: usize, comma: bool, out: &mut String) {
    write_named_name_field("name", name, indent_level, comma, out);
}

fn write_named_name_field(
    key: &str,
    name: &GraphName,
    indent_level: usize,
    comma: bool,
    out: &mut String,
) {
    indent(indent_level, out);
    write_json_string(key, out);
    out.push_str(": ");
    write_name_object(name, indent_level, out);
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn write_name_object(name: &GraphName, indent_level: usize, out: &mut String) {
    out.push_str("{\n");
    match name {
        GraphName::User(text) => {
            write_field_string("space", "user", indent_level + 1, true, out);
            write_field_string("text", text, indent_level + 1, false, out);
        }
        GraphName::Temp(index) => {
            write_field_string("space", "temp", indent_level + 1, true, out);
            write_field_usize("index", *index as usize, indent_level + 1, false, out);
        }
        GraphName::Intrinsic(intrinsic) => {
            write_field_string("space", "intrinsic", indent_level + 1, true, out);
            write_field_string("name", intrinsic.name(), indent_level + 1, false, out);
        }
    }
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

fn write_array_field(
    key: &str,
    values: &[usize],
    indent_level: usize,
    comma: bool,
    out: &mut String,
) {
    indent(indent_level, out);
    write_json_string(key, out);
    out.push_str(": ");
    write_usize_array(values, indent_level, out);
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn write_usize_array(values: &[usize], indent_level: usize, out: &mut String) {
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
        out.push_str(&value.to_string());
    }
    out.push('\n');
    indent(indent_level, out);
    out.push(']');
}

fn write_json_string(value: &str, out: &mut String) {
    let encoded = serde_json::to_string(value).expect("string encoding cannot fail");
    out.push_str(&encoded);
}

fn indent(level: usize, out: &mut String) {
    for _ in 0..level {
        out.push_str("  ");
    }
}
