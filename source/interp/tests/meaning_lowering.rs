use std::path::{Path, PathBuf};
use std::rc::Rc;

use lispex::{
    graph_hash_hex, graph_json_bytes, lower_meaning_graph_program, normalize_program, read_program,
    CoreExpr, CoreKind, Ident, Intrinsic, Span, Value, MEANING_GRAPH_HASH_DOMAIN,
};
use serde_json::Value as JsonValue;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("interp/ has a parent")
        .to_path_buf()
}

fn read_rel(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn lower_source(src: &str, file: &str) -> Result<Vec<u8>, lispex::LowerFault> {
    let program = read_program(src, file).unwrap_or_else(|e| panic!("read {file}: {e}"));
    let core = normalize_program(&program.datums, file)
        .unwrap_or_else(|e| panic!("normalize {file}: {e}"));
    lower_meaning_graph_program(&core).map(|graph| graph_json_bytes(&graph))
}

#[test]
fn lowering_goldens_match_hand_authored_json() {
    for case in [
        "literal",
        "call-user",
        "no-sharing",
        "define-ref",
        "begin-define",
        "quasiquote-intrinsic",
    ] {
        let src_rel = format!("meaning-graph/lowering/cases/{case}.lspx");
        let expected_rel = format!("meaning-graph/lowering/expected/{case}.json");
        let src = read_rel(&src_rel);
        let expected = read_rel(&expected_rel).into_bytes();
        let first = lower_source(&src, &src_rel).expect("case lowers");
        let second = lower_source(&src, &src_rel).expect("case lowers again");
        assert_eq!(first, expected, "{case} expected JSON drifted");
        assert_eq!(first, second, "{case} lowering is not deterministic");
    }
}

#[test]
fn lowering_faults_are_pinned() {
    let manifest: JsonValue =
        serde_json::from_str(&read_rel("meaning-graph/lowering/faults.json")).unwrap();
    for entry in manifest["faults"].as_array().expect("fault list") {
        let case = entry["case"].as_str().expect("case string");
        let kind = entry["kind"].as_str().expect("kind string");
        let line = entry["line"].as_u64().expect("line") as usize;
        let col = entry["col"].as_u64().expect("col") as usize;
        let rel = format!("meaning-graph/lowering/faults/{case}");
        let src = read_rel(&rel);
        let err = lower_source(&src, &rel).expect_err("case must fault");
        assert_eq!(err.kind(), kind, "{case} fault kind");
        assert_eq!(err.span(), Span { line, col }, "{case} fault span");
    }
}

#[test]
fn profile_control_forms_lower_and_eval_graph() {
    for (src, want) in [
        ("(if (< 2 3) \"yes\" \"no\")\n", "\"yes\""),
        ("(cond ((string<? \"a\" \"b\") 10) (else 20))\n", "10"),
        ("(and #t (= 1 1))\n", "#t"),
        ("(and #f (/ 1 0))\n", "#f"),
        ("(or \"kept\" (/ 1 0))\n", "\"kept\""),
    ] {
        let graph = lower_source(src, "<profile-control>").expect("profile control lowers");
        let out = lispex::eval_graph_json_report(&graph, lispex::MEANING_ENV_DEFAULT_STEP_LIMIT)
            .expect("lowered graph evaluates");
        assert!(out.ok, "{src} should evaluate successfully");
        let report: JsonValue = serde_json::from_slice(&out.report).expect("report JSON");
        assert_eq!(report["status"], "ok", "{src} status");
        assert_eq!(report["result"]["values"][0], want, "{src} value");
    }
}

#[test]
fn profile_closures_and_let_lower_and_eval_graph() {
    for (src, want) in [
        ("(let ((x 10)) ((lambda (y) (+ x y)) 5))\n", "15"),
        (
            "(define fact (lambda (n) (if (= n 0) 1 (* n (fact (- n 1))))))\n(fact 5)\n",
            "120",
        ),
    ] {
        let graph = lower_source(src, "<profile-closure>").expect("profile closure lowers");
        let json = String::from_utf8(graph.clone()).expect("graph UTF-8");
        assert!(json.contains("\"kind\": \"lambda\""), "{src} graph");
        let out = lispex::eval_graph_json_report(&graph, lispex::MEANING_ENV_DEFAULT_STEP_LIMIT)
            .expect("lowered graph evaluates");
        assert!(out.ok, "{src} should evaluate successfully");
        let report: JsonValue = serde_json::from_slice(&out.report).expect("report JSON");
        assert_eq!(report["status"], "ok", "{src} status");
        assert_eq!(report["result"]["values"][0], want, "{src} value");
    }
}

#[test]
fn profile_values_lower_as_closed_intrinsic_call_and_eval_graph() {
    for (src, want) in [
        ("(values 1 2)\n", serde_json::json!(["1", "2"])),
        (
            "(call-with-values (lambda () (values 1 2 3)) list)\n",
            serde_json::json!(["(1 2 3)"]),
        ),
        (
            "(call-with-values (lambda () (values)) (lambda () 'done))\n",
            serde_json::json!(["done"]),
        ),
    ] {
        let graph = lower_source(src, "<profile-values>").expect("profile values lower");
        let json = String::from_utf8(graph.clone()).expect("graph UTF-8");
        assert!(json.contains("\"name\": \"values\""), "{src} graph");
        let out = lispex::eval_graph_json_report(&graph, lispex::MEANING_ENV_DEFAULT_STEP_LIMIT)
            .expect("lowered graph evaluates");
        assert!(out.ok, "{src} should evaluate successfully");
        let report: JsonValue = serde_json::from_slice(&out.report).expect("report JSON");
        assert_eq!(report["status"], "ok", "{src} status");
        assert_eq!(report["result"]["values"], want, "{src} value");
    }
}

#[test]
fn profile_lambda_and_let_reserved_binders_fault() {
    for src in [
        "(lambda (+) +)\n",
        "(lambda (input) input)\n",
        "(let ((+ 1)) +)\n",
        "(let ((input 1)) input)\n",
    ] {
        let err = lower_source(src, "<profile-escape>").expect_err("binder must fault");
        assert_eq!(err.kind(), "profile-escape", "{src}");
    }
}

#[test]
fn profile_builtin_refs_lower_to_intrinsic_names() {
    let json = String::from_utf8(lower_source("(+ 1 (/ 6 3))\n", "<profile-builtin>").unwrap())
        .expect("graph UTF-8");
    assert!(json.contains("\"space\": \"intrinsic\""));
    assert!(json.contains("\"name\": \"+\""));
    assert!(json.contains("\"name\": \"/\""));
    assert!(!json.contains("\"text\": \"+\""));
}

#[test]
fn profile_reserved_binders_fault_before_graph_emission() {
    for src in ["(define + 1)\n+\n", "(define input 1)\ninput\n"] {
        let err = lower_source(src, "<profile-escape>").expect_err("binder must fault");
        assert_eq!(err.kind(), "profile-escape", "{src}");
    }
}

#[test]
fn direct_core_covers_temp_and_intrinsic_refs() {
    let span = Span { line: 1, col: 1 };
    let op = CoreExpr::new(CoreKind::Intrinsic(Intrinsic::Cons), span);
    let temp = CoreExpr::new(CoreKind::Var(Ident::Temp(0)), span);
    let nil = CoreExpr::new(CoreKind::Quote(Value::Nil), span);
    let call = CoreExpr::new(
        CoreKind::App {
            op: Box::new(op),
            args: vec![temp, nil],
        },
        span,
    );
    let graph = lower_meaning_graph_program(&[call]).expect("direct core lowers");
    let json = String::from_utf8(graph_json_bytes(&graph)).unwrap();
    assert!(json.contains("\"space\": \"intrinsic\""));
    assert!(json.contains("\"name\": \"cons\""));
    assert!(json.contains("\"space\": \"temp\""));
    assert!(json.contains("\"index\": 0"));
}

#[test]
fn begin_define_is_a_legal_nested_block_body() {
    let json = String::from_utf8(
        lower_source("(begin (define x 1) x)\n", "<begin-define>").expect("begin lowers"),
    )
    .unwrap();
    assert!(json.contains("\"kind\": \"bind\""));
    assert!(json.matches("\"kind\": \"block\"").count() >= 2);
}

#[test]
fn graph_hash_uses_the_reserved_domain_separator() {
    let src = read_rel("meaning-graph/lowering/cases/literal.lspx");
    let bytes = lower_source(&src, "literal.lspx").unwrap();
    let domain_hash = graph_hash_hex(&bytes);
    let naked_hash = lispex::hash_with_domain_hex("", &bytes);
    assert_ne!(domain_hash, naked_hash);
    assert_eq!(MEANING_GRAPH_HASH_DOMAIN, "csk/meaning-graph-hash/v0");
}

#[test]
fn execution_only_literal_faults_instead_of_lowering() {
    let span = Span { line: 1, col: 1 };
    let expr = CoreExpr::new(
        CoreKind::Quote(Value::Primitive(lispex::Primitive {
            name: Rc::from("p"),
            func: |_it, _args, _span| lispex::Eval::Ok(lispex::Outcome::Many(vec![])),
        })),
        span,
    );
    let err = lower_meaning_graph_program(&[expr]).expect_err("primitive literal must fault");
    assert_eq!(err.kind(), "datum-text");
}

#[test]
fn direct_core_define_in_expression_context_faults_bind_position() {
    let span = Span { line: 1, col: 1 };
    let define = CoreExpr::new(
        CoreKind::Define {
            name: Ident::User(Rc::from("x")),
            value: Box::new(CoreExpr::new(CoreKind::Quote(Value::Int(1.into())), span)),
        },
        span,
    );
    let app = CoreExpr::new(
        CoreKind::App {
            op: Box::new(CoreExpr::new(
                CoreKind::Var(Ident::User(Rc::from("f"))),
                span,
            )),
            args: vec![define],
        },
        span,
    );
    let err = lower_meaning_graph_program(&[app]).expect_err("define arg must fault");
    assert_eq!(err.kind(), "bind-position");
}

#[test]
fn direct_core_empty_begin_faults_empty_block() {
    let span = Span { line: 1, col: 1 };
    let expr = CoreExpr::new(CoreKind::Begin(vec![]), span);
    let err = lower_meaning_graph_program(&[expr]).expect_err("empty begin must fault");
    assert_eq!(err.kind(), "empty-block");
}
