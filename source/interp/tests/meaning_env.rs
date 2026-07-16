use std::path::{Path, PathBuf};

use lispex::{
    canonical_datum_parse, eval_graph_json_receipt_projection_with_input, eval_graph_json_report,
    graph_json_bytes, lower_meaning_graph_program, normalize_program, read_program,
    validate_graph_value, MEANING_ENV_DEFAULT_STEP_LIMIT,
};
use serde_json::Value as JsonValue;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("interp/ has a parent")
        .to_path_buf()
}

fn read_rel(rel: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn read_json_rel(rel: &str) -> JsonValue {
    serde_json::from_slice(&read_rel(rel)).unwrap_or_else(|e| panic!("parse {rel}: {e}"))
}

fn lowered_report(src: &str) -> JsonValue {
    let bytes = lowered_graph_bytes(src);
    let out = eval_graph_json_report(&bytes, MEANING_ENV_DEFAULT_STEP_LIMIT).expect("eval graph");
    serde_json::from_slice(&out.report).expect("report JSON")
}

fn lowered_graph_bytes(src: &str) -> Vec<u8> {
    let program = read_program(src, "<meaning-env-profile>").expect("read source");
    let core = normalize_program(&program.datums, "<meaning-env-profile>").expect("normalize");
    let graph = lower_meaning_graph_program(&core).expect("lower source");
    graph_json_bytes(&graph)
}

fn mask_engine_vcs_state(value: &mut JsonValue) {
    let commit = value
        .get_mut("engine")
        .and_then(|engine| engine.get_mut("commit"))
        .expect("engine.commit");
    assert_eq!(commit["vcs"], "git");
    commit["dirty"].as_bool().expect("engine.commit.dirty bool");
    let hex = commit["hex"].as_str().expect("commit hex string");
    assert!(
        hex.len() == 40
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "commit hex must be a full git oid"
    );
    commit["hex"] = JsonValue::String("<masked-commit>".to_string());
    commit["dirty"] = JsonValue::String("<masked-dirty>".to_string());
}

fn assert_report_artifact_eq(actual: &[u8], expected: &[u8], label: &str) {
    let mut actual_json: JsonValue =
        serde_json::from_slice(actual).unwrap_or_else(|e| panic!("{label} actual JSON: {e}"));
    let mut expected_json: JsonValue =
        serde_json::from_slice(expected).unwrap_or_else(|e| panic!("{label} expected JSON: {e}"));
    mask_engine_vcs_state(&mut actual_json);
    mask_engine_vcs_state(&mut expected_json);
    assert_eq!(actual_json, expected_json, "{label} report drifted");
}

#[test]
fn meaning_env_goldens_match_expected_reports() {
    for case in ["literal", "define-ref", "cons-list", "rebind", "append-eqv"] {
        let graph = read_rel(&format!("meaning-env/cases/{case}.json"));
        let expected = read_rel(&format!("meaning-env/expected/{case}.json"));
        let first = eval_graph_json_report(&graph, MEANING_ENV_DEFAULT_STEP_LIMIT)
            .unwrap_or_else(|e| panic!("{case} input error: {e}"));
        let second = eval_graph_json_report(&graph, MEANING_ENV_DEFAULT_STEP_LIMIT)
            .unwrap_or_else(|e| panic!("{case} input error: {e}"));
        assert!(first.ok, "{case} should evaluate successfully");
        assert_report_artifact_eq(&first.report, &expected, case);
        assert_eq!(
            first.report, second.report,
            "{case} report is not deterministic"
        );
    }
}

fn assert_projection_matches_report_fields(
    graph: &[u8],
    step_limit: usize,
    input: Option<lispex::Value>,
    label: &str,
) {
    let report_out = lispex::eval_graph_json_report_with_input(graph, step_limit, input.clone())
        .unwrap_or_else(|e| panic!("{label} report input error: {e}"));
    let report: JsonValue = serde_json::from_slice(&report_out.report).expect("report JSON");
    let projection = eval_graph_json_receipt_projection_with_input(graph, step_limit, input)
        .unwrap_or_else(|e| panic!("{label} projection input error: {e}"));
    let transcript = report["transcript"]
        .as_array()
        .expect("report transcript")
        .iter()
        .map(|entry| entry.as_str().expect("transcript string").to_string())
        .collect::<Vec<_>>();

    assert_eq!(projection.ok, report_out.ok, "{label} ok flag");
    assert_eq!(
        projection.status,
        report["status"].as_str().expect("report status"),
        "{label} status"
    );
    assert_eq!(projection.transcript, transcript, "{label} transcript");
    assert_eq!(
        projection.steps_used,
        report["steps"]["used"].as_u64().expect("steps.used") as usize,
        "{label} steps.used"
    );
    assert_eq!(
        projection.step_limit,
        report["steps"]["limit"].as_u64().expect("steps.limit") as usize,
        "{label} steps.limit"
    );
    assert_eq!(projection.fault, report["fault"], "{label} fault");
}

#[test]
fn meaning_env_receipt_projection_matches_report_receipt_fields() {
    let ok_graph = read_rel("meaning-env/cases/define-ref.json");
    assert_projection_matches_report_fields(
        &ok_graph,
        MEANING_ENV_DEFAULT_STEP_LIMIT,
        None,
        "ok graph",
    );

    let fault_graph = lowered_graph_bytes("(+ 1 #t)\n");
    assert_projection_matches_report_fields(
        &fault_graph,
        MEANING_ENV_DEFAULT_STEP_LIMIT,
        None,
        "domain fault",
    );

    let step_graph = lowered_graph_bytes("(define (loop n) (loop (+ n 1))) (loop 0)\n");
    assert_projection_matches_report_fields(&step_graph, 16, None, "step limit fault");

    let input_graph = lowered_graph_bytes(r#"(if (>= (car input) 18) "adult" "minor")"#);
    let input = canonical_datum_parse("(20)").expect("canonical input datum");
    assert_projection_matches_report_fields(&input_graph, 1000, Some(input), "input-bound graph");
}

#[test]
fn meaning_env_faults_are_structured_reports() {
    let manifest = read_json_rel("meaning-env/faults.json");
    for entry in manifest["faults"].as_array().expect("fault list") {
        let case = entry["case"].as_str().expect("case string");
        let expected_kind = entry["kind"].as_str().expect("kind string");
        let graph = read_rel(&format!("meaning-env/faults/{case}"));
        let out = eval_graph_json_report(&graph, MEANING_ENV_DEFAULT_STEP_LIMIT)
            .unwrap_or_else(|e| panic!("{case} input error: {e}"));
        assert!(!out.ok, "{case} should fault");
        let report: JsonValue = serde_json::from_slice(&out.report).expect("report JSON");
        assert_eq!(report["status"], "fault", "{case} status");
        assert_eq!(report["fault"]["kind"], expected_kind, "{case} fault kind");
        assert!(report["law_errors"]
            .as_array()
            .expect("law errors")
            .is_empty());
    }
}

#[test]
fn profile_control_and_arithmetic_eval_in_meaning_environment() {
    let report = lowered_report("(if (< (+ 1 2) 4) (/ 9 3) 0)\n");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["result"]["values"], serde_json::json!(["3"]));
}

#[test]
fn profile_string_and_list_intrinsics_eval_in_meaning_environment() {
    let report = lowered_report(
        "(string<? \"a\" \"b\")\n(length (list 1 2 3))\n(equal? (cons 1 '()) (list 1))\n",
    );
    assert_eq!(report["status"], "ok");
    assert_eq!(report["transcript"], serde_json::json!(["#t", "3", "#t"]));
    assert_eq!(report["result"]["values"], serde_json::json!(["#t"]));
}

#[test]
fn profile_closures_and_recursive_define_eval_in_meaning_environment() {
    let report = lowered_report(
        "(define add10 (let ((x 10)) (lambda (y) (+ x y))))\n(add10 5)\n\
         (define fact (lambda (n) (if (= n 0) 1 (* n (fact (- n 1))))))\n(fact 5)\n",
    );
    assert_eq!(report["status"], "ok");
    assert_eq!(report["transcript"], serde_json::json!(["15", "120"]));
    assert_eq!(report["result"]["values"], serde_json::json!(["120"]));
}

#[test]
fn top_level_closure_transcript_matches_reference_procedure_marker() {
    let report = lowered_report("(lambda (n) n)\n");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["transcript"], serde_json::json!(["#<procedure>"]));
    assert_eq!(
        report["result"]["values"],
        serde_json::json!(["#<procedure>"])
    );
}

#[test]
fn profile_traversal_intrinsics_eval_in_meaning_environment() {
    let report = lowered_report(
        "(map (lambda (x) (+ x 1)) '(1 2 3))\n\
         (filter (lambda (x) (> x 1)) '(1 2 3))\n\
         (reduce (lambda (acc x) (+ acc x)) 0 '(1 2 3))\n\
         (fold-left (lambda (acc x) (cons x acc)) '() '(1 2))\n\
         (fold-right (lambda (x acc) (cons x acc)) '() '(1 2))\n\
         (list? '(1 2))\n\
         (string? \"x\")\n",
    );
    assert_eq!(report["status"], "ok");
    assert_eq!(
        report["transcript"],
        serde_json::json!(["(2 3 4)", "(2 3)", "6", "(2 1)", "(1 2)", "#t", "#t"])
    );
    assert_eq!(report["result"]["values"], serde_json::json!(["#t"]));
}

#[test]
fn profile_apply_intrinsic_eval_in_meaning_environment() {
    let report = lowered_report(
        "(list (apply + '(1 2 3))\n\
               (apply + 1 2 '(3 4))\n\
               (apply (lambda (x y) (* x y)) '(6 7))\n\
               (apply list 1 '(2 3)))\n",
    );
    assert_eq!(report["status"], "ok");
    assert_eq!(
        report["transcript"],
        serde_json::json!(["(6 10 42 (1 2 3))"])
    );
    assert_eq!(
        report["result"]["values"],
        serde_json::json!(["(6 10 42 (1 2 3))"])
    );
}

#[test]
fn profile_apply_intrinsic_faults_are_structured() {
    let arity = lowered_report("(apply +)\n");
    assert_eq!(arity["status"], "fault");
    assert_eq!(arity["fault"]["kind"], "arity");

    let final_list = lowered_report("(apply + 1 2)\n");
    assert_eq!(final_list["status"], "fault");
    assert_eq!(final_list["fault"]["kind"], "intrinsic-domain");

    let non_callable = lowered_report("(apply 5 '(1 2))\n");
    assert_eq!(non_callable["status"], "fault");
    assert_eq!(non_callable["fault"]["kind"], "non-callable");
}

#[test]
fn profile_values_and_call_with_values_eval_in_meaning_environment() {
    let report = lowered_report(
        "(values 1 2)\n\
         (call-with-values (lambda () (values 1 2 3)) list)\n\
         (call-with-values (lambda () (values)) (lambda () 'done))\n\
         (call-with-values (lambda () (values 5)) values)\n",
    );
    assert_eq!(report["status"], "ok");
    assert_eq!(
        report["transcript"],
        serde_json::json!(["1", "2", "(1 2 3)", "done", "5"])
    );
    assert_eq!(report["result"]["values"], serde_json::json!(["5"]));
}

#[test]
fn profile_values_and_call_with_values_faults_are_structured() {
    let arity = lowered_report("(call-with-values (lambda () 1))\n");
    assert_eq!(arity["status"], "fault");
    assert_eq!(arity["fault"]["kind"], "arity");

    let producer = lowered_report("(call-with-values 1 list)\n");
    assert_eq!(producer["status"], "fault");
    assert_eq!(producer["fault"]["kind"], "non-callable");

    let single_value_context = lowered_report("(+ (values 1 2) 3)\n");
    assert_eq!(single_value_context["status"], "fault");
    assert_eq!(single_value_context["fault"]["kind"], "intrinsic-domain");
}

#[test]
fn profile_division_by_zero_is_a_deterministic_fault() {
    let report = lowered_report("(/ 1 0)\n");
    assert_eq!(report["status"], "fault");
    assert_eq!(report["fault"]["kind"], "division-by-zero");
}

#[test]
fn profile_arithmetic_rejects_inexact_numbers() {
    let report = lowered_report("(+ 1.0 2)\n");
    assert_eq!(report["status"], "fault");
    assert_eq!(report["fault"]["kind"], "intrinsic-domain");
}

#[test]
fn profile_modulo_eval_in_meaning_environment() {
    let report = lowered_report("(modulo 10 3)\n(modulo -10 3)\n");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["transcript"], serde_json::json!(["1", "2"]));
    assert_eq!(report["result"]["values"], serde_json::json!(["2"]));
}

#[test]
fn profile_string_append_and_number_to_string_eval_in_meaning_environment() {
    let report = lowered_report(
        "(string-append \"High score: \" (number->string 8))\n\
         (number->string 15 16)\n",
    );
    assert_eq!(report["status"], "ok");
    assert_eq!(
        report["transcript"],
        serde_json::json!(["\"High score: 8\"", "\"f\""])
    );
    assert_eq!(report["result"]["values"], serde_json::json!(["\"f\""]));
}

#[test]
fn law_error_path_emits_a_report_instead_of_executing() {
    let graph = br#"{"meaning_graph":"csk.meaning-graph/v0","nodes":[],"roots":[]}"#;
    let out = eval_graph_json_report(graph, MEANING_ENV_DEFAULT_STEP_LIMIT)
        .expect("law-invalid graph is still valid JSON input");
    assert!(!out.ok);
    let report: JsonValue = serde_json::from_slice(&out.report).expect("report JSON");
    assert_eq!(report["status"], "law-error");
    assert_eq!(report["result"], JsonValue::Null);
    assert!(report["trace"].as_array().expect("trace").is_empty());
    let rules = report["law_errors"]
        .as_array()
        .expect("law errors")
        .iter()
        .map(|error| error["rule"].as_str().expect("rule"))
        .collect::<Vec<_>>();
    assert!(rules.contains(&"roots-non-empty"), "rules: {rules:?}");
}

#[test]
fn rust_meaning_law_validator_matches_invalid_fixture_rule_ids() {
    let invalid_dir = repo_root().join("meaning-graph/fixtures/invalid");
    let mut files = std::fs::read_dir(&invalid_dir)
        .expect("invalid fixtures")
        .map(|entry| entry.expect("entry").path())
        .collect::<Vec<_>>();
    files.sort();
    assert_eq!(files.len(), 15, "expected the v1.2.5 invalid fixture set");
    for file in files {
        let fixture: JsonValue =
            serde_json::from_slice(&std::fs::read(&file).expect("read fixture"))
                .unwrap_or_else(|e| panic!("parse {}: {e}", file.display()));
        let expected = fixture["expected_error"]
            .as_str()
            .unwrap_or_else(|| panic!("{} missing expected_error", file.display()));
        let errors = validate_graph_value(&fixture["graph"]);
        let rules = errors.iter().map(|e| e.rule()).collect::<Vec<_>>();
        assert!(
            rules.contains(&expected),
            "{} expected {expected}, got {rules:?}",
            file.display()
        );
    }
}

#[test]
fn strict_canonical_datum_parser_rejects_non_canonical_spellings() {
    assert!(canonical_datum_parse("(1 . ())").is_err());
    assert!(canonical_datum_parse("2/4").is_err());
    assert!(canonical_datum_parse("#<procedure>").is_err());
    assert_eq!(
        canonical_datum_parse("#(1 2)").unwrap().write_repr(),
        "#(1 2)"
    );
}

#[test]
fn non_canonical_graph_is_a_reported_fault_not_an_input_error() {
    let compact = br#"{"meaning_graph":"csk.meaning-graph/v0","nodes":[{"kind":"lit","datum":"1","anchor":{"line":1,"col":1}},{"kind":"block","body":[0]}],"roots":[1]}"#;
    let out = eval_graph_json_report(compact, MEANING_ENV_DEFAULT_STEP_LIMIT)
        .expect("compact graph is valid JSON");
    assert!(!out.ok);
    let report: JsonValue = serde_json::from_slice(&out.report).expect("report JSON");
    assert_eq!(report["status"], "fault");
    assert_eq!(report["fault"]["kind"], "non-canonical-graph");
}

#[test]
fn small_step_limit_faults_with_report() {
    let graph = read_rel("meaning-env/cases/literal.json");
    let out = eval_graph_json_report(&graph, 1).expect("valid graph input");
    assert!(!out.ok);
    let report: JsonValue = serde_json::from_slice(&out.report).expect("report JSON");
    assert_eq!(report["status"], "fault");
    assert_eq!(report["fault"]["kind"], "step-limit");
    assert_eq!(report["steps"]["limit"], 1);
}

#[test]
fn lowered_subset_can_flow_into_meaning_environment_without_equivalence_claim() {
    for src in [
        "meaning-graph/lowering/cases/literal.lspx",
        "meaning-graph/lowering/cases/define-ref.lspx",
    ] {
        let text = String::from_utf8(read_rel(src)).expect("UTF-8 source");
        let program = read_program(&text, src).unwrap_or_else(|e| panic!("read {src}: {e}"));
        let core = normalize_program(&program.datums, src)
            .unwrap_or_else(|e| panic!("normalize {src}: {e}"));
        let graph = lispex::graph_json_bytes(
            &lispex::lower_meaning_graph_program(&core)
                .unwrap_or_else(|e| panic!("lower {src}: {e}")),
        );
        let out = eval_graph_json_report(&graph, MEANING_ENV_DEFAULT_STEP_LIMIT)
            .unwrap_or_else(|e| panic!("eval {src}: {e}"));
        assert!(out.ok, "{src} lower | eval-graph should be ok");
        let report: JsonValue = serde_json::from_slice(&out.report).expect("report JSON");
        assert_eq!(report["status"], "ok");
    }
}
