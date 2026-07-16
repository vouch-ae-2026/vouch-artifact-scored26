#![cfg(feature = "scored-native-contract")]

use lispex::vouch_native::workload::{evaluate_workload_case, CaseOutcome};
use lispex::vouch_native::{checked_profile::prepare_checked_program, graph::lower_contract_graph};
use lispex::Decision;
use vouch::artifact_json::{canonical_gate, write_canonical, JsonValue, RawArtifactKind};

fn artifact(path: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(path),
    )
    .unwrap()
}

#[test]
fn every_frozen_development_case_is_a_closed_decision_on_both_rules() {
    let baseline = artifact("artifact/workload/rules/baseline.lspx");
    let changed = artifact("artifact/workload/rules/changed.lspx");
    for source in [&baseline, &changed] {
        let program = prepare_checked_program(source).expect("frozen rule must be checked-profile");
        lower_contract_graph(program.core()).expect("frozen rule must lower to contract graph");
    }
    let split = artifact("artifact/workload/workload-split.json");
    let split = canonical_gate(&split, RawArtifactKind::Artifact).unwrap();
    let root = split.value().as_object().unwrap();
    let cases = root.get("cases").unwrap().as_array().unwrap();
    assert_eq!(cases.len(), 240);
    let mut executions = 0;
    for case in cases {
        let case = case.as_object().unwrap();
        if case.get("partition").unwrap().as_str().unwrap() != "development" {
            continue;
        }
        let class = case.get("candidate_class").unwrap().as_str().unwrap();
        let input = write_canonical(case.get("input").unwrap()).unwrap();
        for source in [&baseline, &changed] {
            let observation = evaluate_workload_case(source, &input);
            match observation.outcome {
                CaseOutcome::Decision(Decision::InvalidInput) if class == "invalid" => {}
                CaseOutcome::Decision(Decision::Approve | Decision::Deny | Decision::Review)
                    if class != "invalid" => {}
                other => panic!("{class} produced {other:?}"),
            }
            assert!(!observation.coverage.covered_nodes.is_empty());
            assert!(!observation.coverage.total_nodes.is_empty());
            executions += 1;
        }
    }
    assert_eq!(executions, 384);
}

#[test]
fn seven_application_invalid_transformations_are_host_valid_and_invalid_input() {
    let source = artifact("artifact/workload/rules/baseline.lspx");
    let rational = JsonValue::object([(
        "$rat",
        JsonValue::object([
            ("d", JsonValue::String("2".to_string())),
            ("n", JsonValue::String("1".to_string())),
        ])
        .unwrap(),
    )])
    .unwrap();
    let values = vec![
        JsonValue::Array(vec![
            JsonValue::Integer(2025),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
        ]),
        JsonValue::Array(vec![
            JsonValue::Integer(2025),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
        ]),
        JsonValue::Array(vec![
            rational.clone(),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
        ]),
        JsonValue::Array(vec![
            JsonValue::Integer(2025),
            rational,
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
        ]),
        JsonValue::Array(vec![
            JsonValue::Integer(2025),
            JsonValue::Integer(0),
            JsonValue::Integer(3),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
        ]),
        JsonValue::Array(vec![
            JsonValue::Integer(2025),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(2),
            JsonValue::Integer(0),
        ]),
        JsonValue::Array(vec![
            JsonValue::Integer(2025),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(-1),
        ]),
    ];
    for value in values {
        let input = write_canonical(
            &JsonValue::object([
                (
                    "input",
                    JsonValue::String("csk.checked-input/v1".to_string()),
                ),
                ("value", value),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            evaluate_workload_case(&source, &input).outcome,
            CaseOutcome::Decision(Decision::InvalidInput)
        );
    }
}

#[test]
fn every_noninteger_host_type_is_rejected_at_every_application_position() {
    let sources = [
        artifact("artifact/workload/rules/baseline.lspx"),
        artifact("artifact/workload/rules/changed.lspx"),
    ];
    let rational = JsonValue::object([(
        "$rat",
        JsonValue::object([
            ("d", JsonValue::String("2".to_string())),
            ("n", JsonValue::String("1".to_string())),
        ])
        .unwrap(),
    )])
    .unwrap();
    let real = JsonValue::object([("$real", JsonValue::String("1.5".to_string()))]).unwrap();
    let integral_real =
        JsonValue::object([("$real", JsonValue::String("3.0".to_string()))]).unwrap();
    let symbol =
        JsonValue::object([("$sym", JsonValue::String("wrong-kind".to_string()))]).unwrap();
    let wrong_types = [
        JsonValue::Bool(true),
        JsonValue::String("wrong-kind".to_string()),
        JsonValue::Array(Vec::new()),
        rational,
        real,
        integral_real,
        symbol,
    ];
    let base = [
        JsonValue::Integer(2025),
        JsonValue::Integer(0),
        JsonValue::Integer(0),
        JsonValue::Integer(0),
        JsonValue::Integer(100_000),
    ];
    let mut executions = 0;
    for position in 0..base.len() {
        for wrong in &wrong_types {
            let mut value = base.to_vec();
            value[position] = wrong.clone();
            let input = checked_input(JsonValue::Array(value));
            for source in &sources {
                assert_eq!(
                    evaluate_workload_case(source, &input).outcome,
                    CaseOutcome::Decision(Decision::InvalidInput),
                    "position {position} accepted {wrong:?}"
                );
                executions += 1;
            }
        }
    }
    assert_eq!(executions, 70);
}

#[test]
fn every_arity_category_and_range_rejection_class_returns_invalid_input() {
    let sources = [
        artifact("artifact/workload/rules/baseline.lspx"),
        artifact("artifact/workload/rules/changed.lspx"),
    ];
    let invalid = [
        Vec::new(),
        vec![
            JsonValue::Integer(2025),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
        ],
        vec![
            JsonValue::Integer(2025),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
            JsonValue::Integer(0),
        ],
        integer_values([2024, 0, 0, 0, 0]),
        integer_values([2025, 4, 0, 0, 0]),
        integer_values([2025, 0, 3, 0, 0]),
        integer_values([2025, 0, 0, 2, 0]),
        integer_values([2025, 0, 0, 0, -1]),
        integer_values([2025, 0, 0, 0, 1_000_001]),
    ];
    let mut executions = 0;
    for value in invalid {
        let input = checked_input(JsonValue::Array(value));
        for source in &sources {
            assert_eq!(
                evaluate_workload_case(source, &input).outcome,
                CaseOutcome::Decision(Decision::InvalidInput)
            );
            executions += 1;
        }
    }
    assert_eq!(executions, 18);
}

#[test]
fn every_frozen_invalid_candidate_executes_to_invalid_input_on_both_rules() {
    let sources = [
        artifact("artifact/workload/rules/baseline.lspx"),
        artifact("artifact/workload/rules/changed.lspx"),
    ];
    let candidates = artifact("artifact/workload/workload-candidates.json");
    let candidates = canonical_gate(&candidates, RawArtifactKind::Artifact).unwrap();
    let rows = candidates
        .value()
        .as_object()
        .unwrap()
        .get("candidates")
        .unwrap()
        .as_array()
        .unwrap();
    let invalid = rows
        .iter()
        .filter(|row| {
            row.as_object()
                .unwrap()
                .get("candidate_class")
                .unwrap()
                .as_str()
                .unwrap()
                == "invalid"
        })
        .collect::<Vec<_>>();
    assert_eq!(invalid.len(), 336);
    let mut executions = 0;
    for row in invalid {
        let row = row.as_object().unwrap();
        let input = write_canonical(row.get("input").unwrap()).unwrap();
        for source in &sources {
            assert_eq!(
                evaluate_workload_case(source, &input).outcome,
                CaseOutcome::Decision(Decision::InvalidInput),
                "{} did not reject",
                row.get("case_id").unwrap().as_str().unwrap()
            );
            executions += 1;
        }
    }
    assert_eq!(executions, 672);
}

fn checked_input(value: JsonValue) -> Vec<u8> {
    write_canonical(
        &JsonValue::object([
            (
                "input",
                JsonValue::String("csk.checked-input/v1".to_string()),
            ),
            ("value", value),
        ])
        .unwrap(),
    )
    .unwrap()
}

fn integer_values<const N: usize>(values: [i64; N]) -> Vec<JsonValue> {
    values.into_iter().map(JsonValue::Integer).collect()
}
