#![cfg(feature = "scored-native-contract")]

use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use lispex::vouch_native::canonical_value::{domain_hash, CanonicalValue};
use lispex::vouch_native::checked_input::{CheckedInput, MAX_INPUT_BYTES};
use lispex::vouch_native::checked_profile::{prepare_checked_program, CHECKED_PROFILE_TAG};
use lispex::vouch_native::graph::{
    contract_graph_bytes, contract_graph_digest, lower_contract_graph, ContractGraph, ContractNode,
};
use lispex::vouch_native::receipt::{
    BuildVariant, ByteIdentity, CanonicalProgramIdentity, Comparison, ComparisonStatus,
    DifferentialReceipt, EngineIdentity, ExecutionIdentity, GraphReceiptValue, InputIdentity,
    MeaningEnvReport, TraceReport,
};
use lispex::vouch_native::structural_verify::{
    verify_structure, StructuralContext, StructuralError, BOUNDARY_STATEMENT,
};
use lispex::vouch_native::transcript::{
    EvaluationPhase, InfrastructureFailureCode, Terminal, Transcript, TranscriptEvent,
};
use lispex::Decision;
use vouch::artifact_json::{write_canonical, JsonValue, MAX_ARTIFACT_BYTES};
use vouch::dsse::encode_base64;

const SOURCE: &[u8] =
    b"(define threshold 10)\n(if (< (car input) threshold) (decision-approve) (decision-review))\n";
const INPUT: &[u8] = b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": [\n    7\n  ]\n}\n";

fn fixture() -> DifferentialReceipt {
    let program = prepare_checked_program(SOURCE).unwrap();
    let input = CheckedInput::parse(INPUT).unwrap();
    let graph = lower_contract_graph(program.core()).unwrap();
    let transcript = Transcript {
        events: vec![
            TranscriptEvent::Value {
                form_index: 0,
                value: CanonicalValue::Void,
            },
            TranscriptEvent::Value {
                form_index: 1,
                value: CanonicalValue::Decision(Decision::Approve),
            },
        ],
        terminal: Terminal::Completed,
    };
    let transcript_bytes = transcript.canonical_bytes().unwrap();
    let executable_sha256 = format!("sha256:{}", "1".repeat(64));
    let normalized_bytes = program.normalized_bytes().to_vec();
    let context = JsonValue::object([
        (
            "normalized_bytes_b64",
            JsonValue::String(encode_base64(&normalized_bytes)),
        ),
        (
            "input_canonical_value_sha256",
            JsonValue::String(input.canonical_value_digest().to_string()),
        ),
        (
            "profile",
            JsonValue::String(CHECKED_PROFILE_TAG.to_string()),
        ),
        (
            "engine_executable_sha256",
            JsonValue::String(executable_sha256.clone()),
        ),
    ])
    .unwrap();
    let context_digest = domain_hash(
        "csk.v0.execution-context",
        &write_canonical(&context).unwrap(),
    );
    DifferentialReceipt {
        engine: EngineIdentity {
            executable_sha256: executable_sha256.clone(),
            target_triple: "aarch64-apple-darwin".to_string(),
        },
        execution: ExecutionIdentity {
            context_digest,
            lispex_version: "1.4.0".to_string(),
            build_commit: "2".repeat(40),
            build_variant: BuildVariant::Release,
            mutant_id: None,
            target_triple: "aarch64-apple-darwin".to_string(),
            executable_sha256,
        },
        source: ByteIdentity {
            sha256: domain_hash("csk.v0.source", SOURCE),
            byte_length: SOURCE.len(),
        },
        input: InputIdentity {
            sha256: input.raw_digest().to_string(),
            byte_length: input.raw_byte_length(),
            canonical_value_sha256: input.canonical_value_digest().to_string(),
        },
        canonical: CanonicalProgramIdentity {
            normalized_sha256: domain_hash("csk.v0.canonical", &normalized_bytes),
            normalized_bytes,
        },
        graph: GraphReceiptValue {
            graph_sha256: contract_graph_digest(&graph).unwrap(),
            graph: graph.clone(),
        },
        reference: TraceReport {
            transcript_sha256: domain_hash("csk.v0.reference", &transcript_bytes),
            transcript: transcript.clone(),
        },
        meaning_env: MeaningEnvReport {
            graph_sha256: contract_graph_digest(&graph).unwrap(),
            transcript_sha256: domain_hash("csk.v0.meaning_env", &transcript_bytes),
            node_count: graph.nodes.len(),
            transcript,
        },
        comparison: Comparison {
            status: ComparisonStatus::Agree,
            first_divergence_index: None,
            comparison_unavailable_at: None,
        },
        diagnostics: vec![],
        boundary_statement_sha256: domain_hash("csk.v0.boundary", BOUNDARY_STATEMENT.as_bytes()),
    }
}

fn verify(receipt: &DifferentialReceipt) -> Result<(), StructuralError> {
    verify_structure(
        &receipt.canonical_bytes().unwrap(),
        StructuralContext {
            input: INPUT,
            source: Some(SOURCE),
            expected_profile: Some(CHECKED_PROFILE_TAG),
            release_signed: false,
        },
    )
    .map(|_| ())
}

fn refresh_graph(receipt: &mut DifferentialReceipt, graph: ContractGraph) {
    receipt.graph.graph_sha256 =
        domain_hash("csk.v0.graph", &contract_graph_bytes(&graph).unwrap());
    receipt.meaning_env.graph_sha256 = receipt.graph.graph_sha256.clone();
    receipt.meaning_env.node_count = graph.nodes.len();
    receipt.graph.graph = graph;
}

fn refresh_transcripts(receipt: &mut DifferentialReceipt) {
    receipt.reference.transcript_sha256 = domain_hash(
        "csk.v0.reference",
        &receipt.reference.transcript.canonical_bytes().unwrap(),
    );
    receipt.meaning_env.transcript_sha256 = domain_hash(
        "csk.v0.meaning_env",
        &receipt.meaning_env.transcript.canonical_bytes().unwrap(),
    );
}

#[test]
fn s3_structure_accepts_only_freshly_rederived_consistency() {
    assert!(verify(&fixture()).is_ok());

    let mut source_graph_mix = fixture();
    let other_program = prepare_checked_program(b"#t\n").unwrap();
    let other_graph = lower_contract_graph(other_program.core()).unwrap();
    refresh_graph(&mut source_graph_mix, other_graph);
    assert_eq!(
        verify(&source_graph_mix).unwrap_err().code(),
        "native-receipt-inconsistent"
    );

    let mut input_value_mix = fixture();
    let other_input = CheckedInput::parse(
        b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": [\n    8\n  ]\n}\n",
    )
    .unwrap();
    input_value_mix.input.canonical_value_sha256 = other_input.canonical_value_digest().to_string();
    assert_eq!(
        verify(&input_value_mix).unwrap_err().code(),
        "native-receipt-inconsistent"
    );

    let mut false_agree = fixture();
    let TranscriptEvent::Value { value, .. } = &mut false_agree.meaning_env.transcript.events[1]
    else {
        panic!("fixture event must be a value")
    };
    *value = CanonicalValue::Decision(Decision::Review);
    refresh_transcripts(&mut false_agree);
    assert_eq!(
        verify(&false_agree).unwrap_err().code(),
        "native-receipt-inconsistent"
    );

    let mut incomplete = fixture();
    incomplete.meaning_env.transcript.events.pop();
    refresh_transcripts(&mut incomplete);
    assert_eq!(
        verify(&incomplete).unwrap_err().code(),
        "native-receipt-inconsistent"
    );

    let mut early_decision = fixture();
    for transcript in [
        &mut early_decision.reference.transcript,
        &mut early_decision.meaning_env.transcript,
    ] {
        let TranscriptEvent::Value { value, .. } = &mut transcript.events[0] else {
            panic!("fixture event must be a value")
        };
        *value = CanonicalValue::Decision(Decision::Deny);
    }
    refresh_transcripts(&mut early_decision);
    assert_eq!(
        verify(&early_decision).unwrap_err().code(),
        "native-receipt-inconsistent"
    );

    let mut output_event = fixture();
    output_event.reference.transcript.events[0] = TranscriptEvent::Output {
        form_index: 0,
        bytes_b64: encode_base64(b"reserved"),
    };
    refresh_transcripts(&mut output_event);
    assert_eq!(
        verify(&output_event).unwrap_err().code(),
        "native-receipt-inconsistent"
    );
}

#[test]
fn s3_structure_freshly_derives_disagree_and_not_comparable_fields() {
    let mut disagree = fixture();
    let TranscriptEvent::Value { value, .. } = &mut disagree.meaning_env.transcript.events[1]
    else {
        panic!("fixture event must be a value")
    };
    *value = CanonicalValue::Decision(Decision::Review);
    disagree.comparison = Comparison {
        status: ComparisonStatus::Disagree,
        first_divergence_index: Some(1),
        comparison_unavailable_at: None,
    };
    refresh_transcripts(&mut disagree);
    assert!(verify(&disagree).is_ok());
    disagree.comparison.first_divergence_index = Some(0);
    assert_eq!(
        verify(&disagree).unwrap_err().code(),
        "native-receipt-inconsistent"
    );

    let mut unavailable = fixture();
    unavailable.meaning_env.transcript.events.pop();
    unavailable.meaning_env.transcript.terminal = Terminal::InfrastructureFailure {
        code: InfrastructureFailureCode::MeaningExecutionFailed,
        phase: EvaluationPhase::Meaning,
        next_form_index: 1,
    };
    unavailable.comparison = Comparison {
        status: ComparisonStatus::NotComparable,
        first_divergence_index: None,
        comparison_unavailable_at: Some(1),
    };
    refresh_transcripts(&mut unavailable);
    assert!(verify(&unavailable).is_ok());
    unavailable.comparison.comparison_unavailable_at = Some(0);
    assert_eq!(
        verify(&unavailable).unwrap_err().code(),
        "native-receipt-inconsistent"
    );
}

#[test]
fn s3_structure_rejects_zero_root_boundary_and_external_context_tampering() {
    let mut zero_root = fixture();
    let mut graph = zero_root.graph.graph.clone();
    graph.roots.clear();
    refresh_graph(&mut zero_root, graph);
    assert_eq!(
        verify(&zero_root).unwrap_err().code(),
        "native-receipt-inconsistent"
    );

    let mut boundary = fixture();
    boundary.boundary_statement_sha256 = "0".repeat(64);
    assert_eq!(
        verify(&boundary).unwrap_err().code(),
        "native-receipt-inconsistent"
    );

    let receipt = fixture();
    let wrong_input = b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": [\n    8\n  ]\n}\n";
    let error = verify_structure(
        &receipt.canonical_bytes().unwrap(),
        StructuralContext {
            input: wrong_input,
            source: Some(SOURCE),
            expected_profile: Some(CHECKED_PROFILE_TAG),
            release_signed: false,
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "native-input-mismatch");

    let error = verify_structure(
        &receipt.canonical_bytes().unwrap(),
        StructuralContext {
            input: INPUT,
            source: Some(b"#f\n"),
            expected_profile: Some(CHECKED_PROFILE_TAG),
            release_signed: false,
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "native-source-mismatch");

    let error = verify_structure(
        &receipt.canonical_bytes().unwrap(),
        StructuralContext {
            input: INPUT,
            source: None,
            expected_profile: Some("csk.checked-profile/v2"),
            release_signed: false,
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "native-profile-mismatch");
}

#[test]
fn s3_structure_rejects_malformed_graph_families_and_resource_precedence() {
    let mut unreachable = fixture();
    let mut graph = unreachable.graph.graph.clone();
    graph.nodes.push(ContractNode::Lit {
        value: CanonicalValue::Boolean(true),
    });
    refresh_graph(&mut unreachable, graph);
    assert_eq!(
        verify(&unreachable).unwrap_err().code(),
        "native-receipt-inconsistent"
    );

    let mut backward_cycle = fixture();
    let mut graph = backward_cycle.graph.graph.clone();
    let ContractNode::Define { value, .. } = &mut graph.nodes[0] else {
        panic!("first fixture root must be define")
    };
    *value = 0;
    refresh_graph(&mut backward_cycle, graph);
    assert_eq!(
        verify(&backward_cycle).unwrap_err().code(),
        "native-receipt-inconsistent"
    );

    let mut forward_reference = fixture();
    refresh_graph(
        &mut forward_reference,
        ContractGraph {
            roots: vec![0, 1],
            nodes: vec![
                ContractNode::Var {
                    name: "later".to_string(),
                },
                ContractNode::Define {
                    name: "later".to_string(),
                    value: 2,
                },
                ContractNode::Lit {
                    value: CanonicalValue::Integer("1".to_string()),
                },
            ],
        },
    );
    assert_eq!(
        verify(&forward_reference).unwrap_err().code(),
        "native-receipt-inconsistent"
    );

    let mut shared = fixture();
    refresh_graph(
        &mut shared,
        ContractGraph {
            roots: vec![0, 2],
            nodes: vec![
                ContractNode::Begin { forms: vec![1] },
                ContractNode::Lit {
                    value: CanonicalValue::Boolean(true),
                },
                ContractNode::Begin { forms: vec![1] },
            ],
        },
    );
    assert_eq!(
        verify(&shared).unwrap_err().code(),
        "native-receipt-inconsistent"
    );

    let receipt = fixture();
    let mut noncanonical = receipt.canonical_bytes().unwrap();
    noncanonical.pop();
    let error = verify_structure(
        &noncanonical,
        StructuralContext {
            input: INPUT,
            source: None,
            expected_profile: None,
            release_signed: false,
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "non-canonical-artifact-json");

    let oversized_input = vec![b'x'; MAX_INPUT_BYTES + 1];
    let oversized_receipt = vec![b'x'; MAX_ARTIFACT_BYTES + 1];
    let error = verify_structure(
        &oversized_receipt,
        StructuralContext {
            input: &oversized_input,
            source: None,
            expected_profile: None,
            release_signed: false,
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "artifact-resource-limit");
    assert_eq!(error.subject(), Some("payload-bytes"));

    let receipt_bytes = fixture().canonical_bytes().unwrap();
    let error = verify_structure(
        &receipt_bytes,
        StructuralContext {
            input: &oversized_input,
            source: None,
            expected_profile: None,
            release_signed: false,
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "artifact-resource-limit");
    assert_eq!(error.subject(), Some("input-bytes"));

    let mut oversized_integer = fixture();
    for transcript in [
        &mut oversized_integer.reference.transcript,
        &mut oversized_integer.meaning_env.transcript,
    ] {
        let TranscriptEvent::Value { value, .. } = &mut transcript.events[1] else {
            panic!("fixture event must be a value")
        };
        *value = CanonicalValue::Integer("9".repeat(4_097));
    }
    refresh_transcripts(&mut oversized_integer);
    let error = verify(&oversized_integer).unwrap_err();
    assert_eq!(error.code(), "artifact-resource-limit");
    assert_eq!(error.subject(), Some("integer-digits"));

    let mut malformed_oversized_integer = fixture();
    for transcript in [
        &mut malformed_oversized_integer.reference.transcript,
        &mut malformed_oversized_integer.meaning_env.transcript,
    ] {
        let TranscriptEvent::Value { value, .. } = &mut transcript.events[1] else {
            panic!("fixture event must be a value")
        };
        *value = CanonicalValue::Integer("x".repeat(4_097));
    }
    refresh_transcripts(&mut malformed_oversized_integer);
    assert_eq!(
        verify(&malformed_oversized_integer).unwrap_err().code(),
        "native-receipt-schema"
    );

    let mut mutant_without_id = fixture();
    mutant_without_id.execution.build_variant = BuildVariant::Mutant;
    assert_eq!(
        verify(&mutant_without_id).unwrap_err().code(),
        "native-receipt-inconsistent"
    );
}

#[test]
fn s3_structure_preserves_checked_input_error_classes_after_raw_binding() {
    for (bytes, expected) in [
        (&b"{\n"[..], "native-input-parse-failed"),
        (&b"{}\n"[..], "native-input-profile-invalid"),
    ] {
        let mut receipt = fixture();
        receipt.input.sha256 = domain_hash("csk.v0.input", bytes);
        receipt.input.byte_length = bytes.len();
        let error = verify_structure(
            &receipt.canonical_bytes().unwrap(),
            StructuralContext {
                input: bytes,
                source: None,
                expected_profile: None,
                release_signed: false,
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), expected);
    }
}

#[test]
fn s3_cli_is_feature_gated_and_emits_only_structural_status() {
    let root = std::env::temp_dir().join(format!(
        "lispex-scored-stage3-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let receipt_path = root.join("receipt.json");
    let input_path = root.join("input.json");
    let source_path = root.join("source.lspx");
    let report_path = root.join("report.json");
    fs::write(&receipt_path, fixture().canonical_bytes().unwrap()).unwrap();
    fs::write(&input_path, INPUT).unwrap();
    fs::write(&source_path, SOURCE).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_lispex"))
        .args([
            "verify-structure",
            "--receipt",
            receipt_path.to_str().unwrap(),
            "--input",
            input_path.to_str().unwrap(),
            "--report-out",
            report_path.to_str().unwrap(),
            "--source",
            source_path.to_str().unwrap(),
            "--profile",
            CHECKED_PROFILE_TAG,
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let report = fs::read_to_string(&report_path).unwrap();
    assert!(report.contains("structurally-consistent"));
    assert!(!report.contains("native"));
    assert!(!report.contains("authenticated-native"));
    assert!(!report.contains("trusted-native"));

    fs::write(
        &input_path,
        b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": [\n    8\n  ]\n}\n",
    )
    .unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_lispex"))
        .args([
            "verify-structure",
            "--receipt",
            receipt_path.to_str().unwrap(),
            "--input",
            input_path.to_str().unwrap(),
            "--report-out",
            report_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert_eq!(rejected.code(), Some(1));
    assert!(fs::read_to_string(&report_path)
        .unwrap()
        .contains("native-input-mismatch"));
    fs::write(&input_path, INPUT).unwrap();

    let usage = Command::new(env!("CARGO_BIN_EXE_lispex"))
        .args([
            "verify-structure",
            "--receipt",
            receipt_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert_eq!(usage.code(), Some(2));

    let duplicate = Command::new(env!("CARGO_BIN_EXE_lispex"))
        .args([
            "verify-structure",
            "--receipt",
            receipt_path.to_str().unwrap(),
            "--input",
            input_path.to_str().unwrap(),
            "--input",
            input_path.to_str().unwrap(),
            "--report-out",
            report_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert_eq!(duplicate.code(), Some(2));

    let missing_receipt = root.join("missing.json");
    let io_failure = Command::new(env!("CARGO_BIN_EXE_lispex"))
        .args([
            "verify-structure",
            "--receipt",
            missing_receipt.to_str().unwrap(),
            "--input",
            input_path.to_str().unwrap(),
            "--report-out",
            report_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert_eq!(io_failure.code(), Some(3));

    let output_failure = Command::new(env!("CARGO_BIN_EXE_lispex"))
        .args([
            "verify-structure",
            "--receipt",
            receipt_path.to_str().unwrap(),
            "--input",
            input_path.to_str().unwrap(),
            "--report-out",
            root.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert_eq!(output_failure.code(), Some(3));
    fs::remove_dir_all(root).unwrap();
}
