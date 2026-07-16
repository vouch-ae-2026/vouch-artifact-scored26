#![cfg(feature = "scored-native-contract")]

use ed25519_dalek::SigningKey;
use lispex::vouch_native::canonical_value::{domain_hash, CanonicalValue};
use lispex::vouch_native::checked_input::CheckedInput;
use lispex::vouch_native::checked_profile::{prepare_checked_program, CHECKED_PROFILE_TAG};
use lispex::vouch_native::graph::{contract_graph_digest, lower_contract_graph};
use lispex::vouch_native::receipt::{
    BuildVariant, ByteIdentity, CanonicalProgramIdentity, Comparison, ComparisonStatus,
    DifferentialReceipt, EngineIdentity, ExecutionIdentity, GraphReceiptValue, InputIdentity,
    MeaningEnvReport, TraceReport,
};
use lispex::vouch_native::structural_verify::BOUNDARY_STATEMENT;
use lispex::vouch_native::transcript::{
    EvaluationPhase, InfrastructureFailureCode, LanguageFaultCode, Terminal, Transcript,
    TranscriptEvent,
};
use lispex::vouch_native::verify::{
    verify_native, NativeVerificationError, PromotionIneligibility,
};
use lispex::Decision;
use std::process::Command;
use vouch::artifact_json::{canonical_gate, write_canonical, JsonValue, RawArtifactKind};
use vouch::dsse::{
    encode_base64, native_key_id, sign_envelope, Envelope, PayloadType, NATIVE_PAYLOAD_TYPE,
};

const SOURCE: &[u8] = b"(if (< input 10) (decision-approve) (decision-review))\n";
const INPUT: &[u8] = b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": 7\n}\n";
const ENGINE: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn receipt() -> DifferentialReceipt {
    let program = prepare_checked_program(SOURCE).unwrap();
    let input = CheckedInput::parse(INPUT).unwrap();
    let graph = lower_contract_graph(program.core()).unwrap();
    let transcript = Transcript {
        events: vec![TranscriptEvent::Value {
            form_index: 0,
            value: CanonicalValue::Decision(Decision::Approve),
        }],
        terminal: Terminal::Completed,
    };
    let transcript_bytes = transcript.canonical_bytes().unwrap();
    let context = JsonValue::object([
        (
            "normalized_bytes_b64",
            JsonValue::String(encode_base64(program.normalized_bytes())),
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
            JsonValue::String(ENGINE.to_string()),
        ),
    ])
    .unwrap();
    DifferentialReceipt {
        engine: EngineIdentity {
            executable_sha256: ENGINE.to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
        },
        execution: ExecutionIdentity {
            context_digest: domain_hash(
                "csk.v0.execution-context",
                &write_canonical(&context).unwrap(),
            ),
            lispex_version: "1.4.0".to_string(),
            build_commit: "2".repeat(40),
            build_variant: BuildVariant::Release,
            mutant_id: None,
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            executable_sha256: ENGINE.to_string(),
        },
        source: ByteIdentity {
            sha256: domain_hash("csk.v0.source", SOURCE),
            byte_length: SOURCE.len(),
        },
        input: InputIdentity {
            sha256: input.raw_digest().to_string(),
            byte_length: INPUT.len(),
            canonical_value_sha256: input.canonical_value_digest().to_string(),
        },
        canonical: CanonicalProgramIdentity {
            normalized_sha256: domain_hash("csk.v0.canonical", program.normalized_bytes()),
            normalized_bytes: program.normalized_bytes().to_vec(),
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

fn policy(keys: &[(&SigningKey, &[&str], &[&str])]) -> Vec<u8> {
    policy_with_minimum(keys, 0)
}

fn policy_with_minimum(keys: &[(&SigningKey, &[&str], &[&str])], native_minimum: i64) -> Vec<u8> {
    let keys = keys
        .iter()
        .map(|(key, profiles, engines)| {
            let public = key.verifying_key().to_bytes();
            JsonValue::object([
                ("key_id", JsonValue::String(native_key_id(&public))),
                ("algorithm", JsonValue::String("ed25519".to_string())),
                ("public_key", JsonValue::String(encode_base64(&public))),
                (
                    "allowed_payload_types",
                    JsonValue::Array(vec![JsonValue::String(NATIVE_PAYLOAD_TYPE.to_string())]),
                ),
                (
                    "allowed_profiles",
                    JsonValue::Array(
                        profiles
                            .iter()
                            .map(|profile| JsonValue::String((*profile).to_string()))
                            .collect(),
                    ),
                ),
                (
                    "allowed_engine_sha256",
                    JsonValue::Array(
                        engines
                            .iter()
                            .map(|engine| JsonValue::String((*engine).to_string()))
                            .collect(),
                    ),
                ),
            ])
            .unwrap()
        })
        .collect();
    write_canonical(
        &JsonValue::object([
            (
                "trust_policy",
                JsonValue::String("csk.native-trust-policy/v0".to_string()),
            ),
            (
                "minimum_versions",
                JsonValue::object([
                    ("native_receipt", JsonValue::Integer(native_minimum)),
                    ("release_descriptor", JsonValue::Integer(0)),
                    ("replay_corpus_manifest", JsonValue::Integer(0)),
                    ("reproduction_observation", JsonValue::Integer(0)),
                ])
                .unwrap(),
            ),
            ("keys", JsonValue::Array(keys)),
        ])
        .unwrap(),
    )
    .unwrap()
}

fn signed(receipt: &DifferentialReceipt, key: &SigningKey) -> Vec<u8> {
    let payload = receipt.canonical_bytes().unwrap();
    signed_payload(&payload, key)
}

fn signed_payload(payload: &[u8], key: &SigningKey) -> Vec<u8> {
    let canonical = canonical_gate(payload, RawArtifactKind::Payload).unwrap();
    sign_envelope(
        PayloadType::NativeReceipt,
        &canonical,
        key,
        &native_key_id(&key.verifying_key().to_bytes()),
    )
    .canonical_bytes()
    .unwrap()
}

fn verify_with(
    envelope: &[u8],
    policy: &[u8],
    profile: &str,
    source: &[u8],
    input: &[u8],
) -> Result<lispex::vouch_native::verify::AuthenticatedNativeEvidence, NativeVerificationError> {
    verify_native(envelope, policy, profile, source, input)
}

#[test]
fn s5_valid_envelope_mints_evidence_then_promotes_eligibility() {
    let key = SigningKey::from_bytes(&[3_u8; 32]);
    let policy = policy(&[(&key, &[CHECKED_PROFILE_TAG], &[ENGINE])]);
    let evidence = verify_with(
        &signed(&receipt(), &key),
        &policy,
        CHECKED_PROFILE_TAG,
        SOURCE,
        INPUT,
    )
    .unwrap();
    assert_eq!(evidence.promotion_ineligibility(), None);
    assert!(String::from_utf8(evidence.report().canonical_bytes())
        .unwrap()
        .contains("\"authentication_status\": \"authenticated\""));
}

#[test]
fn s5_raw_native_and_bridge_artifacts_have_no_attestation() {
    let key = SigningKey::from_bytes(&[4_u8; 32]);
    let policy = policy(&[(&key, &[CHECKED_PROFILE_TAG], &[ENGINE])]);
    for bytes in [
        receipt().canonical_bytes().unwrap(),
        write_canonical(
            &JsonValue::object([(
                "bridge_report",
                JsonValue::String("vouch.bridge-report/v0".to_string()),
            )])
            .unwrap(),
        )
        .unwrap(),
    ] {
        assert_eq!(
            verify_with(&bytes, &policy, CHECKED_PROFILE_TAG, SOURCE, INPUT).unwrap_err(),
            NativeVerificationError::MissingNativeAttestation
        );
    }
}

#[test]
fn s5_signed_schema_invalid_payload_is_not_misreported_as_inconsistent() {
    let key = SigningKey::from_bytes(&[8_u8; 32]);
    let policy = policy(&[(&key, &[CHECKED_PROFILE_TAG], &[ENGINE])]);
    let invalid = write_canonical(
        &JsonValue::object([(
            "differential_receipt",
            JsonValue::String("csk.differential-receipt/v0".to_string()),
        )])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        verify_with(
            &signed_payload(&invalid, &key),
            &policy,
            CHECKED_PROFILE_TAG,
            SOURCE,
            INPUT,
        )
        .unwrap_err(),
        NativeVerificationError::NativeReceiptSchema
    );
}

#[test]
fn s5_version_handling_checks_unknown_before_policy_floor() {
    let key = SigningKey::from_bytes(&[10_u8; 32]);
    let policy = policy(&[(&key, &[CHECKED_PROFILE_TAG], &[ENGINE])]);
    let v1 = String::from_utf8(receipt().canonical_bytes().unwrap())
        .unwrap()
        .replace("csk.differential-receipt/v0", "csk.differential-receipt/v1")
        .into_bytes();
    assert_eq!(
        verify_with(
            &signed_payload(&v1, &key),
            &policy,
            CHECKED_PROFILE_TAG,
            SOURCE,
            INPUT,
        )
        .unwrap_err(),
        NativeVerificationError::UnsupportedNativeVersion
    );

    let floor = policy_with_minimum(&[(&key, &[CHECKED_PROFILE_TAG], &[ENGINE])], 1);
    assert_eq!(
        verify_with(
            &signed(&receipt(), &key),
            &floor,
            CHECKED_PROFILE_TAG,
            SOURCE,
            INPUT,
        )
        .unwrap_err(),
        NativeVerificationError::NativeSchemaVersionBelowPolicy
    );
}

#[test]
fn s5_cli_file_limit_is_a_semantic_rejection_with_report() {
    let directory = std::env::temp_dir().join(format!(
        "lispex-stage5-resource-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let envelope = directory.join("oversize.json");
    let policy = directory.join("policy.json");
    let source = directory.join("source.lspx");
    let input = directory.join("input.json");
    let report = directory.join("report.json");
    std::fs::write(&envelope, vec![b' '; 16_777_217]).unwrap();
    std::fs::write(&policy, b"{}\n").unwrap();
    std::fs::write(&source, SOURCE).unwrap();
    std::fs::write(&input, INPUT).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lispex"))
        .args([
            "verify-native",
            "--envelope",
            envelope.to_str().unwrap(),
            "--trust-policy",
            policy.to_str().unwrap(),
            "--source",
            source.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--profile",
            CHECKED_PROFILE_TAG,
            "--report-out",
            report.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report_bytes = std::fs::read(&report).unwrap();
    assert!(String::from_utf8(report_bytes)
        .unwrap()
        .contains("\"primary_error\": \"artifact-resource-limit\""));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn s5_cli_covers_success_ineligible_rejected_usage_and_io_exits() {
    let directory = std::env::temp_dir().join(format!(
        "lispex-stage5-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let key = SigningKey::from_bytes(&[11_u8; 32]);
    let policy_bytes = policy(&[(&key, &[CHECKED_PROFILE_TAG], &[ENGINE])]);
    let envelope_path = directory.join("envelope.json");
    let policy_path = directory.join("policy.json");
    let source_path = directory.join("source.lspx");
    let input_path = directory.join("input.json");
    std::fs::write(&envelope_path, signed(&receipt(), &key)).unwrap();
    std::fs::write(&policy_path, &policy_bytes).unwrap();
    std::fs::write(&source_path, SOURCE).unwrap();
    std::fs::write(&input_path, INPUT).unwrap();

    let run = |envelope: &std::path::Path, profile: &str, report_name: &str| {
        let report = directory.join(report_name);
        let output = Command::new(env!("CARGO_BIN_EXE_lispex"))
            .args([
                "verify-native",
                "--envelope",
                envelope.to_str().unwrap(),
                "--trust-policy",
                policy_path.to_str().unwrap(),
                "--source",
                source_path.to_str().unwrap(),
                "--input",
                input_path.to_str().unwrap(),
                "--profile",
                profile,
                "--report-out",
                report.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        (output, report)
    };

    let (success, success_report) = run(&envelope_path, CHECKED_PROFILE_TAG, "success.json");
    assert_eq!(success.status.code(), Some(0));
    assert!(String::from_utf8(std::fs::read(success_report).unwrap())
        .unwrap()
        .contains("\"decision_promotion\": \"eligible\""));

    let mut mutant = receipt();
    mutant.execution.build_variant = BuildVariant::Mutant;
    mutant.execution.mutant_id = Some("fixture-mutant".to_string());
    let mutant_path = directory.join("mutant.json");
    std::fs::write(&mutant_path, signed(&mutant, &key)).unwrap();
    let (ineligible, ineligible_report) = run(&mutant_path, CHECKED_PROFILE_TAG, "ineligible.json");
    assert_eq!(ineligible.status.code(), Some(10));
    assert!(String::from_utf8(std::fs::read(ineligible_report).unwrap())
        .unwrap()
        .contains("\"decision_promotion\": \"ineligible\""));

    let parsed = canonical_gate(
        &std::fs::read(&envelope_path).unwrap(),
        RawArtifactKind::Envelope,
    )
    .unwrap();
    let envelope = Envelope::from_canonical_json(&parsed).unwrap();
    let bad_signature = JsonValue::object([
        (
            "payloadType",
            JsonValue::String(NATIVE_PAYLOAD_TYPE.to_string()),
        ),
        (
            "payload",
            JsonValue::String(envelope.payload_base64().to_string()),
        ),
        (
            "signatures",
            JsonValue::Array(vec![JsonValue::object([
                (
                    "keyid",
                    JsonValue::String(envelope.signatures()[0].key_id().to_string()),
                ),
                ("sig", JsonValue::String(encode_base64(&[0_u8; 64]))),
            ])
            .unwrap()]),
        ),
    ])
    .unwrap();
    let invalid_path = directory.join("invalid-signature.json");
    std::fs::write(&invalid_path, write_canonical(&bad_signature).unwrap()).unwrap();
    let (rejected, rejected_report) = run(&invalid_path, CHECKED_PROFILE_TAG, "rejected.json");
    assert_eq!(rejected.status.code(), Some(1));
    let rejection = String::from_utf8(std::fs::read(rejected_report).unwrap()).unwrap();
    assert!(rejection.contains("\"authentication_status\": \"rejected\""));
    assert!(rejection.contains("\"comparison_status\": null"));
    assert!(rejection.contains("\"decision_promotion\": \"not-evaluated\""));
    assert!(rejection.contains("\"primary_error\": \"native-signature-invalid\""));

    let (usage, usage_report) = run(&envelope_path, "bad-profile", "usage.json");
    assert_eq!(usage.status.code(), Some(2));
    assert!(!usage_report.exists());

    let missing = directory.join("missing.json");
    let (io_failure, io_report) = run(&missing, CHECKED_PROFILE_TAG, "io.json");
    assert_eq!(io_failure.status.code(), Some(3));
    assert!(!io_report.exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn s5_selected_key_profile_and_signature_precedence_are_exact() {
    let key_a = SigningKey::from_bytes(&[5_u8; 32]);
    let key_b = SigningKey::from_bytes(&[6_u8; 32]);
    let policy = policy(&[
        (&key_a, &[CHECKED_PROFILE_TAG], &[ENGINE]),
        (&key_b, &["csk.profile-y/v0"], &[ENGINE]),
    ]);
    assert_eq!(
        verify_with(
            &signed(&receipt(), &key_b),
            &policy,
            CHECKED_PROFILE_TAG,
            SOURCE,
            INPUT,
        )
        .unwrap_err(),
        NativeVerificationError::NativeProfileDisallowed
    );

    let valid = signed(&receipt(), &key_a);
    let parsed = canonical_gate(&valid, RawArtifactKind::Envelope).unwrap();
    let envelope = Envelope::from_canonical_json(&parsed).unwrap();
    let mut payload = receipt().canonical_bytes().unwrap();
    payload.pop();
    payload.push(b' ');
    let tampered = JsonValue::object([
        (
            "payloadType",
            JsonValue::String(NATIVE_PAYLOAD_TYPE.to_string()),
        ),
        ("payload", JsonValue::String(encode_base64(&payload))),
        (
            "signatures",
            JsonValue::Array(vec![JsonValue::object([
                (
                    "keyid",
                    JsonValue::String(envelope.signatures()[0].key_id().to_string()),
                ),
                (
                    "sig",
                    JsonValue::String(envelope.signatures()[0].signature_base64().to_string()),
                ),
            ])
            .unwrap()]),
        ),
    ])
    .unwrap();
    assert_eq!(
        verify_with(
            &write_canonical(&tampered).unwrap(),
            &policy,
            CHECKED_PROFILE_TAG,
            SOURCE,
            INPUT,
        )
        .unwrap_err(),
        NativeVerificationError::NativeSignatureInvalid
    );
}

#[test]
fn s5_engine_precedes_source_and_authenticated_nondecisions_stay_evidence() {
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let wrong_engine_policy = policy(&[(
        &key,
        &[CHECKED_PROFILE_TAG],
        &["sha256:9999999999999999999999999999999999999999999999999999999999999999"],
    )]);
    assert_eq!(
        verify_with(
            &signed(&receipt(), &key),
            &wrong_engine_policy,
            CHECKED_PROFILE_TAG,
            b"#f\n",
            INPUT,
        )
        .unwrap_err(),
        NativeVerificationError::NativeEngineDisallowed
    );

    let policy = policy(&[(&key, &[CHECKED_PROFILE_TAG], &[ENGINE])]);
    let mut disagree = receipt();
    let TranscriptEvent::Value { value, .. } = &mut disagree.meaning_env.transcript.events[0]
    else {
        panic!("fixture event is a value")
    };
    *value = CanonicalValue::Decision(Decision::Review);
    disagree.meaning_env.transcript_sha256 = domain_hash(
        "csk.v0.meaning_env",
        &disagree.meaning_env.transcript.canonical_bytes().unwrap(),
    );
    disagree.comparison = Comparison {
        status: ComparisonStatus::Disagree,
        first_divergence_index: Some(0),
        comparison_unavailable_at: None,
    };
    let evidence = verify_with(
        &signed(&disagree, &key),
        &policy,
        CHECKED_PROFILE_TAG,
        SOURCE,
        INPUT,
    )
    .unwrap();
    assert_eq!(
        evidence.promotion_ineligibility(),
        Some(PromotionIneligibility::ComparisonNotAgree)
    );

    let mut fault = receipt();
    for transcript in [
        &mut fault.reference.transcript,
        &mut fault.meaning_env.transcript,
    ] {
        transcript.events.clear();
        transcript.terminal = Terminal::LanguageFault {
            code: LanguageFaultCode::DivisionByZero,
            form_index: 0,
        };
    }
    fault.reference.transcript_sha256 = domain_hash(
        "csk.v0.reference",
        &fault.reference.transcript.canonical_bytes().unwrap(),
    );
    fault.meaning_env.transcript_sha256 = domain_hash(
        "csk.v0.meaning_env",
        &fault.meaning_env.transcript.canonical_bytes().unwrap(),
    );
    let evidence = verify_with(
        &signed(&fault, &key),
        &policy,
        CHECKED_PROFILE_TAG,
        SOURCE,
        INPUT,
    )
    .unwrap();
    assert_eq!(
        evidence.promotion_ineligibility(),
        Some(PromotionIneligibility::TerminalNotCompleted)
    );

    let mut unavailable = receipt();
    unavailable.meaning_env.transcript.events.clear();
    unavailable.meaning_env.transcript.terminal = Terminal::InfrastructureFailure {
        code: InfrastructureFailureCode::MeaningExecutionFailed,
        phase: EvaluationPhase::Meaning,
        next_form_index: 0,
    };
    unavailable.meaning_env.transcript_sha256 = domain_hash(
        "csk.v0.meaning_env",
        &unavailable
            .meaning_env
            .transcript
            .canonical_bytes()
            .unwrap(),
    );
    unavailable.comparison = Comparison {
        status: ComparisonStatus::NotComparable,
        first_divergence_index: None,
        comparison_unavailable_at: Some(0),
    };
    let evidence = verify_with(
        &signed(&unavailable, &key),
        &policy,
        CHECKED_PROFILE_TAG,
        SOURCE,
        INPUT,
    )
    .unwrap();
    assert_eq!(
        evidence.promotion_ineligibility(),
        Some(PromotionIneligibility::ComparisonNotAgree)
    );
}

#[test]
fn s5_promotion_reasons_cover_nondecision_diagnostics_and_mutant_in_order() {
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let policy = policy(&[(&key, &[CHECKED_PROFILE_TAG], &[ENGINE])]);

    let mut nondecision = receipt();
    for transcript in [
        &mut nondecision.reference.transcript,
        &mut nondecision.meaning_env.transcript,
    ] {
        let TranscriptEvent::Value { value, .. } = &mut transcript.events[0] else {
            panic!("fixture event is a value")
        };
        *value = CanonicalValue::Boolean(true);
    }
    nondecision.reference.transcript_sha256 = domain_hash(
        "csk.v0.reference",
        &nondecision.reference.transcript.canonical_bytes().unwrap(),
    );
    nondecision.meaning_env.transcript_sha256 = domain_hash(
        "csk.v0.meaning_env",
        &nondecision
            .meaning_env
            .transcript
            .canonical_bytes()
            .unwrap(),
    );
    let evidence = verify_with(
        &signed(&nondecision, &key),
        &policy,
        CHECKED_PROFILE_TAG,
        SOURCE,
        INPUT,
    )
    .unwrap();
    assert_eq!(
        evidence.promotion_ineligibility(),
        Some(PromotionIneligibility::FinalValueNotDecision)
    );

    let mut diagnostics = receipt();
    diagnostics
        .diagnostics
        .push(lispex::vouch_native::receipt::ReceiptDiagnostic {
            code: "fixture-note".to_string(),
            message: "fixture diagnostic".to_string(),
        });
    let evidence = verify_with(
        &signed(&diagnostics, &key),
        &policy,
        CHECKED_PROFILE_TAG,
        SOURCE,
        INPUT,
    )
    .unwrap();
    assert_eq!(
        evidence.promotion_ineligibility(),
        Some(PromotionIneligibility::DiagnosticsPresent)
    );

    let mut mutant = receipt();
    mutant.execution.build_variant = BuildVariant::Mutant;
    mutant.execution.mutant_id = Some("fixture-mutant".to_string());
    let evidence = verify_with(
        &signed(&mutant, &key),
        &policy,
        CHECKED_PROFILE_TAG,
        SOURCE,
        INPUT,
    )
    .unwrap();
    assert_eq!(
        evidence.promotion_ineligibility(),
        Some(PromotionIneligibility::MutantBuild)
    );
}
