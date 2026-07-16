#![cfg(feature = "scored-native-contract")]

use std::collections::BTreeMap;
use std::process::Command;

use lispex::vouch_native::bridge::sha256_hex;
use vouch::artifact_json::{canonical_gate, write_canonical, JsonValue, RawArtifactKind};

const PROFILE: &str = "csk.checked-profile/v1";
const ENGINE: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const INPUT_VALUE: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const SOURCE: &[u8] = b"bridge source\n";
const INPUT: &[u8] = b"bridge input\n";

#[test]
fn s7_b01_checked_cli_report_is_exact_canonical_and_boundary_safe() {
    let fixture = Fixture::new("b01", valid_report(&[]));
    let output = fixture.command().output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let report = fixture.output_bytes();
    canonical_gate(&report, RawArtifactKind::Artifact).unwrap();
    let text = String::from_utf8(report).unwrap();
    assert!(text.contains("\"bridge_verify_report\": \"vouch.bridge-verify-report/v0\""));
    assert!(text.contains("\"status\": \"checked-external\""));
    assert!(text.contains("\"primary_error\": null"));
    for forbidden in [
        "authenticated",
        "independently witnessed",
        "trusted",
        "fresh",
    ] {
        assert!(
            !text.contains(forbidden),
            "checked report leaked `{forbidden}`"
        );
    }
    assert_eq!(fixture.staging_paths(), Vec::<String>::new());
}

#[test]
fn s7_b03_through_b12_follow_the_fixed_primary_error_order() {
    let native_envelope = write_canonical(
        &JsonValue::object([
            (
                "payloadType",
                JsonValue::String("application/vnd.csk.differential-receipt.v0+json".to_string()),
            ),
            ("payload", JsonValue::String("e30=".to_string())),
            ("signatures", JsonValue::Array(vec![])),
        ])
        .unwrap(),
    )
    .unwrap();
    let compact = b"{\"bridge_report\":\"vouch.bridge-report/v1\"}\n".to_vec();
    let cases = vec![
        ("b03", native_envelope, "bridge-report-schema"),
        (
            "b04",
            vec![b' '; vouch::artifact_json::MAX_ARTIFACT_BYTES + 1],
            "artifact-resource-limit",
        ),
        ("b05", compact, "non-canonical-artifact-json"),
        (
            "b06",
            valid_report(&[(
                "bridge_report",
                JsonValue::String("vouch.bridge-report/v1".to_string()),
            )]),
            "unsupported-bridge-version",
        ),
        (
            "b07",
            valid_report(&[("unknown", JsonValue::Bool(true))]),
            "bridge-report-schema",
        ),
        (
            "b08",
            valid_report(&[("profile", JsonValue::String("other.profile/v0".to_string()))]),
            "bridge-profile-mismatch",
        ),
        (
            "b09",
            valid_report(&[(
                "engine_sha256",
                JsonValue::String(format!("sha256:{}", "3".repeat(64))),
            )]),
            "bridge-engine-mismatch",
        ),
        (
            "b10",
            valid_report(&[("source_sha256", JsonValue::String("3".repeat(64)))]),
            "bridge-source-mismatch",
        ),
        (
            "b11",
            valid_report(&[("input_sha256", JsonValue::String("3".repeat(64)))]),
            "bridge-input-mismatch",
        ),
        (
            "b12",
            valid_report(&[(
                "input_canonical_value_sha256",
                JsonValue::String("3".repeat(64)),
            )]),
            "bridge-input-canonical-value-mismatch",
        ),
    ];

    for (label, input, expected_error) in cases {
        let fixture = Fixture::new(label, input);
        let output = fixture.command().output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{label}");
        let report = fixture.output_bytes();
        canonical_gate(&report, RawArtifactKind::Artifact).unwrap();
        let text = String::from_utf8(report).unwrap();
        assert!(
            text.contains(&format!("\"primary_error\": \"{expected_error}\"")),
            "{label}: {text}"
        );
        assert!(!text.contains("\"profile\""));
    }
}

#[test]
fn s7_cli_usage_io_and_no_replace_contract_is_closed() {
    for (index, invalid) in [
        vec!["positional", "value"],
        vec!["--unknown", "value"],
        vec!["--report", "duplicate"],
        vec!["--profile", "INVALID"],
        vec!["--engine-sha256", "sha256:ABC"],
        vec!["--input-canonical-value-sha256", "ABC"],
        vec!["--source", "-"],
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new(&format!("usage-{index}"), valid_report(&[]));
        let mut command = fixture.command();
        command.args(invalid);
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!fixture.output.exists());
    }

    let missing = Fixture::new("missing", valid_report(&[]));
    std::fs::remove_file(&missing.input).unwrap();
    let output = missing.command().output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(!missing.output.exists());

    let occupied = Fixture::new("occupied", valid_report(&[]));
    std::fs::write(&occupied.output, b"owner\n").unwrap();
    let output = occupied.command().output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(std::fs::read(&occupied.output).unwrap(), b"owner\n");
    assert_eq!(occupied.staging_paths(), Vec::<String>::new());
}

fn valid_report(overrides: &[(&str, JsonValue)]) -> Vec<u8> {
    let mut object = BTreeMap::from([
        (
            "bridge_report".to_string(),
            JsonValue::String("vouch.bridge-report/v0".to_string()),
        ),
        (
            "profile".to_string(),
            JsonValue::String(PROFILE.to_string()),
        ),
        (
            "engine_sha256".to_string(),
            JsonValue::String(ENGINE.to_string()),
        ),
        (
            "source_sha256".to_string(),
            JsonValue::String(sha256_hex(SOURCE)),
        ),
        (
            "input_sha256".to_string(),
            JsonValue::String(sha256_hex(INPUT)),
        ),
        (
            "input_canonical_value_sha256".to_string(),
            JsonValue::String(INPUT_VALUE.to_string()),
        ),
        (
            "comparison_status".to_string(),
            JsonValue::String("agree".to_string()),
        ),
        (
            "decision".to_string(),
            JsonValue::String("approve".to_string()),
        ),
        ("diagnostics".to_string(), JsonValue::Array(vec![])),
    ]);
    for (name, value) in overrides {
        object.insert((*name).to_string(), value.clone());
    }
    write_canonical(&JsonValue::Object(object)).unwrap()
}

struct Fixture {
    root: std::path::PathBuf,
    report: std::path::PathBuf,
    source: std::path::PathBuf,
    input: std::path::PathBuf,
    output: std::path::PathBuf,
}

impl Fixture {
    fn new(label: &str, report_bytes: Vec<u8>) -> Self {
        let root = std::env::temp_dir().join(format!(
            "lispex-stage7-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let report = root.join("bridge.json");
        let source = root.join("source.bin");
        let input = root.join("input.bin");
        let output = root.join("verify-report.json");
        std::fs::write(&report, report_bytes).unwrap();
        std::fs::write(&source, SOURCE).unwrap();
        std::fs::write(&input, INPUT).unwrap();
        Self {
            root,
            report,
            source,
            input,
            output,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lispex"));
        command.args([
            "verify-bridge",
            "--report",
            self.report.to_str().unwrap(),
            "--profile",
            PROFILE,
            "--engine-sha256",
            ENGINE,
            "--source",
            self.source.to_str().unwrap(),
            "--input",
            self.input.to_str().unwrap(),
            "--input-canonical-value-sha256",
            INPUT_VALUE,
            "--report-out",
            self.output.to_str().unwrap(),
        ]);
        command
    }

    fn output_bytes(&self) -> Vec<u8> {
        std::fs::read(&self.output).unwrap()
    }

    fn staging_paths(&self) -> Vec<String> {
        let mut paths = std::fs::read_dir(&self.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".staging-"))
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
