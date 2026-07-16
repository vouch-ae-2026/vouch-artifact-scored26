#![cfg(feature = "scored-native-contract")]

use std::process::Command;

const SOURCE: &[u8] = b"(decision-approve)\n";
const INPUT: &[u8] = b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": 7\n}\n";

#[test]
fn s6_cli_forbidden_payload_input_is_usage_and_report_only_after_out_dir() {
    let fixture = Fixture::new("forbidden");
    let output = Command::new(env!("CARGO_BIN_EXE_lispex"))
        .args([
            "issue-native",
            "--out-dir",
            fixture.output_str(),
            "--receipt",
            "caller.json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fixture.published_names(), vec!["issue-report.json"]);
    assert!(fixture
        .report()
        .contains("\"primary_error\": \"usage-error\""));
}

#[test]
fn s6_cli_input_parse_failure_is_prekey_report_only() {
    let fixture = Fixture::new("input-parse");
    std::fs::write(&fixture.input, b"not-json\n").unwrap();
    let output = fixture.command().output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fixture.published_names(), vec!["issue-report.json"]);
    assert!(fixture
        .report()
        .contains("\"primary_error\": \"native-input-parse-failed\""));
}

#[test]
fn s6_cli_existing_out_dir_is_usage_without_overwrite_or_report() {
    let fixture = Fixture::new("existing-output");
    std::fs::create_dir(&fixture.output).unwrap();
    std::fs::write(fixture.output.join("owner.txt"), b"preserve\n").unwrap();
    let output = fixture.command().output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        std::fs::read(fixture.output.join("owner.txt")).unwrap(),
        b"preserve\n"
    );
    assert!(!fixture.output.join("issue-report.json").exists());
}

#[test]
fn s6_cli_missing_out_dir_is_usage_with_no_final_path() {
    let fixture = Fixture::new("missing-output");
    let output = Command::new(env!("CARGO_BIN_EXE_lispex"))
        .args(["issue-native", "--source", fixture.source_str()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!fixture.output.exists());
}

#[test]
fn s6_cli_rejects_every_caller_artifact_duplicate_unknown_and_positional_form() {
    for (index, forbidden) in [
        vec!["--receipt", "caller.json"],
        vec!["--payload", "caller.json"],
        vec!["--decision", "approve"],
        vec!["--transcript", "caller.json"],
        vec!["--engine", "caller-engine"],
        vec!["--envelope-out", "caller.json"],
        vec!["--payload-out", "caller.json"],
        vec!["--report-out", "caller.json"],
        vec!["--unknown", "value"],
        vec!["positional"],
        vec!["--out-dir", "duplicate"],
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new(&format!("closed-cli-{index}"));
        let mut args = vec![
            "issue-native".to_string(),
            "--out-dir".to_string(),
            fixture.output_str().to_string(),
        ];
        args.extend(forbidden.into_iter().map(str::to_string));
        let output = Command::new(env!("CARGO_BIN_EXE_lispex"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(fixture.published_names(), vec!["issue-report.json"]);
    }
}

#[test]
fn s6_cli_empty_out_dir_is_usage_without_a_final_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_lispex"))
        .args(["issue-native", "--out-dir", ""])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

struct Fixture {
    root: std::path::PathBuf,
    source: std::path::PathBuf,
    input: std::path::PathBuf,
    output: std::path::PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "lispex-stage6-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("source.lspx");
        let input = root.join("input.json");
        std::fs::write(&source, SOURCE).unwrap();
        std::fs::write(&input, INPUT).unwrap();
        let output = root.join("issued");
        Self {
            root,
            source,
            input,
            output,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lispex"));
        command.args([
            "issue-native",
            "--source",
            self.source_str(),
            "--input",
            self.input.to_str().unwrap(),
            "--profile",
            "csk.checked-profile/v1",
            "--key-handle",
            "hsm://fixture/must-not-open",
            "--out-dir",
            self.output_str(),
        ]);
        command
    }

    fn source_str(&self) -> &str {
        self.source.to_str().unwrap()
    }

    fn output_str(&self) -> &str {
        self.output.to_str().unwrap()
    }

    fn published_names(&self) -> Vec<String> {
        let mut names = std::fs::read_dir(&self.output)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn report(&self) -> String {
        std::fs::read_to_string(self.output.join("issue-report.json")).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
