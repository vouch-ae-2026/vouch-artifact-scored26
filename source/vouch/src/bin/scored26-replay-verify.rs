use std::collections::BTreeMap;
use std::process::ExitCode;

use vouch::artifact_json::{write_canonical, JsonValue, MAX_ARTIFACT_BYTES};
use vouch::io_boundary::{FileProvider, OsFileProvider};
use vouch::release::{parse_supplied_corpus, verify_replay_manifest, ReplayArtifacts, ReplayError};

const REPORT_TAG: &str = "csk.replay-verification-report/v0";
const REQUIRED: &[&str] = &[
    "--envelope",
    "--trust-policy",
    "--baseline-rule",
    "--changed-rule",
    "--workload-space",
    "--workload-selection",
    "--workload-split",
    "--holdout-plan",
    "--corpus",
];

fn main() -> ExitCode {
    let arguments = match parse_arguments() {
        Ok(arguments) => arguments,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let provider = OsFileProvider::default();
    let mut files = BTreeMap::new();
    for name in REQUIRED {
        let path = arguments.get(*name).expect("required argument was checked");
        match provider.read_once(path, MAX_ARTIFACT_BYTES) {
            Ok(bytes) => {
                files.insert(*name, bytes);
            }
            Err(error) => {
                eprintln!("scored26-replay-verify: cannot read {name}: {error}");
                return ExitCode::from(3);
            }
        }
    }

    let cases = match parse_supplied_corpus(files["--corpus"].bytes()) {
        Ok(cases) => cases,
        Err(error) => return report_failure(error),
    };
    let artifacts = ReplayArtifacts::from_slices(
        files["--workload-space"].bytes(),
        files["--workload-selection"].bytes(),
        files["--workload-split"].bytes(),
        files["--holdout-plan"].bytes(),
    );
    match verify_replay_manifest(
        files["--envelope"].bytes(),
        files["--trust-policy"].bytes(),
        files["--baseline-rule"].bytes(),
        files["--changed-rule"].bytes(),
        &artifacts,
        &cases,
    ) {
        Ok(verified) => {
            write_report("verified", verified.cases().len());
            ExitCode::SUCCESS
        }
        Err(error) => report_failure(error),
    }
}

fn parse_arguments() -> Result<BTreeMap<String, String>, String> {
    let raw = std::env::args().skip(1).collect::<Vec<_>>();
    if raw.len() % 2 != 0 {
        return Err("scored26-replay-verify: every option requires one path".to_string());
    }
    let mut output = BTreeMap::new();
    for pair in raw.chunks_exact(2) {
        if !REQUIRED.contains(&pair[0].as_str()) {
            return Err(format!(
                "scored26-replay-verify: unknown argument `{}`",
                pair[0]
            ));
        }
        if pair[1].is_empty() || pair[1] == "-" || pair[1].starts_with("--") {
            return Err(format!(
                "scored26-replay-verify: {} requires a path",
                pair[0]
            ));
        }
        if output.insert(pair[0].clone(), pair[1].clone()).is_some() {
            return Err(format!(
                "scored26-replay-verify: {} may be provided only once",
                pair[0]
            ));
        }
    }
    for required in REQUIRED {
        if !output.contains_key(*required) {
            return Err(format!("scored26-replay-verify: {required} is required"));
        }
    }
    Ok(output)
}

fn report_failure(error: ReplayError) -> ExitCode {
    write_report(error.code(), 0);
    eprintln!("{}", error.code());
    ExitCode::FAILURE
}

fn write_report(status: &str, case_count: usize) {
    let report = JsonValue::object([
        (
            "replay_verification_report",
            JsonValue::String(REPORT_TAG.to_string()),
        ),
        ("status", JsonValue::String(status.to_string())),
        ("case_count", JsonValue::Integer(case_count as i64)),
    ])
    .expect("replay report fields are unique");
    let bytes = write_canonical(&report).expect("replay report integers are safe");
    print!(
        "{}",
        String::from_utf8(bytes).expect("canonical JSON is UTF-8")
    );
}
