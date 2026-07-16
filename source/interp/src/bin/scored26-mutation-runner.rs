//! Keyless Stage-9 mutation witness and frozen-workload runner.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use lispex::vouch_native::mutation::run_mutation_bytes;
use sha2::{Digest, Sha256};
use vouch::artifact_json::{
    canonical_gate, write_canonical, JsonValue, RawArtifactKind, MAX_ARTIFACT_BYTES,
};
use vouch::io_boundary::{FileProvider, FrozenBytes, OsFileProvider};
use vouch::release::{parse_supplied_corpus, verify_replay_manifest, ReplayArtifacts, ReplayCase};

const CHECKED_PROFILE: &str = "csk.checked-profile/v1";
const REPORT_TAG: &str = "vouch.scored26-mutation-execution/v0";
const REQUIRED_INPUTS: &[&str] = &[
    "--envelope",
    "--trust-policy",
    "--baseline-rule",
    "--changed-rule",
    "--workload-space",
    "--workload-selection",
    "--workload-split",
    "--holdout-plan",
    "--corpus",
    "--activation-suite",
];
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
    "--activation-suite",
    "--payload-root",
    "--execution-report",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct CaseMetadata {
    case_id: String,
    partition: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActivationCase {
    case_id: String,
    mutant_id: String,
    expected_witness_class: String,
    source: Vec<u8>,
    input: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Observation {
    Receipt {
        comparison_status: String,
        reference_projection_sha256: String,
        meaning_projection_sha256: String,
        payload_sha256: String,
        payload_relative_path: String,
    },
    PipelineFailure {
        error_code: String,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok((cases, payloads)) => {
            println!(
                "SCORED26 keyless mutation execution passed ({cases} workload cases/{payloads} unsigned payloads, mutant={})",
                selected_mutant().unwrap_or("baseline")
            );
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("scored26-mutation-runner: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(usize, usize), String> {
    let arguments = parse_arguments(std::env::args().skip(1))?;
    let payload_root = PathBuf::from(&arguments["--payload-root"]);
    let execution_report = PathBuf::from(&arguments["--execution-report"]);
    if payload_root.exists() || execution_report.exists() {
        return Err("payload root and execution report must not preexist".to_string());
    }

    let provider = OsFileProvider::default();
    let mut files = BTreeMap::<&str, FrozenBytes>::new();
    for name in REQUIRED_INPUTS {
        let bytes = provider
            .read_once(&arguments[*name], MAX_ARTIFACT_BYTES)
            .map_err(|error| format!("cannot read {name}: {error}"))?;
        files.insert(name, bytes);
    }

    let supplied_cases = parse_supplied_corpus(files["--corpus"].bytes())
        .map_err(|error| error.code().to_string())?;
    let artifacts = ReplayArtifacts::from_slices(
        files["--workload-space"].bytes(),
        files["--workload-selection"].bytes(),
        files["--workload-split"].bytes(),
        files["--holdout-plan"].bytes(),
    );
    let verified = verify_replay_manifest(
        files["--envelope"].bytes(),
        files["--trust-policy"].bytes(),
        files["--baseline-rule"].bytes(),
        files["--changed-rule"].bytes(),
        &artifacts,
        &supplied_cases,
    )
    .map_err(|error| error.code().to_string())?;
    if verified.manifest().checked_profile() != CHECKED_PROFILE {
        return Err("verified replay profile mismatch".to_string());
    }
    let metadata = parse_split_metadata(files["--workload-split"].bytes())?;
    validate_case_order(verified.cases(), &metadata)?;
    let activation = parse_activation_suite(files["--activation-suite"].bytes())?;

    // No experiment output exists before replay authentication, order checking,
    // and activation-suite validation have all succeeded.
    fs::create_dir_all(&payload_root)
        .map_err(|error| format!("cannot create payload root: {error}"))?;
    let mut payload_count = 0_usize;
    let mut activation_rows = Vec::with_capacity(activation.len());
    for case in activation {
        let relative = format!("activation/{}/payload.json", case.case_id);
        let observation = execute_one(
            &case.source,
            &case.input,
            &payload_root,
            &relative,
            &mut payload_count,
        )?;
        activation_rows.push(
            JsonValue::object([
                ("case_id", JsonValue::String(case.case_id)),
                ("mutant_id", JsonValue::String(case.mutant_id)),
                (
                    "expected_witness_class",
                    JsonValue::String(case.expected_witness_class),
                ),
                ("observation", observation_json(&observation)?),
            ])
            .map_err(|error| error.to_string())?,
        );
    }

    let rules = [
        ("baseline", files["--baseline-rule"].bytes()),
        ("changed", files["--changed-rule"].bytes()),
    ];
    let mut workload_rows = Vec::with_capacity(verified.cases().len());
    verified
        .execute(|case| {
            let metadata = metadata
                .get(case.case_id())
                .ok_or_else(|| format!("{}: missing split metadata", case.case_id()))?;
            let mut observations = BTreeMap::new();
            for (version, source) in rules {
                let relative = format!("workload/{}/{version}.json", case.case_id());
                let observation = execute_one(
                    source,
                    case.canonical_input_bytes(),
                    &payload_root,
                    &relative,
                    &mut payload_count,
                )?;
                observations.insert(version, observation);
            }
            workload_rows.push(
                JsonValue::object([
                    ("case_id", JsonValue::String(metadata.case_id.clone())),
                    ("partition", JsonValue::String(metadata.partition.clone())),
                    (
                        "baseline",
                        observation_json(observations.get("baseline").unwrap())?,
                    ),
                    (
                        "changed",
                        observation_json(observations.get("changed").unwrap())?,
                    ),
                ])
                .map_err(|error| error.to_string())?,
            );
            Ok::<(), String>(())
        })
        .map_err(|error| format!("execution failed: {error}"))?;

    let report = JsonValue::object([
        (
            "mutation_execution_report",
            JsonValue::String(REPORT_TAG.to_string()),
        ),
        (
            "selected_mutant",
            selected_mutant()
                .map(|value| JsonValue::String(value.to_string()))
                .unwrap_or(JsonValue::Null),
        ),
        ("binary_sha256", JsonValue::String(running_binary_sha256()?)),
        ("activation_cases", JsonValue::Array(activation_rows)),
        ("workload_cases", JsonValue::Array(workload_rows)),
    ])
    .map_err(|error| error.to_string())?;
    let bytes = write_canonical(&report).map_err(|error| error.to_string())?;
    publish_file(&execution_report, &bytes)?;
    Ok((verified.cases().len(), payload_count))
}

fn selected_mutant() -> Option<&'static str> {
    match env!("CSK_SCORED_MUTANT") {
        "" => None,
        value => Some(value),
    }
}

fn execute_one(
    source: &[u8],
    input: &[u8],
    payload_root: &Path,
    relative: &str,
    payload_count: &mut usize,
) -> Result<Observation, String> {
    let payload = match run_mutation_bytes(source, input) {
        Ok(payload) => payload,
        Err(error) if error.is_pre_graph_failure() => {
            return Ok(Observation::PipelineFailure {
                error_code: error.code().to_string(),
            })
        }
        Err(error) => {
            return Err(format!(
                "post-graph mutation execution failed: {}",
                error.code()
            ))
        }
    };
    let bytes = payload.bytes();
    let parsed = canonical_gate(bytes, RawArtifactKind::Payload)
        .map_err(|error| format!("mutation payload is not canonical: {error}"))?;
    let root = object(parsed.value(), "mutation payload")?;
    if root.contains_key("payloadType") || root.contains_key("signatures") {
        return Err("mutation output must not be a DSSE envelope".to_string());
    }
    validate_execution_identity(root)?;
    let comparison = object(field(root, "comparison")?, "comparison")?;
    let comparison_status = string(field(comparison, "status")?, "comparison status")?;
    if !matches!(comparison_status, "agree" | "disagree" | "not-comparable") {
        return Err("unknown comparison status".to_string());
    }
    let reference = transcript_projection(root, "reference")?;
    let meaning = transcript_projection(root, "meaning_env")?;
    let destination = payload_root.join(relative);
    publish_file(&destination, bytes)?;
    *payload_count += 1;
    Ok(Observation::Receipt {
        comparison_status: comparison_status.to_string(),
        reference_projection_sha256: reference,
        meaning_projection_sha256: meaning,
        payload_sha256: digest(bytes),
        payload_relative_path: relative.to_string(),
    })
}

fn validate_execution_identity(root: &BTreeMap<String, JsonValue>) -> Result<(), String> {
    let execution = object(field(root, "execution")?, "execution")?;
    let mutant_id = execution.get("mutant_id").and_then(JsonValue::as_str);
    let variant = string(field(execution, "build_variant")?, "build variant")?;
    match selected_mutant() {
        Some(expected) if mutant_id == Some(expected) && variant == "mutant" => Ok(()),
        None if mutant_id.is_none()
            && execution.get("mutant_id") == Some(&JsonValue::Null)
            && variant == "release" =>
        {
            Ok(())
        }
        _ => Err("payload build identity does not match selected mutant".to_string()),
    }
}

fn transcript_projection(root: &BTreeMap<String, JsonValue>, name: &str) -> Result<String, String> {
    let report = object(field(root, name)?, name)?;
    let transcript = field(report, "transcript")?;
    let bytes = write_canonical(transcript).map_err(|error| error.to_string())?;
    Ok(digest(&bytes))
}

fn observation_json(observation: &Observation) -> Result<JsonValue, String> {
    match observation {
        Observation::Receipt {
            comparison_status,
            reference_projection_sha256,
            meaning_projection_sha256,
            payload_sha256,
            payload_relative_path,
        } => JsonValue::object([
            ("kind", JsonValue::String("receipt".to_string())),
            (
                "comparison_status",
                JsonValue::String(comparison_status.clone()),
            ),
            (
                "reference_projection_sha256",
                JsonValue::String(reference_projection_sha256.clone()),
            ),
            (
                "meaning_projection_sha256",
                JsonValue::String(meaning_projection_sha256.clone()),
            ),
            ("payload_sha256", JsonValue::String(payload_sha256.clone())),
            (
                "payload_relative_path",
                JsonValue::String(payload_relative_path.clone()),
            ),
        ])
        .map_err(|error| error.to_string()),
        Observation::PipelineFailure { error_code } => JsonValue::object([
            ("kind", JsonValue::String("pipeline-failure".to_string())),
            ("error_code", JsonValue::String(error_code.clone())),
        ])
        .map_err(|error| error.to_string()),
    }
}

fn parse_activation_suite(bytes: &[u8]) -> Result<Vec<ActivationCase>, String> {
    let canonical = canonical_gate(bytes, RawArtifactKind::Artifact)
        .map_err(|error| format!("activation suite: {error}"))?;
    let root = object(canonical.value(), "activation suite")?;
    require_exact_keys(root, &["activation_suite", "cases"], "activation suite")?;
    if string(field(root, "activation_suite")?, "activation suite tag")?
        != "vouch.scored26-mutation-activation/v0"
    {
        return Err("activation suite tag mismatch".to_string());
    }
    let rows = array(field(root, "cases")?, "activation cases")?;
    if rows.len() != 12 {
        return Err("activation suite must contain twelve cases".to_string());
    }
    let mut seen = BTreeSet::new();
    let mut output = Vec::with_capacity(rows.len());
    for (index, value) in rows.iter().enumerate() {
        let row = object(value, "activation case")?;
        require_exact_keys(
            row,
            &[
                "case_id",
                "expected_witness_class",
                "input",
                "mutant_id",
                "source",
            ],
            "activation case",
        )?;
        let mutant_id = string(field(row, "mutant_id")?, "mutant id")?.to_string();
        let expected_id = format!("M{:02}", index + 1);
        let case_id = string(field(row, "case_id")?, "activation case id")?.to_string();
        let expected_class = string(
            field(row, "expected_witness_class")?,
            "expected witness class",
        )?
        .to_string();
        let required_class = if index < 6 || index == 8 || index == 9 {
            "disagreement"
        } else {
            "common-mode"
        };
        if mutant_id != expected_id
            || case_id != format!("W-{expected_id}")
            || expected_class != required_class
            || !seen.insert(mutant_id.clone())
        {
            return Err("activation suite ordering or identity mismatch".to_string());
        }
        output.push(ActivationCase {
            case_id,
            mutant_id,
            expected_witness_class: expected_class,
            source: string(field(row, "source")?, "activation source")?
                .as_bytes()
                .to_vec(),
            input: write_canonical(field(row, "input")?).map_err(|error| error.to_string())?,
        });
    }
    Ok(output)
}

fn parse_split_metadata(bytes: &[u8]) -> Result<BTreeMap<String, CaseMetadata>, String> {
    let canonical = canonical_gate(bytes, RawArtifactKind::Artifact)
        .map_err(|error| format!("workload split: {error}"))?;
    let root = object(canonical.value(), "workload split")?;
    let cases = array(field(root, "cases")?, "workload split cases")?;
    let mut output = BTreeMap::new();
    for value in cases {
        let row = object(value, "workload split row")?;
        let metadata = CaseMetadata {
            case_id: string(field(row, "case_id")?, "case_id")?.to_string(),
            partition: string(field(row, "partition")?, "partition")?.to_string(),
        };
        if !matches!(metadata.partition.as_str(), "development" | "held-out")
            || output.insert(metadata.case_id.clone(), metadata).is_some()
        {
            return Err("invalid or duplicate workload split metadata".to_string());
        }
    }
    Ok(output)
}

fn validate_case_order(
    cases: &[ReplayCase],
    metadata: &BTreeMap<String, CaseMetadata>,
) -> Result<(), String> {
    if cases.len() != metadata.len() || cases.len() != 240 {
        return Err("verified replay/split case count mismatch".to_string());
    }
    for (case, expected) in cases.iter().zip(metadata.values()) {
        if case.case_id() != expected.case_id {
            return Err(format!(
                "{}: verified replay/split order mismatch",
                case.case_id()
            ));
        }
    }
    Ok(())
}

fn parse_arguments(raw: impl Iterator<Item = String>) -> Result<BTreeMap<String, String>, String> {
    let raw = raw.collect::<Vec<_>>();
    if raw.len() % 2 != 0 {
        return Err("every option requires one value".to_string());
    }
    let mut output = BTreeMap::new();
    for pair in raw.chunks_exact(2) {
        if !REQUIRED.contains(&pair[0].as_str()) {
            return Err(format!("unknown argument `{}`", pair[0]));
        }
        if pair[1].is_empty() || pair[1] == "-" || pair[1].starts_with("--") {
            return Err(format!("{} requires a value", pair[0]));
        }
        if output.insert(pair[0].clone(), pair[1].clone()).is_some() {
            return Err(format!("{} may be provided only once", pair[0]));
        }
    }
    for required in REQUIRED {
        if !output.contains_key(*required) {
            return Err(format!("{required} is required"));
        }
    }
    Ok(output)
}

fn running_binary_sha256() -> Result<String, String> {
    let path = std::env::current_exe()
        .map_err(|error| format!("cannot resolve running executable: {error}"))?;
    let mut file =
        File::open(path).map_err(|error| format!("cannot open running executable: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read running executable: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn publish_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| format!("cannot create output parent: {error}"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "output path has no UTF-8 filename".to_string())?;
    let staging = parent.join(format!(".{name}.stage-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staging)
        .map_err(|error| format!("cannot create staged output: {error}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write staged output: {error}"))?;
    fs::rename(&staging, path).map_err(|error| format!("cannot publish output: {error}"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync output parent: {error}"))?;
    Ok(())
}

fn field<'a>(object: &'a BTreeMap<String, JsonValue>, name: &str) -> Result<&'a JsonValue, String> {
    object
        .get(name)
        .ok_or_else(|| format!("missing JSON member `{name}`"))
}

fn object<'a>(
    value: &'a JsonValue,
    label: &str,
) -> Result<&'a BTreeMap<String, JsonValue>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))
}

fn array<'a>(value: &'a JsonValue, label: &str) -> Result<&'a [JsonValue], String> {
    value
        .as_array()
        .ok_or_else(|| format!("{label} must be an array"))
}

fn string<'a>(value: &'a JsonValue, label: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("{label} must be a string"))
}

fn require_exact_keys(
    object: &BTreeMap<String, JsonValue>,
    names: &[&str],
    label: &str,
) -> Result<(), String> {
    if object.len() != names.len() || names.iter().any(|name| !object.contains_key(*name)) {
        return Err(format!("{label} members are not the exact closed set"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_handle_and_mutant_selector_are_not_cli_arguments() {
        assert!(!REQUIRED.contains(&"--key-handle"));
        assert!(!REQUIRED.contains(&"--mutant"));
    }

    #[test]
    fn malformed_or_duplicate_arguments_fail_closed() {
        assert!(parse_arguments(["--envelope".to_string()].into_iter()).is_err());
        assert!(
            parse_arguments(["--key-handle".to_string(), "secret".to_string()].into_iter())
                .is_err()
        );
    }
}
