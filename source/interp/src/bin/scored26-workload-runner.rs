//! Authenticated Stage-8 workload replay and ephemeral receipt execution.
//!
//! This binary is release-only in the empirical workflow. It authenticates all
//! frozen inputs before creating an output directory, executes the verified
//! replay capability, issues one Native receipt for each rule/case pair, and
//! derives decision outcomes from those receipt payloads. The independent
//! workload observer contributes coverage only and is required to agree with
//! every receipt-derived decision.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use lispex::vouch_native::issue::{
    issue_native_bytes, IssueOutcome, IssuePrimaryError, SignabilityReason,
};
use lispex::vouch_native::workload::{
    evaluate_workload_case, stable_coverage_identifiers, CaseOutcome, WorkloadObservation,
};
use lispex::Decision;
use sha2::{Digest, Sha256};
use vouch::artifact_json::{
    canonical_gate, write_canonical, JsonValue, RawArtifactKind, MAX_ARTIFACT_BYTES,
};
use vouch::io_boundary::{FileProvider, FrozenBytes, OsFileProvider};
use vouch::release::{parse_supplied_corpus, verify_replay_manifest, ReplayArtifacts, ReplayCase};

const CHECKED_PROFILE: &str = "csk.checked-profile/v1";
const EXECUTION_REPORT_TAG: &str = "vouch.scored26-workload-execution/v0";
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
    "--key-handle",
    "--receipt-root",
    "--execution-report",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct CaseMetadata {
    case_id: String,
    partition: String,
    stratum_id: String,
    candidate_class: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordedOutcome {
    Decision(Decision),
    ProfileEscape,
    NotComparable,
    PipelineFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutionObservation {
    outcome: RecordedOutcome,
    receipt_payload_sha256: Option<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok((cases, receipts)) => {
            println!(
                "SCORED26 authenticated workload execution passed ({cases} cases/{receipts} receipts)"
            );
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("scored26-workload-runner: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(usize, usize), String> {
    let arguments = parse_arguments(std::env::args().skip(1))?;
    let receipt_root = PathBuf::from(&arguments["--receipt-root"]);
    let execution_report = PathBuf::from(&arguments["--execution-report"]);
    if receipt_root.exists() {
        return Err("receipt root already exists".to_string());
    }
    if execution_report.exists() {
        return Err("execution report already exists".to_string());
    }

    // Every supplied path is opened exactly once. FrozenBytes owns the buffers
    // used by verification and all later executions.
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

    // No execution output exists before the complete authentication and order
    // checks above have succeeded.
    fs::create_dir(&receipt_root)
        .map_err(|error| format!("cannot create receipt root: {error}"))?;

    let rules = [
        ("baseline", files["--baseline-rule"].bytes()),
        ("changed", files["--changed-rule"].bytes()),
    ];
    let key_handle = &arguments["--key-handle"];
    let mut covered = BTreeSet::new();
    let mut total = BTreeSet::new();
    let mut records = Vec::with_capacity(verified.cases().len());
    let mut receipt_count = 0_usize;

    verified
        .execute(|case| {
            let case_metadata = metadata
                .get(case.case_id())
                .ok_or_else(|| format!("{}: missing split metadata", case.case_id()))?;
            let case_root = receipt_root.join(case.case_id());
            fs::create_dir(&case_root)
                .map_err(|error| format!("{}: cannot create output: {error}", case.case_id()))?;
            let mut executions = Vec::with_capacity(2);
            for (rule_version, source) in rules {
                let output = case_root.join(rule_version);
                let output_text = output
                    .to_str()
                    .ok_or_else(|| "receipt output path is not UTF-8".to_string())?;
                let issued = issue_native_bytes(
                    source,
                    case.canonical_input_bytes(),
                    CHECKED_PROFILE,
                    key_handle,
                    output_text,
                );
                let execution = classify_issuance(&issued, &output)?;
                if execution.receipt_payload_sha256.is_some() {
                    receipt_count += 1;
                }

                let observation = evaluate_workload_case(source, case.canonical_input_bytes());
                require_receipt_observer_agreement(
                    case.case_id(),
                    rule_version,
                    execution.outcome,
                    &observation,
                )?;
                accumulate_coverage(rule_version, &observation, &mut covered, &mut total);
                executions.push((rule_version, execution));
            }
            records.push(execution_record(case_metadata, &executions)?);
            Ok::<(), String>(())
        })
        .map_err(|error| format!("execution failed: {error}"))?;

    let uncovered = total.difference(&covered).cloned().collect::<Vec<_>>();
    let report = JsonValue::object([
        (
            "workload_execution_report",
            JsonValue::String(EXECUTION_REPORT_TAG.to_string()),
        ),
        (
            "checked_profile",
            JsonValue::String(CHECKED_PROFILE.to_string()),
        ),
        (
            "selected_case_count",
            JsonValue::Integer(records.len() as i64),
        ),
        (
            "execution_count",
            JsonValue::Integer((records.len() * 2) as i64),
        ),
        ("receipt_count", JsonValue::Integer(receipt_count as i64)),
        ("cases", JsonValue::Array(records)),
        (
            "coverage",
            JsonValue::object([
                (
                    "covered",
                    JsonValue::Array(covered.into_iter().map(JsonValue::String).collect()),
                ),
                (
                    "uncovered",
                    JsonValue::Array(uncovered.into_iter().map(JsonValue::String).collect()),
                ),
                (
                    "total",
                    JsonValue::Array(total.into_iter().map(JsonValue::String).collect()),
                ),
            ])
            .map_err(|error| error.to_string())?,
        ),
    ])
    .map_err(|error| error.to_string())?;
    let bytes = write_canonical(&report).map_err(|error| error.to_string())?;
    publish_file(&execution_report, &bytes)?;
    Ok((verified.cases().len(), receipt_count))
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
            stratum_id: string(field(row, "stratum_id")?, "stratum_id")?.to_string(),
            candidate_class: string(field(row, "candidate_class")?, "candidate_class")?.to_string(),
        };
        if !matches!(metadata.partition.as_str(), "development" | "held-out")
            || !matches!(
                metadata.candidate_class.as_str(),
                "boundary" | "interior" | "invalid"
            )
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

fn classify_issuance(issued: &IssueOutcome, output: &Path) -> Result<ExecutionObservation, String> {
    if issued.exit_code == 0 {
        if !issued.published || issued.primary_error.is_some() || issued.reason.is_some() {
            return Err("successful issuer returned inconsistent status".to_string());
        }
        let payload_path = output.join("payload.json");
        let payload = fs::read(&payload_path)
            .map_err(|error| format!("cannot read issued payload: {error}"))?;
        if payload.len() > MAX_ARTIFACT_BYTES {
            return Err("issued payload exceeds artifact limit".to_string());
        }
        let decision = receipt_decision(&payload)?;
        let digest = format!("sha256:{:x}", Sha256::digest(&payload));
        return Ok(ExecutionObservation {
            outcome: RecordedOutcome::Decision(decision),
            receipt_payload_sha256: Some(digest),
        });
    }
    if issued.primary_error.is_none() && issued.published {
        return Err("failed issuer returned no primary error".to_string());
    }
    let outcome = match issued.primary_error {
        Some(IssuePrimaryError::ProfileEscape) => RecordedOutcome::ProfileEscape,
        Some(IssuePrimaryError::NativeResultNotSignable)
            if matches!(
                issued.reason,
                Some(
                    SignabilityReason::ComparisonNotAgree
                        | SignabilityReason::TerminalNotCompleted
                        | SignabilityReason::FinalValueNotDecision
                )
            ) =>
        {
            RecordedOutcome::NotComparable
        }
        _ => RecordedOutcome::PipelineFailure,
    };
    Ok(ExecutionObservation {
        outcome,
        receipt_payload_sha256: None,
    })
}

fn receipt_decision(bytes: &[u8]) -> Result<Decision, String> {
    let canonical = canonical_gate(bytes, RawArtifactKind::Payload)
        .map_err(|error| format!("issued payload is not canonical: {error}"))?;
    let root = object(canonical.value(), "receipt")?;
    if string(field(root, "differential_receipt")?, "differential_receipt")?
        != "csk.differential-receipt/v0"
    {
        return Err("issued payload has the wrong receipt tag".to_string());
    }
    if string(
        field(object(field(root, "comparison")?, "comparison")?, "status")?,
        "comparison status",
    )? != "agree"
        || !array(field(root, "diagnostics")?, "diagnostics")?.is_empty()
    {
        return Err("issued receipt is not release-eligible".to_string());
    }
    let reference = transcript_decision(field(root, "reference")?, "reference")?;
    let meaning = transcript_decision(field(root, "meaning_env")?, "meaning_env")?;
    if reference != meaning {
        return Err("issued receipt decisions disagree".to_string());
    }
    Ok(reference)
}

fn transcript_decision(value: &JsonValue, label: &str) -> Result<Decision, String> {
    let report = object(value, label)?;
    let transcript = object(field(report, "transcript")?, "transcript")?;
    let terminal = object(field(transcript, "terminal")?, "terminal")?;
    if string(field(terminal, "kind")?, "terminal kind")? != "completed" {
        return Err(format!("{label} transcript is not completed"));
    }
    let events = array(field(transcript, "events")?, "events")?;
    let event = object(
        events
            .last()
            .ok_or_else(|| format!("{label} transcript has no final event"))?,
        "final event",
    )?;
    let value = object(field(event, "value")?, "final value")?;
    if string(field(value, "t")?, "final value tag")? != "decision" {
        return Err(format!("{label} final value is not a decision"));
    }
    parse_decision(string(field(value, "v")?, "decision label")?)
}

fn parse_decision(value: &str) -> Result<Decision, String> {
    match value {
        "approve" => Ok(Decision::Approve),
        "deny" => Ok(Decision::Deny),
        "review" => Ok(Decision::Review),
        "invalid-input" => Ok(Decision::InvalidInput),
        _ => Err(format!("unknown decision `{value}`")),
    }
}

fn require_receipt_observer_agreement(
    case_id: &str,
    rule_version: &str,
    receipt: RecordedOutcome,
    observation: &WorkloadObservation,
) -> Result<(), String> {
    let matches = match (receipt, observation.outcome) {
        (RecordedOutcome::Decision(left), CaseOutcome::Decision(right)) => left == right,
        (RecordedOutcome::ProfileEscape, CaseOutcome::ProfileEscape)
        | (RecordedOutcome::NotComparable, CaseOutcome::NotComparable) => true,
        // Pipeline failures can occur after evaluation (for example at key or
        // publication I/O), so the coverage observer is not required to fail.
        (RecordedOutcome::PipelineFailure, _) => true,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(format!(
            "{case_id}/{rule_version}: receipt and coverage observer disagree"
        ))
    }
}

fn accumulate_coverage(
    rule_version: &str,
    observation: &WorkloadObservation,
    covered: &mut BTreeSet<String>,
    total: &mut BTreeSet<String>,
) {
    let (covered_nodes, total_nodes, covered_branches, total_branches) =
        stable_coverage_identifiers(rule_version, &observation.coverage);
    covered.extend(covered_nodes);
    covered.extend(covered_branches);
    total.extend(total_nodes);
    total.extend(total_branches);
}

fn execution_record(
    metadata: &CaseMetadata,
    executions: &[(&str, ExecutionObservation)],
) -> Result<JsonValue, String> {
    let get = |version: &str| {
        executions
            .iter()
            .find(|(name, _)| *name == version)
            .map(|(_, observation)| observation)
            .ok_or_else(|| format!("{}: missing {version} execution", metadata.case_id))
    };
    JsonValue::object([
        ("case_id", JsonValue::String(metadata.case_id.clone())),
        ("partition", JsonValue::String(metadata.partition.clone())),
        ("stratum_id", JsonValue::String(metadata.stratum_id.clone())),
        (
            "candidate_class",
            JsonValue::String(metadata.candidate_class.clone()),
        ),
        ("baseline", execution_json(get("baseline")?)?),
        ("changed", execution_json(get("changed")?)?),
    ])
    .map_err(|error| error.to_string())
}

fn execution_json(execution: &ExecutionObservation) -> Result<JsonValue, String> {
    JsonValue::object([
        ("outcome", outcome_json(execution.outcome)?),
        (
            "receipt_payload_sha256",
            execution
                .receipt_payload_sha256
                .as_ref()
                .map(|value| JsonValue::String(value.clone()))
                .unwrap_or(JsonValue::Null),
        ),
    ])
    .map_err(|error| error.to_string())
}

fn outcome_json(outcome: RecordedOutcome) -> Result<JsonValue, String> {
    let members = match outcome {
        RecordedOutcome::Decision(decision) => vec![
            ("kind", JsonValue::String("decision".to_string())),
            (
                "label",
                JsonValue::String(decision_label(decision).to_string()),
            ),
        ],
        RecordedOutcome::ProfileEscape => {
            vec![("kind", JsonValue::String("profile-escape".to_string()))]
        }
        RecordedOutcome::NotComparable => {
            vec![("kind", JsonValue::String("not-comparable".to_string()))]
        }
        RecordedOutcome::PipelineFailure => {
            vec![("kind", JsonValue::String("pipeline-failure".to_string()))]
        }
    };
    JsonValue::object(members).map_err(|error| error.to_string())
}

fn decision_label(decision: Decision) -> &'static str {
    match decision {
        Decision::Approve => "approve",
        Decision::Deny => "deny",
        Decision::Review => "review",
        Decision::InvalidInput => "invalid-input",
    }
}

fn publish_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| format!("cannot create report parent: {error}"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "execution report path has no UTF-8 filename".to_string())?;
    let staging = parent.join(format!(".{name}.stage-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staging)
        .map_err(|error| format!("cannot create staged report: {error}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write staged report: {error}"))?;
    fs::rename(&staging, path).map_err(|error| format!("cannot publish report: {error}"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync report parent: {error}"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_outcome_json_has_no_boolean_decision_alias() {
        let decision = outcome_json(RecordedOutcome::Decision(Decision::Approve)).unwrap();
        let decision = decision.as_object().unwrap();
        assert_eq!(decision.get("kind").unwrap().as_str(), Some("decision"));
        assert_eq!(decision.get("label").unwrap().as_str(), Some("approve"));
        assert_eq!(
            outcome_json(RecordedOutcome::NotComparable)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn malformed_or_duplicate_arguments_fail_closed() {
        assert!(parse_arguments(["--envelope".to_string()].into_iter()).is_err());
        assert!(
            parse_arguments(["--unknown".to_string(), "value".to_string(),].into_iter()).is_err()
        );
    }
}
