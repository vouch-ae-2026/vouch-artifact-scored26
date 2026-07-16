//! Checked-external Bridge verification for the dormant SCORED contract lane.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use vouch::artifact_json::{
    canonical_gate, write_canonical, JsonGateError, JsonValue, RawArtifactKind,
};
use vouch::io_boundary::{AtomicPublisher, FileProvider, IoBoundaryError};
use vouch::policy::profile_identifier_valid;

use super::{checked_input::MAX_INPUT_BYTES, checked_profile::MAX_SOURCE_BYTES};

pub const BRIDGE_REPORT_TAG: &str = "vouch.bridge-report/v0";
pub const BRIDGE_VERIFY_REPORT_TAG: &str = "vouch.bridge-verify-report/v0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeVerificationError {
    ArtifactResourceLimit,
    NonCanonicalArtifactJson,
    UnsupportedBridgeVersion,
    BridgeReportSchema,
    BridgeProfileMismatch,
    BridgeEngineMismatch,
    BridgeSourceMismatch,
    BridgeInputMismatch,
    BridgeInputCanonicalValueMismatch,
}

impl BridgeVerificationError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ArtifactResourceLimit => "artifact-resource-limit",
            Self::NonCanonicalArtifactJson => "non-canonical-artifact-json",
            Self::UnsupportedBridgeVersion => "unsupported-bridge-version",
            Self::BridgeReportSchema => "bridge-report-schema",
            Self::BridgeProfileMismatch => "bridge-profile-mismatch",
            Self::BridgeEngineMismatch => "bridge-engine-mismatch",
            Self::BridgeSourceMismatch => "bridge-source-mismatch",
            Self::BridgeInputMismatch => "bridge-input-mismatch",
            Self::BridgeInputCanonicalValueMismatch => "bridge-input-canonical-value-mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BridgeExpectedContext<'a> {
    pub profile: &'a str,
    pub engine_sha256: &'a str,
    pub source: &'a [u8],
    pub input: &'a [u8],
    pub input_canonical_value_sha256: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct BridgePathRequest<'a> {
    pub report: &'a str,
    pub profile: &'a str,
    pub engine_sha256: &'a str,
    pub source: &'a str,
    pub input: &'a str,
    pub input_canonical_value_sha256: &'a str,
    pub report_out: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgePathOutcome {
    pub exit_code: u8,
    pub primary_error: Option<BridgeVerificationError>,
}

#[derive(Clone, Debug)]
struct BridgeSnapshot {
    canonical_report_bytes: Vec<u8>,
    report: JsonValue,
    profile: String,
    engine_sha256: String,
    source_sha256: String,
    input_sha256: String,
    input_canonical_value_sha256: String,
}

/// Opaque checked-external evidence. Construction is private to `verify_bridge`.
#[derive(Clone, Debug)]
pub struct CheckedBridgeEvidence {
    snapshot: BridgeSnapshot,
}

impl CheckedBridgeEvidence {
    pub const fn status(&self) -> &'static str {
        "checked-external"
    }

    pub fn canonical_report_bytes(&self) -> &[u8] {
        &self.snapshot.canonical_report_bytes
    }

    pub fn report(&self) -> &JsonValue {
        &self.snapshot.report
    }

    pub fn verify_report(&self) -> BridgeVerifyReport {
        checked_report(&self.snapshot)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeVerifyReport {
    Checked {
        profile: String,
        engine_sha256: String,
        source_sha256: String,
        input_sha256: String,
        input_canonical_value_sha256: String,
        comparison_status: String,
        decision: Option<String>,
    },
    Rejected {
        primary_error: BridgeVerificationError,
    },
}

impl BridgeVerifyReport {
    pub const fn rejected(primary_error: BridgeVerificationError) -> Self {
        Self::Rejected { primary_error }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let value = match self {
            Self::Checked {
                profile,
                engine_sha256,
                source_sha256,
                input_sha256,
                input_canonical_value_sha256,
                comparison_status,
                decision,
            } => JsonValue::object([
                (
                    "bridge_verify_report",
                    JsonValue::String(BRIDGE_VERIFY_REPORT_TAG.to_string()),
                ),
                ("status", JsonValue::String("checked-external".to_string())),
                ("primary_error", JsonValue::Null),
                ("profile", JsonValue::String(profile.clone())),
                ("engine_sha256", JsonValue::String(engine_sha256.clone())),
                ("source_sha256", JsonValue::String(source_sha256.clone())),
                ("input_sha256", JsonValue::String(input_sha256.clone())),
                (
                    "input_canonical_value_sha256",
                    JsonValue::String(input_canonical_value_sha256.clone()),
                ),
                (
                    "comparison_status",
                    JsonValue::String(comparison_status.clone()),
                ),
                (
                    "decision",
                    decision
                        .as_ref()
                        .map_or(JsonValue::Null, |value| JsonValue::String(value.clone())),
                ),
            ])
            .expect("Bridge checked report members are unique"),
            Self::Rejected { primary_error } => JsonValue::object([
                (
                    "bridge_verify_report",
                    JsonValue::String(BRIDGE_VERIFY_REPORT_TAG.to_string()),
                ),
                ("status", JsonValue::String("rejected".to_string())),
                (
                    "primary_error",
                    JsonValue::String(primary_error.code().to_string()),
                ),
            ])
            .expect("Bridge rejection report members are unique"),
        };
        write_canonical(&value).expect("Bridge reports contain only canonical strings")
    }
}

pub fn verify_bridge(
    report_bytes: &[u8],
    expected: BridgeExpectedContext<'_>,
) -> Result<CheckedBridgeEvidence, BridgeVerificationError> {
    verify_bridge_snapshot(report_bytes, expected)
        .map(|snapshot| CheckedBridgeEvidence { snapshot })
}

fn verify_bridge_snapshot(
    report_bytes: &[u8],
    expected: BridgeExpectedContext<'_>,
) -> Result<BridgeSnapshot, BridgeVerificationError> {
    // The Rust API receives borrowed values, so one owned entry copy closes every
    // subsequent caller-mutation and path-replacement opportunity.
    let report_bytes = report_bytes.to_vec();
    let profile = expected.profile.to_string();
    let engine_sha256 = expected.engine_sha256.to_string();
    let source = expected.source.to_vec();
    let input = expected.input.to_vec();
    let input_canonical_value_sha256 = expected.input_canonical_value_sha256.to_string();

    if !profile_identifier_valid(&profile)
        || !executable_digest_valid(&engine_sha256)
        || !hex64(&input_canonical_value_sha256)
    {
        return Err(BridgeVerificationError::BridgeReportSchema);
    }

    // Step 1.
    if report_bytes.len() > vouch::artifact_json::MAX_ARTIFACT_BYTES
        || source.len() > MAX_SOURCE_BYTES
        || input.len() > MAX_INPUT_BYTES
    {
        return Err(BridgeVerificationError::ArtifactResourceLimit);
    }

    // Step 2.
    let canonical = canonical_gate(&report_bytes, RawArtifactKind::BridgeReport).map_err(
        |error| match error {
            JsonGateError::ResourceLimit(_) => BridgeVerificationError::ArtifactResourceLimit,
            JsonGateError::NonCanonicalArtifactJson => {
                BridgeVerificationError::NonCanonicalArtifactJson
            }
        },
    )?;

    // Step 3 may inspect only the discriminator.
    if let Some(discriminator) = discriminator(canonical.value()) {
        if unsupported_bridge_version(discriminator) {
            return Err(BridgeVerificationError::UnsupportedBridgeVersion);
        }
    }

    // Step 4.
    let parsed =
        parse_report(canonical.value()).ok_or(BridgeVerificationError::BridgeReportSchema)?;

    // Steps 5--9.
    if parsed.profile != profile {
        return Err(BridgeVerificationError::BridgeProfileMismatch);
    }
    if parsed.engine_sha256 != engine_sha256 {
        return Err(BridgeVerificationError::BridgeEngineMismatch);
    }
    let source_sha256 = sha256_hex(&source);
    if parsed.source_sha256 != source_sha256 {
        return Err(BridgeVerificationError::BridgeSourceMismatch);
    }
    let input_sha256 = sha256_hex(&input);
    if parsed.input_sha256 != input_sha256 {
        return Err(BridgeVerificationError::BridgeInputMismatch);
    }
    if parsed.input_canonical_value_sha256 != input_canonical_value_sha256 {
        return Err(BridgeVerificationError::BridgeInputCanonicalValueMismatch);
    }

    Ok(BridgeSnapshot {
        canonical_report_bytes: canonical.bytes().to_vec(),
        report: canonical.value().clone(),
        profile,
        engine_sha256,
        source_sha256,
        input_sha256,
        input_canonical_value_sha256,
    })
}

/// Read each CLI input path exactly once, verify only private copies, and
/// publish one canonical report without replacing an existing final path.
pub fn verify_bridge_paths_with(
    request: BridgePathRequest<'_>,
    provider: &dyn FileProvider,
    publisher: &dyn AtomicPublisher,
) -> Result<BridgePathOutcome, IoBoundaryError> {
    let report = provider.read_once(request.report, vouch::artifact_json::MAX_ARTIFACT_BYTES);
    let source = provider.read_once(request.source, MAX_SOURCE_BYTES);
    let input = provider.read_once(request.input, MAX_INPUT_BYTES);

    for observation in [&report, &source, &input] {
        if let Err(error) = observation {
            if *error != IoBoundaryError::ResourceLimit {
                return Err(error.clone());
            }
        }
    }

    let result = if [&report, &source, &input]
        .iter()
        .any(|observation| matches!(observation, Err(IoBoundaryError::ResourceLimit)))
    {
        Err(BridgeVerificationError::ArtifactResourceLimit)
    } else {
        let report = report.expect("non-resource input failures returned above");
        let source = source.expect("non-resource input failures returned above");
        let input = input.expect("non-resource input failures returned above");
        let report_bytes = report.bytes().to_vec();
        let source_bytes = source.bytes().to_vec();
        let input_bytes = input.bytes().to_vec();
        verify_bridge_snapshot(
            &report_bytes,
            BridgeExpectedContext {
                profile: request.profile,
                engine_sha256: request.engine_sha256,
                source: &source_bytes,
                input: &input_bytes,
                input_canonical_value_sha256: request.input_canonical_value_sha256,
            },
        )
    };

    match result {
        Ok(snapshot) => {
            let report = checked_report(&snapshot);
            publisher.publish(request.report_out, &report.canonical_bytes())?;
            // Output publication is part of the CLI minting precondition. The
            // capability is constructed only after the final path exists.
            let evidence = CheckedBridgeEvidence { snapshot };
            debug_assert_eq!(evidence.status(), "checked-external");
            Ok(BridgePathOutcome {
                exit_code: 0,
                primary_error: None,
            })
        }
        Err(error) => {
            let report = BridgeVerifyReport::rejected(error);
            publisher.publish(request.report_out, &report.canonical_bytes())?;
            Ok(BridgePathOutcome {
                exit_code: 1,
                primary_error: Some(error),
            })
        }
    }
}

fn checked_report(snapshot: &BridgeSnapshot) -> BridgeVerifyReport {
    let parsed = parse_report(&snapshot.report)
        .expect("a checked Bridge snapshot retains its validated report");
    BridgeVerifyReport::Checked {
        profile: snapshot.profile.clone(),
        engine_sha256: snapshot.engine_sha256.clone(),
        source_sha256: snapshot.source_sha256.clone(),
        input_sha256: snapshot.input_sha256.clone(),
        input_canonical_value_sha256: snapshot.input_canonical_value_sha256.clone(),
        comparison_status: parsed.comparison_status.to_string(),
        decision: parsed.decision.map(str::to_string),
    }
}

struct ParsedBridgeReport<'a> {
    profile: &'a str,
    engine_sha256: &'a str,
    source_sha256: &'a str,
    input_sha256: &'a str,
    input_canonical_value_sha256: &'a str,
    comparison_status: &'a str,
    decision: Option<&'a str>,
}

fn parse_report(value: &JsonValue) -> Option<ParsedBridgeReport<'_>> {
    let object = exact_object(
        value,
        &[
            "bridge_report",
            "profile",
            "engine_sha256",
            "source_sha256",
            "input_sha256",
            "input_canonical_value_sha256",
            "comparison_status",
            "decision",
            "diagnostics",
        ],
    )?;
    if string(object, "bridge_report")? != BRIDGE_REPORT_TAG {
        return None;
    }
    let profile = string(object, "profile")?;
    let engine_sha256 = string(object, "engine_sha256")?;
    let source_sha256 = string(object, "source_sha256")?;
    let input_sha256 = string(object, "input_sha256")?;
    let input_canonical_value_sha256 = string(object, "input_canonical_value_sha256")?;
    let comparison_status = string(object, "comparison_status")?;
    if !profile_identifier_valid(profile)
        || !executable_digest_valid(engine_sha256)
        || !hex64(source_sha256)
        || !hex64(input_sha256)
        || !hex64(input_canonical_value_sha256)
        || !matches!(comparison_status, "agree" | "disagree" | "not-comparable")
    {
        return None;
    }
    let decision = match object.get("decision")? {
        JsonValue::Null => None,
        JsonValue::String(value)
            if matches!(
                value.as_str(),
                "approve" | "deny" | "review" | "invalid-input"
            ) =>
        {
            Some(value.as_str())
        }
        _ => return None,
    };
    if comparison_status != "agree" && decision.is_some() {
        return None;
    }
    let diagnostics = object.get("diagnostics")?.as_array()?;
    for diagnostic in diagnostics {
        let diagnostic = exact_object(diagnostic, &["code", "message"])?;
        let code = string(diagnostic, "code")?;
        let message = string(diagnostic, "message")?;
        if diagnostic_sensitive(code) || diagnostic_sensitive(message) {
            return None;
        }
    }
    Some(ParsedBridgeReport {
        profile,
        engine_sha256,
        source_sha256,
        input_sha256,
        input_canonical_value_sha256,
        comparison_status,
        decision,
    })
}

fn exact_object<'a>(
    value: &'a JsonValue,
    names: &[&str],
) -> Option<&'a BTreeMap<String, JsonValue>> {
    let object = value.as_object()?;
    if object.len() != names.len() || names.iter().any(|name| !object.contains_key(*name)) {
        return None;
    }
    Some(object)
}

fn string<'a>(object: &'a BTreeMap<String, JsonValue>, name: &str) -> Option<&'a str> {
    object.get(name)?.as_str()
}

fn discriminator(value: &JsonValue) -> Option<&str> {
    value.as_object()?.get("bridge_report")?.as_str()
}

fn unsupported_bridge_version(value: &str) -> bool {
    let Some(version) = value.strip_prefix("vouch.bridge-report/v") else {
        return false;
    };
    !version.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && version.bytes().any(|byte| byte != b'0')
}

pub fn executable_digest_valid(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(hex64)
}

pub fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn diagnostic_sensitive(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "secret",
        "private key",
        "private-key",
        "public key",
        "public-key",
        "panic",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || value
            .split_ascii_whitespace()
            .any(|word| word.starts_with('/') || windows_absolute_path(word))
}

fn windows_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use vouch::io_boundary::{AtomicPublisher, MemoryAtomicPublisher, MemoryFileProvider};

    const PROFILE: &str = "csk.checked-profile/v1";
    const ENGINE: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const SOURCE: &[u8] = b"source\n";
    const INPUT: &[u8] = b"input\n";
    const INPUT_VALUE: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn expected<'a>() -> BridgeExpectedContext<'a> {
        BridgeExpectedContext {
            profile: PROFILE,
            engine_sha256: ENGINE,
            source: SOURCE,
            input: INPUT,
            input_canonical_value_sha256: INPUT_VALUE,
        }
    }

    fn report(overrides: &[(&str, JsonValue)]) -> Vec<u8> {
        let mut object = match JsonValue::object([
            (
                "bridge_report",
                JsonValue::String(BRIDGE_REPORT_TAG.to_string()),
            ),
            ("profile", JsonValue::String(PROFILE.to_string())),
            ("engine_sha256", JsonValue::String(ENGINE.to_string())),
            ("source_sha256", JsonValue::String(sha256_hex(SOURCE))),
            ("input_sha256", JsonValue::String(sha256_hex(INPUT))),
            (
                "input_canonical_value_sha256",
                JsonValue::String(INPUT_VALUE.to_string()),
            ),
            ("comparison_status", JsonValue::String("agree".to_string())),
            ("decision", JsonValue::String("approve".to_string())),
            ("diagnostics", JsonValue::Array(vec![])),
        ])
        .unwrap()
        {
            JsonValue::Object(value) => value,
            _ => unreachable!(),
        };
        for (name, value) in overrides {
            object.insert((*name).to_string(), value.clone());
        }
        write_canonical(&JsonValue::Object(object)).unwrap()
    }

    #[test]
    fn bridge_order_and_checked_report_are_exact() {
        let evidence = verify_bridge(&report(&[]), expected()).unwrap();
        assert_eq!(evidence.status(), "checked-external");
        assert_eq!(evidence.canonical_report_bytes(), report(&[]));
        let checked = evidence.verify_report().canonical_bytes();
        canonical_gate(&checked, RawArtifactKind::Artifact).unwrap();
        let checked = String::from_utf8(checked).unwrap();
        assert!(checked.contains("\"status\": \"checked-external\""));
        assert!(checked.contains("\"primary_error\": null"));

        let v1 = report(&[(
            "bridge_report",
            JsonValue::String("vouch.bridge-report/v1".to_string()),
        )]);
        assert_eq!(
            verify_bridge(&v1, expected()).unwrap_err(),
            BridgeVerificationError::UnsupportedBridgeVersion
        );
        let v01 = report(&[(
            "bridge_report",
            JsonValue::String("vouch.bridge-report/v01".to_string()),
        )]);
        assert_eq!(
            verify_bridge(&v01, expected()).unwrap_err(),
            BridgeVerificationError::UnsupportedBridgeVersion
        );
        let schema = report(&[("unknown", JsonValue::Bool(true))]);
        assert_eq!(
            verify_bridge(&schema, expected()).unwrap_err(),
            BridgeVerificationError::BridgeReportSchema
        );
        let profile = report(&[("profile", JsonValue::String("other.profile/v0".to_string()))]);
        assert_eq!(
            verify_bridge(&profile, expected()).unwrap_err(),
            BridgeVerificationError::BridgeProfileMismatch
        );
    }

    #[test]
    fn bridge_context_mismatches_follow_fixed_precedence() {
        let wrong_engine =
            "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        let cases = [
            (
                vec![("engine_sha256", JsonValue::String(wrong_engine.to_string()))],
                BridgeVerificationError::BridgeEngineMismatch,
            ),
            (
                vec![("source_sha256", JsonValue::String("3".repeat(64)))],
                BridgeVerificationError::BridgeSourceMismatch,
            ),
            (
                vec![("input_sha256", JsonValue::String("3".repeat(64)))],
                BridgeVerificationError::BridgeInputMismatch,
            ),
            (
                vec![(
                    "input_canonical_value_sha256",
                    JsonValue::String("3".repeat(64)),
                )],
                BridgeVerificationError::BridgeInputCanonicalValueMismatch,
            ),
        ];
        for (overrides, expected_error) in cases {
            assert_eq!(
                verify_bridge(&report(&overrides), expected()).unwrap_err(),
                expected_error
            );
        }
    }

    #[test]
    fn bridge_resource_and_canonical_errors_precede_schema() {
        assert_eq!(
            verify_bridge(
                &vec![b' '; vouch::artifact_json::MAX_ARTIFACT_BYTES + 1],
                expected()
            )
            .unwrap_err(),
            BridgeVerificationError::ArtifactResourceLimit
        );
        assert_eq!(
            verify_bridge(
                b"{\"bridge_report\":\"vouch.bridge-report/v1\"}\n",
                expected()
            )
            .unwrap_err(),
            BridgeVerificationError::NonCanonicalArtifactJson
        );
    }

    #[test]
    fn bridge_path_boundary_reads_three_times_and_never_replaces_output() {
        let provider = MemoryFileProvider::default();
        provider.insert("report", report(&[]));
        provider.insert("source", SOURCE.to_vec());
        provider.insert("input", INPUT.to_vec());
        let publisher = MemoryAtomicPublisher::default();
        let request = BridgePathRequest {
            report: "report",
            profile: PROFILE,
            engine_sha256: ENGINE,
            source: "source",
            input: "input",
            input_canonical_value_sha256: INPUT_VALUE,
            report_out: "out",
        };
        let outcome = verify_bridge_paths_with(request, &provider, &publisher).unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(provider.read_count(), 3);
        assert_eq!(publisher.final_rename_count(), 1);
        assert!(publisher.read("out").is_some());

        assert_eq!(
            verify_bridge_paths_with(request, &provider, &publisher),
            Err(IoBoundaryError::OutputExists)
        );
        assert_eq!(provider.read_count(), 6);
        assert_eq!(publisher.final_rename_count(), 1);
    }
}
