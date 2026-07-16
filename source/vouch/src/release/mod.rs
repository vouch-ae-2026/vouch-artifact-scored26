//! Signed replay-corpus manifest verification.
//!
//! The verifier owns every input buffer before it authenticates or compares
//! anything. A caller may execute the returned ordered corpus only after this
//! module has authenticated the manifest and checked every frozen artifact,
//! rule byte string, case identifier, position, count, and canonical input
//! hash.

use crate::artifact_json::{
    canonical_gate, JsonGateError, JsonValue, RawArtifactKind, MAX_ARTIFACT_BYTES,
};
use crate::dsse::{
    ordinary_sha256, verify_envelope, DsseError, Envelope, PayloadType,
    REPLAY_MANIFEST_PAYLOAD_TYPE,
};
use crate::io_boundary::FrozenBytes;
use crate::policy::{parse_native_trust_policy, PolicyError};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;

pub const REPLAY_MANIFEST_TAG: &str = "csk.replay-corpus-manifest/v0";
pub const REPLAY_CORPUS_TAG: &str = "csk.replay-corpus/v0";
pub const RULE_HASH_DOMAIN: &str = "vouch/rule-source/v0";

const CHECKED_PROFILE: &str = "csk.checked-profile/v1";
const EXPECTED_SCHEMA_VERSIONS: &[(&str, &str)] = &[
    ("checked_input", "csk.checked-input/v1"),
    ("holdout_plan", "vouch.scored26-holdout-plan/v0"),
    ("workload_selection", "vouch.scored26-workload-selection/v0"),
    ("workload_space", "vouch.scored26-workload-space/v0"),
    ("workload_split", "vouch.scored26-workload-split/v0"),
];

#[derive(Clone, Debug)]
pub struct ReplayCase {
    case_id: String,
    canonical_input: FrozenBytes,
}

impl ReplayCase {
    pub fn new(case_id: impl Into<String>, canonical_input: &[u8]) -> Self {
        Self {
            case_id: case_id.into(),
            canonical_input: FrozenBytes::from_slice(canonical_input),
        }
    }

    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    pub fn canonical_input_bytes(&self) -> &[u8] {
        self.canonical_input.bytes()
    }
}

#[derive(Clone, Debug)]
pub struct ReplayArtifacts {
    workload_space: FrozenBytes,
    workload_selection: FrozenBytes,
    workload_split: FrozenBytes,
    holdout_plan: FrozenBytes,
}

impl ReplayArtifacts {
    pub fn from_slices(
        workload_space: &[u8],
        workload_selection: &[u8],
        workload_split: &[u8],
        holdout_plan: &[u8],
    ) -> Self {
        Self {
            workload_space: FrozenBytes::from_slice(workload_space),
            workload_selection: FrozenBytes::from_slice(workload_selection),
            workload_split: FrozenBytes::from_slice(workload_split),
            holdout_plan: FrozenBytes::from_slice(holdout_plan),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManifestCase {
    case_id: String,
    canonical_input_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayManifest {
    ordered_cases: Vec<ManifestCase>,
    baseline_rule_sha256: String,
    changed_rule_sha256: String,
    expected_case_count: usize,
    workload_space_sha256: String,
    workload_selection_sha256: String,
    workload_split_sha256: String,
    holdout_plan_sha256: String,
    checked_profile: String,
}

impl ReplayManifest {
    pub fn expected_case_count(&self) -> usize {
        self.expected_case_count
    }

    pub fn checked_profile(&self) -> &str {
        &self.checked_profile
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedReplayCorpus {
    manifest: ReplayManifest,
    cases: Vec<ReplayCase>,
}

impl VerifiedReplayCorpus {
    pub fn manifest(&self) -> &ReplayManifest {
        &self.manifest
    }

    pub fn cases(&self) -> &[ReplayCase] {
        &self.cases
    }

    /// Execution is deliberately a separate operation available only on the
    /// post-verification capability.
    pub fn execute<E>(
        &self,
        mut executor: impl FnMut(&ReplayCase) -> Result<(), E>,
    ) -> Result<usize, E> {
        for case in &self.cases {
            executor(case)?;
        }
        Ok(self.cases.len())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayError {
    ArtifactResourceLimit,
    NonCanonicalArtifactJson,
    NativeEnvelopeSchema,
    NativePayloadType,
    NativeBase64Invalid,
    NativeTrustPolicyInvalid,
    NativeSchemaVersionBelowPolicy,
    UntrustedNativeKey,
    NativePayloadTypeDisallowed,
    NativeProfileDisallowed,
    NativeSignatureInvalid,
    ReplayManifestInvalid,
    ReplayArtifactMismatch,
    ReplayRuleMismatch,
    ReplayCorpusMemberMissing,
    ReplayCorpusOrderMismatch,
    ReplayCorpusInputMismatch,
}

impl ReplayError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ArtifactResourceLimit => "artifact-resource-limit",
            Self::NonCanonicalArtifactJson => "non-canonical-artifact-json",
            Self::NativeEnvelopeSchema => "native-envelope-schema",
            Self::NativePayloadType => "native-payload-type",
            Self::NativeBase64Invalid => "native-base64-invalid",
            Self::NativeTrustPolicyInvalid => "native-trust-policy-invalid",
            Self::NativeSchemaVersionBelowPolicy => "native-schema-version-below-policy",
            Self::UntrustedNativeKey => "untrusted-native-key",
            Self::NativePayloadTypeDisallowed => "native-payload-type-disallowed",
            Self::NativeProfileDisallowed => "native-profile-disallowed",
            Self::NativeSignatureInvalid => "native-signature-invalid",
            Self::ReplayManifestInvalid => "replay-corpus-manifest-invalid",
            Self::ReplayArtifactMismatch => "replay-artifact-mismatch",
            Self::ReplayRuleMismatch => "replay-rule-mismatch",
            Self::ReplayCorpusMemberMissing => "replay-corpus-member-missing",
            Self::ReplayCorpusOrderMismatch => "replay-corpus-order-mismatch",
            Self::ReplayCorpusInputMismatch => "replay-corpus-input-mismatch",
        }
    }
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl Error for ReplayError {}

/// Authenticate and compare every replay precondition before returning the
/// only capability that can iterate the supplied corpus.
#[allow(clippy::too_many_arguments)]
pub fn verify_replay_manifest(
    envelope_bytes: &[u8],
    trust_policy_bytes: &[u8],
    baseline_rule_bytes: &[u8],
    changed_rule_bytes: &[u8],
    artifacts: &ReplayArtifacts,
    supplied_cases: &[ReplayCase],
) -> Result<VerifiedReplayCorpus, ReplayError> {
    let envelope_owned = FrozenBytes::from_slice(envelope_bytes);
    let policy_owned = FrozenBytes::from_slice(trust_policy_bytes);
    let baseline_owned = FrozenBytes::from_slice(baseline_rule_bytes);
    let changed_owned = FrozenBytes::from_slice(changed_rule_bytes);
    let cases_owned = supplied_cases
        .iter()
        .map(|case| ReplayCase::new(&case.case_id, case.canonical_input.bytes()))
        .collect::<Vec<_>>();

    let envelope_json =
        canonical_gate(envelope_owned.bytes(), RawArtifactKind::Envelope).map_err(map_json_gate)?;
    let envelope = Envelope::from_canonical_json(&envelope_json).map_err(map_envelope_schema)?;
    if envelope.payload_type() != REPLAY_MANIFEST_PAYLOAD_TYPE {
        return Err(ReplayError::NativePayloadType);
    }

    let policy = parse_native_trust_policy(policy_owned.bytes()).map_err(map_policy)?;
    if policy.minimum_versions().replay_corpus_manifest > 0 {
        return Err(ReplayError::NativeSchemaVersionBelowPolicy);
    }
    let signature = envelope
        .signatures()
        .first()
        .ok_or(ReplayError::NativeEnvelopeSchema)?;
    let key = policy
        .select_key(signature.key_id())
        .ok_or(ReplayError::UntrustedNativeKey)?;
    if !key.allows_payload_type(REPLAY_MANIFEST_PAYLOAD_TYPE) {
        return Err(ReplayError::NativePayloadTypeDisallowed);
    }
    let payload = verify_envelope(&envelope, PayloadType::ReplayManifest, key.public_key())
        .map_err(map_signature)?;
    let payload = canonical_gate(&payload, RawArtifactKind::Payload).map_err(map_json_gate)?;
    let manifest = parse_manifest(payload.value())?;
    if !key.allows_profile(&manifest.checked_profile) {
        return Err(ReplayError::NativeProfileDisallowed);
    }

    if rule_hash(baseline_owned.bytes()) != manifest.baseline_rule_sha256
        || rule_hash(changed_owned.bytes()) != manifest.changed_rule_sha256
    {
        return Err(ReplayError::ReplayRuleMismatch);
    }
    let artifact_checks = [
        (
            artifacts.workload_space.bytes(),
            &manifest.workload_space_sha256,
        ),
        (
            artifacts.workload_selection.bytes(),
            &manifest.workload_selection_sha256,
        ),
        (
            artifacts.workload_split.bytes(),
            &manifest.workload_split_sha256,
        ),
        (
            artifacts.holdout_plan.bytes(),
            &manifest.holdout_plan_sha256,
        ),
    ];
    if artifact_checks
        .into_iter()
        .any(|(bytes, expected)| ordinary_sha256(bytes) != *expected)
    {
        return Err(ReplayError::ReplayArtifactMismatch);
    }

    if cases_owned.len() < manifest.expected_case_count {
        return Err(ReplayError::ReplayCorpusMemberMissing);
    }
    if cases_owned.len() > manifest.expected_case_count {
        return Err(ReplayError::ReplayCorpusOrderMismatch);
    }
    for (index, (expected, supplied)) in manifest
        .ordered_cases
        .iter()
        .zip(cases_owned.iter())
        .enumerate()
    {
        if expected.case_id != supplied.case_id {
            let supplied_ids = cases_owned
                .iter()
                .map(|case| case.case_id.as_str())
                .collect::<HashSet<_>>();
            if !supplied_ids.contains(expected.case_id.as_str()) {
                return Err(ReplayError::ReplayCorpusMemberMissing);
            }
            let _ = index;
            return Err(ReplayError::ReplayCorpusOrderMismatch);
        }
        if ordinary_sha256(supplied.canonical_input.bytes()) != expected.canonical_input_sha256 {
            return Err(ReplayError::ReplayCorpusInputMismatch);
        }
    }

    Ok(VerifiedReplayCorpus {
        manifest,
        cases: cases_owned,
    })
}

pub fn parse_supplied_corpus(bytes: &[u8]) -> Result<Vec<ReplayCase>, ReplayError> {
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(ReplayError::ArtifactResourceLimit);
    }
    let canonical = canonical_gate(bytes, RawArtifactKind::Artifact).map_err(map_json_gate)?;
    let root = exact_object(canonical.value(), &["replay_corpus", "cases"])?;
    require_string(root, "replay_corpus", REPLAY_CORPUS_TAG)?;
    let cases = field(root, "cases")?
        .as_array()
        .ok_or(ReplayError::ReplayManifestInvalid)?;
    let mut seen = HashSet::new();
    cases
        .iter()
        .map(|value| {
            let object = exact_object(value, &["case_id", "input"])?;
            let case_id = string(object, "case_id")?;
            if !case_identifier(case_id) || !seen.insert(case_id.to_string()) {
                return Err(ReplayError::ReplayManifestInvalid);
            }
            let input = crate::artifact_json::write_canonical(field(object, "input")?)
                .map_err(|_| ReplayError::ReplayManifestInvalid)?;
            Ok(ReplayCase::new(case_id, &input))
        })
        .collect()
}

pub fn rule_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RULE_HASH_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn parse_manifest(value: &JsonValue) -> Result<ReplayManifest, ReplayError> {
    let root = exact_object(
        value,
        &[
            "replay_corpus_manifest",
            "ordered_cases",
            "baseline_rule_sha256",
            "changed_rule_sha256",
            "expected_case_count",
            "workload_space_sha256",
            "workload_selection_sha256",
            "workload_split_sha256",
            "holdout_plan_sha256",
            "checked_profile",
            "artifact_schema_versions",
        ],
    )?;
    require_string(root, "replay_corpus_manifest", REPLAY_MANIFEST_TAG)?;
    require_string(root, "checked_profile", CHECKED_PROFILE)?;
    let versions = field(root, "artifact_schema_versions")?
        .as_object()
        .ok_or(ReplayError::ReplayManifestInvalid)?;
    if versions.len() != EXPECTED_SCHEMA_VERSIONS.len() {
        return Err(ReplayError::ReplayManifestInvalid);
    }
    for (name, expected) in EXPECTED_SCHEMA_VERSIONS {
        require_string(versions, name, expected)?;
    }
    let expected_case_count = uint(root, "expected_case_count")?;
    let cases = field(root, "ordered_cases")?
        .as_array()
        .ok_or(ReplayError::ReplayManifestInvalid)?;
    if cases.len() != expected_case_count || cases.is_empty() {
        return Err(ReplayError::ReplayManifestInvalid);
    }
    let mut seen = HashSet::new();
    let ordered_cases = cases
        .iter()
        .map(|value| {
            let object = exact_object(value, &["case_id", "canonical_input_sha256"])?;
            let case_id = string(object, "case_id")?.to_string();
            let digest = string(object, "canonical_input_sha256")?.to_string();
            if !case_identifier(&case_id)
                || !digest_identifier(&digest)
                || !seen.insert(case_id.clone())
            {
                return Err(ReplayError::ReplayManifestInvalid);
            }
            Ok(ManifestCase {
                case_id,
                canonical_input_sha256: digest,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let digest = |name| -> Result<String, ReplayError> {
        let value = string(root, name)?.to_string();
        digest_identifier(&value)
            .then_some(value)
            .ok_or(ReplayError::ReplayManifestInvalid)
    };
    Ok(ReplayManifest {
        ordered_cases,
        baseline_rule_sha256: digest("baseline_rule_sha256")?,
        changed_rule_sha256: digest("changed_rule_sha256")?,
        expected_case_count,
        workload_space_sha256: digest("workload_space_sha256")?,
        workload_selection_sha256: digest("workload_selection_sha256")?,
        workload_split_sha256: digest("workload_split_sha256")?,
        holdout_plan_sha256: digest("holdout_plan_sha256")?,
        checked_profile: string(root, "checked_profile")?.to_string(),
    })
}

fn map_json_gate(error: JsonGateError) -> ReplayError {
    match error {
        JsonGateError::ResourceLimit(_) => ReplayError::ArtifactResourceLimit,
        JsonGateError::NonCanonicalArtifactJson => ReplayError::NonCanonicalArtifactJson,
    }
}

fn map_policy(error: PolicyError) -> ReplayError {
    match error {
        PolicyError::ResourceLimit => ReplayError::ArtifactResourceLimit,
        PolicyError::NonCanonicalArtifactJson => ReplayError::NonCanonicalArtifactJson,
        PolicyError::Invalid => ReplayError::NativeTrustPolicyInvalid,
    }
}

fn map_envelope_schema(error: DsseError) -> ReplayError {
    match error {
        DsseError::EnvelopeSchema => ReplayError::NativeEnvelopeSchema,
        DsseError::PayloadType => ReplayError::NativePayloadType,
        DsseError::Base64 => ReplayError::NativeBase64Invalid,
        DsseError::SignatureLength | DsseError::PublicKey | DsseError::SignatureInvalid => {
            ReplayError::NativeSignatureInvalid
        }
    }
}

fn map_signature(error: DsseError) -> ReplayError {
    match error {
        DsseError::EnvelopeSchema => ReplayError::NativeEnvelopeSchema,
        DsseError::PayloadType => ReplayError::NativePayloadType,
        DsseError::Base64 => ReplayError::NativeBase64Invalid,
        DsseError::SignatureLength | DsseError::PublicKey | DsseError::SignatureInvalid => {
            ReplayError::NativeSignatureInvalid
        }
    }
}

fn exact_object<'a>(
    value: &'a JsonValue,
    expected: &[&str],
) -> Result<&'a BTreeMap<String, JsonValue>, ReplayError> {
    let object = value
        .as_object()
        .ok_or(ReplayError::ReplayManifestInvalid)?;
    if object.len() != expected.len() || expected.iter().any(|name| !object.contains_key(*name)) {
        return Err(ReplayError::ReplayManifestInvalid);
    }
    Ok(object)
}

fn field<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a JsonValue, ReplayError> {
    object.get(name).ok_or(ReplayError::ReplayManifestInvalid)
}

fn string<'a>(object: &'a BTreeMap<String, JsonValue>, name: &str) -> Result<&'a str, ReplayError> {
    field(object, name)?
        .as_str()
        .ok_or(ReplayError::ReplayManifestInvalid)
}

fn require_string(
    object: &BTreeMap<String, JsonValue>,
    name: &str,
    expected: &str,
) -> Result<(), ReplayError> {
    (string(object, name)? == expected)
        .then_some(())
        .ok_or(ReplayError::ReplayManifestInvalid)
}

fn uint(object: &BTreeMap<String, JsonValue>, name: &str) -> Result<usize, ReplayError> {
    match field(object, name)? {
        JsonValue::Integer(value) if *value >= 0 => {
            usize::try_from(*value).map_err(|_| ReplayError::ReplayManifestInvalid)
        }
        _ => Err(ReplayError::ReplayManifestInvalid),
    }
}

fn digest_identifier(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn case_identifier(value: &str) -> bool {
    value.len() == 4
        && matches!(value.as_bytes()[0], b'D' | b'H')
        && value.as_bytes()[1..].iter().all(u8::is_ascii_digit)
        && &value[1..] != "000"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_json::{canonical_gate, write_canonical, RawArtifactKind};
    use crate::dsse::{encode_base64, native_key_id, sign_envelope};
    use ed25519_dalek::SigningKey;

    const INPUT_ONE: &[u8] = b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": 1\n}\n";
    const INPUT_TWO: &[u8] = b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": 2\n}\n";
    const BASELINE: &[u8] = b"(decision-deny)\n";
    const CHANGED: &[u8] = b"(decision-approve)\n";
    const SPACE: &[u8] = b"space\n";
    const SELECTION: &[u8] = b"selection\n";
    const SPLIT: &[u8] = b"split\n";
    const HOLDOUT: &[u8] = b"holdout\n";

    struct Fixture {
        envelope: Vec<u8>,
        policy: Vec<u8>,
        artifacts: ReplayArtifacts,
        cases: Vec<ReplayCase>,
        payload: JsonValue,
    }

    impl Fixture {
        fn new(seed: u8) -> Self {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let cases = vec![
                ReplayCase::new("D001", INPUT_ONE),
                ReplayCase::new("H001", INPUT_TWO),
            ];
            let payload = manifest_value(&cases, 2);
            let payload_bytes = write_canonical(&payload).unwrap();
            let canonical = canonical_gate(&payload_bytes, RawArtifactKind::Payload).unwrap();
            let key_id = native_key_id(&key.verifying_key().to_bytes());
            let envelope = sign_envelope(PayloadType::ReplayManifest, &canonical, &key, &key_id)
                .canonical_bytes()
                .unwrap();
            Self {
                policy: policy(&key),
                envelope,
                artifacts: ReplayArtifacts::from_slices(SPACE, SELECTION, SPLIT, HOLDOUT),
                cases,
                payload,
            }
        }

        fn verify(&self) -> Result<VerifiedReplayCorpus, ReplayError> {
            verify_replay_manifest(
                &self.envelope,
                &self.policy,
                BASELINE,
                CHANGED,
                &self.artifacts,
                &self.cases,
            )
        }
    }

    fn manifest_value(cases: &[ReplayCase], expected: usize) -> JsonValue {
        JsonValue::object([
            (
                "replay_corpus_manifest",
                JsonValue::String(REPLAY_MANIFEST_TAG.to_string()),
            ),
            (
                "ordered_cases",
                JsonValue::Array(
                    cases
                        .iter()
                        .map(|case| {
                            JsonValue::object([
                                ("case_id", JsonValue::String(case.case_id.clone())),
                                (
                                    "canonical_input_sha256",
                                    JsonValue::String(ordinary_sha256(
                                        case.canonical_input.bytes(),
                                    )),
                                ),
                            ])
                            .unwrap()
                        })
                        .collect(),
                ),
            ),
            (
                "baseline_rule_sha256",
                JsonValue::String(rule_hash(BASELINE)),
            ),
            ("changed_rule_sha256", JsonValue::String(rule_hash(CHANGED))),
            ("expected_case_count", JsonValue::Integer(expected as i64)),
            (
                "workload_space_sha256",
                JsonValue::String(ordinary_sha256(SPACE)),
            ),
            (
                "workload_selection_sha256",
                JsonValue::String(ordinary_sha256(SELECTION)),
            ),
            (
                "workload_split_sha256",
                JsonValue::String(ordinary_sha256(SPLIT)),
            ),
            (
                "holdout_plan_sha256",
                JsonValue::String(ordinary_sha256(HOLDOUT)),
            ),
            (
                "checked_profile",
                JsonValue::String(CHECKED_PROFILE.to_string()),
            ),
            (
                "artifact_schema_versions",
                JsonValue::object(
                    EXPECTED_SCHEMA_VERSIONS
                        .iter()
                        .map(|(name, value)| (*name, JsonValue::String((*value).to_string()))),
                )
                .unwrap(),
            ),
        ])
        .unwrap()
    }

    fn policy(key: &SigningKey) -> Vec<u8> {
        let public = key.verifying_key().to_bytes();
        write_canonical(
            &JsonValue::object([
                (
                    "trust_policy",
                    JsonValue::String("csk.native-trust-policy/v0".to_string()),
                ),
                (
                    "minimum_versions",
                    JsonValue::object([
                        ("native_receipt", JsonValue::Integer(0)),
                        ("release_descriptor", JsonValue::Integer(0)),
                        ("replay_corpus_manifest", JsonValue::Integer(0)),
                        ("reproduction_observation", JsonValue::Integer(0)),
                    ])
                    .unwrap(),
                ),
                (
                    "keys",
                    JsonValue::Array(vec![JsonValue::object([
                        ("key_id", JsonValue::String(native_key_id(&public))),
                        ("algorithm", JsonValue::String("ed25519".to_string())),
                        ("public_key", JsonValue::String(encode_base64(&public))),
                        (
                            "allowed_payload_types",
                            JsonValue::Array(vec![JsonValue::String(
                                REPLAY_MANIFEST_PAYLOAD_TYPE.to_string(),
                            )]),
                        ),
                        (
                            "allowed_profiles",
                            JsonValue::Array(vec![JsonValue::String(CHECKED_PROFILE.to_string())]),
                        ),
                        (
                            "allowed_engine_sha256",
                            JsonValue::Array(vec![JsonValue::String(format!(
                                "sha256:{}",
                                "1".repeat(64)
                            ))]),
                        ),
                    ])
                    .unwrap()]),
                ),
            ])
            .unwrap(),
        )
        .unwrap()
    }

    fn resign(payload: JsonValue, key: &SigningKey) -> Vec<u8> {
        let bytes = write_canonical(&payload).unwrap();
        let canonical = canonical_gate(&bytes, RawArtifactKind::Payload).unwrap();
        let key_id = native_key_id(&key.verifying_key().to_bytes());
        sign_envelope(PayloadType::ReplayManifest, &canonical, key, &key_id)
            .canonical_bytes()
            .unwrap()
    }

    #[test]
    fn r01_authenticates_every_precondition_before_execution() {
        let fixture = Fixture::new(21);
        let verified = fixture.verify().unwrap();
        let mut executed = Vec::new();
        assert_eq!(
            verified
                .execute::<()>(|case| {
                    executed.push(case.case_id().to_string());
                    Ok(())
                })
                .unwrap(),
            2
        );
        assert_eq!(executed, ["D001", "H001"]);
    }

    #[test]
    fn r02_r03_delete_and_reorder_stop_before_execution() {
        let fixture = Fixture::new(22);
        let deleted = vec![fixture.cases[0].clone()];
        assert_eq!(
            verify_replay_manifest(
                &fixture.envelope,
                &fixture.policy,
                BASELINE,
                CHANGED,
                &fixture.artifacts,
                &deleted,
            )
            .unwrap_err(),
            ReplayError::ReplayCorpusMemberMissing
        );
        let reordered = vec![fixture.cases[1].clone(), fixture.cases[0].clone()];
        assert_eq!(
            verify_replay_manifest(
                &fixture.envelope,
                &fixture.policy,
                BASELINE,
                CHANGED,
                &fixture.artifacts,
                &reordered,
            )
            .unwrap_err(),
            ReplayError::ReplayCorpusOrderMismatch
        );
    }

    #[test]
    fn r04_attacker_substitute_is_untrusted() {
        let mut fixture = Fixture::new(23);
        let attacker = SigningKey::from_bytes(&[24; 32]);
        fixture.envelope = resign(fixture.payload.clone(), &attacker);
        assert_eq!(
            fixture.verify().unwrap_err(),
            ReplayError::UntrustedNativeKey
        );
    }

    #[test]
    fn r05_count_change_after_signing_is_signature_invalid() {
        let fixture = Fixture::new(25);
        let mut payload = fixture.payload.clone();
        let root = payload.as_object().unwrap();
        let mut changed = root.clone();
        changed.insert("expected_case_count".to_string(), JsonValue::Integer(3));
        payload = JsonValue::Object(changed);
        let payload_bytes = write_canonical(&payload).unwrap();
        let original = canonical_gate(&fixture.envelope, RawArtifactKind::Envelope).unwrap();
        let envelope = Envelope::from_canonical_json(&original).unwrap();
        let tampered = write_canonical(
            &JsonValue::object([
                (
                    "payloadType",
                    JsonValue::String(REPLAY_MANIFEST_PAYLOAD_TYPE.to_string()),
                ),
                ("payload", JsonValue::String(encode_base64(&payload_bytes))),
                (
                    "signatures",
                    JsonValue::Array(vec![JsonValue::object([
                        (
                            "keyid",
                            JsonValue::String(envelope.signatures()[0].key_id().to_string()),
                        ),
                        (
                            "sig",
                            JsonValue::String(
                                envelope.signatures()[0].signature_base64().to_string(),
                            ),
                        ),
                    ])
                    .unwrap()]),
                ),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_replay_manifest(
                &tampered,
                &fixture.policy,
                BASELINE,
                CHANGED,
                &fixture.artifacts,
                &fixture.cases,
            )
            .unwrap_err(),
            ReplayError::NativeSignatureInvalid
        );
    }

    #[test]
    fn rule_artifact_and_input_substitution_stop_before_capability() {
        let fixture = Fixture::new(26);
        assert_eq!(
            verify_replay_manifest(
                &fixture.envelope,
                &fixture.policy,
                b"(decision-review)\n",
                CHANGED,
                &fixture.artifacts,
                &fixture.cases,
            )
            .unwrap_err(),
            ReplayError::ReplayRuleMismatch
        );
        let wrong_artifacts = ReplayArtifacts::from_slices(b"other\n", SELECTION, SPLIT, HOLDOUT);
        assert_eq!(
            verify_replay_manifest(
                &fixture.envelope,
                &fixture.policy,
                BASELINE,
                CHANGED,
                &wrong_artifacts,
                &fixture.cases,
            )
            .unwrap_err(),
            ReplayError::ReplayArtifactMismatch
        );
        let substituted = vec![ReplayCase::new("D001", INPUT_TWO), fixture.cases[1].clone()];
        assert_eq!(
            verify_replay_manifest(
                &fixture.envelope,
                &fixture.policy,
                BASELINE,
                CHANGED,
                &fixture.artifacts,
                &substituted,
            )
            .unwrap_err(),
            ReplayError::ReplayCorpusInputMismatch
        );
    }
}
