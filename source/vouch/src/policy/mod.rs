//! Canonical, closed consumer trust-policy parser (Stage 5).

use std::collections::{BTreeMap, HashSet};

use ed25519_dalek::VerifyingKey;

use crate::artifact_json::{canonical_gate, JsonGateError, JsonValue, RawArtifactKind};
use crate::dsse::{decode_base64_canonical, native_key_id, PayloadType};

pub const NATIVE_TRUST_POLICY_TAG: &str = "csk.native-trust-policy/v0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustKey {
    key_id: String,
    public_key: [u8; 32],
    allowed_payload_types: Vec<String>,
    allowed_profiles: Vec<String>,
    allowed_engine_sha256: Vec<String>,
}

impl TrustKey {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn allows_payload_type(&self, payload_type: &str) -> bool {
        self.allowed_payload_types
            .iter()
            .any(|allowed| allowed == payload_type)
    }

    pub fn allows_profile(&self, profile: &str) -> bool {
        self.allowed_profiles
            .iter()
            .any(|allowed| allowed == profile)
    }

    pub fn allows_engine(&self, engine: &str) -> bool {
        self.allowed_engine_sha256
            .iter()
            .any(|allowed| allowed == engine)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinimumVersions {
    pub native_receipt: usize,
    pub release_descriptor: usize,
    pub replay_corpus_manifest: usize,
    pub reproduction_observation: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTrustPolicy {
    minimum_versions: MinimumVersions,
    keys: Vec<TrustKey>,
}

impl NativeTrustPolicy {
    pub const fn minimum_versions(&self) -> MinimumVersions {
        self.minimum_versions
    }

    pub fn select_key(&self, key_id: &str) -> Option<&TrustKey> {
        self.keys.iter().find(|key| key.key_id == key_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    ResourceLimit,
    NonCanonicalArtifactJson,
    Invalid,
}

impl PolicyError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ResourceLimit => "artifact-resource-limit",
            Self::NonCanonicalArtifactJson => "non-canonical-artifact-json",
            Self::Invalid => "native-trust-policy-invalid",
        }
    }
}

pub fn parse_native_trust_policy(bytes: &[u8]) -> Result<NativeTrustPolicy, PolicyError> {
    let canonical = canonical_gate(bytes, RawArtifactKind::Artifact).map_err(map_gate)?;
    let root = exact_object(
        canonical.value(),
        &["trust_policy", "minimum_versions", "keys"],
    )?;
    require_string(root, "trust_policy", NATIVE_TRUST_POLICY_TAG)?;

    let versions = exact_object(
        field(root, "minimum_versions")?,
        &[
            "native_receipt",
            "release_descriptor",
            "replay_corpus_manifest",
            "reproduction_observation",
        ],
    )?;
    let minimum_versions = MinimumVersions {
        native_receipt: uint(versions, "native_receipt")?,
        release_descriptor: uint(versions, "release_descriptor")?,
        replay_corpus_manifest: uint(versions, "replay_corpus_manifest")?,
        reproduction_observation: uint(versions, "reproduction_observation")?,
    };

    let key_values = field(root, "keys")?
        .as_array()
        .filter(|keys| !keys.is_empty())
        .ok_or(PolicyError::Invalid)?;
    let mut keys = Vec::with_capacity(key_values.len());
    let mut key_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    for value in key_values {
        let object = exact_object(
            value,
            &[
                "key_id",
                "algorithm",
                "public_key",
                "allowed_payload_types",
                "allowed_profiles",
                "allowed_engine_sha256",
            ],
        )?;
        require_string(object, "algorithm", "ed25519")?;
        let key_id = string(object, "key_id")?.to_string();
        if !digest_identifier(&key_id) || !key_ids.insert(key_id.clone()) {
            return Err(PolicyError::Invalid);
        }
        let public_key: [u8; 32] = decode_base64_canonical(string(object, "public_key")?)
            .map_err(|_| PolicyError::Invalid)?
            .try_into()
            .map_err(|_| PolicyError::Invalid)?;
        VerifyingKey::from_bytes(&public_key).map_err(|_| PolicyError::Invalid)?;
        if native_key_id(&public_key) != key_id || !public_keys.insert(public_key) {
            return Err(PolicyError::Invalid);
        }
        let allowed_payload_types = unique_strings(object, "allowed_payload_types", |value| {
            PayloadType::parse_exact(value).is_ok()
        })?;
        let allowed_profiles =
            unique_strings(object, "allowed_profiles", profile_identifier_valid)?;
        let allowed_engine_sha256 =
            unique_strings(object, "allowed_engine_sha256", digest_identifier)?;
        keys.push(TrustKey {
            key_id,
            public_key,
            allowed_payload_types,
            allowed_profiles,
            allowed_engine_sha256,
        });
    }

    Ok(NativeTrustPolicy {
        minimum_versions,
        keys,
    })
}

pub fn profile_identifier_valid(value: &str) -> bool {
    let Some((name, version)) = value.rsplit_once("/v") else {
        return false;
    };
    if name.is_empty()
        || version.is_empty()
        || (!version.starts_with('0') && !version.bytes().all(|byte| byte.is_ascii_digit()))
        || (version.starts_with('0') && version != "0")
        || !version.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut segment_start = true;
    for byte in bytes {
        match *byte {
            b'a'..=b'z' | b'0'..=b'9' => segment_start = false,
            b'.' | b'-' if !segment_start => segment_start = true,
            _ => return false,
        }
    }
    !segment_start
}

fn map_gate(error: JsonGateError) -> PolicyError {
    match error {
        JsonGateError::ResourceLimit(_) => PolicyError::ResourceLimit,
        JsonGateError::NonCanonicalArtifactJson => PolicyError::NonCanonicalArtifactJson,
    }
}

fn unique_strings(
    object: &BTreeMap<String, JsonValue>,
    name: &str,
    valid: impl Fn(&str) -> bool,
) -> Result<Vec<String>, PolicyError> {
    let values = field(object, name)?
        .as_array()
        .filter(|values| !values.is_empty())
        .ok_or(PolicyError::Invalid)?;
    let mut seen = HashSet::new();
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let value = value.as_str().ok_or(PolicyError::Invalid)?;
        if !valid(value) || !seen.insert(value.to_string()) {
            return Err(PolicyError::Invalid);
        }
        output.push(value.to_string());
    }
    Ok(output)
}

fn digest_identifier(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn exact_object<'a>(
    value: &'a JsonValue,
    expected: &[&str],
) -> Result<&'a BTreeMap<String, JsonValue>, PolicyError> {
    let object = value.as_object().ok_or(PolicyError::Invalid)?;
    if object.len() != expected.len() || expected.iter().any(|name| !object.contains_key(*name)) {
        return Err(PolicyError::Invalid);
    }
    Ok(object)
}

fn field<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a JsonValue, PolicyError> {
    object.get(name).ok_or(PolicyError::Invalid)
}

fn string<'a>(object: &'a BTreeMap<String, JsonValue>, name: &str) -> Result<&'a str, PolicyError> {
    field(object, name)?.as_str().ok_or(PolicyError::Invalid)
}

fn require_string(
    object: &BTreeMap<String, JsonValue>,
    name: &str,
    expected: &str,
) -> Result<(), PolicyError> {
    if string(object, name)? == expected {
        Ok(())
    } else {
        Err(PolicyError::Invalid)
    }
}

fn uint(object: &BTreeMap<String, JsonValue>, name: &str) -> Result<usize, PolicyError> {
    match field(object, name)? {
        JsonValue::Integer(value) if *value >= 0 => {
            usize::try_from(*value).map_err(|_| PolicyError::Invalid)
        }
        _ => Err(PolicyError::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_json::{write_canonical, JsonValue};
    use crate::dsse::encode_base64;
    use ed25519_dalek::SigningKey;

    fn test_key(public_key: [u8; 32], profiles: &[&str]) -> JsonValue {
        JsonValue::object([
            ("key_id", JsonValue::String(native_key_id(&public_key))),
            ("algorithm", JsonValue::String("ed25519".into())),
            ("public_key", JsonValue::String(encode_base64(&public_key))),
            (
                "allowed_payload_types",
                JsonValue::Array(vec![JsonValue::String(
                    PayloadType::NativeReceipt.as_str().into(),
                )]),
            ),
            (
                "allowed_profiles",
                JsonValue::Array(
                    profiles
                        .iter()
                        .map(|profile| JsonValue::String((*profile).into()))
                        .collect(),
                ),
            ),
            (
                "allowed_engine_sha256",
                JsonValue::Array(vec![JsonValue::String(format!(
                    "sha256:{}",
                    "1".repeat(64)
                ))]),
            ),
        ])
        .unwrap()
    }

    fn test_policy(keys: Vec<JsonValue>) -> Vec<u8> {
        write_canonical(
            &JsonValue::object([
                (
                    "trust_policy",
                    JsonValue::String(NATIVE_TRUST_POLICY_TAG.into()),
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
                ("keys", JsonValue::Array(keys)),
            ])
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn profile_identifier_grammar_is_exact() {
        for valid in ["csk.checked-profile/v1", "x/v12", "a-b.c9/v1"] {
            assert!(profile_identifier_valid(valid), "{valid}");
        }
        for invalid in ["", "Csk/v0", "csk/v01", "csk//v0", "csk-/v0", "csk/v"] {
            assert!(!profile_identifier_valid(invalid), "{invalid}");
        }
    }

    #[test]
    fn selected_key_policy_is_closed_and_key_bound() {
        let public_key = SigningKey::from_bytes(&[7_u8; 32])
            .verifying_key()
            .to_bytes();
        let key_id = native_key_id(&public_key);
        let policy = JsonValue::object([
            (
                "trust_policy",
                JsonValue::String(NATIVE_TRUST_POLICY_TAG.into()),
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
                    ("key_id", JsonValue::String(key_id.clone())),
                    ("algorithm", JsonValue::String("ed25519".into())),
                    ("public_key", JsonValue::String(encode_base64(&public_key))),
                    (
                        "allowed_payload_types",
                        JsonValue::Array(vec![JsonValue::String(
                            PayloadType::NativeReceipt.as_str().into(),
                        )]),
                    ),
                    (
                        "allowed_profiles",
                        JsonValue::Array(vec![JsonValue::String("csk.checked-profile/v1".into())]),
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
        .unwrap();
        let bytes = write_canonical(&policy).unwrap();
        let parsed = parse_native_trust_policy(&bytes).unwrap();
        let selected = parsed.select_key(&key_id).unwrap();
        assert!(selected.allows_profile("csk.checked-profile/v1"));
        assert!(!selected.allows_profile("csk.other/v0"));
    }

    #[test]
    fn policy_rejects_duplicate_authority_and_invalid_ed25519_points() {
        let public_key = SigningKey::from_bytes(&[8_u8; 32])
            .verifying_key()
            .to_bytes();
        let key = test_key(public_key, &["csk.checked-profile/v1"]);
        assert_eq!(
            parse_native_trust_policy(&test_policy(vec![key.clone(), key])),
            Err(PolicyError::Invalid)
        );
        assert_eq!(
            parse_native_trust_policy(&test_policy(vec![test_key(
                public_key,
                &["csk.checked-profile/v1", "csk.checked-profile/v1"],
            )])),
            Err(PolicyError::Invalid)
        );
        assert_eq!(
            parse_native_trust_policy(&test_policy(vec![test_key(
                {
                    let mut invalid_point = [0_u8; 32];
                    invalid_point[0] = 2;
                    invalid_point
                },
                &["csk.checked-profile/v1"],
            )])),
            Err(PolicyError::Invalid)
        );
    }
}
