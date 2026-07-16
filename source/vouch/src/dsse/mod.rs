//! Canonical base64, DSSE PAE, Ed25519, key identifiers, and SHA-256 domains.

use crate::artifact_json::{write_canonical, CanonicalJson, JsonValue, JsonWriteError};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

pub const NATIVE_PAYLOAD_TYPE: &str = "application/vnd.csk.differential-receipt.v0+json";
pub const REPLAY_MANIFEST_PAYLOAD_TYPE: &str = "application/vnd.csk.replay-corpus-manifest.v0+json";
pub const RELEASE_DESCRIPTOR_PAYLOAD_TYPE: &str = "application/vnd.csk.release-descriptor.v0+json";
pub const REPRODUCTION_OBSERVATION_PAYLOAD_TYPE: &str =
    "application/vnd.csk.reproduction-observation.v0+json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadType {
    NativeReceipt,
    ReplayManifest,
    ReleaseDescriptor,
    ReproductionObservation,
}

impl PayloadType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeReceipt => NATIVE_PAYLOAD_TYPE,
            Self::ReplayManifest => REPLAY_MANIFEST_PAYLOAD_TYPE,
            Self::ReleaseDescriptor => RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
            Self::ReproductionObservation => REPRODUCTION_OBSERVATION_PAYLOAD_TYPE,
        }
    }

    pub fn parse_exact(value: &str) -> Result<Self, DsseError> {
        match value {
            NATIVE_PAYLOAD_TYPE => Ok(Self::NativeReceipt),
            REPLAY_MANIFEST_PAYLOAD_TYPE => Ok(Self::ReplayManifest),
            RELEASE_DESCRIPTOR_PAYLOAD_TYPE => Ok(Self::ReleaseDescriptor),
            REPRODUCTION_OBSERVATION_PAYLOAD_TYPE => Ok(Self::ReproductionObservation),
            _ => Err(DsseError::PayloadType),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeSignature {
    keyid: String,
    sig: String,
}

impl EnvelopeSignature {
    pub fn key_id(&self) -> &str {
        &self.keyid
    }

    pub fn signature_base64(&self) -> &str {
        &self.sig
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    payload_type: String,
    payload: String,
    signatures: Vec<EnvelopeSignature>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DsseError {
    EnvelopeSchema,
    PayloadType,
    Base64,
    SignatureLength,
    PublicKey,
    SignatureInvalid,
}

impl DsseError {
    pub const fn class(&self) -> &'static str {
        match self {
            Self::EnvelopeSchema => "native-envelope-schema",
            Self::PayloadType => "native-payload-type",
            Self::Base64 => "native-base64-invalid",
            Self::SignatureLength | Self::PublicKey | Self::SignatureInvalid => {
                "native-signature-invalid"
            }
        }
    }
}

impl fmt::Display for DsseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class())
    }
}

impl Error for DsseError {}

impl Envelope {
    pub fn payload_type(&self) -> &str {
        &self.payload_type
    }

    pub fn payload_base64(&self) -> &str {
        &self.payload
    }

    pub fn signatures(&self) -> &[EnvelopeSignature] {
        &self.signatures
    }

    pub fn to_json(&self) -> JsonValue {
        JsonValue::object([
            ("payloadType", JsonValue::String(self.payload_type.clone())),
            ("payload", JsonValue::String(self.payload.clone())),
            (
                "signatures",
                JsonValue::Array(
                    self.signatures
                        .iter()
                        .map(|signature| {
                            JsonValue::object([
                                ("keyid", JsonValue::String(signature.keyid.clone())),
                                ("sig", JsonValue::String(signature.sig.clone())),
                            ])
                            .expect("signature fields are unique")
                        })
                        .collect(),
                ),
            ),
        ])
        .expect("envelope fields are unique")
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, JsonWriteError> {
        write_canonical(&self.to_json())
    }

    pub fn from_canonical_json(value: &CanonicalJson) -> Result<Self, DsseError> {
        Self::from_json(value.value())
    }

    pub fn from_json(value: &JsonValue) -> Result<Self, DsseError> {
        let object = exact_object(value, &["payloadType", "payload", "signatures"])?;
        let payload_type = required_string(object, "payloadType")?.to_owned();
        let payload = required_string(object, "payload")?.to_owned();
        let signatures = match object.get("signatures") {
            Some(JsonValue::Array(values)) if values.len() == 1 => values,
            _ => return Err(DsseError::EnvelopeSchema),
        };
        let signature = exact_object(&signatures[0], &["keyid", "sig"])?;
        Ok(Self {
            payload_type,
            payload,
            signatures: vec![EnvelopeSignature {
                keyid: required_string(signature, "keyid")?.to_owned(),
                sig: required_string(signature, "sig")?.to_owned(),
            }],
        })
    }

    /// Decode only after envelope schema and exact payload-type checks.
    pub fn decode_for(
        &self,
        expected_payload_type: PayloadType,
    ) -> Result<(Vec<u8>, [u8; 64]), DsseError> {
        if self.signatures.len() != 1 {
            return Err(DsseError::EnvelopeSchema);
        }
        if self.payload_type != expected_payload_type.as_str() {
            return Err(DsseError::PayloadType);
        }
        let payload = decode_base64_canonical(&self.payload)?;
        let signature: [u8; 64] = decode_base64_canonical(&self.signatures[0].sig)?
            .try_into()
            .map_err(|_| DsseError::SignatureLength)?;
        Ok((payload, signature))
    }
}

pub fn sign_envelope(
    payload_type: PayloadType,
    payload: &CanonicalJson,
    signing_key: &SigningKey,
    key_id: &str,
) -> Envelope {
    let signature = signing_key.sign(&pae(payload_type.as_str(), payload.bytes()));
    Envelope {
        payload_type: payload_type.as_str().to_owned(),
        payload: encode_base64(payload.bytes()),
        signatures: vec![EnvelopeSignature {
            keyid: key_id.to_owned(),
            sig: encode_base64(&signature.to_bytes()),
        }],
    }
}

pub fn verify_envelope(
    envelope: &Envelope,
    expected_payload_type: PayloadType,
    public_key: &[u8; 32],
) -> Result<Vec<u8>, DsseError> {
    let (payload, signature_bytes) = envelope.decode_for(expected_payload_type)?;
    let verifying_key = VerifyingKey::from_bytes(public_key).map_err(|_| DsseError::PublicKey)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&pae(envelope.payload_type.as_str(), &payload), &signature)
        .map_err(|_| DsseError::SignatureInvalid)?;
    Ok(payload)
}

pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let payload_type = payload_type.as_bytes();
    let mut output = Vec::with_capacity(32 + payload_type.len() + payload.len());
    output.extend_from_slice(b"DSSEv1 ");
    output.extend_from_slice(payload_type.len().to_string().as_bytes());
    output.push(b' ');
    output.extend_from_slice(payload_type);
    output.push(b' ');
    output.extend_from_slice(payload.len().to_string().as_bytes());
    output.push(b' ');
    output.extend_from_slice(payload);
    output
}

pub fn encode_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn decode_base64_canonical(value: &str) -> Result<Vec<u8>, DsseError> {
    let output = STANDARD.decode(value).map_err(|_| DsseError::Base64)?;
    if encode_base64(&output) != value {
        return Err(DsseError::Base64);
    }
    Ok(output)
}

pub fn domain_separated_digest(label: &str, content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update([0x1f]);
    hasher.update(content);
    lowercase_hex(&hasher.finalize())
}

pub fn ordinary_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", lowercase_hex(&digest))
}

pub fn native_key_id(public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"csk/native-key-id/v0");
    hasher.update([0x00]);
    hasher.update(public_key);
    format!("sha256:{}", lowercase_hex(&hasher.finalize()))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn exact_object<'a>(
    value: &'a JsonValue,
    expected_names: &[&str],
) -> Result<&'a BTreeMap<String, JsonValue>, DsseError> {
    let object = value.as_object().ok_or(DsseError::EnvelopeSchema)?;
    if object.len() != expected_names.len()
        || expected_names
            .iter()
            .any(|name| !object.contains_key(*name))
    {
        return Err(DsseError::EnvelopeSchema);
    }
    Ok(object)
}

fn required_string<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a str, DsseError> {
    object
        .get(name)
        .and_then(JsonValue::as_str)
        .ok_or(DsseError::EnvelopeSchema)
}
