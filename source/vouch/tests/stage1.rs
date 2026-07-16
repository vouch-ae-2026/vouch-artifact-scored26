use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use vouch::artifact_json::{
    canonical_gate, resource_preflight, write_canonical, JsonGateError, JsonValue, RawArtifactKind,
    MAX_ARRAY_MEMBERS, MAX_ARTIFACT_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES, MAX_OBJECT_MEMBERS,
    MAX_STRING_BYTES,
};
use vouch::dsse::{
    decode_base64_canonical, domain_separated_digest, encode_base64, native_key_id, pae,
    sign_envelope, verify_envelope, DsseError, PayloadType,
};
use vouch::io_boundary::{
    AtomicDirectoryPublisher, AtomicPublisher, FileProvider, FrozenBytes, KeyProvider,
    MemoryAtomicDirectoryPublisher, MemoryAtomicPublisher, MemoryFileProvider, MemoryKeyProvider,
    OsFileProvider, PublicationFault, PublicationFile,
};

#[test]
fn rust_writer_matches_every_shared_cross_writer_golden() {
    let fixture_bytes = include_bytes!("../../artifact/tests/cross-writer-goldens.json");
    let fixture = canonical_gate(fixture_bytes, RawArtifactKind::Artifact).unwrap();
    let root = fixture.value().as_object().unwrap();
    assert_eq!(
        root.get("cross_writer_goldens").and_then(JsonValue::as_str),
        Some("csk.artifact-json-cross-writer/v0")
    );
    assert_eq!(
        root.get("fixture_id").and_then(JsonValue::as_str),
        Some("S1-CROSS-WRITER-01")
    );
    let required: BTreeSet<&str> = root["required_artifact_classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    let mut covered = BTreeSet::new();
    for vector in root["vectors"].as_array().unwrap() {
        let vector = vector.as_object().unwrap();
        let id = vector["id"].as_str().unwrap();
        covered.insert(vector["artifact_class"].as_str().unwrap());
        let expected =
            decode_base64_canonical(vector["expected_base64"].as_str().unwrap()).unwrap();
        assert_eq!(write_canonical(&vector["value"]).unwrap(), expected, "{id}");
    }
    assert_eq!(covered, required);
}

#[test]
fn depth_limit_and_limit_plus_one() {
    let at_limit = format!(
        "{}0{}",
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    let parsed = resource_preflight(at_limit.as_bytes(), RawArtifactKind::Payload).unwrap();
    assert_eq!(parsed.counts().maximum_container_depth, MAX_JSON_DEPTH);

    let over_limit = format!(
        "{}0{}",
        "[".repeat(MAX_JSON_DEPTH + 1),
        "]".repeat(MAX_JSON_DEPTH + 1)
    );
    assert_eq!(
        resource_preflight(over_limit.as_bytes(), RawArtifactKind::Payload),
        Err(JsonGateError::ResourceLimit("json-depth"))
    );
}

fn node_boundary(extra_node: bool) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(500_000);
    bytes.push(b'[');
    for outer in 0..10_000 {
        if outer != 0 {
            bytes.push(b',');
        }
        bytes.push(b'[');
        let scalar_count = if outer == 9_999 && !extra_node { 8 } else { 9 };
        for inner in 0..scalar_count {
            if inner != 0 {
                bytes.push(b',');
            }
            bytes.extend_from_slice(b"null");
        }
        bytes.push(b']');
    }
    bytes.push(b']');
    bytes
}

#[test]
fn total_node_limit_and_limit_plus_one() {
    let at_limit = node_boundary(false);
    let parsed = resource_preflight(&at_limit, RawArtifactKind::Payload).unwrap();
    assert_eq!(parsed.counts().total_json_node_count, MAX_JSON_NODES);
    assert_eq!(
        resource_preflight(&node_boundary(true), RawArtifactKind::Payload),
        Err(JsonGateError::ResourceLimit("json-nodes"))
    );
}

#[test]
fn object_member_names_count_as_json_string_nodes() {
    let parsed = resource_preflight(br#"{"a":null}"#, RawArtifactKind::Payload).unwrap();
    assert_eq!(parsed.counts().total_json_node_count, 3);
}

#[test]
fn raw_byte_limit_and_limit_plus_one() {
    let mut at_limit = b"null".to_vec();
    at_limit.resize(MAX_ARTIFACT_BYTES, b' ');
    let parsed = resource_preflight(&at_limit, RawArtifactKind::Envelope).unwrap();
    assert_eq!(parsed.counts().raw_byte_count, MAX_ARTIFACT_BYTES);
    at_limit.push(b' ');
    assert_eq!(
        resource_preflight(&at_limit, RawArtifactKind::Envelope),
        Err(JsonGateError::ResourceLimit("envelope-bytes"))
    );
}

#[test]
fn string_member_and_array_boundaries() {
    let at_string_limit = format!("\"{}\"", "a".repeat(MAX_STRING_BYTES));
    assert!(resource_preflight(at_string_limit.as_bytes(), RawArtifactKind::Payload).is_ok());
    let over_string_limit = format!("\"{}\"", "a".repeat(MAX_STRING_BYTES + 1));
    assert_eq!(
        resource_preflight(over_string_limit.as_bytes(), RawArtifactKind::Payload),
        Err(JsonGateError::ResourceLimit("string-bytes"))
    );

    let at_array_limit = format!("[{}]", vec!["null"; MAX_ARRAY_MEMBERS].join(","));
    assert!(resource_preflight(at_array_limit.as_bytes(), RawArtifactKind::Payload).is_ok());
    let over_array_limit = format!("[{},null]", vec!["null"; MAX_ARRAY_MEMBERS].join(","));
    assert_eq!(
        resource_preflight(over_array_limit.as_bytes(), RawArtifactKind::Payload),
        Err(JsonGateError::ResourceLimit("array-members"))
    );

    let at_object_limit = format!(
        "{{{}}}",
        (0..MAX_OBJECT_MEMBERS)
            .map(|index| format!("\"k{index}\":null"))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(resource_preflight(at_object_limit.as_bytes(), RawArtifactKind::Payload).is_ok());
    let over_object_limit =
        at_object_limit.strip_suffix('}').unwrap().to_owned() + ",\"over\":null}";
    assert_eq!(
        resource_preflight(over_object_limit.as_bytes(), RawArtifactKind::Payload),
        Err(JsonGateError::ResourceLimit("object-members"))
    );
}

#[test]
fn duplicate_is_rejected_before_its_value_is_constructed() {
    let bytes = format!("{{\"a\":0,\"a\":\"{}\"}}", "x".repeat(MAX_STRING_BYTES + 1));
    assert_eq!(
        resource_preflight(bytes.as_bytes(), RawArtifactKind::Payload),
        Err(JsonGateError::NonCanonicalArtifactJson)
    );
}

#[test]
fn canonical_gate_rejects_repairs_and_unsupported_numbers() {
    for bytes in [
        b"{\"x\":1}".as_slice(),
        b"\"\\u00e9\"\n",
        b"-0\n",
        b"1.0\n",
        b"9007199254740992\n",
    ] {
        assert_eq!(
            canonical_gate(bytes, RawArtifactKind::Payload),
            Err(JsonGateError::NonCanonicalArtifactJson)
        );
    }
}

#[test]
fn canonical_base64_and_dsse_ed25519_contract_vector() {
    for (bytes, encoded) in [
        (b"".as_slice(), ""),
        (b"f".as_slice(), "Zg=="),
        (b"fo".as_slice(), "Zm8="),
        (b"foo".as_slice(), "Zm9v"),
    ] {
        assert_eq!(encode_base64(bytes), encoded);
        assert_eq!(decode_base64_canonical(encoded).unwrap(), bytes);
    }
    for invalid in ["Zg", "Zg=", "Zg===", "Zh==", "Zg==\n", "Zg-="] {
        assert_eq!(decode_base64_canonical(invalid), Err(DsseError::Base64));
    }

    let payload = canonical_gate(b"null\n", RawArtifactKind::Payload).unwrap();
    let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    assert_eq!(
        hex(&public_key),
        "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
    );
    assert_eq!(
        hex(&pae(PayloadType::NativeReceipt.as_str(), payload.bytes())),
        "445353457631203438206170706c69636174696f6e2f766e642e63736b2e646966666572656e7469616c2d726563656970742e76302b6a736f6e2035206e756c6c0a"
    );
    let envelope = sign_envelope(
        PayloadType::NativeReceipt,
        &payload,
        &signing_key,
        &native_key_id(&public_key),
    );
    assert_eq!(
        envelope.signatures()[0].signature_base64(),
        "eeTs1lk4oGHs7V7IIiR7cu9ycTuTTXCbW4b9is3FXxn97ad+ps1MrIMNH4hRZ1TVY85Vttf4XuSbzY3nmHR4Ag=="
    );
    assert_eq!(
        native_key_id(&public_key),
        "sha256:eee31876bbf14c973e626db1757259cf0509af246c5fd6d7d4ac95d7606a8383"
    );
    assert_eq!(
        domain_separated_digest("csk.v0.source", b"source\n"),
        "9b213d049e67c5d7264fc87e1fc0254131ef3e4461a3046524ee9435b80a6e8d"
    );
    assert_eq!(
        verify_envelope(&envelope, PayloadType::NativeReceipt, &public_key).unwrap(),
        b"null\n"
    );
}

#[test]
fn dsse_payload_type_precedes_base64_and_signature_work() {
    let envelope_json = JsonValue::object([
        (
            "payloadType",
            JsonValue::String(PayloadType::ReplayManifest.as_str().to_owned()),
        ),
        ("payload", JsonValue::String("not base64".to_owned())),
        (
            "signatures",
            JsonValue::Array(vec![JsonValue::object([
                ("keyid", JsonValue::String("fixture".to_owned())),
                ("sig", JsonValue::String("not base64".to_owned())),
            ])
            .unwrap()]),
        ),
    ])
    .unwrap();
    let envelope_bytes = write_canonical(&envelope_json).unwrap();
    let canonical = canonical_gate(&envelope_bytes, RawArtifactKind::Envelope).unwrap();
    let envelope = vouch::dsse::Envelope::from_canonical_json(&canonical).unwrap();
    assert_eq!(
        envelope.decode_for(PayloadType::NativeReceipt),
        Err(DsseError::PayloadType)
    );
}

#[test]
fn frozen_bytes_defend_against_caller_and_provider_mutation() {
    let mut caller = b"original".to_vec();
    let frozen = FrozenBytes::from_slice(&caller);
    caller.fill(b'X');
    assert_eq!(frozen.access_count(), 0);
    assert_eq!(frozen.bytes(), b"original");
    assert_eq!(frozen.access_count(), 1);

    let provider = MemoryFileProvider::default();
    provider.insert("input", b"first".to_vec());
    let inode = provider.inode("input").unwrap();
    let captured = provider.read_once("input", 100).unwrap();
    provider
        .mutate_same_inode("input", b"second".to_vec())
        .unwrap();
    assert_eq!(provider.inode("input"), Some(inode));
    assert_eq!(captured.bytes(), b"first");
    provider.replace_path("input", b"third".to_vec()).unwrap();
    assert_ne!(provider.inode("input"), Some(inode));
    assert_eq!(captured.bytes(), b"first");
    assert_eq!(provider.read_count(), 1);
}

#[test]
fn os_file_provider_stops_after_observing_limit_plus_one() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "vouch-stage1-read-limit-{}-{unique}",
        std::process::id()
    ));
    std::fs::write(&path, b"limit+1").unwrap();
    let provider = OsFileProvider::default();
    assert!(matches!(
        provider.read_once(path.to_str().unwrap(), 6),
        Err(vouch::io_boundary::IoBoundaryError::ResourceLimit)
    ));
    assert_eq!(provider.read_count(), 1);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn key_provider_stays_at_zero_until_resolution_and_counts_wrong_handles() {
    let provider = MemoryKeyProvider::default();
    provider.insert("fixture://right", [4_u8; 32]);
    assert_eq!(provider.access_counts().total(), 0);
    let _key = provider.resolve("fixture://right").unwrap();
    assert_eq!(provider.access_counts().resolution, 1);
    assert_eq!(provider.access_counts().load, 1);
    assert!(provider.resolve("fixture://wrong").is_err());
    assert_eq!(provider.access_counts().resolution, 2);
    assert_eq!(provider.access_counts().load, 1);
}

#[test]
fn portable_publishers_expose_short_write_fsync_and_rename_faults() {
    let publisher = MemoryAtomicPublisher::default();
    for fault in [
        PublicationFault::ShortWrite,
        PublicationFault::FsyncFailure,
        PublicationFault::FinalRenameFailure,
    ] {
        publisher.set_fault(fault);
        assert!(publisher.publish("report.json", b"{}\n").is_err());
        assert!(publisher.read("report.json").is_none());
        assert_eq!(AtomicPublisher::final_rename_count(&publisher), 0);
    }

    let directory = MemoryAtomicDirectoryPublisher::default();
    directory
        .publish_directory(
            "issued",
            &[
                PublicationFile {
                    name: "payload.json",
                    bytes: b"{}\n",
                },
                PublicationFile {
                    name: "envelope.json",
                    bytes: b"{}\n",
                },
            ],
        )
        .unwrap();
    assert_eq!(AtomicDirectoryPublisher::final_rename_count(&directory), 1);
    assert_eq!(directory.directory("issued").unwrap().len(), 2);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        },
    )
}
