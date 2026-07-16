//! Native issuer boundary (Stage 6).
//!
//! The issuer is deliberately split by type.  All parsing, execution,
//! token-bound receipt construction, structural verification, signability, and
//! build self-checks finish before `SignablePayload` can exist.  A key provider
//! accepts only that private type, so no pre-key refusal can reach key loading
//! or signing through this module.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::{pkcs8::DecodePrivateKey, SigningKey};
use sha2::{Digest, Sha256};
use vouch::artifact_json::{
    canonical_gate, write_canonical, CanonicalJson, JsonValue, RawArtifactKind,
};
use vouch::dsse::{
    encode_base64, native_key_id, sign_envelope, Envelope, PayloadType, NATIVE_PAYLOAD_TYPE,
};
#[cfg(test)]
use vouch::io_boundary::KeyAccessCounts;
use vouch::io_boundary::{
    AtomicDirectoryPublisher, FileProvider, FrozenBytes, IoBoundaryError, OsFileProvider,
    PublicationFile,
};

use super::canonical_value::domain_hash;
use super::checked_input::{CheckedInput, CheckedInputError, MAX_INPUT_BYTES};
use super::checked_profile::{
    parse_checked_source, prepare_parsed_checked_source, ProfileErrorCode, CHECKED_PROFILE_TAG,
    MAX_SOURCE_BYTES,
};
use super::graph::{contract_graph_digest, lower_contract_graph, GraphError};
use super::meaning_trace::{mint_meaning_token, MeaningEvaluationError};
use super::receipt::{
    BuildVariant, ByteIdentity, CanonicalProgramIdentity, DifferentialReceipt, EngineIdentity,
    ExecutionIdentity, GraphReceiptValue, InputIdentity,
};
use super::reference_trace::{mint_reference_token, ReferenceEvaluationError};
use super::structural_verify::{verify_structure, StructuralContext, BOUNDARY_STATEMENT};
use super::tokens::{
    bind_and_consume, build_trace_reports, verify_consumed_binding, EvaluationBudgets,
    InvocationContext, TokenBoundTraceReports,
};
use super::transcript::{Terminal, TranscriptEvent};
use super::verify::verify_native;
use crate::Decision;

pub const NATIVE_ISSUE_REPORT_TAG: &str = "csk.native-issue-report/v0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuePrimaryError {
    ArtifactResourceLimit,
    NativeInputParseFailed,
    NativeInputProfileInvalid,
    ProfileEscape,
    NativeLoweringFailed,
    NativeSelfVerificationFailed,
    NativeResultNotSignable,
    NativeKeyLoadFailed,
    NativeSigningFailed,
    ArtifactIoError,
    UsageError,
}

impl IssuePrimaryError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ArtifactResourceLimit => "artifact-resource-limit",
            Self::NativeInputParseFailed => "native-input-parse-failed",
            Self::NativeInputProfileInvalid => "native-input-profile-invalid",
            Self::ProfileEscape => "profile-escape",
            Self::NativeLoweringFailed => "native-lowering-failed",
            Self::NativeSelfVerificationFailed => "native-self-verification-failed",
            Self::NativeResultNotSignable => "native-result-not-signable",
            Self::NativeKeyLoadFailed => "native-key-load-failed",
            Self::NativeSigningFailed => "native-signing-failed",
            Self::ArtifactIoError => "artifact-io-error",
            Self::UsageError => "usage-error",
        }
    }

    pub const fn exit_code(self) -> u8 {
        match self {
            Self::UsageError => 2,
            Self::ArtifactIoError => 3,
            Self::NativeKeyLoadFailed | Self::NativeSigningFailed => 4,
            _ => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignabilityReason {
    ComparisonNotAgree,
    TerminalNotCompleted,
    FinalValueNotDecision,
    DiagnosticsPresent,
    MutantBuild,
}

impl SignabilityReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ComparisonNotAgree => "comparison-not-agree",
            Self::TerminalNotCompleted => "terminal-not-completed",
            Self::FinalValueNotDecision => "final-value-not-decision",
            Self::DiagnosticsPresent => "diagnostics-present",
            Self::MutantBuild => "mutant-build",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeIssueReport {
    status: &'static str,
    primary_error: Option<IssuePrimaryError>,
    reason: Option<SignabilityReason>,
}

impl NativeIssueReport {
    fn issued() -> Self {
        Self {
            status: "issued-native",
            primary_error: None,
            reason: None,
        }
    }

    fn refused(primary_error: IssuePrimaryError, reason: Option<SignabilityReason>) -> Self {
        Self {
            status: primary_error.code(),
            primary_error: Some(primary_error),
            reason,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        write_canonical(
            &JsonValue::object([
                (
                    "native_issue_report",
                    JsonValue::String(NATIVE_ISSUE_REPORT_TAG.to_string()),
                ),
                ("status", JsonValue::String(self.status.to_string())),
                (
                    "primary_error",
                    self.primary_error
                        .map(|error| JsonValue::String(error.code().to_string()))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "reason",
                    self.reason
                        .map(|reason| JsonValue::String(reason.code().to_string()))
                        .unwrap_or(JsonValue::Null),
                ),
            ])
            .expect("native issue report fields are unique"),
        )
        .expect("native issue report contains no integers")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueOutcome {
    pub exit_code: u8,
    pub primary_error: Option<IssuePrimaryError>,
    pub reason: Option<SignabilityReason>,
    pub published: bool,
}

impl IssueOutcome {
    fn issued() -> Self {
        Self {
            exit_code: 0,
            primary_error: None,
            reason: None,
            published: true,
        }
    }

    fn unpublished(primary_error: IssuePrimaryError, reason: Option<SignabilityReason>) -> Self {
        Self {
            exit_code: primary_error.exit_code(),
            primary_error: Some(primary_error),
            reason,
            published: false,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct IssueBuildIdentity {
    executable_sha256: String,
    target_triple: String,
    lispex_version: String,
    build_commit: String,
    build_dirty: bool,
    rustflags: String,
    encoded_rustflags: String,
    mutant_id: Option<String>,
}

impl IssueBuildIdentity {
    pub(super) fn current() -> Result<Self, IoBoundaryError> {
        static CURRENT: std::sync::OnceLock<Result<IssueBuildIdentity, IoBoundaryError>> =
            std::sync::OnceLock::new();
        CURRENT.get_or_init(Self::read_current).clone()
    }

    fn read_current() -> Result<Self, IoBoundaryError> {
        Ok(Self {
            executable_sha256: running_executable_digest()?,
            target_triple: env!("CSK_TARGET_TRIPLE").to_string(),
            lispex_version: env!("CSK_LISPEX_VERSION").to_string(),
            build_commit: env!("CSK_BUILD_COMMIT").to_string(),
            build_dirty: env!("LISPEX_BUILD_COMMIT_DIRTY") == "true",
            rustflags: env!("CSK_RUSTFLAGS").to_string(),
            encoded_rustflags: env!("CSK_CARGO_ENCODED_RUSTFLAGS").to_string(),
            mutant_id: match env!("CSK_SCORED_MUTANT") {
                "" => None,
                value => Some(value.to_string()),
            },
        })
    }

    fn build_variant(&self) -> BuildVariant {
        if self.mutant_id.is_some() {
            BuildVariant::Mutant
        } else {
            BuildVariant::Release
        }
    }

    pub(super) fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }
}

struct IssueRequest<'a> {
    source: &'a [u8],
    input: &'a [u8],
    profile: &'a str,
    key_handle: &'a str,
    output: &'a str,
    output_preexists: bool,
}

struct SignablePayload {
    canonical: CanonicalJson,
}

struct LoadedReleaseKey {
    signing_key: SigningKey,
    key_id: String,
    expected_key_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyOperationError {
    Load,
}

trait ReleaseKeyProvider {
    fn load(&self, handle: &str) -> Result<LoadedReleaseKey, KeyOperationError>;
    fn sign(
        &self,
        key: &LoadedReleaseKey,
        payload: &SignablePayload,
    ) -> Result<Envelope, KeyOperationError>;
    #[cfg(test)]
    fn access_counts(&self) -> KeyAccessCounts;
}

#[derive(Debug, Default)]
struct Pkcs8FileKeyProvider {
    resolution: AtomicUsize,
    open: AtomicUsize,
    load: AtomicUsize,
    signing: AtomicUsize,
}

impl ReleaseKeyProvider for Pkcs8FileKeyProvider {
    fn load(&self, handle: &str) -> Result<LoadedReleaseKey, KeyOperationError> {
        self.resolution.fetch_add(1, Ordering::SeqCst);
        let path = pkcs8_path(handle).ok_or(KeyOperationError::Load)?;
        self.open.fetch_add(1, Ordering::SeqCst);
        let mut file = File::open(path).map_err(|_| KeyOperationError::Load)?;
        let mut bytes = Vec::with_capacity(128);
        Read::by_ref(&mut file)
            .take(4_097)
            .read_to_end(&mut bytes)
            .map_err(|_| KeyOperationError::Load)?;
        if bytes.len() > 4_096 {
            return Err(KeyOperationError::Load);
        }
        let signing_key =
            SigningKey::from_pkcs8_der(&bytes).map_err(|_| KeyOperationError::Load)?;
        self.load.fetch_add(1, Ordering::SeqCst);
        let key_id = native_key_id(&signing_key.verifying_key().to_bytes());
        Ok(LoadedReleaseKey {
            signing_key,
            expected_key_id: key_id.clone(),
            key_id,
        })
    }

    fn sign(
        &self,
        key: &LoadedReleaseKey,
        payload: &SignablePayload,
    ) -> Result<Envelope, KeyOperationError> {
        self.signing.fetch_add(1, Ordering::SeqCst);
        if key.key_id != key.expected_key_id {
            return Err(KeyOperationError::Load);
        }
        Ok(sign_envelope(
            PayloadType::NativeReceipt,
            &payload.canonical,
            &key.signing_key,
            &key.key_id,
        ))
    }

    #[cfg(test)]
    fn access_counts(&self) -> KeyAccessCounts {
        KeyAccessCounts {
            resolution: self.resolution.load(Ordering::SeqCst),
            open: self.open.load(Ordering::SeqCst),
            load: self.load.load(Ordering::SeqCst),
            signing: self.signing.load(Ordering::SeqCst),
            ..KeyAccessCounts::default()
        }
    }
}

#[derive(Debug, Default)]
struct FilesystemDirectoryPublisher {
    renames: AtomicUsize,
}

impl AtomicDirectoryPublisher for FilesystemDirectoryPublisher {
    fn publish_directory(
        &self,
        output: &str,
        files: &[PublicationFile<'_>],
    ) -> Result<(), IoBoundaryError> {
        let output_path = Path::new(output);
        let output_name = output_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(IoBoundaryError::InvalidOutputName)?;
        if output_path.exists() {
            return Err(IoBoundaryError::OutputExists);
        }
        let parent = output_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| IoBoundaryError::PlatformIo)?;
        let random = random.iter().fold(
            String::with_capacity(random.len() * 2),
            |mut output, byte| {
                std::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}"))
                    .expect("writing to String cannot fail");
                output
            },
        );
        let staging = parent.join(format!(".{output_name}.stage-{random}"));
        fs::create_dir(&staging).map_err(|_| IoBoundaryError::PlatformIo)?;
        let result = (|| {
            for publication in files {
                validate_publication_name(publication.name)?;
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(staging.join(publication.name))
                    .map_err(|_| IoBoundaryError::PlatformIo)?;
                file.write_all(publication.bytes)
                    .map_err(|_| IoBoundaryError::ShortWrite)?;
                file.sync_all().map_err(|_| IoBoundaryError::FsyncFailure)?;
            }
            File::open(&staging)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| IoBoundaryError::FsyncFailure)?;
            fs::rename(&staging, output_path).map_err(|_| IoBoundaryError::FinalRenameFailure)?;
            self.renames.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })();
        if result.is_err() && staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    fn final_rename_count(&self) -> usize {
        self.renames.load(Ordering::SeqCst)
    }
}

/// Run the exact public issuer over two read-once paths.
pub fn issue_native_paths(
    source_path: &str,
    input_path: &str,
    profile: &str,
    key_handle: &str,
    output: &str,
) -> IssueOutcome {
    if Path::new(output).exists() {
        return IssueOutcome::unpublished(IssuePrimaryError::UsageError, None);
    }
    if profile != CHECKED_PROFILE_TAG || !validate_key_handle_uri(key_handle) {
        return publish_issue_usage_error(Some(output));
    }
    let publisher = FilesystemDirectoryPublisher::default();
    let files = OsFileProvider::default();
    let source = match files.read_once(source_path, MAX_SOURCE_BYTES) {
        Ok(bytes) => bytes,
        Err(IoBoundaryError::ResourceLimit) => {
            return publish_failure(
                IssuePrimaryError::ArtifactResourceLimit,
                None,
                &publisher,
                output,
            )
        }
        Err(_) => {
            return publish_failure(IssuePrimaryError::ArtifactIoError, None, &publisher, output)
        }
    };
    let input = match files.read_once(input_path, MAX_INPUT_BYTES) {
        Ok(bytes) => bytes,
        Err(IoBoundaryError::ResourceLimit) => {
            return publish_failure(
                IssuePrimaryError::ArtifactResourceLimit,
                None,
                &publisher,
                output,
            )
        }
        Err(_) => {
            return publish_failure(IssuePrimaryError::ArtifactIoError, None, &publisher, output)
        }
    };
    let identity = match IssueBuildIdentity::current() {
        Ok(identity) => identity,
        Err(_) => {
            return publish_failure(IssuePrimaryError::ArtifactIoError, None, &publisher, output)
        }
    };
    let mut nonce = [0_u8; 32];
    if getrandom::getrandom(&mut nonce).is_err() {
        return publish_failure(IssuePrimaryError::ArtifactIoError, None, &publisher, output);
    }
    let keys = Pkcs8FileKeyProvider::default();
    issue_native_with(
        IssueRequest {
            source: source.bytes(),
            input: input.bytes(),
            profile,
            key_handle,
            output,
            output_preexists: false,
        },
        &identity,
        nonce,
        &keys,
        &publisher,
    )
}

/// Run the exact public issuer over caller-owned authenticated bytes.
///
/// This entry point exists for the replay runner: the replay boundary reads
/// every rule and corpus member once, verifies their signed manifest, and then
/// passes those frozen buffers here without reopening mutable paths.  The
/// issuer still takes its own defensive copies before parsing or evaluation.
pub fn issue_native_bytes(
    source: &[u8],
    input: &[u8],
    profile: &str,
    key_handle: &str,
    output: &str,
) -> IssueOutcome {
    if Path::new(output).exists() {
        return IssueOutcome::unpublished(IssuePrimaryError::UsageError, None);
    }
    if profile != CHECKED_PROFILE_TAG || !validate_key_handle_uri(key_handle) {
        return publish_issue_usage_error(Some(output));
    }
    let publisher = FilesystemDirectoryPublisher::default();
    if source.len() > MAX_SOURCE_BYTES || input.len() > MAX_INPUT_BYTES {
        return publish_failure(
            IssuePrimaryError::ArtifactResourceLimit,
            None,
            &publisher,
            output,
        );
    }
    let identity = match IssueBuildIdentity::current() {
        Ok(identity) => identity,
        Err(_) => {
            return publish_failure(IssuePrimaryError::ArtifactIoError, None, &publisher, output)
        }
    };
    let mut nonce = [0_u8; 32];
    if getrandom::getrandom(&mut nonce).is_err() {
        return publish_failure(IssuePrimaryError::ArtifactIoError, None, &publisher, output);
    }
    let keys = Pkcs8FileKeyProvider::default();
    issue_native_with(
        IssueRequest {
            source,
            input,
            profile,
            key_handle,
            output,
            output_preexists: false,
        },
        &identity,
        nonce,
        &keys,
        &publisher,
    )
}

/// Publish a report-only usage refusal when parsing already established one
/// usable output path.  Missing/malformed output paths and pre-existing output
/// directories intentionally publish nothing.
pub fn publish_issue_usage_error(output: Option<&str>) -> IssueOutcome {
    let Some(output) = output else {
        return IssueOutcome::unpublished(IssuePrimaryError::UsageError, None);
    };
    if Path::new(output).exists() {
        return IssueOutcome::unpublished(IssuePrimaryError::UsageError, None);
    }
    publish_failure(
        IssuePrimaryError::UsageError,
        None,
        &FilesystemDirectoryPublisher::default(),
        output,
    )
}

pub fn validate_key_handle_uri(handle: &str) -> bool {
    if handle.is_empty()
        || handle
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte < 0x20)
    {
        return false;
    }
    let Some((scheme, rest)) = handle.split_once(':') else {
        return false;
    };
    let mut scheme_bytes = scheme.bytes();
    if !scheme_bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic())
        || !scheme_bytes.all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
        || rest.is_empty()
        || ["env", "inline", "stdin"]
            .iter()
            .any(|forbidden| scheme.eq_ignore_ascii_case(forbidden))
    {
        return false;
    }
    if scheme == "pkcs8-file" {
        let Some(path) = rest.strip_prefix("//") else {
            return false;
        };
        return Path::new(path).is_absolute();
    }
    true
}

fn issue_native_with(
    request: IssueRequest<'_>,
    identity: &IssueBuildIdentity,
    nonce: [u8; 32],
    keys: &dyn ReleaseKeyProvider,
    publisher: &dyn AtomicDirectoryPublisher,
) -> IssueOutcome {
    // Step 1. Syntax/resource checks may inspect only the key-handle string.
    if request.output_preexists {
        return IssueOutcome::unpublished(IssuePrimaryError::UsageError, None);
    }
    if request.profile != CHECKED_PROFILE_TAG || !validate_key_handle_uri(request.key_handle) {
        return publish_failure(
            IssuePrimaryError::UsageError,
            None,
            publisher,
            request.output,
        );
    }
    if request.source.len() > MAX_SOURCE_BYTES || request.input.len() > MAX_INPUT_BYTES {
        return publish_failure(
            IssuePrimaryError::ArtifactResourceLimit,
            None,
            publisher,
            request.output,
        );
    }

    // Step 2. Defensive entry copies become the only byte authority below.
    let source = FrozenBytes::from_slice(request.source);
    let input = FrozenBytes::from_slice(request.input);

    // Step 3. Parse the source and checked-input host value before profile
    // classification or normalization.
    let parsed_source = match parse_checked_source(source.bytes()) {
        Ok(program) => program,
        Err(error) => {
            return publish_failure(
                map_profile_error(error.code),
                None,
                publisher,
                request.output,
            )
        }
    };
    let checked_input = match CheckedInput::parse(input.bytes()) {
        Ok(input) => input,
        Err(error) => {
            return publish_failure(map_input_error(error), None, publisher, request.output)
        }
    };

    // Step 4. Validate the checked profile and deterministically normalize.
    let program = match prepare_parsed_checked_source(parsed_source) {
        Ok(program) => program,
        Err(error) => {
            return publish_failure(
                map_profile_error(error.code),
                None,
                publisher,
                request.output,
            )
        }
    };

    // Step 5. Deterministic complete graph lowering.
    let graph = match lower_contract_graph(program.core()) {
        Ok(graph) => graph,
        Err(error) => {
            return publish_failure(map_graph_error(error), None, publisher, request.output)
        }
    };
    let graph_sha256 = match contract_graph_digest(&graph) {
        Ok(digest) => digest,
        Err(_) => {
            return publish_failure(
                IssuePrimaryError::NativeLoweringFailed,
                None,
                publisher,
                request.output,
            )
        }
    };
    let normalized_sha256 = domain_hash("csk.v0.canonical", program.normalized_bytes());
    let context_digest = match execution_context_digest(
        program.normalized_bytes(),
        checked_input.canonical_value_digest(),
        request.profile,
        &identity.executable_sha256,
    ) {
        Ok(digest) => digest,
        Err(_) => {
            return publish_failure(
                IssuePrimaryError::NativeSelfVerificationFailed,
                None,
                publisher,
                request.output,
            )
        }
    };
    let context = InvocationContext::new(
        nonce,
        context_digest.clone(),
        normalized_sha256.clone(),
        graph_sha256.clone(),
        checked_input.canonical_value_digest().to_string(),
        request.profile.to_string(),
        EvaluationBudgets::CONTRACT,
        graph.roots.len(),
    );

    // Steps 6-7. Each live evaluator mints its own private token.
    let reference = match mint_reference_token(&program, checked_input.mapped_value(), &context) {
        Ok(token) => token,
        Err(ReferenceEvaluationError::ProfileEscape) => {
            return publish_failure(
                IssuePrimaryError::ProfileEscape,
                None,
                publisher,
                request.output,
            )
        }
        Err(ReferenceEvaluationError::InvocationMismatch) => {
            return publish_failure(
                IssuePrimaryError::NativeSelfVerificationFailed,
                None,
                publisher,
                request.output,
            )
        }
    };
    let meaning = match mint_meaning_token(&graph, checked_input.mapped_value(), &context) {
        Ok(token) => token,
        Err(MeaningEvaluationError::ProfileEscape) => {
            return publish_failure(
                IssuePrimaryError::ProfileEscape,
                None,
                publisher,
                request.output,
            )
        }
        Err(MeaningEvaluationError::InvocationMismatch) => {
            return publish_failure(
                IssuePrimaryError::NativeSelfVerificationFailed,
                None,
                publisher,
                request.output,
            )
        }
    };

    // Step 8. Only the two live current-invocation tokens can supply traces.
    let bound = match bind_and_consume(&context, &reference, &meaning) {
        Ok(bound) => bound,
        Err(_) => {
            return publish_failure(
                IssuePrimaryError::NativeSelfVerificationFailed,
                None,
                publisher,
                request.output,
            )
        }
    };
    let reports = match build_trace_reports(&context, graph.nodes.len(), bound) {
        Ok(reports) => reports,
        Err(_) => {
            return publish_failure(
                IssuePrimaryError::NativeSelfVerificationFailed,
                None,
                publisher,
                request.output,
            )
        }
    };
    let receipt = build_receipt(
        source.bytes(),
        &checked_input,
        &program,
        graph,
        reports.clone(),
        identity,
        context_digest,
        normalized_sha256,
        graph_sha256,
    );

    // Step 9. Canonical payload serialization.
    let payload = match receipt.canonical_bytes() {
        Ok(payload) => payload,
        Err(_) => {
            return publish_failure(
                IssuePrimaryError::NativeSelfVerificationFailed,
                None,
                publisher,
                request.output,
            )
        }
    };

    // Step 10. Structural checks plus the exact consumed-token binding.
    if verify_structure(
        &payload,
        StructuralContext {
            input: input.bytes(),
            source: Some(source.bytes()),
            expected_profile: Some(request.profile),
            release_signed: false,
        },
    )
    .is_err()
        || verify_consumed_binding(&context, &reference, &meaning, &reports).is_err()
    {
        return publish_failure(
            IssuePrimaryError::NativeSelfVerificationFailed,
            None,
            publisher,
            request.output,
        );
    }

    // Step 11. The closed release signability order.
    if let Some(reason) = signability_reason(&receipt) {
        return publish_failure(
            IssuePrimaryError::NativeResultNotSignable,
            Some(reason),
            publisher,
            request.output,
        );
    }

    // Step 12. Rebind sealed receipt fields to the current build/invocation.
    if !build_self_check(&receipt, identity, &context) {
        return publish_failure(
            IssuePrimaryError::NativeSelfVerificationFailed,
            None,
            publisher,
            request.output,
        );
    }

    // `SignablePayload` has no constructor on any earlier control-flow path.
    let signable = match canonical_gate(&payload, RawArtifactKind::Payload) {
        Ok(canonical) => SignablePayload { canonical },
        Err(_) => {
            return publish_failure(
                IssuePrimaryError::NativeSelfVerificationFailed,
                None,
                publisher,
                request.output,
            )
        }
    };

    // Step 13. First and only key-handle resolution/open point.
    let loaded = match keys.load(request.key_handle) {
        Ok(key) if key.key_id == key.expected_key_id => key,
        _ => {
            return publish_failure(
                IssuePrimaryError::NativeKeyLoadFailed,
                None,
                publisher,
                request.output,
            )
        }
    };

    // Step 14. Sign only the typed payload, then run the complete Native
    // verifier against an in-memory policy for this exact key/profile/engine.
    let envelope = match keys.sign(&loaded, &signable) {
        Ok(envelope) => envelope,
        Err(_) => {
            return publish_failure(
                IssuePrimaryError::NativeSigningFailed,
                None,
                publisher,
                request.output,
            )
        }
    };
    let envelope_bytes = match envelope.canonical_bytes() {
        Ok(bytes) => bytes,
        Err(_) => {
            return publish_failure(
                IssuePrimaryError::NativeSigningFailed,
                None,
                publisher,
                request.output,
            )
        }
    };
    let policy = match self_verification_policy(&loaded, identity) {
        Ok(policy) => policy,
        Err(_) => {
            return publish_failure(
                IssuePrimaryError::NativeSigningFailed,
                None,
                publisher,
                request.output,
            )
        }
    };
    let verified = verify_native(
        &envelope_bytes,
        &policy,
        request.profile,
        source.bytes(),
        input.bytes(),
    );
    if !matches!(verified, Ok(ref evidence) if evidence.promotion_ineligibility().is_none()) {
        return publish_failure(
            IssuePrimaryError::NativeSigningFailed,
            None,
            publisher,
            request.output,
        );
    }

    // Step 15. One directory rename exposes the exact success set.
    let report = NativeIssueReport::issued().canonical_bytes();
    if publisher
        .publish_directory(
            request.output,
            &[
                PublicationFile {
                    name: "payload.json",
                    bytes: signable.canonical.bytes(),
                },
                PublicationFile {
                    name: "envelope.dsse.json",
                    bytes: &envelope_bytes,
                },
                PublicationFile {
                    name: "issue-report.json",
                    bytes: &report,
                },
            ],
        )
        .is_err()
    {
        return IssueOutcome::unpublished(IssuePrimaryError::ArtifactIoError, None);
    }
    IssueOutcome::issued()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_receipt(
    source: &[u8],
    input: &CheckedInput,
    program: &super::checked_profile::CheckedProgram,
    graph: super::graph::ContractGraph,
    reports: TokenBoundTraceReports,
    identity: &IssueBuildIdentity,
    context_digest: String,
    normalized_sha256: String,
    graph_sha256: String,
) -> DifferentialReceipt {
    DifferentialReceipt {
        engine: EngineIdentity {
            executable_sha256: identity.executable_sha256.clone(),
            target_triple: identity.target_triple.clone(),
        },
        execution: ExecutionIdentity {
            context_digest,
            lispex_version: identity.lispex_version.clone(),
            build_commit: identity.build_commit.clone(),
            build_variant: identity.build_variant(),
            mutant_id: identity.mutant_id.clone(),
            target_triple: identity.target_triple.clone(),
            executable_sha256: identity.executable_sha256.clone(),
        },
        source: ByteIdentity {
            sha256: domain_hash("csk.v0.source", source),
            byte_length: source.len(),
        },
        input: InputIdentity {
            sha256: input.raw_digest().to_string(),
            byte_length: input.raw_byte_length(),
            canonical_value_sha256: input.canonical_value_digest().to_string(),
        },
        canonical: CanonicalProgramIdentity {
            normalized_sha256,
            normalized_bytes: program.normalized_bytes().to_vec(),
        },
        graph: GraphReceiptValue {
            graph_sha256,
            graph,
        },
        reference: reports.reference,
        meaning_env: reports.meaning,
        comparison: reports.comparison,
        diagnostics: Vec::new(),
        boundary_statement_sha256: domain_hash("csk.v0.boundary", BOUNDARY_STATEMENT.as_bytes()),
    }
}

fn signability_reason(receipt: &DifferentialReceipt) -> Option<SignabilityReason> {
    if receipt.comparison.status != super::receipt::ComparisonStatus::Agree {
        return Some(SignabilityReason::ComparisonNotAgree);
    }
    if receipt.reference.transcript.terminal != Terminal::Completed
        || receipt.meaning_env.transcript.terminal != Terminal::Completed
    {
        return Some(SignabilityReason::TerminalNotCompleted);
    }
    if !matches!(
        final_value(&receipt.reference.transcript.events),
        Some(Decision::Approve | Decision::Deny | Decision::Review | Decision::InvalidInput)
    ) {
        return Some(SignabilityReason::FinalValueNotDecision);
    }
    if !receipt.diagnostics.is_empty() {
        return Some(SignabilityReason::DiagnosticsPresent);
    }
    if receipt.execution.build_variant != BuildVariant::Release
        || receipt.execution.mutant_id.is_some()
    {
        return Some(SignabilityReason::MutantBuild);
    }
    None
}

fn final_value(events: &[TranscriptEvent]) -> Option<Decision> {
    match events.last() {
        Some(TranscriptEvent::Value {
            value: super::canonical_value::CanonicalValue::Decision(decision),
            ..
        }) => Some(*decision),
        _ => None,
    }
}

fn build_self_check(
    receipt: &DifferentialReceipt,
    identity: &IssueBuildIdentity,
    context: &InvocationContext,
) -> bool {
    !identity.build_dirty
        && identity.rustflags.is_empty()
        && identity.encoded_rustflags.is_empty()
        && lowercase_hex(&identity.build_commit, 40)
        && executable_digest_valid(&identity.executable_sha256)
        && !identity.target_triple.is_empty()
        && !identity.lispex_version.is_empty()
        && identity.mutant_id.is_none()
        && receipt.execution.context_digest == context_digest_from_context(context)
        && receipt.execution.build_commit == identity.build_commit
        && receipt.execution.lispex_version == identity.lispex_version
        && receipt.execution.target_triple == identity.target_triple
        && receipt.execution.executable_sha256 == identity.executable_sha256
        && receipt.engine.target_triple == identity.target_triple
        && receipt.engine.executable_sha256 == identity.executable_sha256
        && receipt.execution.build_variant == BuildVariant::Release
        && receipt.execution.mutant_id.is_none()
}

fn context_digest_from_context(context: &InvocationContext) -> String {
    // The context's private digest is intentionally exposed only through this
    // same-module recomputation path, keeping nonce and fields nonserializable.
    // The receipt check above has already recomputed the digest from its fields.
    context_digest_marker(context)
}

fn context_digest_marker(context: &InvocationContext) -> String {
    // `InvocationContext` keeps its digest private to the token boundary.  The
    // normalized/graph accessors below make it impossible to confuse contexts;
    // this helper is replaced by a private accessor rather than serializing it.
    context.context_digest().to_string()
}

pub(super) fn execution_context_digest(
    normalized: &[u8],
    input_canonical_value_sha256: &str,
    profile: &str,
    engine_executable_sha256: &str,
) -> Result<String, vouch::artifact_json::JsonWriteError> {
    let value = JsonValue::object([
        (
            "normalized_bytes_b64",
            JsonValue::String(encode_base64(normalized)),
        ),
        (
            "input_canonical_value_sha256",
            JsonValue::String(input_canonical_value_sha256.to_string()),
        ),
        ("profile", JsonValue::String(profile.to_string())),
        (
            "engine_executable_sha256",
            JsonValue::String(engine_executable_sha256.to_string()),
        ),
    ])
    .expect("execution context fields are unique");
    Ok(domain_hash(
        "csk.v0.execution-context",
        &write_canonical(&value)?,
    ))
}

fn self_verification_policy(
    key: &LoadedReleaseKey,
    identity: &IssueBuildIdentity,
) -> Result<Vec<u8>, vouch::artifact_json::JsonWriteError> {
    let public = key.signing_key.verifying_key().to_bytes();
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
                .expect("minimum version fields are unique"),
            ),
            (
                "keys",
                JsonValue::Array(vec![JsonValue::object([
                    ("key_id", JsonValue::String(key.key_id.clone())),
                    ("algorithm", JsonValue::String("ed25519".to_string())),
                    ("public_key", JsonValue::String(encode_base64(&public))),
                    (
                        "allowed_payload_types",
                        JsonValue::Array(vec![JsonValue::String(NATIVE_PAYLOAD_TYPE.to_string())]),
                    ),
                    (
                        "allowed_profiles",
                        JsonValue::Array(vec![JsonValue::String(CHECKED_PROFILE_TAG.to_string())]),
                    ),
                    (
                        "allowed_engine_sha256",
                        JsonValue::Array(vec![JsonValue::String(
                            identity.executable_sha256.clone(),
                        )]),
                    ),
                ])
                .expect("self-verification key fields are unique")]),
            ),
        ])
        .expect("self-verification policy fields are unique"),
    )
}

fn publish_failure(
    primary_error: IssuePrimaryError,
    reason: Option<SignabilityReason>,
    publisher: &dyn AtomicDirectoryPublisher,
    output: &str,
) -> IssueOutcome {
    let report = NativeIssueReport::refused(primary_error, reason).canonical_bytes();
    if publisher
        .publish_directory(
            output,
            &[PublicationFile {
                name: "issue-report.json",
                bytes: &report,
            }],
        )
        .is_err()
    {
        return IssueOutcome::unpublished(IssuePrimaryError::ArtifactIoError, None);
    }
    IssueOutcome {
        exit_code: primary_error.exit_code(),
        primary_error: Some(primary_error),
        reason,
        published: true,
    }
}

fn map_input_error(error: CheckedInputError) -> IssuePrimaryError {
    match error {
        CheckedInputError::ResourceLimit => IssuePrimaryError::ArtifactResourceLimit,
        CheckedInputError::ParseFailed => IssuePrimaryError::NativeInputParseFailed,
        CheckedInputError::ProfileInvalid => IssuePrimaryError::NativeInputProfileInvalid,
    }
}

fn map_profile_error(error: ProfileErrorCode) -> IssuePrimaryError {
    match error {
        ProfileErrorCode::ResourceLimit => IssuePrimaryError::ArtifactResourceLimit,
        ProfileErrorCode::NativeLoweringFailed => IssuePrimaryError::NativeLoweringFailed,
        ProfileErrorCode::ProfileEscape => IssuePrimaryError::ProfileEscape,
    }
}

fn map_graph_error(error: GraphError) -> IssuePrimaryError {
    match error {
        GraphError::ResourceLimit => IssuePrimaryError::ArtifactResourceLimit,
        GraphError::ProfileEscape(_) => IssuePrimaryError::ProfileEscape,
        GraphError::Invalid(_) => IssuePrimaryError::NativeLoweringFailed,
    }
}

fn pkcs8_path(handle: &str) -> Option<PathBuf> {
    let path = handle.strip_prefix("pkcs8-file://")?;
    let path = PathBuf::from(path);
    path.is_absolute().then_some(path)
}

fn validate_publication_name(name: &str) -> Result<(), IoBoundaryError> {
    let path = Path::new(name);
    if name.is_empty()
        || path.is_absolute()
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(IoBoundaryError::InvalidOutputName);
    }
    Ok(())
}

fn running_executable_digest() -> Result<String, IoBoundaryError> {
    let path = std::env::current_exe().map_err(|_| IoBoundaryError::PlatformIo)?;
    let mut file = File::open(path).map_err(|_| IoBoundaryError::PlatformIo)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| IoBoundaryError::PlatformIo)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn executable_digest_valid(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| lowercase_hex(hex, 64))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use vouch::io_boundary::{MemoryAtomicDirectoryPublisher, PublicationFault};

    use super::*;

    const SOURCE: &[u8] = b"(if (< input 10) (decision-approve) (decision-review))\n";
    const INPUT: &[u8] = b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": 7\n}\n";
    const OUTPUT: &str = "issued";
    const HANDLE: &str = "fixture://release";

    type FixtureKeyEntry = ([u8; 32], Option<String>);

    #[derive(Debug, Default)]
    struct CountingFixtureKeyProvider {
        keys: Mutex<BTreeMap<String, FixtureKeyEntry>>,
        resolution: AtomicUsize,
        load: AtomicUsize,
        signing: AtomicUsize,
        fail_sign: Mutex<bool>,
    }

    impl CountingFixtureKeyProvider {
        fn insert(&self, handle: &str, seed: [u8; 32]) {
            self.keys
                .lock()
                .expect("fixture key lock")
                .insert(handle.to_string(), (seed, None));
        }

        fn set_fail_sign(&self, fail: bool) {
            *self.fail_sign.lock().expect("fixture sign lock") = fail;
        }
    }

    impl ReleaseKeyProvider for CountingFixtureKeyProvider {
        fn load(&self, handle: &str) -> Result<LoadedReleaseKey, KeyOperationError> {
            self.resolution.fetch_add(1, Ordering::SeqCst);
            let (seed, expected) = self
                .keys
                .lock()
                .expect("fixture key lock")
                .get(handle)
                .cloned()
                .ok_or(KeyOperationError::Load)?;
            self.load.fetch_add(1, Ordering::SeqCst);
            let signing_key = SigningKey::from_bytes(&seed);
            let key_id = native_key_id(&signing_key.verifying_key().to_bytes());
            Ok(LoadedReleaseKey {
                signing_key,
                expected_key_id: expected.unwrap_or_else(|| key_id.clone()),
                key_id,
            })
        }

        fn sign(
            &self,
            key: &LoadedReleaseKey,
            payload: &SignablePayload,
        ) -> Result<Envelope, KeyOperationError> {
            self.signing.fetch_add(1, Ordering::SeqCst);
            if *self.fail_sign.lock().expect("fixture sign lock") {
                return Err(KeyOperationError::Load);
            }
            Ok(sign_envelope(
                PayloadType::NativeReceipt,
                &payload.canonical,
                &key.signing_key,
                &key.key_id,
            ))
        }

        fn access_counts(&self) -> KeyAccessCounts {
            KeyAccessCounts {
                resolution: self.resolution.load(Ordering::SeqCst),
                load: self.load.load(Ordering::SeqCst),
                signing: self.signing.load(Ordering::SeqCst),
                ..KeyAccessCounts::default()
            }
        }
    }

    fn identity(mutant: Option<&str>) -> IssueBuildIdentity {
        IssueBuildIdentity {
            executable_sha256: format!("sha256:{}", "1".repeat(64)),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            lispex_version: "1.4.0".to_string(),
            build_commit: "2".repeat(40),
            build_dirty: false,
            rustflags: String::new(),
            encoded_rustflags: String::new(),
            mutant_id: mutant.map(str::to_string),
        }
    }

    fn request<'a>(source: &'a [u8], input: &'a [u8]) -> IssueRequest<'a> {
        IssueRequest {
            source,
            input,
            profile: CHECKED_PROFILE_TAG,
            key_handle: HANDLE,
            output: OUTPUT,
            output_preexists: false,
        }
    }

    #[test]
    fn stage6_success_signs_self_verifies_and_single_rename_publishes_exact_set() {
        let keys = CountingFixtureKeyProvider::default();
        keys.insert(HANDLE, [7_u8; 32]);
        let publisher = MemoryAtomicDirectoryPublisher::default();
        let outcome = issue_native_with(
            request(SOURCE, INPUT),
            &identity(None),
            [3_u8; 32],
            &keys,
            &publisher,
        );
        assert_eq!(outcome, IssueOutcome::issued());
        assert_eq!(publisher.final_rename_count(), 1);
        let directory = publisher.directory(OUTPUT).expect("published directory");
        assert_eq!(
            directory.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["envelope.dsse.json", "issue-report.json", "payload.json"]
        );
        assert_eq!(keys.access_counts().resolution, 1);
        assert_eq!(keys.access_counts().load, 1);
        assert_eq!(keys.access_counts().signing, 1);
        assert!(String::from_utf8(directory["issue-report.json"].clone())
            .unwrap()
            .contains("\"status\": \"issued-native\""));
    }

    #[test]
    fn stage6_prekey_refusals_have_zero_aggregate_key_access_and_report_only() {
        let keys = CountingFixtureKeyProvider::default();
        keys.insert(HANDLE, [8_u8; 32]);
        let mut dirty_build = identity(None);
        dirty_build.build_dirty = true;
        let mut flagged_build = identity(None);
        flagged_build.rustflags = "-Ctarget-cpu=native".to_string();

        for (index, (source, input, build, expected, reason)) in [
            (
                SOURCE,
                b"not-json\n".as_slice(),
                identity(None),
                IssuePrimaryError::NativeInputParseFailed,
                None,
            ),
            (
                SOURCE,
                b"{\n  \"input\": \"wrong\",\n  \"value\": 7\n}\n".as_slice(),
                identity(None),
                IssuePrimaryError::NativeInputProfileInvalid,
                None,
            ),
            (
                b"(/ 1 0)".as_slice(),
                INPUT,
                identity(None),
                IssuePrimaryError::NativeResultNotSignable,
                Some(SignabilityReason::TerminalNotCompleted),
            ),
            (
                b"(+ input 1)".as_slice(),
                INPUT,
                identity(None),
                IssuePrimaryError::NativeResultNotSignable,
                Some(SignabilityReason::FinalValueNotDecision),
            ),
            (
                SOURCE,
                INPUT,
                identity(Some("M01")),
                IssuePrimaryError::NativeResultNotSignable,
                Some(SignabilityReason::MutantBuild),
            ),
            (
                SOURCE,
                INPUT,
                dirty_build,
                IssuePrimaryError::NativeSelfVerificationFailed,
                None,
            ),
            (
                SOURCE,
                INPUT,
                flagged_build,
                IssuePrimaryError::NativeSelfVerificationFailed,
                None,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let publisher = MemoryAtomicDirectoryPublisher::default();
            let output = format!("refused-{index}");
            let mut req = request(source, input);
            req.output = &output;
            let outcome = issue_native_with(req, &build, [index as u8; 32], &keys, &publisher);
            assert_eq!(outcome.primary_error, Some(expected));
            assert_eq!(outcome.reason, reason);
            assert_eq!(publisher.final_rename_count(), 1);
            assert_eq!(
                publisher
                    .directory(&output)
                    .expect("failure report directory")
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                vec!["issue-report.json"]
            );
        }
        assert_eq!(keys.access_counts().total(), 0);
    }

    #[test]
    fn stage6_complete_prekey_gate_audit_covers_closed_reasons_and_structural_refusals() {
        use super::super::receipt::{ComparisonStatus, ReceiptDiagnostic};

        let keys = CountingFixtureKeyProvider::default();
        keys.insert(HANDLE, [13_u8; 32]);

        let mut disagree = fixture_receipt(SOURCE);
        disagree.comparison.status = ComparisonStatus::Disagree;
        disagree.comparison.first_divergence_index = Some(0);
        assert_eq!(
            signability_reason(&disagree),
            Some(SignabilityReason::ComparisonNotAgree)
        );

        let mut not_comparable = fixture_receipt(SOURCE);
        not_comparable.comparison.status = ComparisonStatus::NotComparable;
        not_comparable.comparison.comparison_unavailable_at = Some(0);
        assert_eq!(
            signability_reason(&not_comparable),
            Some(SignabilityReason::ComparisonNotAgree)
        );

        let fault = fixture_receipt(b"(/ 1 0)\n");
        assert_eq!(
            signability_reason(&fault),
            Some(SignabilityReason::TerminalNotCompleted)
        );

        let nondecision = fixture_receipt(b"(+ input 1)\n");
        assert_eq!(
            signability_reason(&nondecision),
            Some(SignabilityReason::FinalValueNotDecision)
        );

        let mut diagnostics = fixture_receipt(SOURCE);
        diagnostics.diagnostics.push(ReceiptDiagnostic {
            code: "fixture-diagnostic".to_string(),
            message: "fixture diagnostic".to_string(),
        });
        assert_eq!(
            signability_reason(&diagnostics),
            Some(SignabilityReason::DiagnosticsPresent)
        );

        let mut mutant = fixture_receipt(SOURCE);
        mutant.execution.build_variant = BuildVariant::Mutant;
        mutant.execution.mutant_id = Some("M01".to_string());
        assert_eq!(
            signability_reason(&mutant),
            Some(SignabilityReason::MutantBuild)
        );

        // The displayed order is load-bearing when several reasons apply.
        mutant.comparison.status = ComparisonStatus::Disagree;
        mutant.reference.transcript.terminal = Terminal::LanguageFault {
            code: super::super::transcript::LanguageFaultCode::DivisionByZero,
            form_index: 0,
        };
        assert_eq!(
            signability_reason(&mutant),
            Some(SignabilityReason::ComparisonNotAgree)
        );

        // These malformed receipts are rejected by structural verification,
        // before the signability helper above or any key-provider operation.
        for (index, mut receipt) in [
            fixture_receipt(SOURCE),
            fixture_receipt(SOURCE),
            fixture_receipt(SOURCE),
            fixture_receipt(SOURCE),
        ]
        .into_iter()
        .enumerate()
        {
            match index {
                0 => {
                    receipt.graph.graph.roots.clear();
                    let digest = contract_graph_digest(&receipt.graph.graph).unwrap();
                    receipt.graph.graph_sha256 = digest.clone();
                    receipt.meaning_env.graph_sha256 = digest;
                }
                1 => {
                    receipt.reference.transcript.events.clear();
                    let bytes = receipt.reference.transcript.canonical_bytes().unwrap();
                    receipt.reference.transcript_sha256 = domain_hash("csk.v0.reference", &bytes);
                }
                2 => {
                    receipt.meaning_env.transcript.events.clear();
                    let bytes = receipt.meaning_env.transcript.canonical_bytes().unwrap();
                    receipt.meaning_env.transcript_sha256 =
                        domain_hash("csk.v0.meaning_env", &bytes);
                }
                3 => {
                    let Some(TranscriptEvent::Value { value, .. }) =
                        receipt.meaning_env.transcript.events.last_mut()
                    else {
                        panic!("fixture has final value event");
                    };
                    *value =
                        super::super::canonical_value::CanonicalValue::Decision(Decision::Deny);
                    let bytes = receipt.meaning_env.transcript.canonical_bytes().unwrap();
                    receipt.meaning_env.transcript_sha256 =
                        domain_hash("csk.v0.meaning_env", &bytes);
                }
                _ => unreachable!(),
            }
            let payload = receipt.canonical_bytes().unwrap();
            assert!(verify_structure(
                &payload,
                StructuralContext {
                    input: INPUT,
                    source: Some(SOURCE),
                    expected_profile: Some(CHECKED_PROFILE_TAG),
                    release_signed: false,
                },
            )
            .is_err());
        }

        // A same-root-count prior-invocation pair cannot be consumed for the
        // current invocation, which covers the transcript-swap key boundary.
        let (program, checked_input, graph, current) = fixture_execution(SOURCE, [21_u8; 32]);
        let (_, _, _, prior) = fixture_execution(SOURCE, [22_u8; 32]);
        let reference = mint_reference_token(&program, checked_input.mapped_value(), &prior)
            .expect("prior reference token");
        let meaning = mint_meaning_token(&graph, checked_input.mapped_value(), &prior)
            .expect("prior meaning token");
        assert!(bind_and_consume(&current, &reference, &meaning).is_err());

        assert_eq!(keys.access_counts().total(), 0);
    }

    #[test]
    fn stage6_output_exists_refuses_before_key_without_overwrite_or_report() {
        let keys = CountingFixtureKeyProvider::default();
        keys.insert(HANDLE, [9_u8; 32]);
        let publisher = MemoryAtomicDirectoryPublisher::default();
        let mut req = request(SOURCE, INPUT);
        req.output_preexists = true;
        let outcome = issue_native_with(req, &identity(None), [4_u8; 32], &keys, &publisher);
        assert_eq!(outcome.primary_error, Some(IssuePrimaryError::UsageError));
        assert!(!outcome.published);
        assert_eq!(publisher.final_rename_count(), 0);
        assert_eq!(keys.access_counts().total(), 0);
    }

    #[test]
    fn stage6_postkey_signing_and_publication_failures_are_distinct() {
        let signing_keys = CountingFixtureKeyProvider::default();
        signing_keys.insert(HANDLE, [10_u8; 32]);
        signing_keys.set_fail_sign(true);
        let signing_publisher = MemoryAtomicDirectoryPublisher::default();
        let signing = issue_native_with(
            request(SOURCE, INPUT),
            &identity(None),
            [5_u8; 32],
            &signing_keys,
            &signing_publisher,
        );
        assert_eq!(signing.exit_code, 4);
        assert_eq!(
            signing.primary_error,
            Some(IssuePrimaryError::NativeSigningFailed)
        );
        assert_eq!(signing_keys.access_counts().signing, 1);
        assert_eq!(signing_publisher.final_rename_count(), 1);
        assert_eq!(
            signing_publisher
                .directory(OUTPUT)
                .expect("signing failure report")
                .len(),
            1
        );

        let publish_keys = CountingFixtureKeyProvider::default();
        publish_keys.insert(HANDLE, [11_u8; 32]);
        let publish_publisher = MemoryAtomicDirectoryPublisher::default();
        publish_publisher.set_fault(PublicationFault::FinalRenameFailure);
        let publication = issue_native_with(
            request(SOURCE, INPUT),
            &identity(None),
            [6_u8; 32],
            &publish_keys,
            &publish_publisher,
        );
        assert_eq!(publication.exit_code, 3);
        assert_eq!(
            publication.primary_error,
            Some(IssuePrimaryError::ArtifactIoError)
        );
        assert_eq!(publish_keys.access_counts().signing, 1);
        assert_eq!(publish_publisher.final_rename_count(), 0);
        assert!(publish_publisher.directory(OUTPUT).is_none());
    }

    #[test]
    fn stage6_key_handle_syntax_is_string_only_and_forbids_inline_sources() {
        assert!(validate_key_handle_uri("pkcs8-file:///absolute/key.der"));
        assert!(validate_key_handle_uri("hsm://slot/release"));
        assert!(!validate_key_handle_uri("pkcs8-file://relative/key.der"));
        assert!(!validate_key_handle_uri("inline:AAAA"));
        assert!(!validate_key_handle_uri("INLINE:AAAA"));
        assert!(!validate_key_handle_uri("env:RELEASE_KEY"));
        assert!(!validate_key_handle_uri("ENV:RELEASE_KEY"));
        assert!(!validate_key_handle_uri("stdin:-"));
        assert!(!validate_key_handle_uri("not-a-uri"));
    }

    #[test]
    fn stage6_pkcs8_file_provider_loads_one_absolute_uri_and_signs_typed_payload() {
        let directory = std::env::temp_dir().join(format!(
            "lispex-stage6-pkcs8-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("release.pk8");
        let mut der = hex_bytes("302e020100300506032b657004220420");
        der.extend_from_slice(&[12_u8; 32]);
        fs::write(&path, der).unwrap();
        let provider = Pkcs8FileKeyProvider::default();
        let handle = format!("pkcs8-file://{}", path.display());
        let loaded = provider.load(&handle).unwrap();
        let signable = SignablePayload {
            canonical: canonical_gate(b"{}\n", RawArtifactKind::Payload).unwrap(),
        };
        let envelope = provider.sign(&loaded, &signable).unwrap();
        assert_eq!(envelope.signatures()[0].key_id(), loaded.key_id);
        assert_eq!(provider.access_counts().resolution, 1);
        assert_eq!(provider.access_counts().open, 1);
        assert_eq!(provider.access_counts().load, 1);
        assert_eq!(provider.access_counts().signing, 1);
        fs::remove_dir_all(directory).unwrap();
    }

    fn fixture_receipt(source: &[u8]) -> DifferentialReceipt {
        let (program, checked_input, graph, context) = fixture_execution(source, [17_u8; 32]);
        let graph_sha256 = context.graph_sha256().to_string();
        let normalized_sha256 = context.normalized_sha256().to_string();
        let context_digest = context.context_digest().to_string();
        let reference = mint_reference_token(&program, checked_input.mapped_value(), &context)
            .expect("reference fixture token");
        let meaning = mint_meaning_token(&graph, checked_input.mapped_value(), &context)
            .expect("meaning fixture token");
        let bound = bind_and_consume(&context, &reference, &meaning).expect("fixture token pair");
        let reports =
            build_trace_reports(&context, graph.nodes.len(), bound).expect("fixture trace reports");
        build_receipt(
            source,
            &checked_input,
            &program,
            graph,
            reports,
            &identity(None),
            context_digest,
            normalized_sha256,
            graph_sha256,
        )
    }

    fn fixture_execution(
        source: &[u8],
        nonce: [u8; 32],
    ) -> (
        super::super::checked_profile::CheckedProgram,
        CheckedInput,
        super::super::graph::ContractGraph,
        InvocationContext,
    ) {
        let program = super::super::checked_profile::prepare_checked_program(source)
            .expect("checked fixture program");
        let checked_input = CheckedInput::parse(INPUT).expect("checked fixture input");
        let graph = lower_contract_graph(program.core()).expect("fixture graph");
        let graph_sha256 = contract_graph_digest(&graph).expect("fixture graph digest");
        let normalized_sha256 = domain_hash("csk.v0.canonical", program.normalized_bytes());
        let context_digest = execution_context_digest(
            program.normalized_bytes(),
            checked_input.canonical_value_digest(),
            CHECKED_PROFILE_TAG,
            &identity(None).executable_sha256,
        )
        .expect("fixture context digest");
        let context = InvocationContext::new(
            nonce,
            context_digest,
            normalized_sha256,
            graph_sha256,
            checked_input.canonical_value_digest().to_string(),
            CHECKED_PROFILE_TAG.to_string(),
            EvaluationBudgets::CONTRACT,
            graph.roots.len(),
        );
        (program, checked_input, graph, context)
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }
}
