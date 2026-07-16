//! Thin Lispex CLI (Round 3): read → normalize → evaluate a source file (or stdin),
//! auto-printing each top-level result via `write`, one value per line (zero values
//! print nothing; multiple values print one per line — the REPL/corpus convention,
//! LISPEX-RUNTIME.md §11). On any reader/normalizer/runtime error it prints the
//! `CODE file:line:col message` diagnostic to stderr and exits non-zero.
//!
//! Usage:
//!   lispex [FILE]        evaluate FILE (or stdin if omitted / `-`)
//!
//! A deep *non-tail* recursion reaches the interpreter's logical recursion bound (a
//! clean `RecursionLimit`) rather than overflowing the host stack, because the
//! evaluator grows its host stack on the heap on demand via `stacker` (see
//! `eval::Interp::eval`). No big-stack worker thread is needed — the guarantee holds on
//! the default stack, so the CLI just evaluates inline.

use std::io::Read;
use std::process::ExitCode;

use lispex::{
    canonical_datum_string, canonical_program_bytes, core_hash_hex,
    eval_graph_json_receipt_projection_with_input, eval_graph_json_report_with_input,
    graph_json_bytes, hash_with_domain_hex, lower_meaning_graph_program, profile_input_hash_hex,
    runtime_hash_hex, source_hash_hex, CoreExpr, Diagnostic, Eval, Interp, Outcome, RuntimeError,
    Value, Warning, CANONICAL_FORMAT_TAG, CORE_HASH_DOMAIN, ESCAPE_CONTINUATION_INACTIVE_MESSAGE,
    MEANING_ENV_DEFAULT_STEP_LIMIT, PROFILE_INPUT_HASH_DOMAIN, RUNTIME_HASH_DOMAIN,
    SOURCE_HASH_DOMAIN,
};
use serde_json::{json, Value as JsonValue};

#[cfg(feature = "scored-native-contract")]
use lispex::vouch_native::bridge::{
    executable_digest_valid, hex64, verify_bridge_paths_with, BridgePathRequest,
};
#[cfg(feature = "scored-native-contract")]
use lispex::vouch_native::issue::{
    issue_native_paths, publish_issue_usage_error, validate_key_handle_uri,
};
#[cfg(feature = "scored-native-contract")]
use lispex::vouch_native::structural_verify::{
    verify_structure, StructuralContext, StructuralError, StructuralReport,
};
#[cfg(feature = "scored-native-contract")]
use lispex::vouch_native::verify::{
    verify_native, AuthenticatedNativeEvidence, NativeVerificationError, NativeVerifyReport,
};
#[cfg(feature = "scored-native-contract")]
use lispex::vouch_native::{checked_input::MAX_INPUT_BYTES, checked_profile::MAX_SOURCE_BYTES};
#[cfg(feature = "scored-native-contract")]
use vouch::artifact_json::MAX_ARTIFACT_BYTES;
#[cfg(feature = "scored-native-contract")]
use vouch::io_boundary::{
    FileProvider, FilesystemAtomicPublisher, IoBoundaryError, OsFileProvider,
};
#[cfg(feature = "scored-native-contract")]
use vouch::policy::profile_identifier_valid;

const DIFF_RECEIPT_MEANING_ENV_STEP_LIMIT: usize = 1_000_000;

const HELP: &str = "\
lispex — the Lispex reference interpreter

Usage:
  lispex run <file.lspx>     Evaluate a file
  lispex <file.lspx>         Shorthand for `run`
  lispex receipt <file.lspx> Emit a machine-readable receipt
  lispex receipt -           Emit a receipt for source read from stdin
  lispex lower <file.lspx>   Emit a Meaning Graph v0 lowering for the supported subset
  lispex lower -             Emit a Meaning Graph v0 lowering for stdin
  lispex eval-graph <graph.json|-> Evaluate canonical Meaning Graph v0 JSON
  lispex eval-graph --steps N <graph.json|-> Override the Meaning Environment step limit
  lispex eval-graph --input <datum-file> <graph.json|-> Bind profile input as `input`
  lispex diff-receipt <file.lspx> Emit a CSK differential receipt for the lowered subset
  lispex diff-receipt -           Emit a differential receipt for source read from stdin
  lispex diff-receipt --input <datum-file> <file.lspx>
                                Emit an input-bound CSK differential receipt
  lispex -                    Evaluate source from stdin
  cat file.lspx | lispex     Same, via a pipe
  lispex --version            Print the version
  lispex --help               Show this help

Exit code: 0 on success, non-zero on a reader/normalizer/runtime diagnostic
(written to stderr). Same evaluation core as the browser playground and the npm
`lispex` package.
";

// A user-facing failure: a message + exit code, surfaced by the top-level command.
struct CliError {
    message: String,
    code: u8,
}

#[derive(Clone)]
struct ProfileInput {
    path: String,
    value: Value,
    datum: String,
    byte_len: usize,
    hash_hex: String,
}

#[derive(Clone)]
struct ProfileInputError {
    path: String,
    code: String,
    line: usize,
    col: usize,
    message: String,
}

#[derive(Clone)]
enum ProfileInputState {
    Absent,
    Bound(ProfileInput),
    Error(ProfileInputError),
}

struct EvalGraphArgs {
    step_limit: usize,
    profile_input: Option<ProfileInput>,
    graph_args: Vec<String>,
}

struct DiffReceiptArgs {
    profile_input: ProfileInputState,
    source_args: Vec<String>,
}

#[cfg(feature = "scored-native-contract")]
struct VerifyStructureArgs {
    receipt: String,
    input: String,
    report_out: String,
    source: Option<String>,
    profile: Option<String>,
}

#[cfg(feature = "scored-native-contract")]
struct VerifyNativeArgs {
    envelope: String,
    trust_policy: String,
    source: String,
    input: String,
    profile: String,
    report_out: String,
}

#[cfg(feature = "scored-native-contract")]
struct VerifyBridgeArgs {
    report: String,
    profile: String,
    engine_sha256: String,
    source: String,
    input: String,
    input_canonical_value_sha256: String,
    report_out: String,
}

#[cfg(feature = "scored-native-contract")]
struct IssueNativeArgs {
    source: String,
    input: String,
    profile: String,
    key_handle: String,
    out_dir: String,
}

#[cfg(feature = "scored-native-contract")]
struct IssueCliError {
    message: String,
    output: Option<String>,
}

impl ProfileInputError {
    fn new(
        path: &str,
        code: impl Into<String>,
        line: usize,
        col: usize,
        message: impl Into<String>,
    ) -> ProfileInputError {
        ProfileInputError {
            path: path.to_string(),
            code: code.into(),
            line,
            col,
            message: message.into(),
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("--version" | "-V" | "version") => {
            println!("lispex {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h" | "help") => {
            print!("{HELP}");
            #[cfg(feature = "scored-native-contract")]
            println!(
                "  lispex verify-structure --receipt <path> --input <path> --report-out <path> [--source <path>] [--profile <profile-id>]"
            );
            #[cfg(feature = "scored-native-contract")]
            println!(
                "  lispex verify-native --envelope <path> --trust-policy <path> --source <path> --input <path> --profile <profile-id> --report-out <path>"
            );
            #[cfg(feature = "scored-native-contract")]
            println!(
                "  lispex verify-bridge --report <path> --profile <profile-id> --engine-sha256 <digest> --source <path> --input <path> --input-canonical-value-sha256 <digest> --report-out <path>"
            );
            #[cfg(feature = "scored-native-contract")]
            println!(
                "  lispex issue-native --source <path> --input <path> --profile <profile-id> --key-handle <uri> --out-dir <path>"
            );
            return ExitCode::SUCCESS;
        }
        Some("receipt") => return receipt_command(&args[1..]),
        Some("lower") => return lower_command(&args[1..]),
        Some("eval-graph") => return eval_graph_command(&args[1..]),
        Some("diff-receipt") => return diff_receipt_command(&args[1..]),
        #[cfg(feature = "scored-native-contract")]
        Some("verify-structure") => return verify_structure_command(&args[1..]),
        #[cfg(feature = "scored-native-contract")]
        Some("verify-native") => return verify_native_command(&args[1..]),
        #[cfg(feature = "scored-native-contract")]
        Some("verify-bridge") => return verify_bridge_command(&args[1..]),
        #[cfg(feature = "scored-native-contract")]
        Some("issue-native") => return issue_native_command(&args[1..]),
        _ => {}
    }

    // `run <file>` is an alias of `<file>` (parity with the npm CLI); otherwise the
    // first argument is the source file (`-` or none = stdin).
    let rest: &[String] = match args.first().map(String::as_str) {
        Some("run") => &args[1..],
        _ => &args,
    };

    let (src, file) = match rest.first().map(String::as_str) {
        None | Some("-") => {
            let mut buf = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                eprintln!("error: cannot read stdin: {e}");
                return ExitCode::FAILURE;
            }
            (buf, "<stdin>".to_string())
        }
        Some(path) => match std::fs::read_to_string(path) {
            Ok(s) => (s, path.to_string()),
            Err(e) => {
                eprintln!("error: cannot read `{path}`: {e}");
                return ExitCode::FAILURE;
            }
        },
    };

    run(&src, &file)
}

fn run(src: &str, file: &str) -> ExitCode {
    let prog = match lispex::read_program(src, file) {
        Ok(p) => p,
        Err(diag) => {
            eprintln!("{diag}");
            return ExitCode::FAILURE;
        }
    };
    let core = match lispex::normalize_program(&prog.datums, file) {
        Ok(c) => c,
        Err(diag) => {
            eprintln!("{diag}");
            return ExitCode::FAILURE;
        }
    };

    let run = eval_core(core, file);
    print!("{}", run.stdout);
    for w in &run.warnings {
        eprintln!("{w}");
    }
    if let Some(failure) = &run.failure {
        eprintln!("{}", failure.display(file));
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn receipt_command(args: &[String]) -> ExitCode {
    let (source_bytes, file) = match read_source_bytes(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e.message);
            return ExitCode::from(e.code);
        }
    };

    let src = match String::from_utf8(source_bytes.clone()) {
        Ok(src) => src,
        Err(_) => {
            eprintln!("lispex receipt: source is not valid UTF-8");
            return ExitCode::from(2);
        }
    };

    let (receipt, ok) = build_receipt(&src, &source_bytes, &file);
    match serde_json::to_string_pretty(&receipt) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("lispex receipt: cannot encode receipt JSON: {e}");
            return ExitCode::from(2);
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn lower_command(args: &[String]) -> ExitCode {
    let (source_bytes, file) = match read_source_bytes(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e.message);
            return ExitCode::from(e.code);
        }
    };

    let src = match String::from_utf8(source_bytes) {
        Ok(src) => src,
        Err(_) => {
            eprintln!("lispex lower: source is not valid UTF-8");
            return ExitCode::from(2);
        }
    };

    let prog = match lispex::read_program(&src, &file) {
        Ok(p) => p,
        Err(diag) => {
            eprintln!("{diag}");
            return ExitCode::FAILURE;
        }
    };
    let core = match lispex::normalize_program(&prog.datums, &file) {
        Ok(c) => c,
        Err(diag) => {
            eprintln!("{diag}");
            return ExitCode::FAILURE;
        }
    };
    let graph = match lower_meaning_graph_program(&core) {
        Ok(graph) => graph,
        Err(fault) => {
            eprintln!("{}", fault.display(&file));
            return ExitCode::FAILURE;
        }
    };
    print!("{}", String::from_utf8_lossy(&graph_json_bytes(&graph)));
    ExitCode::SUCCESS
}

fn eval_graph_command(args: &[String]) -> ExitCode {
    let parsed = match parse_eval_graph_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{}", error.message);
            return ExitCode::from(2);
        }
    };

    let (graph_bytes, _file) = match read_source_bytes(&parsed.graph_args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e.message);
            return ExitCode::from(e.code);
        }
    };

    let output = match eval_graph_json_report_with_input(
        &graph_bytes,
        parsed.step_limit,
        parsed
            .profile_input
            .as_ref()
            .map(|input| input.value.clone()),
    ) {
        Ok(output) => output,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    print!("{}", String::from_utf8_lossy(&output.report));
    if output.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn diff_receipt_command(args: &[String]) -> ExitCode {
    let parsed = match parse_diff_receipt_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{}", error.message);
            return ExitCode::from(error.code);
        }
    };

    let (source_bytes, file) = match read_source_bytes(&parsed.source_args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e.message);
            return ExitCode::from(e.code);
        }
    };

    let src = match String::from_utf8(source_bytes.clone()) {
        Ok(src) => src,
        Err(_) => {
            eprintln!("lispex diff-receipt: source is not valid UTF-8");
            return ExitCode::from(2);
        }
    };

    let (receipt, ok) = build_diff_receipt(&src, &source_bytes, &file, &parsed.profile_input);
    match serde_json::to_string_pretty(&receipt) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("lispex diff-receipt: cannot encode receipt JSON: {e}");
            return ExitCode::from(2);
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(feature = "scored-native-contract")]
fn verify_structure_command(args: &[String]) -> ExitCode {
    let parsed = match parse_verify_structure_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{}", error.message);
            return ExitCode::from(2);
        }
    };
    let provider = OsFileProvider::default();
    let receipt = match provider.read_once(&parsed.receipt, MAX_ARTIFACT_BYTES) {
        Ok(bytes) => bytes,
        Err(IoBoundaryError::ResourceLimit) => {
            return finish_structural_report(
                &parsed.report_out,
                Err(StructuralError::ResourceLimit("payload-bytes")),
            )
        }
        Err(error) => return structural_io_failure("receipt", &parsed.report_out, error),
    };
    let input = match provider.read_once(&parsed.input, MAX_INPUT_BYTES) {
        Ok(bytes) => bytes,
        Err(IoBoundaryError::ResourceLimit) => {
            return finish_structural_report(
                &parsed.report_out,
                Err(StructuralError::ResourceLimit("input-bytes")),
            )
        }
        Err(error) => return structural_io_failure("input", &parsed.report_out, error),
    };
    let source = match parsed.source.as_deref() {
        Some(path) => match provider.read_once(path, MAX_SOURCE_BYTES) {
            Ok(bytes) => Some(bytes),
            Err(IoBoundaryError::ResourceLimit) => {
                return finish_structural_report(
                    &parsed.report_out,
                    Err(StructuralError::ResourceLimit("source-bytes")),
                )
            }
            Err(error) => return structural_io_failure("source", &parsed.report_out, error),
        },
        None => None,
    };
    let result = verify_structure(
        receipt.bytes(),
        StructuralContext {
            input: input.bytes(),
            source: source.as_ref().map(|bytes| bytes.bytes()),
            expected_profile: parsed.profile.as_deref(),
            release_signed: false,
        },
    );
    finish_structural_report(&parsed.report_out, result)
}

#[cfg(feature = "scored-native-contract")]
fn finish_structural_report(
    path: &str,
    result: Result<StructuralReport, StructuralError>,
) -> ExitCode {
    let report = match &result {
        Ok(report) => report.clone(),
        Err(error) => StructuralReport::rejected(error),
    };
    if let Err(error) = std::fs::write(path, report.canonical_bytes()) {
        eprintln!("lispex verify-structure: cannot write report `{path}`: {error}");
        return ExitCode::from(3);
    }
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error.code());
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "scored-native-contract")]
fn structural_io_failure(subject: &str, report_out: &str, error: IoBoundaryError) -> ExitCode {
    eprintln!("lispex verify-structure: cannot read {subject}: {error}");
    let _ = report_out;
    ExitCode::from(3)
}

#[cfg(feature = "scored-native-contract")]
fn parse_verify_structure_args(args: &[String]) -> Result<VerifyStructureArgs, CliError> {
    let mut receipt = None;
    let mut input = None;
    let mut report_out = None;
    let mut source = None;
    let mut profile = None;
    let mut index = 0usize;
    while index < args.len() {
        let (slot, label) = match args[index].as_str() {
            "--receipt" => (&mut receipt, "--receipt"),
            "--input" => (&mut input, "--input"),
            "--report-out" => (&mut report_out, "--report-out"),
            "--source" => (&mut source, "--source"),
            "--profile" => (&mut profile, "--profile"),
            other => {
                return Err(CliError::new(
                    format!("lispex verify-structure: unknown argument `{other}`"),
                    2,
                ))
            }
        };
        if slot.is_some() {
            return Err(CliError::new(
                format!("lispex verify-structure: {label} may be provided only once"),
                2,
            ));
        }
        let Some(value) = args.get(index + 1) else {
            return Err(CliError::new(
                format!("lispex verify-structure: {label} requires a value"),
                2,
            ));
        };
        if value == "-" || value.starts_with("--") {
            return Err(CliError::new(
                format!("lispex verify-structure: {label} requires a path or identifier"),
                2,
            ));
        }
        *slot = Some(value.clone());
        index += 2;
    }
    Ok(VerifyStructureArgs {
        receipt: receipt.ok_or_else(|| {
            CliError::new(
                "lispex verify-structure: --receipt is required".to_string(),
                2,
            )
        })?,
        input: input.ok_or_else(|| {
            CliError::new(
                "lispex verify-structure: --input is required".to_string(),
                2,
            )
        })?,
        report_out: report_out.ok_or_else(|| {
            CliError::new(
                "lispex verify-structure: --report-out is required".to_string(),
                2,
            )
        })?,
        source,
        profile,
    })
}

#[cfg(feature = "scored-native-contract")]
fn verify_native_command(args: &[String]) -> ExitCode {
    let parsed = match parse_verify_native_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{}", error.message);
            return ExitCode::from(2);
        }
    };
    let provider = OsFileProvider::default();
    let envelope = match provider.read_once(&parsed.envelope, MAX_ARTIFACT_BYTES) {
        Ok(bytes) => bytes,
        Err(IoBoundaryError::ResourceLimit) => {
            return finish_native_report(
                &parsed.report_out,
                Err(NativeVerificationError::ArtifactResourceLimit),
            )
        }
        Err(error) => return native_io_failure("envelope", error),
    };
    let trust_policy = match provider.read_once(&parsed.trust_policy, MAX_ARTIFACT_BYTES) {
        Ok(bytes) => bytes,
        Err(IoBoundaryError::ResourceLimit) => {
            return finish_native_report(
                &parsed.report_out,
                Err(NativeVerificationError::ArtifactResourceLimit),
            )
        }
        Err(error) => return native_io_failure("trust policy", error),
    };
    let source = match provider.read_once(&parsed.source, MAX_SOURCE_BYTES) {
        Ok(bytes) => bytes,
        Err(IoBoundaryError::ResourceLimit) => {
            return finish_native_report(
                &parsed.report_out,
                Err(NativeVerificationError::ArtifactResourceLimit),
            )
        }
        Err(error) => return native_io_failure("source", error),
    };
    let input = match provider.read_once(&parsed.input, MAX_INPUT_BYTES) {
        Ok(bytes) => bytes,
        Err(IoBoundaryError::ResourceLimit) => {
            return finish_native_report(
                &parsed.report_out,
                Err(NativeVerificationError::ArtifactResourceLimit),
            )
        }
        Err(error) => return native_io_failure("input", error),
    };
    let result = verify_native(
        envelope.bytes(),
        trust_policy.bytes(),
        &parsed.profile,
        source.bytes(),
        input.bytes(),
    );
    finish_native_report(&parsed.report_out, result)
}

#[cfg(feature = "scored-native-contract")]
fn finish_native_report(
    path: &str,
    result: Result<AuthenticatedNativeEvidence, NativeVerificationError>,
) -> ExitCode {
    let (report, exit) = match &result {
        Ok(evidence) if evidence.promotion_ineligibility().is_none() => {
            (evidence.report(), ExitCode::SUCCESS)
        }
        Ok(evidence) => (evidence.report(), ExitCode::from(10)),
        Err(error) => (NativeVerifyReport::rejected(*error), ExitCode::FAILURE),
    };
    if let Err(error) = std::fs::write(path, report.canonical_bytes()) {
        eprintln!("lispex verify-native: cannot write report `{path}`: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) = result {
        eprintln!("{}", error.code());
    }
    exit
}

#[cfg(feature = "scored-native-contract")]
fn native_io_failure(subject: &str, error: IoBoundaryError) -> ExitCode {
    eprintln!("lispex verify-native: cannot read {subject}: {error}");
    ExitCode::from(3)
}

#[cfg(feature = "scored-native-contract")]
fn parse_verify_native_args(args: &[String]) -> Result<VerifyNativeArgs, CliError> {
    let mut envelope = None;
    let mut trust_policy = None;
    let mut source = None;
    let mut input = None;
    let mut profile = None;
    let mut report_out = None;
    let mut index = 0usize;
    while index < args.len() {
        let (slot, label) = match args[index].as_str() {
            "--envelope" => (&mut envelope, "--envelope"),
            "--trust-policy" => (&mut trust_policy, "--trust-policy"),
            "--source" => (&mut source, "--source"),
            "--input" => (&mut input, "--input"),
            "--profile" => (&mut profile, "--profile"),
            "--report-out" => (&mut report_out, "--report-out"),
            other => {
                return Err(CliError::new(
                    format!("lispex verify-native: unknown argument `{other}`"),
                    2,
                ))
            }
        };
        if slot.is_some() {
            return Err(CliError::new(
                format!("lispex verify-native: {label} may be provided only once"),
                2,
            ));
        }
        let Some(value) = args.get(index + 1) else {
            return Err(CliError::new(
                format!("lispex verify-native: {label} requires a value"),
                2,
            ));
        };
        if value == "-" || value.starts_with("--") {
            return Err(CliError::new(
                format!("lispex verify-native: {label} requires a path or identifier"),
                2,
            ));
        }
        *slot = Some(value.clone());
        index += 2;
    }
    let profile = profile.ok_or_else(|| {
        CliError::new("lispex verify-native: --profile is required".to_string(), 2)
    })?;
    if !profile_identifier_valid(&profile) {
        return Err(CliError::new(
            "lispex verify-native: --profile is malformed".to_string(),
            2,
        ));
    }
    Ok(VerifyNativeArgs {
        envelope: required_native_arg(envelope, "--envelope")?,
        trust_policy: required_native_arg(trust_policy, "--trust-policy")?,
        source: required_native_arg(source, "--source")?,
        input: required_native_arg(input, "--input")?,
        profile,
        report_out: required_native_arg(report_out, "--report-out")?,
    })
}

#[cfg(feature = "scored-native-contract")]
fn required_native_arg(value: Option<String>, label: &str) -> Result<String, CliError> {
    value.ok_or_else(|| CliError::new(format!("lispex verify-native: {label} is required"), 2))
}

#[cfg(feature = "scored-native-contract")]
fn verify_bridge_command(args: &[String]) -> ExitCode {
    let parsed = match parse_verify_bridge_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{}", error.message);
            return ExitCode::from(2);
        }
    };

    let provider = OsFileProvider::default();
    let publisher = FilesystemAtomicPublisher::default();
    match verify_bridge_paths_with(
        BridgePathRequest {
            report: &parsed.report,
            profile: &parsed.profile,
            engine_sha256: &parsed.engine_sha256,
            source: &parsed.source,
            input: &parsed.input,
            input_canonical_value_sha256: &parsed.input_canonical_value_sha256,
            report_out: &parsed.report_out,
        },
        &provider,
        &publisher,
    ) {
        Ok(outcome) => {
            if let Some(error) = outcome.primary_error {
                eprintln!("{}", error.code());
            }
            ExitCode::from(outcome.exit_code)
        }
        Err(error) => bridge_io_failure(error),
    }
}

#[cfg(feature = "scored-native-contract")]
fn bridge_io_failure(error: IoBoundaryError) -> ExitCode {
    eprintln!("lispex verify-bridge: input or output failure: {error}");
    ExitCode::from(3)
}

#[cfg(feature = "scored-native-contract")]
fn parse_verify_bridge_args(args: &[String]) -> Result<VerifyBridgeArgs, CliError> {
    let mut report = None;
    let mut profile = None;
    let mut engine_sha256 = None;
    let mut source = None;
    let mut input = None;
    let mut input_canonical_value_sha256 = None;
    let mut report_out = None;
    let mut index = 0usize;
    while index < args.len() {
        let (slot, label) = match args[index].as_str() {
            "--report" => (&mut report, "--report"),
            "--profile" => (&mut profile, "--profile"),
            "--engine-sha256" => (&mut engine_sha256, "--engine-sha256"),
            "--source" => (&mut source, "--source"),
            "--input" => (&mut input, "--input"),
            "--input-canonical-value-sha256" => (
                &mut input_canonical_value_sha256,
                "--input-canonical-value-sha256",
            ),
            "--report-out" => (&mut report_out, "--report-out"),
            other => {
                return Err(CliError::new(
                    format!("lispex verify-bridge: unknown argument `{other}`"),
                    2,
                ))
            }
        };
        if slot.is_some() {
            return Err(CliError::new(
                format!("lispex verify-bridge: {label} may be provided only once"),
                2,
            ));
        }
        let Some(value) = args.get(index + 1) else {
            return Err(CliError::new(
                format!("lispex verify-bridge: {label} requires a value"),
                2,
            ));
        };
        if value.is_empty() || value == "-" || value.starts_with("--") {
            return Err(CliError::new(
                format!("lispex verify-bridge: {label} requires a path or identifier"),
                2,
            ));
        }
        *slot = Some(value.clone());
        index += 2;
    }

    let profile = required_bridge_arg(profile, "--profile")?;
    if !profile_identifier_valid(&profile) {
        return Err(CliError::new(
            "lispex verify-bridge: --profile is malformed".to_string(),
            2,
        ));
    }
    let engine_sha256 = required_bridge_arg(engine_sha256, "--engine-sha256")?;
    if !executable_digest_valid(&engine_sha256) {
        return Err(CliError::new(
            "lispex verify-bridge: --engine-sha256 is malformed".to_string(),
            2,
        ));
    }
    let input_canonical_value_sha256 = required_bridge_arg(
        input_canonical_value_sha256,
        "--input-canonical-value-sha256",
    )?;
    if !hex64(&input_canonical_value_sha256) {
        return Err(CliError::new(
            "lispex verify-bridge: --input-canonical-value-sha256 is malformed".to_string(),
            2,
        ));
    }

    Ok(VerifyBridgeArgs {
        report: required_bridge_arg(report, "--report")?,
        profile,
        engine_sha256,
        source: required_bridge_arg(source, "--source")?,
        input: required_bridge_arg(input, "--input")?,
        input_canonical_value_sha256,
        report_out: required_bridge_arg(report_out, "--report-out")?,
    })
}

#[cfg(feature = "scored-native-contract")]
fn required_bridge_arg(value: Option<String>, label: &str) -> Result<String, CliError> {
    value.ok_or_else(|| CliError::new(format!("lispex verify-bridge: {label} is required"), 2))
}

#[cfg(feature = "scored-native-contract")]
fn issue_native_command(args: &[String]) -> ExitCode {
    let parsed = match parse_issue_native_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{}", error.message);
            let outcome = publish_issue_usage_error(error.output.as_deref());
            return ExitCode::from(outcome.exit_code);
        }
    };
    let outcome = issue_native_paths(
        &parsed.source,
        &parsed.input,
        &parsed.profile,
        &parsed.key_handle,
        &parsed.out_dir,
    );
    if let Some(error) = outcome.primary_error {
        eprintln!("{}", error.code());
    }
    ExitCode::from(outcome.exit_code)
}

#[cfg(feature = "scored-native-contract")]
fn parse_issue_native_args(args: &[String]) -> Result<IssueNativeArgs, IssueCliError> {
    let mut source = None;
    let mut input = None;
    let mut profile = None;
    let mut key_handle = None;
    let mut out_dir = None;
    let mut index = 0usize;
    while index < args.len() {
        let (slot, label) = match args[index].as_str() {
            "--source" => (&mut source, "--source"),
            "--input" => (&mut input, "--input"),
            "--profile" => (&mut profile, "--profile"),
            "--key-handle" => (&mut key_handle, "--key-handle"),
            "--out-dir" => (&mut out_dir, "--out-dir"),
            other => {
                return Err(issue_cli_error(
                    format!("lispex issue-native: unknown argument `{other}`"),
                    &out_dir,
                ))
            }
        };
        if slot.is_some() {
            return Err(issue_cli_error(
                format!("lispex issue-native: {label} may be provided only once"),
                &out_dir,
            ));
        }
        let Some(value) = args.get(index + 1) else {
            return Err(issue_cli_error(
                format!("lispex issue-native: {label} requires a value"),
                &out_dir,
            ));
        };
        if value.is_empty() || value == "-" || value.starts_with("--") {
            return Err(issue_cli_error(
                format!("lispex issue-native: {label} requires a path or identifier"),
                &out_dir,
            ));
        }
        *slot = Some(value.clone());
        index += 2;
    }

    let out_dir = out_dir.ok_or_else(|| {
        issue_cli_error(
            "lispex issue-native: --out-dir is required".to_string(),
            &None,
        )
    })?;
    let profile = required_issue_arg(profile, "--profile", &out_dir)?;
    if !profile_identifier_valid(&profile) || profile != "csk.checked-profile/v1" {
        return Err(IssueCliError {
            message: "lispex issue-native: --profile is malformed or unsupported".to_string(),
            output: Some(out_dir),
        });
    }
    let key_handle = required_issue_arg(key_handle, "--key-handle", &out_dir)?;
    if !validate_key_handle_uri(&key_handle) {
        return Err(IssueCliError {
            message: "lispex issue-native: --key-handle is malformed or forbidden".to_string(),
            output: Some(out_dir),
        });
    }
    Ok(IssueNativeArgs {
        source: required_issue_arg(source, "--source", &out_dir)?,
        input: required_issue_arg(input, "--input", &out_dir)?,
        profile,
        key_handle,
        out_dir,
    })
}

#[cfg(feature = "scored-native-contract")]
fn required_issue_arg(
    value: Option<String>,
    label: &str,
    output: &str,
) -> Result<String, IssueCliError> {
    value.ok_or_else(|| IssueCliError {
        message: format!("lispex issue-native: {label} is required"),
        output: Some(output.to_string()),
    })
}

#[cfg(feature = "scored-native-contract")]
fn issue_cli_error(message: String, output: &Option<String>) -> IssueCliError {
    IssueCliError {
        message,
        output: output.clone(),
    }
}

fn parse_eval_graph_args(args: &[String]) -> Result<EvalGraphArgs, CliError> {
    let mut step_limit = MEANING_ENV_DEFAULT_STEP_LIMIT;
    let mut saw_steps = false;
    let mut input_path: Option<String> = None;
    let mut graph_args = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--steps" => {
                if saw_steps {
                    return Err(CliError::new(
                        "lispex eval-graph: --steps may be provided only once".to_string(),
                        2,
                    ));
                }
                saw_steps = true;
                let Some(raw) = args.get(index + 1) else {
                    return Err(CliError::new(
                        "lispex eval-graph: --steps requires a positive integer".to_string(),
                        2,
                    ));
                };
                step_limit = raw
                    .parse::<usize>()
                    .ok()
                    .filter(|limit| *limit > 0)
                    .ok_or_else(|| {
                        CliError::new(
                            "lispex eval-graph: --steps requires a positive integer".to_string(),
                            2,
                        )
                    })?;
                index += 2;
            }
            "--input" => {
                if input_path.is_some() {
                    return Err(CliError::new(
                        "lispex eval-graph: --input may be provided only once".to_string(),
                        2,
                    ));
                }
                let Some(path) = args.get(index + 1) else {
                    return Err(CliError::new(
                        "lispex eval-graph: --input requires a datum file".to_string(),
                        2,
                    ));
                };
                if path == "-" {
                    return Err(CliError::new(
                        "lispex eval-graph: --input requires a file path, not `-`".to_string(),
                        2,
                    ));
                }
                input_path = Some(path.clone());
                index += 2;
            }
            other if other.starts_with("--") => {
                return Err(CliError::new(
                    format!("lispex eval-graph: unknown option `{other}`"),
                    2,
                ));
            }
            _ => {
                graph_args.push(args[index].clone());
                index += 1;
            }
        }
    }

    let profile_input = match input_path {
        Some(path) => match load_profile_input(&path) {
            Ok(input) => Some(input),
            Err(ProfileInputLoadError::Cli(error)) => return Err(error),
            Err(ProfileInputLoadError::Datum(error)) => {
                return Err(CliError::new(
                    format!("lispex eval-graph: {}", error.message),
                    2,
                ));
            }
        },
        None => None,
    };

    Ok(EvalGraphArgs {
        step_limit,
        profile_input,
        graph_args,
    })
}

fn parse_diff_receipt_args(args: &[String]) -> Result<DiffReceiptArgs, CliError> {
    let mut input_path: Option<String> = None;
    let mut source_args = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                if input_path.is_some() {
                    return Err(CliError::new(
                        "lispex diff-receipt: --input may be provided only once".to_string(),
                        2,
                    ));
                }
                let Some(path) = args.get(index + 1) else {
                    return Err(CliError::new(
                        "lispex diff-receipt: --input requires a datum file".to_string(),
                        2,
                    ));
                };
                if path == "-" {
                    return Err(CliError::new(
                        "lispex diff-receipt: --input requires a file path, not `-`".to_string(),
                        2,
                    ));
                }
                input_path = Some(path.clone());
                index += 2;
            }
            other if other.starts_with("--") => {
                return Err(CliError::new(
                    format!("lispex diff-receipt: unknown option `{other}`"),
                    2,
                ));
            }
            _ => {
                source_args.push(args[index].clone());
                index += 1;
            }
        }
    }

    let profile_input = match input_path {
        Some(path) => match load_profile_input(&path) {
            Ok(input) => ProfileInputState::Bound(input),
            Err(ProfileInputLoadError::Cli(error)) => return Err(error),
            Err(ProfileInputLoadError::Datum(error)) => ProfileInputState::Error(error),
        },
        None => ProfileInputState::Absent,
    };

    Ok(DiffReceiptArgs {
        profile_input,
        source_args,
    })
}

enum ProfileInputLoadError {
    Cli(CliError),
    Datum(ProfileInputError),
}

fn load_profile_input(path: &str) -> Result<ProfileInput, ProfileInputLoadError> {
    let bytes = std::fs::read(path).map_err(|e| {
        ProfileInputLoadError::Cli(CliError::new(
            format!("error: cannot read input `{path}`: {e}"),
            2,
        ))
    })?;
    let src = String::from_utf8(bytes).map_err(|_| {
        ProfileInputLoadError::Datum(ProfileInputError::new(
            path,
            "profile-input-utf8",
            1,
            1,
            "input datum is not valid UTF-8",
        ))
    })?;
    let program = lispex::read_program(&src, path).map_err(|diag| {
        ProfileInputLoadError::Datum(ProfileInputError::new(
            path,
            diag.code.to_string(),
            diag.span.line,
            diag.span.col,
            format!("input datum reader error: {}", diag.message),
        ))
    })?;
    let [datum] = program.datums.as_slice() else {
        return Err(ProfileInputLoadError::Datum(ProfileInputError::new(
            path,
            "profile-input-count",
            1,
            1,
            "input datum file must contain exactly one datum",
        )));
    };
    let value = datum.to_value();
    validate_profile_input_value(&value).map_err(|message| {
        ProfileInputLoadError::Datum(ProfileInputError::new(
            path,
            "profile-input-domain",
            1,
            1,
            message,
        ))
    })?;
    let datum = canonical_datum_string(&value).map_err(|e| {
        ProfileInputLoadError::Datum(ProfileInputError::new(
            path,
            "profile-input-canonical",
            1,
            1,
            format!("input datum cannot be canonicalized: {e}"),
        ))
    })?;
    let byte_len = datum.len();
    let hash_hex = profile_input_hash_hex(datum.as_bytes());
    Ok(ProfileInput {
        path: path.to_string(),
        value,
        datum,
        byte_len,
        hash_hex,
    })
}

fn validate_profile_input_value(value: &Value) -> Result<(), String> {
    match value {
        Value::Bool(_)
        | Value::Int(_)
        | Value::Rational(_)
        | Value::Sym(_)
        | Value::Str(_)
        | Value::Nil => Ok(()),
        Value::Pair(pair) => {
            validate_profile_input_value(&pair.car)?;
            validate_profile_input_value(&pair.cdr)
        }
        Value::Real(_) => Err(
            "profile input excludes inexact reals/floats until deterministic float input is pinned"
                .to_string(),
        ),
        Value::Char(_) => Err("profile input excludes characters".to_string()),
        Value::Vector(_) => Err("profile input excludes vectors".to_string()),
        Value::Bytevector(_) => Err("profile input excludes bytevectors".to_string()),
        Value::Closure(_) | Value::Primitive(_) | Value::Cont(_) | Value::ErrorObject(_) => {
            Err("profile input excludes execution-only values".to_string())
        }
        #[cfg(feature = "scored-native-contract")]
        Value::Decision(_) => Err("profile input excludes contract decisions".to_string()),
    }
}

fn profile_input_json(input: &ProfileInputState) -> JsonValue {
    match input {
        ProfileInputState::Absent => json!({ "status": "absent" }),
        ProfileInputState::Bound(input) => json!({
            "status": "bound",
            "path": input.path,
            "name": "input",
            "datum": input.datum,
            "byte_len": input.byte_len,
            "hash": hash_obj(PROFILE_INPUT_HASH_DOMAIN, input.hash_hex.clone()),
        }),
        ProfileInputState::Error(error) => json!({
            "status": "error",
            "path": error.path,
            "message": error.message,
        }),
    }
}

fn profile_input_diag_json(error: &ProfileInputError) -> JsonValue {
    json!({
        "severity": "error",
        "code": error.code,
        "file": error.path,
        "line": error.line,
        "col": error.col,
        "message": error.message,
    })
}

fn read_source_bytes(args: &[String]) -> Result<(Vec<u8>, String), CliError> {
    if args.len() > 1 {
        return Err(CliError::new(
            "error: expected at most one file argument".to_string(),
            2,
        ));
    }
    match args.first().map(String::as_str) {
        None | Some("-") => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| CliError::new(format!("error: cannot read stdin: {e}"), 2))?;
            Ok((buf, "<stdin>".to_string()))
        }
        Some(path) => {
            let bytes = std::fs::read(path)
                .map_err(|e| CliError::new(format!("error: cannot read `{path}`: {e}"), 2))?;
            Ok((bytes, path.to_string()))
        }
    }
}

fn build_receipt(src: &str, source_bytes: &[u8], file: &str) -> (JsonValue, bool) {
    let source = json!({
        "path": file,
        "byte_len": source_bytes.len(),
        "hash": hash_obj(SOURCE_HASH_DOMAIN, source_hash_hex(source_bytes)),
    });

    let prog = match lispex::read_program(src, file) {
        Ok(p) => p,
        Err(diag) => {
            return (
                receipt_json(
                    source,
                    json!({ "status": "read-error" }),
                    json!({ "status": "not-run" }),
                    vec![reader_diag_json(&diag)],
                ),
                false,
            );
        }
    };

    let core = match lispex::normalize_program(&prog.datums, file) {
        Ok(c) => c,
        Err(diag) => {
            return (
                receipt_json(
                    source,
                    json!({ "status": "normalize-error" }),
                    json!({ "status": "not-run" }),
                    vec![reader_diag_json(&diag)],
                ),
                false,
            );
        }
    };

    let canonical_bytes = match canonical_program_bytes(&core) {
        Ok(bytes) => bytes,
        Err(e) => {
            let diag = json!({
                "severity": "error",
                "code": "internal-canonical-error",
                "file": file,
                "line": 1,
                "col": 1,
                "message": e.to_string(),
            });
            return (
                receipt_json(
                    source,
                    json!({ "status": "normalize-error" }),
                    json!({ "status": "not-run" }),
                    vec![diag],
                ),
                false,
            );
        }
    };

    let canonical = json!({
        "status": "ok",
        "byte_len": canonical_bytes.len(),
        "hash": hash_obj(CORE_HASH_DOMAIN, core_hash_hex(&canonical_bytes)),
    });

    let run = eval_core(core, file);
    let mut diagnostics: Vec<JsonValue> = run.warnings.iter().map(warning_json).collect();

    let (runtime, ok) = match &run.failure {
        None => (
            json!({
                "status": "ok",
                "transcript_byte_len": run.stdout.len(),
                "hash": hash_obj(RUNTIME_HASH_DOMAIN, runtime_hash_hex(run.stdout.as_bytes())),
            }),
            true,
        ),
        Some(failure) => {
            diagnostics.push(runtime_failure_json(failure, file));
            (json!({ "status": "error" }), false)
        }
    };

    (receipt_json(source, canonical, runtime, diagnostics), ok)
}

const DIFF_RECEIPT_TAG: &str = "csk.differential-receipt/v0";
const ME_TRANSCRIPT_HASH_DOMAIN: &str = "csk/meaning-env-transcript-hash/v0";

fn build_diff_receipt(
    src: &str,
    source_bytes: &[u8],
    file: &str,
    profile_input: &ProfileInputState,
) -> (JsonValue, bool) {
    let source = json!({
        "path": file,
        "byte_len": source_bytes.len(),
        "hash": hash_obj(SOURCE_HASH_DOMAIN, source_hash_hex(source_bytes)),
    });
    let input = profile_input_json(profile_input);
    let input_error = match profile_input {
        ProfileInputState::Error(error) => Some(error),
        ProfileInputState::Absent | ProfileInputState::Bound(_) => None,
    };

    let prog = match lispex::read_program(src, file) {
        Ok(p) => p,
        Err(diag) => {
            let mut diagnostics = vec![reader_diag_json(&diag)];
            push_profile_input_diag(&mut diagnostics, input_error);
            return (
                diff_receipt_json(DiffReceiptParts {
                    source,
                    input,
                    canonical: json!({ "status": "read-error" }),
                    graph: json!({ "status": "not-run" }),
                    reference: json!({ "status": "not-run" }),
                    meaning_env: json!({ "status": "not-run" }),
                    comparison: comparison_not_comparable_with_input(
                        "read-error",
                        "read-error".to_string(),
                        input_error,
                    ),
                    diagnostics,
                }),
                false,
            );
        }
    };

    let core = match lispex::normalize_program(&prog.datums, file) {
        Ok(c) => c,
        Err(diag) => {
            let mut diagnostics = vec![reader_diag_json(&diag)];
            push_profile_input_diag(&mut diagnostics, input_error);
            return (
                diff_receipt_json(DiffReceiptParts {
                    source,
                    input,
                    canonical: json!({ "status": "normalize-error" }),
                    graph: json!({ "status": "not-run" }),
                    reference: json!({ "status": "not-run" }),
                    meaning_env: json!({ "status": "not-run" }),
                    comparison: comparison_not_comparable_with_input(
                        "normalize-error",
                        "normalize-error".to_string(),
                        input_error,
                    ),
                    diagnostics,
                }),
                false,
            );
        }
    };

    let canonical_bytes = match canonical_program_bytes(&core) {
        Ok(bytes) => bytes,
        Err(e) => {
            let diag = json!({
                "severity": "error",
                "code": "internal-canonical-error",
                "file": file,
                "line": 1,
                "col": 1,
                "message": e.to_string(),
            });
            let mut diagnostics = vec![diag];
            push_profile_input_diag(&mut diagnostics, input_error);
            return (
                diff_receipt_json(DiffReceiptParts {
                    source,
                    input,
                    canonical: json!({ "status": "normalize-error" }),
                    graph: json!({ "status": "not-run" }),
                    reference: json!({ "status": "not-run" }),
                    meaning_env: json!({ "status": "not-run" }),
                    comparison: comparison_not_comparable_with_input(
                        "normalize-error",
                        "normalize-error".to_string(),
                        input_error,
                    ),
                    diagnostics,
                }),
                false,
            );
        }
    };

    let canonical = json!({
        "status": "ok",
        "byte_len": canonical_bytes.len(),
        "hash": hash_obj(CORE_HASH_DOMAIN, core_hash_hex(&canonical_bytes)),
    });

    let graph_result = lower_meaning_graph_program(&core);
    if let Err(fault) = graph_result.as_ref() {
        let mut diagnostics = vec![json!({
            "severity": "error",
            "code": "meaning-graph-lowering",
            "file": file,
            "line": fault.span().line,
            "col": fault.span().col,
            "message": fault.message(),
        })];
        push_profile_input_diag(&mut diagnostics, input_error);
        let graph = json!({
            "status": "fault",
            "kind": fault.kind(),
            "line": fault.span().line,
            "col": fault.span().col,
            "message": fault.message(),
        });
        return (
            diff_receipt_json(DiffReceiptParts {
                source,
                input,
                canonical,
                graph,
                reference: json!({ "status": "not-run" }),
                meaning_env: json!({ "status": "not-run" }),
                comparison: comparison_not_comparable_with_input(
                    "lowering-fault",
                    format!("lowering-{}", fault.kind()),
                    input_error,
                ),
                diagnostics,
            }),
            false,
        );
    }

    let graph = graph_result.expect("handled graph lowering fault");
    let graph_bytes = graph_json_bytes(&graph);
    let graph_json = json!({
        "status": "ok",
        "byte_len": graph_bytes.len(),
        "hash": hash_obj(lispex::MEANING_GRAPH_HASH_DOMAIN, lispex::graph_hash_hex(&graph_bytes)),
    });

    if let Some(error) = input_error {
        return (
            diff_receipt_json(DiffReceiptParts {
                source,
                input,
                canonical,
                graph: graph_json,
                reference: json!({ "status": "not-run" }),
                meaning_env: json!({ "status": "not-run" }),
                comparison: comparison_not_comparable("input-error"),
                diagnostics: vec![profile_input_diag_json(error)],
            }),
            false,
        );
    }

    let reference_run = eval_core_with_profile_input(
        core.clone(),
        file,
        match profile_input {
            ProfileInputState::Bound(input) => Some(input),
            ProfileInputState::Absent | ProfileInputState::Error(_) => None,
        },
    );
    let mut diagnostics: Vec<JsonValue> = reference_run.warnings.iter().map(warning_json).collect();
    let reference_entries = transcript_entries(&reference_run.stdout);
    let reference = match &reference_run.failure {
        None => json!({
            "status": "ok",
            "transcript": reference_entries,
            "transcript_byte_len": reference_run.stdout.len(),
            "hash": hash_obj(RUNTIME_HASH_DOMAIN, runtime_hash_hex(reference_run.stdout.as_bytes())),
        }),
        Some(failure) => {
            diagnostics.push(runtime_failure_json(failure, file));
            json!({
                "status": "error",
                "transcript": reference_entries,
                "transcript_byte_len": reference_run.stdout.len(),
                "hash": JsonValue::Null,
            })
        }
    };

    let (meaning_env, comparison, ok) = diff_meaning_env_and_comparison(
        &graph_bytes,
        &reference_run,
        match profile_input {
            ProfileInputState::Bound(input) => Some(&input.value),
            ProfileInputState::Absent | ProfileInputState::Error(_) => None,
        },
    );
    (
        diff_receipt_json(DiffReceiptParts {
            source,
            input,
            canonical,
            graph: graph_json,
            reference,
            meaning_env,
            comparison,
            diagnostics,
        }),
        ok,
    )
}

fn diff_meaning_env_and_comparison(
    graph_bytes: &[u8],
    reference_run: &EvalRun,
    profile_input: Option<&Value>,
) -> (JsonValue, JsonValue, bool) {
    let projection = eval_graph_json_receipt_projection_with_input(
        graph_bytes,
        DIFF_RECEIPT_MEANING_ENV_STEP_LIMIT,
        profile_input.cloned(),
    )
    .expect("lowered graph bytes must be valid receipt projection input");
    let me_entries = projection.transcript;
    let transcript_bytes = transcript_bytes(&me_entries);
    let meaning_env = json!({
        "status": projection.status,
        "transcript": me_entries,
        "transcript_byte_len": transcript_bytes.len(),
        "hash": hash_obj(ME_TRANSCRIPT_HASH_DOMAIN, hash_with_domain_hex(ME_TRANSCRIPT_HASH_DOMAIN, &transcript_bytes)),
        "steps": {
            "used": projection.steps_used,
            "limit": projection.step_limit,
        },
        "fault": projection.fault,
    });

    if reference_run.failure.is_some() {
        return (
            meaning_env,
            comparison_not_comparable("reference-runtime-error"),
            false,
        );
    }
    if projection.status != "ok" {
        let fault_class = meaning_env_fault_class(&meaning_env);
        return (
            meaning_env,
            comparison_not_comparable_with_class("meaning-env-fault", fault_class),
            false,
        );
    }

    let reference_bytes = reference_run.stdout.as_bytes();
    if reference_bytes == transcript_bytes {
        (
            meaning_env,
            json!({
                "status": "agree",
                "reason": "transcript-bytes-equal",
                "fault_class": JsonValue::Null,
                "substrate": "shared-rust-reference",
                "first_divergence": JsonValue::Null,
                "blockers": [],
            }),
            true,
        )
    } else {
        (
            meaning_env,
            json!({
                "status": "disagree",
                "reason": "transcript-bytes-differ",
                "fault_class": JsonValue::Null,
                "substrate": "shared-rust-reference",
                "first_divergence": first_divergence(&transcript_entries(&reference_run.stdout), &me_entries),
                "blockers": [],
            }),
            false,
        )
    }
}

struct DiffReceiptParts {
    source: JsonValue,
    input: JsonValue,
    canonical: JsonValue,
    graph: JsonValue,
    reference: JsonValue,
    meaning_env: JsonValue,
    comparison: JsonValue,
    diagnostics: Vec<JsonValue>,
}

fn diff_receipt_json(parts: DiffReceiptParts) -> JsonValue {
    json!({
        "differential_receipt": DIFF_RECEIPT_TAG,
        "engine": {
            "name": "lispex-rust-reference",
            "version": env!("CARGO_PKG_VERSION"),
            "canonical_format": CANONICAL_FORMAT_TAG,
            "commit": artifact_commit_json(),
        },
        "source": parts.source,
        "input": parts.input,
        "canonical": parts.canonical,
        "graph": parts.graph,
        "reference": parts.reference,
        "meaning_env": parts.meaning_env,
        "comparison": parts.comparison,
        "diagnostics": parts.diagnostics,
        "boundary": {
            "attests": [
                "source-bytes",
                "profile-input-hash-binding",
                "canonical-core-v0-bytes",
                "meaning-graph-v0-hash-binding",
                "reference-transcript-bytes",
                "meaning-env-transcript-bytes",
                "lowered-subset-transcript-agreement",
            ],
            "excludes": [
                "semantic-equivalence",
                "independent-witness",
                "substrate-independence",
                "error-agreement",
                "input-provenance",
                "external-backend-reporting",
                "full-cskernel-coverage",
                "target-code-generation",
                "private-implementation-detail",
                "receipt-authenticity",
                "generation-honesty",
                "issuer-binding",
                "timestamping",
                "non-repudiation",
            ],
        },
    })
}

fn comparison_not_comparable(reason: &str) -> JsonValue {
    comparison_not_comparable_with_class(reason, default_fault_class(reason))
}

fn comparison_not_comparable_with_class(reason: &str, fault_class: String) -> JsonValue {
    comparison_not_comparable_with_input(reason, fault_class, None)
}

fn comparison_not_comparable_with_input(
    reason: &str,
    fault_class: String,
    input_error: Option<&ProfileInputError>,
) -> JsonValue {
    let mut blockers = vec![comparison_blocker(reason, &fault_class)];
    if input_error.is_some() && reason != "input-error" {
        blockers.push(comparison_blocker("input-error", "input-error"));
    }
    json!({
        "status": "not-comparable",
        "reason": reason,
        "fault_class": fault_class,
        "substrate": "shared-rust-reference",
        "first_divergence": JsonValue::Null,
        "blockers": blockers,
    })
}

fn comparison_blocker(reason: &str, fault_class: &str) -> JsonValue {
    json!({
        "reason": reason,
        "fault_class": fault_class,
    })
}

fn default_fault_class(reason: &str) -> String {
    match reason {
        "read-error" => "read-error",
        "normalize-error" => "normalize-error",
        "input-error" => "input-error",
        "lowering-fault" => "lowering-fault",
        "reference-runtime-error" => "reference-runtime-error",
        "meaning-env-fault" => "meaning-fault",
        other => other,
    }
    .to_string()
}

fn meaning_env_fault_class(report: &JsonValue) -> String {
    match report["status"].as_str() {
        Some("law-error") => "meaning-law-error".to_string(),
        Some("fault") => report["fault"]["kind"]
            .as_str()
            .map(|kind| format!("meaning-{kind}"))
            .unwrap_or_else(|| "meaning-fault".to_string()),
        _ => "meaning-fault".to_string(),
    }
}

fn push_profile_input_diag(
    diagnostics: &mut Vec<JsonValue>,
    input_error: Option<&ProfileInputError>,
) {
    if let Some(error) = input_error {
        diagnostics.push(profile_input_diag_json(error));
    }
}

fn transcript_entries(stdout: &str) -> Vec<String> {
    stdout
        .split_terminator('\n')
        .map(ToString::to_string)
        .collect()
}

fn transcript_bytes(entries: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        out.extend_from_slice(entry.as_bytes());
        out.push(b'\n');
    }
    out
}

fn first_divergence(reference: &[String], meaning_env: &[String]) -> JsonValue {
    let len = reference.len().max(meaning_env.len());
    for index in 0..len {
        let left = reference.get(index);
        let right = meaning_env.get(index);
        if left != right {
            return json!({
                "index": index,
                "reference": left,
                "meaning_env": right,
            });
        }
    }
    JsonValue::Null
}

fn receipt_json(
    source: JsonValue,
    canonical: JsonValue,
    runtime: JsonValue,
    diagnostics: Vec<JsonValue>,
) -> JsonValue {
    json!({
        "receipt": "lispex.receipt/v0",
        "engine": {
            "name": "lispex-rust-reference",
            "version": env!("CARGO_PKG_VERSION"),
            "canonical_format": CANONICAL_FORMAT_TAG,
            "commit": artifact_commit_json(),
        },
        "source": source,
        "canonical": canonical,
        "runtime": runtime,
        "diagnostics": diagnostics,
        "boundary": {
            "attests": [
                "source-bytes",
                "canonical-core-v0-bytes",
                "stdout-transcript",
            ],
            "excludes": [
                "semantic-equivalence",
                "meaning-graph-lowering",
                "independent-witness",
            ],
        },
    })
}

fn artifact_commit_json() -> JsonValue {
    let env_hex = std::env::var("LISPEX_ARTIFACT_COMMIT_HEX")
        .ok()
        .filter(|hex| is_git_hex(hex));
    let hex = env_hex.unwrap_or_else(|| env!("LISPEX_BUILD_COMMIT_HEX").to_string());
    let dirty = std::env::var("LISPEX_ARTIFACT_COMMIT_DIRTY")
        .ok()
        .and_then(|value| match value.as_str() {
            "false" | "0" => Some(false),
            "true" | "1" => Some(true),
            _ => None,
        })
        .unwrap_or_else(|| env!("LISPEX_BUILD_COMMIT_DIRTY") == "true");
    json!({
        "vcs": "git",
        "hex": hex,
        "dirty": dirty,
    })
}

fn is_git_hex(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hash_obj(domain: &str, hex: String) -> JsonValue {
    json!({
        "domain": domain,
        "algo": "sha-256",
        "hex": hex,
    })
}

struct EvalRun {
    stdout: String,
    warnings: Vec<Warning>,
    failure: Option<RuntimeFailure>,
}

enum RuntimeFailure {
    Error(RuntimeError),
    Escape,
}

impl RuntimeFailure {
    fn display(&self, file: &str) -> String {
        match self {
            RuntimeFailure::Error(e) => e.to_string(),
            RuntimeFailure::Escape => format!("{file}: {ESCAPE_CONTINUATION_INACTIVE_MESSAGE}"),
        }
    }
}

fn eval_core(core: Vec<CoreExpr>, file: &str) -> EvalRun {
    eval_core_with_profile_input(core, file, None)
}

fn eval_core_with_profile_input(
    core: Vec<CoreExpr>,
    file: &str,
    profile_input: Option<&ProfileInput>,
) -> EvalRun {
    let mut it = Interp::new();
    it.set_file(file);
    if let Some(input) = profile_input {
        it.define_global("input", input.value.clone());
    }
    let mut stdout = String::new();
    let mut warnings = Vec::new();

    for expr in core {
        let outcome = it.eval_toplevel(expr);
        stdout.push_str(&it.take_output());
        warnings.extend(it.take_warnings());
        match outcome {
            Eval::Ok(outcome) => auto_print_into(&outcome, &mut stdout),
            Eval::Error(e) => {
                return EvalRun {
                    stdout,
                    warnings,
                    failure: Some(RuntimeFailure::Error(e)),
                };
            }
            Eval::Escape { .. } => {
                return EvalRun {
                    stdout,
                    warnings,
                    failure: Some(RuntimeFailure::Escape),
                };
            }
            Eval::TailApply { .. } => {
                unreachable!("Eval::TailApply must be resolved inside the trampoline")
            }
        }
    }

    EvalRun {
        stdout,
        warnings,
        failure: None,
    }
}

/// REPL/corpus auto-print (§11): one value per line; zero values print nothing.
fn auto_print_into(outcome: &Outcome, out: &mut String) {
    match outcome {
        Outcome::One(v) => {
            out.push_str(&v.write_repr());
            out.push('\n');
        }
        Outcome::Many(vs) => {
            for v in vs {
                out.push_str(&v.write_repr());
                out.push('\n');
            }
        }
    }
}

fn reader_diag_json(diag: &Diagnostic) -> JsonValue {
    json!({
        "severity": "error",
        "code": diag.code.to_string(),
        "file": diag.file,
        "line": diag.span.line,
        "col": diag.span.col,
        "message": diag.message,
    })
}

fn warning_json(w: &Warning) -> JsonValue {
    json!({
        "severity": "warning",
        "code": w.code.to_string(),
        "file": w.file,
        "line": w.span.line,
        "col": w.span.col,
        "message": w.message,
    })
}

fn runtime_failure_json(failure: &RuntimeFailure, file: &str) -> JsonValue {
    match failure {
        RuntimeFailure::Error(e) => json!({
            "severity": "error",
            "code": e.code.to_string(),
            "file": e.file,
            "line": e.span.line,
            "col": e.span.col,
            "message": e.message,
        }),
        RuntimeFailure::Escape => json!({
            "severity": "error",
            "code": "E340",
            "file": file,
            "line": 1,
            "col": 1,
            "message": ESCAPE_CONTINUATION_INACTIVE_MESSAGE,
        }),
    }
}

impl CliError {
    fn new(message: String, code: u8) -> CliError {
        CliError { message, code }
    }
}

#[cfg(test)]
mod differential_tests {
    use super::*;

    #[test]
    fn first_divergence_reports_index_and_both_entries() {
        let left = vec!["1".to_string(), "2".to_string()];
        let right = vec!["1".to_string(), "3".to_string()];
        let divergence = first_divergence(&left, &right);
        assert_eq!(divergence["index"], 1);
        assert_eq!(divergence["reference"], "2");
        assert_eq!(divergence["meaning_env"], "3");

        let missing = first_divergence(&left, &right[..1]);
        assert_eq!(missing["index"], 1);
        assert_eq!(missing["reference"], "2");
        assert!(missing["meaning_env"].is_null());
    }

    #[test]
    fn differential_comparison_disagree_branch_is_unit_tested() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("interp/ parent");
        let graph_bytes =
            std::fs::read(repo_root.join("meaning-env/cases/literal.json")).expect("literal graph");
        let reference_run = EvalRun {
            stdout: "2\n".to_string(),
            warnings: Vec::new(),
            failure: None,
        };

        let (_meaning_env, comparison, ok) =
            diff_meaning_env_and_comparison(&graph_bytes, &reference_run, None);
        assert!(!ok);
        assert_eq!(comparison["status"], "disagree");
        assert_eq!(comparison["reason"], "transcript-bytes-differ");
        assert_eq!(comparison["first_divergence"]["index"], 0);
        assert_eq!(comparison["first_divergence"]["reference"], "2");
        assert_eq!(comparison["first_divergence"]["meaning_env"], "1");
    }
}
