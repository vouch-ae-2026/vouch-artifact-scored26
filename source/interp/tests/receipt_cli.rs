use std::io::Write;
use std::process::{Command, Stdio};

use lispex::{core_hash_hex, hash_with_domain_hex, CORE_HASH_DOMAIN};
use serde_json::Value;

const SAMPLE: &str = "(define x 1)\n(display \"hi\")\n(+ x 2)\n";

fn lispex_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lispex"))
}

fn run_with_stdin(args: &[&str], stdin: &str) -> std::process::Output {
    let mut child = lispex_cmd()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lispex");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait lispex")
}

fn receipt_from_stdin(src: &str) -> (std::process::Output, Value) {
    let out = run_with_stdin(&["receipt", "-"], src);
    let json: Value = serde_json::from_slice(&out.stdout).expect("receipt JSON");
    (out, json)
}

fn get_hex<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for key in path {
        cur = &cur[*key];
    }
    cur.as_str().expect("hex string")
}

#[test]
fn receipt_known_hashes_and_run_stdout_match() {
    let run = run_with_stdin(&["-"], SAMPLE);
    assert!(run.status.success());
    assert_eq!(run.stdout, b"hi3\n");
    assert!(run.stderr.is_empty());

    let (receipt_out, receipt) = receipt_from_stdin(SAMPLE);
    assert!(receipt_out.status.success());
    assert!(receipt_out.stderr.is_empty());

    assert_eq!(receipt["receipt"], "lispex.receipt/v0");
    assert_eq!(receipt["engine"]["name"], "lispex-rust-reference");
    assert_eq!(
        receipt["engine"]["canonical_format"],
        "lispex.core.canonical/v0"
    );
    assert_eq!(receipt["engine"]["commit"]["vcs"], "git");
    receipt["engine"]["commit"]["dirty"]
        .as_bool()
        .expect("engine commit dirty bool");
    assert_eq!(
        receipt["engine"]["commit"]["hex"]
            .as_str()
            .expect("commit hex")
            .len(),
        40
    );
    assert_eq!(receipt["canonical"]["status"], "ok");
    assert_eq!(receipt["runtime"]["status"], "ok");
    assert_eq!(receipt["runtime"]["transcript_byte_len"], 4);
    assert_eq!(receipt["diagnostics"].as_array().unwrap().len(), 0);

    assert_eq!(
        get_hex(&receipt, &["source", "hash", "hex"]),
        "ff5b7dfc5667fbf50879b5afb1a2676fd941d9045c1061b410fb608f48058c96"
    );
    assert_eq!(
        get_hex(&receipt, &["canonical", "hash", "hex"]),
        "9b78fb6ee6545ae5673561fb4f4b5ef94f147dd8c25287a0f51cb5322122f908"
    );
    assert_eq!(
        get_hex(&receipt, &["runtime", "hash", "hex"]),
        "2430cf56b833c21407449087195fcd1643997b13cca36f523b645250860c3dd9"
    );
}

#[test]
fn receipt_file_and_stdin_hashes_match_for_same_bytes() {
    let path = std::env::temp_dir().join(format!(
        "lispex-receipt-{}-{}.lspx",
        std::process::id(),
        "same-bytes"
    ));
    std::fs::write(&path, SAMPLE).expect("write temp source");

    let file_out = lispex_cmd()
        .arg("receipt")
        .arg(&path)
        .output()
        .expect("run file receipt");
    let stdin = receipt_from_stdin(SAMPLE).1;
    let file: Value = serde_json::from_slice(&file_out.stdout).expect("file receipt JSON");
    std::fs::remove_file(&path).ok();

    assert!(file_out.status.success());
    for stage in ["source", "canonical", "runtime"] {
        assert_eq!(
            get_hex(&file, &[stage, "hash", "hex"]),
            get_hex(&stdin, &[stage, "hash", "hex"])
        );
    }
    assert_ne!(file["source"]["path"], stdin["source"]["path"]);
}

#[test]
fn receipt_reports_reader_error_but_keeps_source_hash() {
    let (out, receipt) = receipt_from_stdin("(");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(receipt["canonical"]["status"], "read-error");
    assert_eq!(receipt["runtime"]["status"], "not-run");
    assert!(receipt["source"]["hash"]["hex"].as_str().unwrap().len() == 64);
    assert_eq!(receipt["diagnostics"][0]["severity"], "error");
    assert_eq!(receipt["diagnostics"][0]["code"], "E100");
}

#[test]
fn receipt_reports_runtime_error_without_runtime_hash() {
    let (out, receipt) = receipt_from_stdin("(+ 1 #t)\n");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(receipt["canonical"]["status"], "ok");
    assert_eq!(receipt["runtime"]["status"], "error");
    assert!(receipt["runtime"]["hash"].is_null());
    assert_eq!(receipt["diagnostics"][0]["severity"], "error");
    assert_eq!(receipt["diagnostics"][0]["code"], "E312");
}

#[test]
fn receipt_keeps_warnings_out_of_runtime_hash() {
    let (out, receipt) = receipt_from_stdin("(% 5 2)\n");
    assert!(out.status.success());
    assert_eq!(receipt["runtime"]["status"], "ok");
    assert_eq!(receipt["diagnostics"][0]["severity"], "warning");
    assert_eq!(receipt["diagnostics"][0]["code"], "W330");
    assert!(receipt["runtime"]["hash"]["hex"].as_str().unwrap().len() == 64);
}

#[test]
fn hash_domain_separator_is_load_bearing() {
    let bytes = b"abc";
    let domain_hash = core_hash_hex(bytes);
    let naked_hash = hash_with_domain_hex("", bytes);
    let sibling_hash = hash_with_domain_hex(CORE_HASH_DOMAIN, b"abc\n");
    assert_ne!(domain_hash, naked_hash);
    assert_ne!(domain_hash, sibling_hash);
}
