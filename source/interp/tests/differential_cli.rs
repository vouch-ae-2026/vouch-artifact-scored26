use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value as JsonValue;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("interp/ has a parent")
        .to_path_buf()
}

fn read_rel(rel: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn lispex_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lispex"));
    cmd.current_dir(repo_root());
    cmd
}

fn temp_file(name: &str, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "lispex-{}-{}-{name}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    std::fs::write(&path, bytes).expect("write temp file");
    path
}

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "lispex-{}-{}-{name}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    std::fs::remove_dir_all(&path).ok();
    std::fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn run_with_stdin(args: &[&str], stdin: &[u8]) -> std::process::Output {
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
        .write_all(stdin)
        .expect("write stdin");
    child.wait_with_output().expect("wait lispex")
}

fn transcript_bytes(entries: &[JsonValue]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        let text = entry.as_str().expect("transcript entry string");
        assert!(
            !text.contains('\n'),
            "transcript entries must not contain raw LF"
        );
        out.extend_from_slice(text.as_bytes());
        out.push(b'\n');
    }
    out
}

fn mask_engine_vcs_state(value: &mut JsonValue) {
    let commit = value
        .get_mut("engine")
        .and_then(|engine| engine.get_mut("commit"))
        .expect("engine.commit");
    assert_eq!(commit["vcs"], "git");
    commit["dirty"].as_bool().expect("engine.commit.dirty bool");
    let hex = commit["hex"].as_str().expect("commit hex string");
    assert!(
        hex.len() == 40
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "commit hex must be a full git oid"
    );
    commit["hex"] = JsonValue::String("<masked-commit>".to_string());
    commit["dirty"] = JsonValue::String("<masked-dirty>".to_string());
}

fn assert_json_artifact_eq(actual: &[u8], expected: &[u8], label: &str) {
    let mut actual_json: JsonValue =
        serde_json::from_slice(actual).unwrap_or_else(|e| panic!("{label} actual JSON: {e}"));
    let mut expected_json: JsonValue =
        serde_json::from_slice(expected).unwrap_or_else(|e| panic!("{label} expected JSON: {e}"));
    mask_engine_vcs_state(&mut actual_json);
    mask_engine_vcs_state(&mut expected_json);
    assert_eq!(actual_json, expected_json, "{label} artifact drifted");
}

#[test]
fn differential_receipts_match_goldens() {
    let expected_dir = repo_root().join("differential/expected");
    let mut files = std::fs::read_dir(&expected_dir)
        .expect("expected dir")
        .map(|entry| entry.expect("entry").path())
        .collect::<Vec<_>>();
    files.sort();
    assert!(files.len() >= 14, "corpus should stay non-trivial");

    for expected_path in files {
        let name = expected_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("stem");
        let case_rel = format!("differential/cases/{name}.lspx");
        let expected = std::fs::read(&expected_path).expect("read expected");
        let out = lispex_cmd()
            .arg("diff-receipt")
            .arg(&case_rel)
            .output()
            .expect("run diff-receipt");
        let receipt: JsonValue = serde_json::from_slice(&expected).expect("expected JSON");
        let status = receipt["comparison"]["status"].as_str().expect("status");
        if status == "agree" {
            assert!(out.status.success(), "{name} should agree");
        } else {
            assert_eq!(out.status.code(), Some(1), "{name} should exit 1");
        }
        assert!(out.stderr.is_empty(), "{name} stderr");
        assert_json_artifact_eq(&out.stdout, &expected, name);
    }
}

#[test]
fn differential_graph_goldens_match_lowering() {
    let graph_dir = repo_root().join("differential/graphs");
    let mut files = std::fs::read_dir(&graph_dir)
        .expect("graph dir")
        .map(|entry| entry.expect("entry").path())
        .collect::<Vec<_>>();
    files.sort();
    for graph_path in files {
        let name = graph_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("stem");
        let case_rel = format!("differential/cases/{name}.lspx");
        let out = lispex_cmd()
            .arg("lower")
            .arg(&case_rel)
            .output()
            .expect("run lower");
        assert!(out.status.success(), "{name} should lower");
        assert_eq!(
            out.stdout,
            std::fs::read(&graph_path).expect("read graph"),
            "{name} graph drifted"
        );
    }
}

#[test]
fn agreed_reference_transcript_is_bound_to_actual_run_stdout() {
    let expected_dir = repo_root().join("differential/expected");
    let mut files = std::fs::read_dir(&expected_dir)
        .expect("expected dir")
        .map(|entry| entry.expect("entry").path())
        .collect::<Vec<_>>();
    files.sort();
    for expected_path in files {
        let receipt: JsonValue =
            serde_json::from_slice(&std::fs::read(&expected_path).expect("read expected"))
                .expect("expected JSON");
        if receipt["comparison"]["status"] != "agree" {
            continue;
        }
        let name = expected_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("stem");
        let case_rel = format!("differential/cases/{name}.lspx");
        let run = lispex_cmd().arg(&case_rel).output().expect("run source");
        assert!(run.status.success(), "{name} reference run");
        let entries = receipt["reference"]["transcript"]
            .as_array()
            .expect("reference transcript");
        assert_eq!(
            run.stdout,
            transcript_bytes(entries),
            "{name} stdout binding"
        );
        let me_entries = receipt["meaning_env"]["transcript"]
            .as_array()
            .expect("meaning env transcript");
        assert_eq!(transcript_bytes(entries), transcript_bytes(me_entries));
    }
}

#[test]
fn diff_receipt_stdin_and_utf8_boundaries() {
    let src = read_rel("differential/cases/define-ref.lspx");
    let out = run_with_stdin(&["diff-receipt", "-"], &src);
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let receipt: JsonValue = serde_json::from_slice(&out.stdout).expect("receipt JSON");
    assert_eq!(receipt["source"]["path"], "<stdin>");
    assert_eq!(receipt["comparison"]["status"], "agree");

    let bad = run_with_stdin(&["diff-receipt", "-"], &[0xff, 0xfe]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
    assert!(String::from_utf8(bad.stderr)
        .expect("stderr utf8")
        .contains("not valid UTF-8"));
}

#[test]
fn diff_receipt_deep_tco_agrees_under_receipt_fuel_boundary() {
    let src = b"(define (loop n acc) (if (= n 0) acc (loop (- n 1) (+ acc 1)))) (loop 50000 0)";
    let out = run_with_stdin(&["diff-receipt", "-"], src);
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let receipt: JsonValue = serde_json::from_slice(&out.stdout).expect("receipt JSON");
    assert_eq!(
        receipt["differential_receipt"],
        "csk.differential-receipt/v0"
    );
    assert_eq!(receipt["reference"]["status"], "ok");
    assert_eq!(receipt["meaning_env"]["status"], "ok");
    assert_eq!(receipt["meaning_env"]["steps"]["limit"], 1_000_000);
    assert_eq!(receipt["comparison"]["status"], "agree");
}

#[test]
fn diff_receipt_deeper_tco_still_reports_bounded_step_limit() {
    let src = b"(define (loop n acc) (if (= n 0) acc (loop (- n 1) (+ acc 1)))) (loop 80000 0)";
    let out = run_with_stdin(&["diff-receipt", "-"], src);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty());
    let receipt: JsonValue = serde_json::from_slice(&out.stdout).expect("receipt JSON");
    assert_eq!(receipt["reference"]["status"], "ok");
    assert_eq!(receipt["meaning_env"]["status"], "fault");
    assert_eq!(receipt["meaning_env"]["steps"]["limit"], 1_000_000);
    assert_eq!(receipt["meaning_env"]["fault"]["kind"], "step-limit");
    assert_eq!(receipt["comparison"]["status"], "not-comparable");
    assert_eq!(receipt["comparison"]["reason"], "meaning-env-fault");
}

#[test]
fn eval_graph_default_step_limit_is_not_raised_for_deep_tco() {
    let src = b"(define (loop n acc) (if (= n 0) acc (loop (- n 1) (+ acc 1)))) (loop 50000 0)";
    let source_path = temp_file("default-step-limit.lspx", src);
    let lower = lispex_cmd()
        .arg("lower")
        .arg(&source_path)
        .output()
        .expect("lower source");
    std::fs::remove_file(&source_path).ok();
    assert!(lower.status.success(), "lower should succeed");
    assert!(lower.stderr.is_empty(), "lower stderr");

    let graph_path = temp_file("default-step-limit.json", &lower.stdout);
    let out = lispex_cmd()
        .arg("eval-graph")
        .arg(&graph_path)
        .output()
        .expect("eval graph");
    std::fs::remove_file(&graph_path).ok();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty());
    let report: JsonValue = serde_json::from_slice(&out.stdout).expect("report JSON");
    assert_eq!(report["status"], "fault");
    assert_eq!(report["steps"]["limit"], 65_536);
    assert_eq!(report["fault"]["kind"], "step-limit");
}

#[test]
fn diff_receipt_tco_through_apply_agrees_under_receipt_fuel_boundary() {
    let src = b"(define (loop n acc) (if (= n 0) acc (apply loop (list (- n 1) (+ acc 1))))) (loop 50000 0)";
    let out = run_with_stdin(&["diff-receipt", "-"], src);
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let receipt: JsonValue = serde_json::from_slice(&out.stdout).expect("receipt JSON");
    assert_eq!(receipt["reference"]["status"], "ok");
    assert_eq!(receipt["meaning_env"]["status"], "ok");
    assert_eq!(receipt["meaning_env"]["steps"]["limit"], 1_000_000);
    assert_eq!(receipt["comparison"]["status"], "agree");
}

#[test]
fn diff_receipt_tco_through_call_with_values_agrees_under_receipt_fuel_boundary() {
    let src = b"(define (loop n acc) (if (= n 0) acc (call-with-values (lambda () (values (- n 1) (+ acc 1))) loop))) (loop 50000 0)";
    let out = run_with_stdin(&["diff-receipt", "-"], src);
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let receipt: JsonValue = serde_json::from_slice(&out.stdout).expect("receipt JSON");
    assert_eq!(receipt["reference"]["status"], "ok");
    assert_eq!(receipt["meaning_env"]["status"], "ok");
    assert_eq!(receipt["meaning_env"]["steps"]["limit"], 1_000_000);
    assert_eq!(receipt["comparison"]["status"], "agree");
}

#[test]
fn diff_receipt_uses_build_commit_outside_git_worktree() {
    let dir = temp_dir("outside-git");
    let source = dir.join("rule.lspx");
    let input = dir.join("input.datum");
    std::fs::write(
        &source,
        b"(define (adult? age) (>= age 20))\n(adult? input)\n",
    )
    .expect("write source");
    std::fs::write(&input, b"20\n").expect("write input");

    let out = Command::new(env!("CARGO_BIN_EXE_lispex"))
        .current_dir(&dir)
        .arg("diff-receipt")
        .arg("--input")
        .arg("input.datum")
        .arg("rule.lspx")
        .output()
        .expect("run diff-receipt outside git");
    std::fs::remove_dir_all(&dir).ok();

    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let receipt: JsonValue = serde_json::from_slice(&out.stdout).expect("receipt JSON");
    assert_eq!(receipt["comparison"]["status"], "agree");
    assert_eq!(receipt["engine"]["commit"]["vcs"], "git");
    receipt["engine"]["commit"]["dirty"]
        .as_bool()
        .expect("build commit dirty bool");
    let hex = receipt["engine"]["commit"]["hex"]
        .as_str()
        .expect("commit hex");
    assert!(
        hex.len() == 40
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "commit hex must be a full git oid"
    );
    assert_ne!(hex, "0000000000000000000000000000000000000000");
}

#[test]
fn diff_receipt_binds_profile_input_to_both_evaluators() {
    let input_path = temp_file("adult-input.datum", b"(20)");
    let input_arg = input_path.to_str().expect("input path");
    let src = br#"(if (>= (car input) 18) "adult" "minor")"#;

    let out = run_with_stdin(&["diff-receipt", "--input", input_arg, "-"], src);
    std::fs::remove_file(&input_path).ok();

    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let receipt: JsonValue = serde_json::from_slice(&out.stdout).expect("receipt JSON");
    assert_eq!(receipt["comparison"]["status"], "agree");
    assert_eq!(receipt["input"]["status"], "bound");
    assert_eq!(receipt["input"]["name"], "input");
    assert_eq!(receipt["input"]["datum"], "(20)");
    assert_eq!(receipt["input"]["byte_len"], 4);
    assert_eq!(
        receipt["input"]["hash"]["hex"],
        "110af5fa552beb95424869a04b48937f7ebe323198aeb2dbb68c8e27f8966c28"
    );
    assert_eq!(receipt["reference"]["transcript"][0], "\"adult\"");
    assert_eq!(receipt["meaning_env"]["transcript"][0], "\"adult\"");
    assert!(receipt["boundary"]["attests"]
        .as_array()
        .expect("attests")
        .iter()
        .any(|claim| claim == "profile-input-hash-binding"));
    assert!(receipt["boundary"]["excludes"]
        .as_array()
        .expect("excludes")
        .iter()
        .any(|claim| claim == "input-provenance"));
}

#[test]
fn diff_receipt_input_errors_are_receipted_not_comparable() {
    let input_path = temp_file("bad-input.datum", b"1.5");
    let input_arg = input_path.to_str().expect("input path");

    let out = run_with_stdin(&["diff-receipt", "--input", input_arg, "-"], b"1");
    std::fs::remove_file(&input_path).ok();

    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty());
    let receipt: JsonValue = serde_json::from_slice(&out.stdout).expect("receipt JSON");
    assert_eq!(receipt["input"]["status"], "error");
    assert_eq!(receipt["comparison"]["status"], "not-comparable");
    assert_eq!(receipt["comparison"]["reason"], "input-error");
    assert_eq!(receipt["comparison"]["fault_class"], "input-error");
    assert_eq!(
        receipt["comparison"]["blockers"][0]["reason"],
        "input-error"
    );
    assert_eq!(receipt["canonical"]["status"], "ok");
    assert_eq!(receipt["graph"]["status"], "ok");
    assert_eq!(receipt["reference"]["status"], "not-run");
    assert_eq!(receipt["diagnostics"][0]["code"], "profile-input-domain");
}

#[test]
fn diff_receipt_input_does_not_perturb_source_core_or_graph_hashes() {
    let input_one = temp_file("input-one.datum", b"(1)");
    let input_two = temp_file("input-two.datum", b"(2)");
    let one_arg = input_one.to_str().expect("input one path");
    let two_arg = input_two.to_str().expect("input two path");
    let src = b"(if #t 7 8)";

    let out_one = run_with_stdin(&["diff-receipt", "--input", one_arg, "-"], src);
    let out_two = run_with_stdin(&["diff-receipt", "--input", two_arg, "-"], src);
    std::fs::remove_file(&input_one).ok();
    std::fs::remove_file(&input_two).ok();

    assert!(out_one.status.success());
    assert!(out_two.status.success());
    let one: JsonValue = serde_json::from_slice(&out_one.stdout).expect("receipt one");
    let two: JsonValue = serde_json::from_slice(&out_two.stdout).expect("receipt two");

    assert_eq!(one["source"]["hash"], two["source"]["hash"]);
    assert_eq!(one["canonical"]["hash"], two["canonical"]["hash"]);
    assert_eq!(one["graph"]["hash"], two["graph"]["hash"]);
    assert_ne!(one["input"]["hash"]["hex"], two["input"]["hash"]["hex"]);
    assert_eq!(
        one["input"]["hash"]["hex"],
        "584e7fc997cea9a341f244b17d82a058084528c12162d90e927c5dd3d3a7dd6c"
    );
    assert_eq!(
        two["input"]["hash"]["hex"],
        "35e44cdaa4f3e1adfcc36a8deb8d2f723b471df61c8fc9eacee23ecf5dd9ff4c"
    );
}

#[test]
fn diff_receipt_without_input_leaves_input_unbound_but_recorded_absent() {
    let out = run_with_stdin(&["diff-receipt", "-"], b"input");
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty());
    let receipt: JsonValue = serde_json::from_slice(&out.stdout).expect("receipt JSON");
    assert_eq!(receipt["input"]["status"], "absent");
    assert_eq!(receipt["comparison"]["status"], "not-comparable");
    assert_eq!(receipt["comparison"]["reason"], "reference-runtime-error");
    assert_eq!(
        receipt["comparison"]["fault_class"],
        "reference-runtime-error"
    );
}
