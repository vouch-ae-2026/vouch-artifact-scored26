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
    let path = std::env::temp_dir().join(format!("lispex-{}-{name}", std::process::id()));
    std::fs::write(&path, bytes).expect("write temp file");
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

#[test]
fn eval_graph_file_and_stdin_emit_same_report_bytes() {
    let graph = read_rel("meaning-env/cases/literal.json");
    let path = std::env::temp_dir().join(format!(
        "lispex-eval-graph-{}-literal.json",
        std::process::id()
    ));
    std::fs::write(&path, &graph).expect("write temp graph");

    let file_out = lispex_cmd()
        .arg("eval-graph")
        .arg(&path)
        .output()
        .expect("run file eval-graph");
    let stdin_out = run_with_stdin(&["eval-graph", "-"], &graph);
    std::fs::remove_file(&path).ok();

    assert!(file_out.status.success());
    assert!(stdin_out.status.success());
    assert!(file_out.stderr.is_empty());
    assert!(stdin_out.stderr.is_empty());
    assert_eq!(file_out.stdout, stdin_out.stdout);
}

#[test]
fn eval_graph_fault_emits_report_stdout_and_exit_one() {
    let graph = read_rel("meaning-env/faults/unbound-ref.json");
    let out = run_with_stdin(&["eval-graph", "-"], &graph);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty());
    let report: JsonValue = serde_json::from_slice(&out.stdout).expect("report JSON");
    assert_eq!(report["status"], "fault");
    assert_eq!(report["fault"]["kind"], "unbound-ref");
}

#[test]
fn eval_graph_law_error_emits_report_stdout_and_exit_one() {
    let graph = br#"{"meaning_graph":"csk.meaning-graph/v0","nodes":[],"roots":[]}"#;
    let out = run_with_stdin(&["eval-graph", "-"], graph);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty());
    let report: JsonValue = serde_json::from_slice(&out.stdout).expect("report JSON");
    assert_eq!(report["status"], "law-error");
    assert_eq!(report["result"], JsonValue::Null);
    assert!(!report["law_errors"]
        .as_array()
        .expect("law errors")
        .is_empty());
}

#[test]
fn eval_graph_malformed_json_emits_no_report_and_exit_two() {
    let out = run_with_stdin(&["eval-graph", "-"], b"{ not json");
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).expect("stderr UTF-8");
    assert!(stderr.contains("graph JSON parse failed"));
}

#[test]
fn eval_graph_invalid_utf8_emits_no_report_and_exit_two() {
    let out = run_with_stdin(&["eval-graph", "-"], &[0xff, 0xfe, 0xfd]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).expect("stderr UTF-8");
    assert!(stderr.contains("not valid UTF-8"));
}

#[test]
fn eval_graph_steps_override_can_fault() {
    let graph = read_rel("meaning-env/cases/literal.json");
    let out = run_with_stdin(&["eval-graph", "--steps", "1", "-"], &graph);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty());
    let report: JsonValue = serde_json::from_slice(&out.stdout).expect("report JSON");
    assert_eq!(report["status"], "fault");
    assert_eq!(report["fault"]["kind"], "step-limit");
    assert_eq!(report["steps"]["limit"], 1);
}

#[test]
fn eval_graph_input_binding_and_steps_are_order_insensitive() {
    let lower = run_with_stdin(
        &["lower", "-"],
        br#"(if (>= (car input) 18) "adult" "minor")"#,
    );
    assert!(lower.status.success());
    assert!(lower.stderr.is_empty());

    let input_path = temp_file("meaning-env-input.datum", b"(20)");
    let input_arg = input_path.to_str().expect("input path");
    let first = run_with_stdin(
        &["eval-graph", "--input", input_arg, "--steps", "1000", "-"],
        &lower.stdout,
    );
    let second = run_with_stdin(
        &["eval-graph", "--steps", "1000", "--input", input_arg, "-"],
        &lower.stdout,
    );
    std::fs::remove_file(&input_path).ok();

    assert!(first.status.success());
    assert!(second.status.success());
    assert!(first.stderr.is_empty());
    assert!(second.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);

    let report: JsonValue = serde_json::from_slice(&first.stdout).expect("report JSON");
    assert_eq!(report["input"]["status"], "bound");
    assert_eq!(report["input"]["name"], "input");
    assert_eq!(report["input"]["datum"], "(20)");
    assert_eq!(
        report["input"]["hash"]["hex"],
        "110af5fa552beb95424869a04b48937f7ebe323198aeb2dbb68c8e27f8966c28"
    );
    assert_eq!(report["transcript"][0], "\"adult\"");
    assert_eq!(report["steps"]["limit"], 1000);
}

#[test]
fn eval_graph_input_domain_errors_exit_two_without_report() {
    let graph = read_rel("meaning-env/cases/literal.json");
    let input_path = temp_file("meaning-env-bad-input.datum", b"#\\a");
    let input_arg = input_path.to_str().expect("input path");
    let out = run_with_stdin(&["eval-graph", "--input", input_arg, "-"], &graph);
    std::fs::remove_file(&input_path).ok();

    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).expect("stderr UTF-8");
    assert!(stderr.contains("profile input excludes characters"));
}
