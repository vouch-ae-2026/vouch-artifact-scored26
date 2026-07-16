use std::io::Write;
use std::process::{Command, Stdio};

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

#[test]
fn lower_file_and_stdin_emit_same_graph_bytes() {
    let src = "(define x 1)\nx\n";
    let path = std::env::temp_dir().join(format!(
        "lispex-lower-{}-same-bytes.lspx",
        std::process::id()
    ));
    std::fs::write(&path, src).expect("write temp source");

    let file_out = lispex_cmd()
        .arg("lower")
        .arg(&path)
        .output()
        .expect("run file lower");
    let stdin_out = run_with_stdin(&["lower", "-"], src);
    std::fs::remove_file(&path).ok();

    assert!(file_out.status.success());
    assert!(stdin_out.status.success());
    assert!(file_out.stderr.is_empty());
    assert!(stdin_out.stderr.is_empty());
    assert_eq!(file_out.stdout, stdin_out.stdout);
}

#[test]
fn lower_fault_emits_no_partial_stdout() {
    let out = run_with_stdin(&["lower", "-"], "(letrec ((x 1)) x)\n");
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("E-MG-LOWER"));
    assert!(stderr.contains("outside Meaning Graph v0 lowering"));
}
