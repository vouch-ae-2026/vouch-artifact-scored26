use std::path::PathBuf;
use std::process::Command;

const SCORED_MUTANTS: [&str; 12] = [
    "M01", "M02", "M03", "M04", "M05", "M06", "M07", "M08", "M09", "M10", "M11", "M12",
];

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}

fn is_git_hex(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn build_commit_hex() -> String {
    std::env::var("LISPEX_BUILD_COMMIT_HEX")
        .ok()
        .filter(|value| is_git_hex(value))
        .or_else(|| {
            std::env::var("GITHUB_SHA")
                .ok()
                .filter(|value| is_git_hex(value))
        })
        .or_else(|| {
            git_output(&["rev-parse", "--verify", "HEAD"]).filter(|value| is_git_hex(value))
        })
        .unwrap_or_else(|| "0000000000000000000000000000000000000000".to_string())
}

fn build_commit_dirty() -> bool {
    if let Ok(value) = std::env::var("LISPEX_BUILD_COMMIT_DIRTY") {
        return matches!(value.as_str(), "true" | "1");
    }
    if std::env::var("GITHUB_SHA").is_ok() {
        return false;
    }
    git_output(&["status", "--porcelain"])
        .map(|status| !status.is_empty())
        .unwrap_or(true)
}

fn scored_release_git_identity() -> (String, bool) {
    let commit = git_output(&["rev-parse", "--verify", "HEAD"])
        .filter(|value| is_git_hex(value))
        .unwrap_or_else(|| panic!("SCORED release build requires a verified 40-hex Git HEAD"));
    if git_output(&["symbolic-ref", "-q", "HEAD"]).is_some() {
        panic!("SCORED release build requires detached HEAD");
    }
    let dirty = git_output(&["status", "--porcelain"])
        .map(|status| !status.is_empty())
        .unwrap_or(true);
    (commit, dirty)
}

fn git_path(args: &[&str]) -> Option<PathBuf> {
    let path = PathBuf::from(git_output(args)?);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(std::env::current_dir().ok()?.join(path))
    }
}

fn emit_git_rerun_triggers() {
    let Some(git_dir) = git_path(&["rev-parse", "--git-dir"]) else {
        return;
    };
    let common_dir =
        git_path(&["rev-parse", "--git-common-dir"]).unwrap_or_else(|| git_dir.clone());
    let head = git_dir.join("HEAD");

    println!("cargo:rerun-if-changed={}", head.display());
    println!("cargo:rerun-if-changed={}", git_dir.join("index").display());
    println!(
        "cargo:rerun-if-changed={}",
        common_dir.join("packed-refs").display()
    );

    if let Ok(head_text) = std::fs::read_to_string(&head) {
        if let Some(reference) = head_text.trim().strip_prefix("ref: ") {
            println!(
                "cargo:rerun-if-changed={}",
                common_dir.join(reference).display()
            );
        }
    }
}

fn emit_scored_mutant_configuration() {
    println!("cargo:rerun-if-env-changed=SCORED_MUTANT");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    println!("cargo:rustc-check-cfg=cfg(scored_mutant)");
    println!("cargo:rustc-check-cfg=cfg(scored_mutant_injected)");
    println!(
        "cargo:rustc-check-cfg=cfg(scored_mutant, values(\"M01\", \"M02\", \"M03\", \"M04\", \"M05\", \"M06\", \"M07\", \"M08\", \"M09\", \"M10\", \"M11\", \"M12\"))"
    );
    println!(
        "cargo:rustc-check-cfg=cfg(scored_mutant_expected, values(\"none\", \"M01\", \"M02\", \"M03\", \"M04\", \"M05\", \"M06\", \"M07\", \"M08\", \"M09\", \"M10\", \"M11\", \"M12\"))"
    );
    let selected = if std::env::var_os("CARGO_FEATURE_SCORED_NATIVE_CONTRACT").is_some() {
        std::env::var("SCORED_MUTANT").unwrap_or_default()
    } else {
        String::new()
    };
    if !selected.is_empty() && !SCORED_MUTANTS.contains(&selected.as_str()) {
        panic!("SCORED_MUTANT must be empty or one of M01 through M12");
    }
    let expected = if selected.is_empty() {
        "none"
    } else {
        selected.as_str()
    };
    println!("cargo:rustc-cfg=scored_mutant_expected=\"{expected}\"");
    if !selected.is_empty() {
        println!("cargo:rustc-cfg=scored_mutant=\"{selected}\"");
    }
    let injected = std::env::var("RUSTFLAGS").unwrap_or_default()
        + &std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    if injected.contains("scored_mutant") {
        println!("cargo:rustc-cfg=scored_mutant_injected");
    }
    println!("cargo:rustc-env=CSK_SCORED_MUTANT={selected}");
}

fn main() {
    println!("cargo:rerun-if-env-changed=LISPEX_BUILD_COMMIT_HEX");
    println!("cargo:rerun-if-env-changed=LISPEX_BUILD_COMMIT_DIRTY");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    emit_scored_mutant_configuration();
    emit_git_rerun_triggers();
    let scored_feature = std::env::var_os("CARGO_FEATURE_SCORED_NATIVE_CONTRACT").is_some();
    let release_profile = std::env::var("PROFILE").is_ok_and(|profile| profile == "release");
    let scored_release = scored_feature && release_profile;
    let (build_commit, build_dirty) = if scored_release {
        scored_release_git_identity()
    } else {
        (build_commit_hex(), build_commit_dirty())
    };
    let rustflags = std::env::var("RUSTFLAGS").unwrap_or_default();
    let encoded_rustflags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    if scored_release && build_dirty {
        panic!("SCORED release build requires a clean worktree and index");
    }
    if scored_release && (!rustflags.is_empty() || !encoded_rustflags.is_empty()) {
        panic!("SCORED release build requires empty Rust flag environments");
    }
    println!("cargo:rustc-env=LISPEX_BUILD_COMMIT_HEX={}", build_commit);
    println!("cargo:rustc-env=CSK_BUILD_COMMIT={build_commit}");
    println!(
        "cargo:rustc-env=CSK_TARGET_TRIPLE={}",
        std::env::var("TARGET").expect("Cargo sets TARGET")
    );
    println!(
        "cargo:rustc-env=CSK_LISPEX_VERSION={}",
        std::env::var("CARGO_PKG_VERSION").expect("Cargo sets CARGO_PKG_VERSION")
    );
    println!("cargo:rustc-env=CSK_RUSTFLAGS={rustflags}");
    println!("cargo:rustc-env=CSK_CARGO_ENCODED_RUSTFLAGS={encoded_rustflags}");
    println!(
        "cargo:rustc-env=LISPEX_BUILD_COMMIT_DIRTY={}",
        if build_dirty { "true" } else { "false" }
    );
}
