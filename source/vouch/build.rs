const SCORED_MUTANTS: [&str; 12] = [
    "M01", "M02", "M03", "M04", "M05", "M06", "M07", "M08", "M09", "M10", "M11", "M12",
];

fn main() {
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
    let selected = std::env::var("SCORED_MUTANT").unwrap_or_default();
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
    if std::env::var("PROFILE").is_ok_and(|profile| profile == "release") && !injected.is_empty() {
        panic!("SCORED release build requires empty Rust flag environments");
    }
    if injected.contains("scored_mutant") {
        println!("cargo:rustc-cfg=scored_mutant_injected");
    }
    println!("cargo:rustc-env=CSK_SCORED_MUTANT={selected}");
}
