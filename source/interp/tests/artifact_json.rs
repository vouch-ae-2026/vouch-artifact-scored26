use std::fs;
use std::path::Path;

#[test]
fn artifact_json_cross_writer_fixture_matches_serde_json_pretty() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("interp has repo parent");
    let fixture = repo_root
        .join("artifact-json")
        .join("fixtures")
        .join("cross-writer-strings.json");
    let text = fs::read_to_string(&fixture).expect("fixture readable");
    assert!(text.ends_with('\n'), "fixture must end with exactly one LF");
    assert!(!text.ends_with("\n\n"), "fixture must not end with two LFs");
    let value: serde_json::Value = serde_json::from_str(&text).expect("fixture JSON");
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&value).expect("serde_json pretty")
    );
    assert_eq!(text, rendered);
}
