//! Version-surface drift guard (the "single source of truth" enforcement).
//!
//! Lispex states its version in several places that different build systems own —
//! the interpreter crate (`interp/Cargo.toml`), the wasm crate, the npm CLI package,
//! the site package, and the site's download config. They cannot literally share one
//! file, so this test makes them share one VALUE: the interpreter crate version
//! (`CARGO_PKG_VERSION`) is the SSOT, and every other surface must match it. Bump one
//! and this test fails until the rest are bumped in lockstep — so "one version across
//! docs and interpreter" is enforced, not merely documented.
//!
//! The user-facing form is the major.minor of this (v1.2.0 → v1.2), derived in
//! `src/config/release.ts`; the `;! lispex X.Y` grammar header tracks that major.minor.

use std::path::Path;

#[test]
fn version_surfaces_agree_with_the_crate() {
    let ver = env!("CARGO_PKG_VERSION"); // interp/Cargo.toml — the single source of truth
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root is the interp crate's parent");

    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
    };

    // The user-facing display form is the major.minor of the crate version (1.2.0 → v1.2),
    // matching DISPLAY_VERSION in src/config/release.ts. public/version.json carries this
    // display form, so it is checked against the derived value, not the full semver.
    let (major, minor) = {
        let mut it = ver.split('.');
        let major = it.next().expect("crate version has a major");
        let minor = it.next().expect("crate version has a minor");
        (major, minor)
    };
    let display = format!("v{major}.{minor}"); // e.g. "v1.2"

    // Each surface, and the exact substring it must contain for the current crate version.
    let checks = [
        ("wasm/Cargo.toml", format!("version = \"{ver}\"")),
        ("cli/package.json", format!("\"version\": \"{ver}\"")),
        ("package.json", format!("\"version\": \"{ver}\"")),
        (
            "src/config/release.ts",
            format!("RELEASE_VERSION = 'v{ver}'"),
        ),
        // Generated from release.ts at build time (scripts/gen-version-json.mjs), but the
        // generated file is committed — pin BOTH version-bearing fields here (the `version`
        // and the leading version in `spec`) so neither can silently drift.
        ("public/version.json", format!("\"version\": \"{display}\"")),
        ("public/version.json", format!("\"spec\": \"{display} ")),
    ];
    for (rel, needle) in checks {
        let body = read(rel);
        assert!(
            body.contains(&needle),
            "version drift: {rel} does not match the crate version {ver} \
             (expected to contain `{needle}`). Bump every version surface in lockstep."
        );
    }
}
