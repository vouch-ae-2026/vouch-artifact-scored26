//! Workspace anchor that makes the contract lane part of the pinned release build.
//!
//! General Lispex builds remain feature-off when they use `interp/Cargo.toml`.
//! The Stage-10 root workspace is a separate release surface: this dependency
//! activates `scored-native-contract`, so the contract binaries are selected by
//! the contract's exact root `cargo build --frozen --offline --release` command.

/// Names the two dependency-direction components selected by this anchor.
pub const RELEASE_COMPONENTS: (&str, &str) = ("lispex", "vouch");
