//! Dependency-only anchor retaining the exact release Cargo.lock closure.
//!
//! The product WebAssembly surface is intentionally absent from this review
//! projection. This empty crate preserves only the original workspace package
//! identity and dependency edges so Cargo can validate the release lockfile
//! without rewriting it.
#![forbid(unsafe_code)]
