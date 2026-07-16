//! Strict SCORED native-contract primitives.
//!
//! Stage 1 implements only byte, cryptographic, and fault-injectable I/O
//! primitives. It deliberately contains no Lispex evaluator, issuer, verifier,
//! or release-key path.

pub mod artifact_json;
pub mod dsse;
pub mod io_boundary;
pub mod policy;
pub mod release;
mod scored_mutation_guard;
pub mod test_support;
