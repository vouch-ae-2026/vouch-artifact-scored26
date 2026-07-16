//! Dormant SCORED native-contract integration lane.
//!
//! This module is compiled only with the off-by-default
//! `scored-native-contract` feature. Existing `diff-receipt` behavior remains
//! owned by the existing interpreter modules and CLI.

pub mod bridge;
pub mod canonical_value;
pub mod checked_input;
pub mod checked_profile;
pub mod eval_observer;
pub mod graph;
pub mod issue;
pub mod meaning_trace;
pub mod mutation;
pub mod receipt;
pub mod reference_trace;
pub mod structural_verify;
pub mod tokens;
pub mod transcript;
pub mod verify;
pub mod workload;
