//! Lispex v1.2 reference interpreter — library crate.
//!
//! **Rounds 1–3 scope:** the value core ([`value`]), the reader/lexer ([`reader`]),
//! the spanned surface syntax tree it emits ([`syntax`]), the hygienic normalizer
//! ([`normalize`]) that lowers surface syntax to the Core AST ([`core`]), and the
//! **evaluator core** — the `Eval<Outcome>` trampoline with guaranteed TCO, mutable
//! environment cells, closures, the four hidden intrinsics, and the evaluation
//! faults ([`eval`] + [`error`]). R3 ships a CLEARLY-TEMPORARY bootstrap primitive
//! set (integer-only arithmetic + list basics) that R4/R5 replace.
//! Later rounds add the full numeric tower with the pinned float formatter (R4), the
//! stdlib + aliases (R5), the rest of the error model with escape `call/cc` /
//! `dynamic-wind` (R6), the conformance corpus (R7), and the wasm playground (R8).
//! See `LISPEX-RUNTIME.md` §16 for the build order.

pub mod canonical;
pub mod core;
pub mod error;
pub mod eval;
pub mod meaning_env;
pub mod meaning_graph;
pub mod normalize;
pub mod number;
pub mod reader;
mod scored_mutation_guard;
pub mod syntax;
pub mod value;
#[cfg(feature = "scored-native-contract")]
pub mod vouch_native;

// Re-export the exact-number types so downstream code (and tests) can construct
// expected `Value::Int` / `Value::Rational` without depending on num-* directly.
pub use num_bigint::BigInt;
pub use num_rational::BigRational;

pub use canonical::{
    canonical_datum_parse, canonical_datum_string, canonical_expr_string, canonical_program_bytes,
    core_hash_hex, hash_with_domain_hex, profile_input_hash_hex, runtime_hash_hex, source_hash_hex,
    CanonFault, CANONICAL_FORMAT_TAG, CORE_HASH_DOMAIN, ENGINE_VERSION_DOMAIN,
    PROFILE_INPUT_HASH_DOMAIN, RUNTIME_HASH_DOMAIN, SOURCE_HASH_DOMAIN,
};
pub use core::{Binding, CoreExpr, CoreKind, Formals, Ident, Intrinsic};
pub use error::{
    RuntimeCode, RuntimeError, WarnCode, Warning, ESCAPE_CONTINUATION_INACTIVE_MESSAGE,
};
pub use eval::{
    ClosureData, Continuation, Eval, Interp, Outcome, Primitive, RunError, CALL_DEPTH_LIMIT,
};
pub use meaning_env::{
    eval_graph_json_receipt_projection_with_input, eval_graph_json_report,
    eval_graph_json_report_with_input, MeaningEnvFault, MeaningEnvInputError, MeaningEnvOutput,
    MeaningEnvReceiptProjection, MEANING_ENV_DEFAULT_STEP_LIMIT, MEANING_ENV_REPORT_HASH_DOMAIN,
    MEANING_ENV_REPORT_TAG,
};
pub use meaning_graph::{
    graph_from_json_bytes, graph_from_json_value, graph_hash_hex, graph_json_bytes,
    lower_program as lower_meaning_graph_program, validate_graph_value, GraphLawError, GraphName,
    GraphNode, LowerFault, MeaningGraph, MEANING_GRAPH_HASH_DOMAIN, MEANING_GRAPH_TAG,
};
pub use normalize::{normalize_one, normalize_program};
pub use number::{AErr, CmpOp, Num};
pub use reader::{
    parse_number_token, read_one, read_program, Diagnostic, ErrCode, Header, NumberParse, Program,
    Span,
};
pub use syntax::{Syntax, SyntaxKind};
#[cfg(feature = "scored-native-contract")]
pub use value::Decision;
pub use value::{format_real, Cons, ErrorObj, Finite, Interner, Value, VectorData};
