//! Runtime error model (LISPEX-RUNTIME.md §8) — the `E3xx` faults the evaluator
//! raises, plus the (deliberately non-`E3xx`) recursion-bound resource limit.
//!
//! Distinct from the reader/normalizer's [`crate::reader::ErrCode`] (E1xx static +
//! reader diagnostics): runtime faults live in their own `E3xx` namespace per §8.
//! The full table is defined now (so R6's `(error)`/`call/cc`/`dynamic-wind` slot
//! in without rework); R3 only ever *raises* E300/E301/E302/E303/E310/E312/E320/
//! E321 + [`RuntimeCode::RecursionLimit`]. The rest (E311/E313/E314/E330/E340) are
//! reserved for R4/R6.

use std::fmt;
use std::rc::Rc;

use crate::reader::Span;
use crate::value::{ErrorObj, Value};

/// Deterministic E340 text for a consumed or out-of-extent escape continuation.
pub const ESCAPE_CONTINUATION_INACTIVE_MESSAGE: &str = "escape continuation is no longer active";

/// A runtime fault code. `E3xx` are the spec's catchable runtime faults (§8);
/// [`RuntimeCode::RecursionLimit`] is a deterministic **resource limit**, kept
/// outside the `E3xx` namespace on purpose so a future `guard-call` (R6) never
/// treats it as a catchable fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeCode {
    /// Unbound variable.
    E300,
    /// Attempt to apply a non-procedure.
    E301,
    /// Arity mismatch on a call.
    E302,
    /// `set!` on an unbound variable.
    E303,
    /// Pair expected (`car`/`cdr`/…).
    E310,
    /// Index out of range (R5 vector/string ops). Reserved.
    E311,
    /// Wrong type passed to a primitive.
    E312,
    /// Division by zero (R4 arithmetic). Reserved.
    E313,
    /// Inexact result not finite / overflow (R4). Reserved.
    E314,
    /// Multiple-values misuse: a single-value context got 0 or ≥2 values.
    E320,
    /// Read of an unassigned `letrec` (or internal-`define`) variable.
    E321,
    /// User `(error …)` (R6). Reserved.
    E330,
    /// An object passed to `(raise obj)` reached the top level uncaught (v1.2).
    E331,
    /// A non-continuable `raise` handler returned to its `raise` (v1.2).
    E332,
    /// Escape continuation already consumed or outside its dynamic extent (R6).
    E340,
    /// Recursion bound exceeded — a deterministic resource limit, **not** a
    /// catchable `E3xx` fault (see module docs).
    RecursionLimit,
    /// SCORED checked-profile logical evaluator budget. This variant exists only
    /// in the dormant contract build and is never raised in normal Lispex mode.
    #[cfg(feature = "scored-native-contract")]
    ReferenceBudgetExhausted,
    /// A covered checked-profile shape escaped its dynamic value boundary.
    #[cfg(feature = "scored-native-contract")]
    ProfileEscape,
}

impl RuntimeCode {
    /// The code token used in the `CODE file:line:col message` rendering (§8).
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeCode::E300 => "E300",
            RuntimeCode::E301 => "E301",
            RuntimeCode::E302 => "E302",
            RuntimeCode::E303 => "E303",
            RuntimeCode::E310 => "E310",
            RuntimeCode::E311 => "E311",
            RuntimeCode::E312 => "E312",
            RuntimeCode::E313 => "E313",
            RuntimeCode::E314 => "E314",
            RuntimeCode::E320 => "E320",
            RuntimeCode::E321 => "E321",
            RuntimeCode::E330 => "E330",
            RuntimeCode::E331 => "E331",
            RuntimeCode::E332 => "E332",
            RuntimeCode::E340 => "E340",
            RuntimeCode::RecursionLimit => "recursion-limit",
            #[cfg(feature = "scored-native-contract")]
            RuntimeCode::ReferenceBudgetExhausted => "reference-budget-exhausted",
            #[cfg(feature = "scored-native-contract")]
            RuntimeCode::ProfileEscape => "profile-escape",
        }
    }
}

impl fmt::Display for RuntimeCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A structured runtime fault (§8: `{ code, message, irritants, span }` plus the
/// source `file`, mirroring [`crate::reader::Diagnostic`]). Renders as
/// `CODE file:line:col message [irritants…]`; irritants are rendered via `write`.
#[derive(Clone, Debug)]
pub struct RuntimeError {
    pub code: RuntimeCode,
    pub file: String,
    pub span: Span,
    pub message: String,
    /// Extra values attached to the fault (rendered via `write`). Used by R6
    /// `(error msg irritant…)`; empty for the evaluator-intrinsic faults.
    pub irritants: Vec<Value>,
    /// The condition object a handler/`guard` sees (v1.2). `Some(obj)` for
    /// `(raise obj)` (an arbitrary value) and `(error …)` (an error object);
    /// `None` for an intrinsic fault — a catch site then synthesizes an error
    /// object from `message`+`irritants`. [`RuntimeError::condition_value`].
    /// Boxed (and usually `None`) to keep `RuntimeError` small: it rides in the
    /// hot `Eval::Error` variant on every `Result<_, Eval>` the evaluator returns.
    pub condition: Option<Box<Value>>,
    /// `true` once this fault has been offered to the whole exception-handler chain
    /// (v1.2). The `eval` boundary dispatches a fresh catchable fault to the current
    /// handler in place; if no handler catches it, it is marked dispatched so an outer
    /// `eval` boundary does not re-offer it. Always `true` for an uncatchable fault.
    pub dispatched: bool,
    /// `true` for `raise-continuable` (v1.2): if the handler returns, its value(s)
    /// become the value of the raising call; otherwise a returning handler is the
    /// `E332` violation.
    pub continuable: bool,
}

impl RuntimeError {
    /// True iff a handler / `guard` may catch this fault (v1.2). Every `E3xx` is
    /// catchable; the `RecursionLimit` resource limit is not — it unwinds past every
    /// handler to the top (kept outside the `E3xx` namespace on purpose).
    pub fn is_catchable(&self) -> bool {
        match self.code {
            RuntimeCode::RecursionLimit => false,
            #[cfg(feature = "scored-native-contract")]
            RuntimeCode::ReferenceBudgetExhausted => false,
            #[cfg(feature = "scored-native-contract")]
            RuntimeCode::ProfileEscape => false,
            _ => true,
        }
    }

    /// The condition object a handler / `guard` binds (v1.2): the attached
    /// `raise`/`error` object if any, else a fresh error object synthesized from this
    /// fault's `message` + `irritants` (so an intrinsic fault reads as `error-object?`).
    pub fn condition_value(&self) -> Value {
        self.condition.as_deref().cloned().unwrap_or_else(|| {
            Value::ErrorObject(Rc::new(ErrorObj {
                message: self.message.as_str().into(),
                irritants: self.irritants.clone(),
            }))
        })
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}:{}:{} {}",
            self.code, self.file, self.span.line, self.span.col, self.message
        )?;
        for ir in &self.irritants {
            write!(f, " {}", ir.write_repr())?;
        }
        Ok(())
    }
}

/// A non-fatal **W3xx** runtime warning (LISPEX.md §13 diagnostics table). Emitted —
/// but never aborting — when a *deprecated* stdlib alias is actually invoked (R5
/// canonicalization policy, LISPEX-RUNTIME.md §10: "deprecated aliases emit a W3xx
/// style warning but still run"). The warning fires at the call **only when the
/// genuine deprecated primitive runs**, so a program that shadows the name with its
/// own binding produces no warning (more precise than a name-based static check).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WarnCode {
    /// `%` used — `modulo` is the canonical spelling (LISPEX.md §13 W330).
    W330,
    /// `list-first` / `list-rest` used — `first` / `rest` are the canonical spellings.
    /// A W3xx-style style/deprecation code in the same `W33x` family as W330 (§10
    /// names no fixed number for these, so the reference pins one here).
    W331,
}

impl WarnCode {
    /// The code token used in the `CODE file:line:col message` rendering (§13 style).
    pub fn as_str(self) -> &'static str {
        match self {
            WarnCode::W330 => "W330",
            WarnCode::W331 => "W331",
        }
    }
}

impl fmt::Display for WarnCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A structured deprecation warning, rendered like a [`RuntimeError`] (the §13
/// `CODE file:line:col message` format) but reported on a side channel — the
/// interpreter keeps running.
#[derive(Clone, Debug)]
pub struct Warning {
    pub code: WarnCode,
    pub file: String,
    pub span: Span,
    pub message: String,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}:{}:{} {}",
            self.code, self.file, self.span.line, self.span.col, self.message
        )
    }
}
