//! Evaluator core — the `Eval<Outcome>` trampoline, environments with mutable cells,
//! closures, **guaranteed proper TCO**, the four hidden intrinsics, and the builtin
//! primitive set (R3 core forms; R4 installs the full exact numeric tower + pinned
//! float formatter) (LISPEX-RUNTIME.md §1/§2/§3/§4/§5/§6/§7/§8).
//!
//! ## The signal: `Eval<Outcome>` threaded by value, never host control flow (§1)
//! Every (sub)evaluation returns an [`Eval`]: `Ok(Outcome)`, `Error(RuntimeError)`,
//! or `Escape { tag, vals }`. There is **no `panic`/unwind for control flow** — the
//! only model that ports to external backend (whose faults are uncatchable, so a port threads a
//! `Result`/trampoline). Sub-evaluations are threaded with explicit `match … { Ok =>
//! …, Err/other => return … }`, the by-value stand-in for `?`. [`Eval::Escape`] is
//! emitted by [`Interp::invoke_cont`] (an escape-only `call/cc` `k` invoked while its
//! frame is live, §9) and caught by the owning `call/cc` frame ([`prim_call_cc`]); every
//! other frame propagates it via its catch-all arm.
//!
//! [`Outcome`] is `One(Value)` or `Many(Vec<Value>)` (`Many` carries 0 or ≥2). A
//! `values` producer normalizes exactly-one to `One`. Multiple values are an
//! *evaluation outcome*, never a storable [`Value`].
//!
//! ## TCO without host-stack growth (§4)
//! [`Interp::eval`] is a thin wrapper that does the recursion-depth bookkeeping and
//! delegates to [`Interp::eval_loop`], an **explicit-control loop**. A form in TAIL
//! position (an `if` branch, the last expr of a `begin`/`let`/`letrec` body, a closure
//! call) does NOT recurse: it rebinds the loop's `(expr, env)` and `continue`s, so the
//! current control frame is *reused*. Self- and mutual-recursion both get this for
//! free (mutual recursion is just two closures whose bodies tail-call each other → the
//! one loop alternates between them). Only **non-tail** sub-evaluations (call operands,
//! the `if` test, `let`/`set!`/`define` RHSs) re-enter [`Interp::eval`], growing the
//! host stack — and that is bounded by [`CALL_DEPTH_LIMIT`]; exceeding it is a clean
//! [`RuntimeCode::RecursionLimit`] resource limit, not a host stack overflow. To make
//! that logical bound reachable on ANY thread (a default ~2 MiB one, or a library
//! embedder's `Interp::new()`) without first overflowing the real host stack, the
//! non-tail re-entry grows the host stack on the heap on demand via `stacker` — the
//! bound stays a fixed *logical* depth (deterministic), only the host stack it needs
//! is supplied lazily.
//!
//! ## Environment & cells (§1)
//! [`Env`] is a chain of [`Frame`]s; a frame maps an [`Ident`] to a mutable cell
//! `Rc<RefCell<Slot>>`. A variable read walks the chain and loads the cell (unbound →
//! E300; cell still holding the [`Slot::Uninitialized`] sentinel → E321). `set!`
//! mutates an existing cell (unbound → E303). Closures capture the [`Env`] *handle*
//! (an `Rc` clone), so they share cells → lexical, shared-mutable capture. The
//! `Uninitialized` sentinel is a `Slot` variant, **not** a representable [`Value`].

use std::cell::{Cell as FlagCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::rc::Rc;

use crate::core::{CoreExpr, CoreKind, Formals, Ident, Intrinsic};
use crate::error::{
    RuntimeCode, RuntimeError, WarnCode, Warning, ESCAPE_CONTINUATION_INACTIVE_MESSAGE,
};
use crate::number::{self, AErr, CmpOp, Num};
use crate::reader::{parse_number_token, NumberParse, Span};
use crate::value::Value;

/// Default recursion bound for **non-tail** call depth (§4). Tail calls do not count
/// (they reuse the control frame). Exceeding this is a deterministic resource limit.
///
/// This is a purely **logical** cap, kept fixed so the same program faults at the same
/// depth on every platform regardless of host stack size (determinism is the product
/// identity, §4). The host stack needed to *reach* it is made available on demand by
/// `stacker` in [`Interp::eval`] — see the note there.
///
/// **wasm32 profile (R8).** On `wasm32` `stacker::maybe_grow` is a no-op — there is no
/// real host stack to grow (see [`Interp::eval`]) — so the only stack available to reach
/// the bound is the fixed wasm linear-memory stack (~1 MiB by default). At 10_000 the
/// native bound would overflow that and TRAP (a hard, blank crash) *before* the clean
/// `RecursionLimit` fault could fire. We therefore pin a smaller, deterministic bound on
/// `wasm32` so deep non-tail recursion yields the same clean `RecursionLimit` diagnostic
/// the native build gives — never a wasm trap. It is intentionally a *different* number
/// from native: the value is a host-resource ceiling, not part of the language contract,
/// and determinism is preserved *within each build profile* (every wasm run faults at the
/// same depth).
///
/// The value is set EMPIRICALLY, not by a per-frame estimate. The original `2_000` was
/// wrong: it sits ABOVE the actual wasm stack-overflow depth, so deep recursion trapped
/// instead of faulting cleanly (the R8 acceptance test in `wasm/verify.mjs` caught it).
/// Crucially the trap depth is NOT shape-independent — wrapper forms (`dynamic-wind`,
/// `call/cc`, `call-with-values`, HOFs) push extra *uncounted* host frames around each
/// counted `eval`, so they exhaust the wasm stack at a much lower counted depth than plain
/// non-tail recursion. Measured (default ~1 MiB stack): plain `(+ 1 (deep …))` traps near
/// counted-depth ~1.9k; a `dynamic-wind`+`call/cc` per level traps near ~0.5k. `512` sits
/// safely under the worst measured wrapper case, and `wasm/verify.mjs` probes those shapes
/// at huge depth to keep the margin honest. See LISPEX-RUNTIME.md §15.
#[cfg(not(target_arch = "wasm32"))]
pub const CALL_DEPTH_LIMIT: usize = 10_000;
/// wasm32 recursion bound — see [`CALL_DEPTH_LIMIT`] (native) for the rationale.
#[cfg(target_arch = "wasm32")]
pub const CALL_DEPTH_LIMIT: usize = 512;

/// `stacker` red zone: when fewer than this many bytes of host stack remain at a
/// non-tail re-entry, grow onto the heap before recursing further (see [`Interp::eval`]).
/// Native-only — `wasm32` does not use `stacker` (see [`Interp::eval`]).
#[cfg(not(target_arch = "wasm32"))]
const STACK_RED_ZONE: usize = 64 * 1024; // 64 KiB
/// Size of each fresh stack segment `stacker` allocates on the heap when it grows.
/// Native-only — see [`STACK_RED_ZONE`].
#[cfg(not(target_arch = "wasm32"))]
const STACK_GROW_SIZE: usize = 2 * 1024 * 1024; // 2 MiB

// ─────────────────────────────────────────────────────────────────────────────
// The evaluation signal (§1) and its single-/multi-value Outcome.
// ─────────────────────────────────────────────────────────────────────────────

/// The result of evaluating one expression (§1/§5): a single value, or 0/≥2 values.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// Exactly one value (the common case).
    One(Value),
    /// Zero or ≥2 values (a `values` outcome). Never holds exactly one — a single
    /// value normalizes to [`Outcome::One`] via [`into_outcome`].
    Many(Vec<Value>),
}

/// The threaded evaluation signal (§1). Propagated by value — never via `panic`.
#[derive(Debug)]
pub enum Eval {
    /// Normal completion.
    Ok(Outcome),
    /// A runtime fault (first error aborts, §8).
    Error(RuntimeError),
    /// An escape-continuation jump minted by invoking a `call/cc` `k` (§9). It unwinds
    /// outward (threaded by value — never a host unwind) until the owning `call/cc`
    /// frame, whose `tag` matches, catches it and returns `(values …)`; every other
    /// frame propagates it via the catch-all `other` arm.
    Escape { tag: u64, vals: Outcome },
    /// **Internal trampoline request** (§4) — a primitive (`call-with-values`/`apply`) asking
    /// the evaluator to perform `f`'s call in the CALLER'S TAIL position. It is NOT a
    /// user-visible outcome: it is produced only by a primitive that must hand off a
    /// tail call it cannot perform itself (a primitive runs *below* the trampoline, so
    /// its own `apply` would grow the host stack), and it is consumed (resolved into a
    /// real `Eval`) at exactly two sites: the `App` `Primitive` arm in
    /// [`Interp::eval_loop`] (a genuine tail loop) and the `Primitive` arm of
    /// [`Interp::apply`] (a bounded, non-tail resolution). It must never escape to
    /// `eval1`/`eval_discard`/`run_str`/a HOF; any `match` on [`Eval`] outside those two
    /// resolution sites treats it as `unreachable!` (an internal invariant), so a leak
    /// is a loud bug, not silent misbehaviour.
    TailApply { f: Value, args: Vec<Value> },
}

/// Zero values — the result of `set!`/`define`/false-branch `when`/`unless` (§0.3).
fn zero() -> Outcome {
    Outcome::Many(Vec::new())
}

/// Normalize a value list into an [`Outcome`], collapsing the single-value case to
/// [`Outcome::One`] so the "`Many` is 0 or ≥2" invariant holds.
fn into_outcome(mut vals: Vec<Value>) -> Outcome {
    if vals.len() == 1 {
        Outcome::One(vals.pop().unwrap())
    } else {
        Outcome::Many(vals)
    }
}

/// Truthiness (§7): only `#f` is false; everything else (incl. `()`, `0`, `""`,
/// vectors) is true.
fn is_truthy(v: &Value) -> bool {
    !matches!(v, Value::Bool(false))
}

/// Display name of an identifier, for diagnostics.
fn ident_name(id: &Ident) -> String {
    match id {
        Ident::User(n) => n.to_string(),
        Ident::Temp(k) => format!("#:t{k}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Environment: a chain of frames of mutable cells (§1).
// ─────────────────────────────────────────────────────────────────────────────

/// A mutable binding cell. Shared by `Rc` so closures capturing a frame observe one
/// another's `set!`s (shared-mutable lexical capture, §7).
type Cell = Rc<RefCell<Slot>>;

/// The contents of a cell: a value, or the `letrec`/internal-`define` sentinel that
/// is **not** a representable user [`Value`] (reading it → E321, §7).
#[derive(Debug)]
enum Slot {
    Value(Value),
    Uninitialized,
}

/// A lexical environment handle: a reference-counted frame chain. Cloning is an `Rc`
/// bump (closures capture by cloning this handle).
#[derive(Clone)]
pub struct Env(Rc<Frame>);

struct Frame {
    vars: RefCell<HashMap<Ident, Cell>>,
    parent: Option<Env>,
}

impl fmt::Debug for Env {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Shallow — never traverse the chain (it may be cyclic via captured closures).
        f.write_str("#<env>")
    }
}

impl Env {
    /// A fresh root (global) frame with no parent.
    fn root() -> Env {
        Env(Rc::new(Frame {
            vars: RefCell::new(HashMap::new()),
            parent: None,
        }))
    }

    /// A fresh child frame whose parent is `self`.
    fn child(&self) -> Env {
        Env(Rc::new(Frame {
            vars: RefCell::new(HashMap::new()),
            parent: Some(self.clone()),
        }))
    }

    /// Walk the chain for `id`, returning its cell (an `Rc` clone) if bound.
    fn lookup(&self, id: &Ident) -> Option<Cell> {
        let mut cur = self.clone();
        loop {
            if let Some(c) = cur.0.vars.borrow().get(id).cloned() {
                return Some(c);
            }
            cur = cur.0.parent.clone()?;
        }
    }

    /// Insert a fresh bound cell into THIS frame (shadowing any outer binding).
    fn bind_value(&self, id: Ident, v: Value) {
        self.0
            .vars
            .borrow_mut()
            .insert(id, Rc::new(RefCell::new(Slot::Value(v))));
    }

    /// Insert a fresh `Uninitialized` cell into THIS frame (letrec / internal define).
    fn bind_uninit(&self, id: Ident) {
        self.0
            .vars
            .borrow_mut()
            .insert(id, Rc::new(RefCell::new(Slot::Uninitialized)));
    }

    /// Assign into an existing cell in THIS frame (the letrec/internal-define "assign"
    /// step). No-op if absent (callers always pre-bind first).
    fn assign_local(&self, id: &Ident, v: Value) {
        if let Some(c) = self.0.vars.borrow().get(id) {
            *c.borrow_mut() = Slot::Value(v);
        }
    }

    /// `define` semantics (§7.8): **reassign the existing cell if present** in THIS
    /// frame (so early closures holding the cell and later lookups agree), else create
    /// one. At top level `self` is the global frame, giving the spec's "duplicate
    /// top-level `define` reassigns the global cell".
    fn define(&self, id: Ident, v: Value) {
        let mut vars = self.0.vars.borrow_mut();
        if let Some(c) = vars.get(&id) {
            *c.borrow_mut() = Slot::Value(v);
        } else {
            vars.insert(id, Rc::new(RefCell::new(Slot::Value(v))));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Closures, primitives, and the (R6-reserved) continuation value.
// ─────────────────────────────────────────────────────────────────────────────

/// A user closure (§7): formals (incl. an optional dotted rest), a body, and the
/// captured lexical environment. Stored behind `Rc` in [`Value::Closure`] so calling
/// is cheap; the body is `Rc` so a tail-call only deep-clones it (not the whole value).
pub struct ClosureData {
    pub formals: Formals,
    pub body: Rc<CoreExpr>,
    pub env: Env,
}

impl fmt::Debug for ClosureData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("#<closure>")
    }
}

/// A primitive's Rust implementation. Receives the interpreter (so R5/R6 prims such
/// as `apply`/`map`/`call-with-values` can re-enter [`Interp::eval`]), the already
/// evaluated arguments, and the call-site span (for fault spans, §8).
pub type PrimFn = fn(&mut Interp, &[Value], Span) -> Eval;

/// A built-in procedure value. R4 installs the exact numeric tower + list basics (see
/// [`Interp::install_builtins`]) plus the four hidden intrinsics; R5 adds the rest of
/// the stdlib + friendly aliases.
#[derive(Clone)]
pub struct Primitive {
    pub name: Rc<str>,
    pub func: PrimFn,
}

impl Primitive {
    /// `eqv?`/`eq?` identity on procedures = function-pointer identity (§6).
    pub fn ptr_eq(&self, other: &Primitive) -> bool {
        self.func as usize == other.func as usize
    }
}

impl fmt::Debug for Primitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#<primitive {}>", self.name)
    }
}

/// An escape continuation (one-shot, upward) minted by `call/cc` (§9). The first
/// invocation consumes it before emitting an [`Eval::Escape`]. Any later invocation,
/// including from a `dynamic-wind` `after` that runs during that escape, faults E340;
/// invocation after the owning extent has ended faults E340 as well.
pub struct Continuation {
    /// The unique tag the matching [`Eval::Escape`] carries (and that the owning
    /// `call/cc` frame keeps in [`Interp`]'s live set while on the stack).
    pub tag: u64,
    /// `false` until the first invocation. `replace(true)` is the atomic semantic gate
    /// for this single-threaded interpreter: consumption happens before unwinding.
    used: FlagCell<bool>,
}

impl fmt::Debug for Continuation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("#<continuation>")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The interpreter.
// ─────────────────────────────────────────────────────────────────────────────

/// The evaluator state: the global frame (holding the bootstrap primitives), the
/// source file name (for fault spans), and the recursion-depth bookkeeping.
pub struct Interp {
    global: Env,
    file: String,
    depth: usize,
    limit: usize,
    /// Deprecation warnings (W3xx) accumulated during evaluation, in occurrence order
    /// (§10). Drained by the CLI / inspected by tests; never aborts a run.
    warnings: Vec<Warning>,
    /// Call sites that have already warned, so a deprecated alias inside a loop warns
    /// once per source location rather than flooding (deterministic).
    warned: HashSet<(WarnCode, usize, usize)>,
    /// Accumulated program output from `display`/`write`/`newline`/`println` (§11).
    /// Buffered on the interpreter (rather than written straight to a host stream) so
    /// it is testable and the effect is a plain value — a backend-portable I/O model. The
    /// CLI flushes it to stdout after each top-level form.
    output: String,
    /// **R6 (§9):** monotonic source of FRESH escape-continuation tags. Each `call/cc`
    /// invocation mints `next_tag` then increments it, so every escape continuation has
    /// a globally unique tag for the lifetime of the interpreter (never reused — so a
    /// stale `k` can never be mistaken for a live one).
    next_tag: u64,
    /// **R6 (§9):** the tags whose owning `call/cc` frame is CURRENTLY on the stack
    /// (i.e. within its dynamic extent). A tag is inserted when its `call/cc` frame is
    /// entered and removed when that frame returns (normally, or as a signal unwinds
    /// through it). An escape continuation is valid iff its tag is in this set;
    /// invoking one whose tag is absent → `E340` (used outside its extent), the
    /// deterministic stand-in for the multi-shot re-entry that is v2. Because a tag is
    /// live exactly while its frame is on the stack, a live escape's [`Eval::Escape`]
    /// is ALWAYS caught by its owning frame (never reaches the top level).
    live_tags: HashSet<u64>,
    /// **v1.2:** the current exception-handler stack (§8). `with-exception-handler`
    /// pushes a handler for the dynamic extent of its thunk; the top of the stack is
    /// the current handler. Managed by a base-length/truncate discipline so it never
    /// leaks on an escape/error unwind, and cleared between top-level forms.
    handlers: Vec<Value>,
    /// Contract-only logical form/primitive accounting. Absent in every normal
    /// Lispex interpreter, so product behavior retains its existing recursion
    /// semantics and cost model.
    #[cfg(feature = "scored-native-contract")]
    contract_observer: Option<Box<dyn crate::vouch_native::eval_observer::EvalObserver>>,
    #[cfg(feature = "scored-native-contract")]
    contract_decisions_created: usize,
}

impl Default for Interp {
    fn default() -> Self {
        Interp::new()
    }
}

/// A whole-program error: either a static (reader/normalizer) diagnostic or a runtime
/// fault. Returned by [`Interp::run_str`].
#[derive(Debug)]
pub enum RunError {
    Static(crate::reader::Diagnostic),
    Runtime(RuntimeError),
}

impl Interp {
    /// A fresh interpreter with the bootstrap primitives installed and the default
    /// recursion bound.
    pub fn new() -> Interp {
        Interp::with_limit(CALL_DEPTH_LIMIT)
    }

    /// A fresh interpreter with a custom recursion bound (the limit is configurable
    /// per §4; tests use a small one to exercise the bound without a deep run).
    pub fn with_limit(limit: usize) -> Interp {
        let it = Interp {
            global: Env::root(),
            file: "<input>".to_string(),
            depth: 0,
            limit,
            warnings: Vec::new(),
            warned: HashSet::new(),
            output: String::new(),
            next_tag: 0,
            live_tags: HashSet::new(),
            handlers: Vec::new(),
            #[cfg(feature = "scored-native-contract")]
            contract_observer: None,
            #[cfg(feature = "scored-native-contract")]
            contract_decisions_created: 0,
        };
        it.install_builtins();
        it
    }

    /// Set the source-file name used in fault spans.
    pub fn set_file(&mut self, file: &str) {
        self.file = file.to_string();
    }

    /// Bind a host-provided value into the global frame before evaluation.
    ///
    /// The full Lispex language does not reserve these names. Profile commands use
    /// this hook to install their distinguished immutable input binding without
    /// injecting source or Core forms that would perturb source/core/graph hashes.
    pub fn define_global(&self, name: &str, value: Value) {
        self.global.define(Ident::User(Rc::from(name)), value);
    }

    /// Enable the dormant SCORED logical budget lane for this interpreter.
    #[cfg(feature = "scored-native-contract")]
    pub fn set_contract_observer(
        &mut self,
        observer: Box<dyn crate::vouch_native::eval_observer::EvalObserver>,
    ) {
        self.contract_observer = Some(observer);
        self.install_contract_decisions();
    }

    /// Reset the dynamic decision-constructor count for one checked-profile
    /// top-level root.  The contract driver uses the post-root count to ensure
    /// exactly one decision was created only when it is the complete final
    /// observable value.
    #[cfg(feature = "scored-native-contract")]
    pub fn begin_contract_root(&mut self) {
        self.contract_decisions_created = 0;
    }

    #[cfg(feature = "scored-native-contract")]
    pub fn contract_decisions_created(&self) -> usize {
        self.contract_decisions_created
    }

    #[cfg(feature = "scored-native-contract")]
    fn install_contract_decisions(&self) {
        for (name, func) in [
            (
                "decision-approve",
                prim_decision_approve as crate::eval::PrimFn,
            ),
            ("decision-deny", prim_decision_deny),
            ("decision-review", prim_decision_review),
            ("decision-invalid-input", prim_decision_invalid_input),
        ] {
            self.global.define(
                Ident::User(Rc::from(name)),
                Value::Primitive(Primitive {
                    name: Rc::from(name),
                    func,
                }),
            );
        }
    }

    // ── deprecation warnings (W3xx, §10) ─────────────────────────────────────────

    /// Record a deprecation warning at `span` (deduplicated per call site, so a loop
    /// warns once). Used by the deprecated stdlib aliases (`%`, `list-first`,
    /// `list-rest`); never aborts the run.
    fn warn(&mut self, code: WarnCode, span: Span, message: impl Into<String>) {
        if self.warned.insert((code, span.line, span.col)) {
            self.warnings.push(Warning {
                code,
                file: self.file.clone(),
                span,
                message: message.into(),
            });
        }
    }

    /// The deprecation warnings emitted so far (occurrence order).
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }

    /// Drain the accumulated deprecation warnings (the CLI prints them per top-level
    /// form; tests assert on them).
    pub fn take_warnings(&mut self) -> Vec<Warning> {
        std::mem::take(&mut self.warnings)
    }

    /// The program output buffered by `display`/`write`/`newline`/`println` so far (§11).
    pub fn output(&self) -> &str {
        &self.output
    }

    /// Drain the buffered program output (the CLI flushes it to stdout per top-level
    /// form; tests assert on it).
    pub fn take_output(&mut self) -> String {
        std::mem::take(&mut self.output)
    }

    /// Build a runtime fault carrying the current file.
    fn rt(&self, code: RuntimeCode, span: Span, message: impl Into<String>) -> RuntimeError {
        RuntimeError {
            code,
            file: self.file.clone(),
            span,
            message: message.into(),
            irritants: Vec::new(),
            condition: None,
            dispatched: false,
            continuable: false,
        }
    }

    // ── public driver ───────────────────────────────────────────────────────────

    /// Evaluate ONE top-level form in the global env. Resets the recursion counter
    /// (the bound is per top-level form; §8 "first error aborts").
    pub fn eval_toplevel(&mut self, expr: CoreExpr) -> Eval {
        self.depth = 0;
        // No `call/cc` frame survives a top-level form (each frame removes its tag as
        // it returns/unwinds), so this set is already empty; clear it for determinism
        // in case a future driver ever re-enters mid-form.
        self.live_tags.clear();
        // No exception handler survives a top-level form (each `with-exception-handler`
        // frame truncates the stack as it returns/unwinds); clear for determinism.
        self.handlers.clear();
        let g = self.global.clone();
        self.eval(expr, g)
    }

    /// Read → normalize → evaluate a whole source string, returning the [`Outcome`] of
    /// the LAST top-level form (empty program → zero values), or the first error.
    pub fn run_str(&mut self, src: &str, file: &str) -> Result<Outcome, RunError> {
        self.set_file(file);
        let prog = crate::reader::read_program(src, file).map_err(RunError::Static)?;
        let core =
            crate::normalize::normalize_program(&prog.datums, file).map_err(RunError::Static)?;
        let mut last = zero();
        for expr in core {
            match self.eval_toplevel(expr) {
                Eval::Ok(o) => last = o,
                Eval::Error(e) => return Err(RunError::Runtime(e)),
                // Defensive (§9): a *live* escape is always caught by its owning
                // `call/cc` frame (the tag is live iff that frame is on the stack), and
                // invoking a stale `k` already faults E340 at the call site — so no
                // escape should reach here. If one ever does, it was used outside any
                // owning frame → E340.
                Eval::Escape { .. } => {
                    return Err(RunError::Runtime(self.rt(
                        RuntimeCode::E340,
                        Span { line: 1, col: 1 },
                        "escape continuation used outside its dynamic extent",
                    )));
                }
                // `TailApply` is an INTERNAL trampoline hand-off (§4): it is resolved at
                // the App `Primitive` arm / `Interp::apply` before any outcome flows out
                // of `eval`/`eval_toplevel`, so it can never reach a top-level result.
                // Reaching here would be an interpreter invariant violation.
                Eval::TailApply { .. } => {
                    unreachable!("Eval::TailApply must be resolved inside the trampoline")
                }
            }
        }
        Ok(last)
    }

    // ── recursion-bounded entry + the explicit-control loop ──────────────────────

    /// Evaluate `expr` in `env`, accounting one unit of **non-tail** recursion depth.
    /// All non-tail sub-evaluations funnel through here (via [`Interp::eval1`] /
    /// [`Interp::eval_discard`]), so the bound is enforced exactly where the host
    /// stack would otherwise grow. Tail steps loop inside [`Interp::eval_loop`] and
    /// never call this, so they cost no depth.
    fn eval(&mut self, expr: CoreExpr, env: Env) -> Eval {
        self.depth += 1;
        if self.depth > self.limit {
            let span = expr.span;
            self.depth -= 1;
            return Eval::Error(self.rt(
                RuntimeCode::RecursionLimit,
                span,
                format!("recursion bound ({}) exceeded", self.limit),
            ));
        }
        // This is the ONLY host-stack-growing path: every non-tail sub-evaluation
        // (operands, the `if` test, let/letrec/set!/define RHSs) funnels through here
        // via eval1/eval_discard, whereas the tail loop in `eval_loop` reuses its frame
        // and never grows. `stacker::maybe_grow` grows the host stack on the heap on
        // demand, so the *logical* `CALL_DEPTH_LIMIT` is reachable on ANY thread — a
        // default ~2 MiB one, or a library embedder's `Interp::new()` — WITHOUT
        // aborting via a host stack overflow (the §4 guarantee: exceeding the bound is a
        // clean RecursionLimit, never a host overflow). The grow is a host-resource
        // detail only: it does NOT move the bound, so the same program still faults at
        // the same logical depth everywhere (determinism preserved).
        //
        // R8/wasm: `stacker` CANNOT grow the stack on wasm32 (there is no real stack to
        // grow), so the grow would be a no-op there. We therefore drop the `stacker`
        // dependency entirely on `wasm32` (the crate is `cfg`-gated out in Cargo.toml —
        // it also pulls a host-only C build chain via `psm`/`cc` that wasm doesn't need)
        // and call `eval_loop` directly. Determinism is preserved because the smaller
        // wasm `CALL_DEPTH_LIMIT` (see its def above) keeps the bound reachable WITHIN
        // the fixed ~1 MiB wasm stack: a deep non-tail recursion faults with a clean
        // RecursionLimit instead of overflowing and trapping. Native + library embeddings
        // keep the on-demand heap stack growth and the 10_000 bound.
        let out = self.eval_step(expr, env);
        self.depth -= 1;
        self.settle(out)
    }

    /// The exception-dispatch boundary (v1.2, §8): a fresh CATCHABLE fault returned by a
    /// sub-evaluation OR an application is offered to the CURRENT handler IN PLACE
    /// (R7RS non-unwinding —
    /// the handler runs in the raise's dynamic extent, before any enclosing
    /// `dynamic-wind` `after`). The current handler is suppressed while it runs so its
    /// OWN raises reach the outer handler; a `raise-continuable` handler's return value
    /// becomes the raising call's value; a non-continuable handler that returns is the
    /// `E332` secondary, offered to the OUTER handler. With no handler the fault is
    /// marked dispatched and propagates to the top. `guard` installs its escape
    /// continuation as the handler, so a caught fault reaches the `guard` frame as an
    /// `Eval::Escape`.
    fn settle(&mut self, r: Eval) -> Eval {
        let re = match r {
            Eval::Error(re) if !re.dispatched && re.is_catchable() => re,
            other => return other,
        };
        let Some(handler) = self.handlers.last().cloned() else {
            let mut re = re;
            re.dispatched = true; // nobody caught it — an outer boundary won't re-offer
            return Eval::Error(re);
        };
        let continuable = re.continuable;
        let span = re.span;
        let cond = re.condition_value();
        self.handlers.pop(); // suppress the current handler while it runs
        let hr = self.apply(&handler, vec![cond], span);
        let out = match hr {
            Eval::Ok(o) => {
                if continuable {
                    Eval::Ok(o)
                } else {
                    // A non-continuable handler returned → the E332 secondary, offered to
                    // the OUTER handler (this handler is still suppressed).
                    let e = self.rt(
                        RuntimeCode::E332,
                        span,
                        "exception handler returned from a non-continuable raise",
                    );
                    self.settle(Eval::Error(e))
                }
            }
            // The handler escaped (`guard`/`call/cc`) or raised again (dispatched at its
            // own boundary) → propagate.
            sig => sig,
        };
        self.handlers.push(handler); // restore for stack balance
        out
    }

    /// Run one non-tail sub-evaluation, growing the host stack on demand on native
    /// targets. On `wasm32` this is a direct call (no `stacker` — see [`Interp::eval`]).
    #[cfg(not(target_arch = "wasm32"))]
    fn eval_step(&mut self, expr: CoreExpr, env: Env) -> Eval {
        let me = &mut *self;
        stacker::maybe_grow(STACK_RED_ZONE, STACK_GROW_SIZE, move || {
            me.eval_loop(expr, env)
        })
    }

    /// wasm32 sub-evaluation — no `stacker` (see [`Interp::eval`]).
    #[cfg(target_arch = "wasm32")]
    fn eval_step(&mut self, expr: CoreExpr, env: Env) -> Eval {
        self.eval_loop(expr, env)
    }

    /// The trampoline: a `while`-style loop over the current `(expr, env)`. Tail
    /// positions rebind `expr`/`env` and `continue` (no host-stack growth); everything
    /// else returns or delegates to a bounded sub-evaluation.
    fn eval_loop(&mut self, mut expr: CoreExpr, mut env: Env) -> Eval {
        // Retaining one guard per trampoline iteration is intentional. A tail
        // transition may reuse the host frame, but it must not erase the logical
        // evaluator frame counted by the frozen contract.
        #[cfg(feature = "scored-native-contract")]
        let mut contract_frames = Vec::new();
        loop {
            let span = expr.span;
            #[cfg(feature = "scored-native-contract")]
            if let Some(observer) = self.contract_observer.as_mut() {
                match observer.enter_form() {
                    Ok(frame) => contract_frames.push(frame),
                    Err(fault) => {
                        return Eval::Error(self.rt(
                            RuntimeCode::ReferenceBudgetExhausted,
                            span,
                            format!(
                                "reference evaluator {:?} budget exhausted after {} steps at depth {}",
                                fault.kind, fault.steps_used, fault.depth
                            ),
                        ));
                    }
                }
            }
            match expr.kind {
                // ── self-evaluating / atoms ──────────────────────────────────────
                CoreKind::Quote(v) => return Eval::Ok(Outcome::One(v)),

                // A hidden intrinsic node resolves DIRECTLY to its primitive value,
                // bypassing the lexical env (so a user-bound `cons`/`eqv?`/… cannot
                // change a desugared form's meaning — §7.1 hygiene).
                CoreKind::Intrinsic(i) => return Eval::Ok(Outcome::One(intrinsic_value(i))),

                CoreKind::Var(id) => {
                    return match env.lookup(&id) {
                        None => Eval::Error(self.rt(
                            RuntimeCode::E300,
                            span,
                            format!("unbound variable: {}", ident_name(&id)),
                        )),
                        Some(cell) => match &*cell.borrow() {
                            Slot::Value(v) => Eval::Ok(Outcome::One(v.clone())),
                            Slot::Uninitialized => Eval::Error(self.rt(
                                RuntimeCode::E321,
                                span,
                                format!(
                                    "variable used before its letrec initialization: {}",
                                    ident_name(&id)
                                ),
                            )),
                        },
                    };
                }

                CoreKind::Lambda { formals, body } => {
                    let c = ClosureData {
                        formals,
                        body: Rc::from(body),
                        env: env.clone(),
                    };
                    return Eval::Ok(Outcome::One(Value::Closure(Rc::new(c))));
                }

                // ── multiple values (§5) ─────────────────────────────────────────
                CoreKind::Values(es) => {
                    let mut vals = Vec::with_capacity(es.len());
                    for e in es {
                        match self.eval1(e, &env) {
                            Ok(v) => vals.push(v),
                            Err(sig) => return sig,
                        }
                    }
                    return Eval::Ok(into_outcome(vals));
                }

                // ── if: 3-arm, only #f is false; taken branch is a TAIL position ──
                CoreKind::If(t, a, b) => {
                    let cond = match self.eval1(*t, &env) {
                        Ok(v) => v,
                        Err(sig) => return sig,
                    };
                    // SCORED-MUTATION-SITE M05: swap only the source evaluator's
                    // selected `if` branch.
                    expr = match (is_truthy(&cond), cfg!(scored_mutant = "M05")) {
                        (true, false) | (false, true) => *a,
                        (false, false) | (true, true) => *b,
                    };
                    continue;
                }

                // ── set! / define: both yield zero values (§7) ───────────────────
                CoreKind::Set { target, value } => {
                    let v = match self.eval1(*value, &env) {
                        Ok(v) => v,
                        Err(sig) => return sig,
                    };
                    return match env.lookup(&target) {
                        Some(cell) => {
                            *cell.borrow_mut() = Slot::Value(v);
                            Eval::Ok(zero())
                        }
                        None => Eval::Error(self.rt(
                            RuntimeCode::E303,
                            span,
                            format!("set! on unbound variable: {}", ident_name(&target)),
                        )),
                    };
                }

                CoreKind::Define { name, value } => {
                    let v = match self.eval1(*value, &env) {
                        Ok(v) => v,
                        Err(sig) => return sig,
                    };
                    env.define(name, v);
                    return Eval::Ok(zero());
                }

                // ── let: parallel — inits in the ENCLOSING env, then bind (§3) ────
                CoreKind::Let { bindings, body } => {
                    let mut evaled = Vec::with_capacity(bindings.len());
                    for b in bindings {
                        match self.eval1(b.init, &env) {
                            Ok(v) => evaled.push((b.name, v)),
                            Err(sig) => return sig,
                        }
                    }
                    let child = env.child();
                    for (name, v) in evaled {
                        child.bind_value(name, v);
                    }
                    env = child;
                    expr = *body;
                    continue;
                }

                // ── letrec: allocate sentinels, eval L→R in the all-visible env,
                //    assign (§7). A forward read of a not-yet-assigned cell → E321. ─
                CoreKind::Letrec { bindings, body } => {
                    let child = env.child();
                    for b in &bindings {
                        child.bind_uninit(b.name.clone());
                    }
                    for b in bindings {
                        match self.eval1(b.init, &child) {
                            Ok(v) => child.assign_local(&b.name, v),
                            Err(sig) => return sig,
                        }
                    }
                    env = child;
                    expr = *body;
                    continue;
                }

                // ── guard (v1.2, §8): install guard's own escape continuation as the
                //    current handler so a `raise` in the body comes HERE (not an outer
                //    handler) and unwinds to this frame as an `Eval::Escape`; an
                //    INTRINSIC fault instead unwinds here as a catchable `Eval::Error`.
                //    Either way bind `var`, run the cond-style clauses, and reraise the
                //    condition when none match and there is no `else`. Non-tail. ───────
                CoreKind::Guard {
                    var,
                    clauses,
                    else_body,
                    body,
                } => {
                    let tag = self.next_tag;
                    self.next_tag += 1;
                    self.live_tags.insert(tag);
                    let base = self.handlers.len();
                    self.handlers.push(Value::Cont(Rc::new(Continuation {
                        tag,
                        used: FlagCell::new(false),
                    })));
                    let r = self.eval(*body, env.clone());
                    self.handlers.truncate(base);
                    self.live_tags.remove(&tag);
                    // A fault inside the body was dispatched to our installed escape
                    // continuation by `settle` (in place, at the fault site), arriving
                    // here as an escape to OUR tag carrying the condition. Anything else —
                    // a normal value, a non-catchable fault (the recursion bound), or some
                    // OTHER frame's escape — passes straight through.
                    let cond = match r {
                        Eval::Escape { tag: t, vals } if t == tag => match vals {
                            Outcome::One(v) => v,
                            Outcome::Many(mut vs) => vs.drain(..).next().unwrap_or(Value::Nil),
                        },
                        other => return other,
                    };
                    let child = env.child();
                    child.bind_value(var, cond.clone());
                    let mut chosen: Option<CoreExpr> = None;
                    for c in clauses {
                        match self.eval1(c.test, &child) {
                            Ok(t) => {
                                if is_truthy(&t) {
                                    chosen = Some(c.body);
                                    break;
                                }
                            }
                            Err(sig) => return sig,
                        }
                    }
                    return match chosen {
                        Some(b) => self.eval(b, child),
                        None => match else_body {
                            Some(eb) => self.eval(*eb, child),
                            // No clause matched and no `else`: reraise the condition. Our
                            // handler is already popped, so `settle` at the enclosing
                            // boundary offers it to the OUTER handler (if any); uncaught it
                            // renders as E331 carrying the reraised object.
                            None => {
                                let mut re = self.rt(
                                    RuntimeCode::E331,
                                    span,
                                    format!("raised: {}", cond.write_repr()),
                                );
                                re.condition = Some(Box::new(cond));
                                Eval::Error(re)
                            }
                        },
                    };
                }

                // ── begin / body: leading internal defines → letrec* (§7) ─────────
                CoreKind::Begin(es) => match self.enter_begin(es, &mut env) {
                    BeginStep::Tail(last) => {
                        expr = last;
                        continue;
                    }
                    BeginStep::Done(out) => return out,
                },

                // ── application: operator first, then operands L→R (§3); apply ────
                CoreKind::App { op, args } => {
                    // `f`/`argv` are MUTABLE: a primitive may hand back an
                    // `Eval::TailApply` (`call-with-values` or `apply`, asking the
                    // trampoline to apply its target in THIS tail slot — §4), and the
                    // inner `loop` below re-resolves them in place. A `TailApply` whose
                    // target is itself a primitive returning another `TailApply` keeps
                    // looping there (bounded only by real work, never recursion).
                    let mut f = match self.eval1(*op, &env) {
                        Ok(v) => v,
                        Err(sig) => return sig,
                    };
                    let mut argv = Vec::with_capacity(args.len());
                    for a in args {
                        match self.eval1(a, &env) {
                            Ok(v) => argv.push(v),
                            Err(sig) => return sig,
                        }
                    }
                    #[cfg(feature = "scored-native-contract")]
                    if self.contract_observer.is_some()
                        && !matches!(f, Value::Primitive(_))
                        && argv.iter().any(|value| matches!(value, Value::Decision(_)))
                    {
                        return Eval::Error(self.rt(
                            RuntimeCode::ProfileEscape,
                            span,
                            "decision value reached an application operand boundary",
                        ));
                    }
                    // Resolve the call in TAIL position, looping to resolve any
                    // `TailApply` hand-off so a `call-with-values`-driven self loop reuses
                    // this control frame instead of growing the host stack (the P0 fix).
                    loop {
                        match f {
                            // Closure call in TAIL position: bind a fresh frame and LOOP
                            // the OUTER trampoline — reuse this control frame instead of
                            // recursing (proper TCO).
                            Value::Closure(c) => {
                                let new_env = match self.bind_call(&c, argv, span) {
                                    Ok(e) => e,
                                    Err(sig) => return sig,
                                };
                                env = new_env;
                                expr = (*c.body).clone();
                                break; // re-enter the outer `loop` with the new (expr, env)
                            }
                            Value::Primitive(p) => {
                                #[cfg(feature = "scored-native-contract")]
                                if let Some(observer) = self.contract_observer.as_mut() {
                                    if let Err(fault) = observer.primitive_call() {
                                        return Eval::Error(self.rt(
                                            RuntimeCode::ReferenceBudgetExhausted,
                                            span,
                                            format!(
                                                "reference evaluator {:?} budget exhausted after {} steps at depth {}",
                                                fault.kind, fault.steps_used, fault.depth
                                            ),
                                        ));
                                    }
                                }
                                #[cfg(feature = "scored-native-contract")]
                                if argv.iter().any(|value| matches!(value, Value::Decision(_))) {
                                    return Eval::Error(self.rt(
                                        RuntimeCode::ProfileEscape,
                                        span,
                                        "decision value reached a primitive operand boundary",
                                    ));
                                }
                                match (p.func)(self, &argv, span) {
                                    // A tail-apply hand-off: re-resolve `f`/`args` in THIS
                                    // tail slot (so the consumer of a tail `call-with-values`
                                    // gets proper TCO — the P0 fix).
                                    Eval::TailApply { f: nf, args: nargs } => {
                                        f = nf;
                                        argv = nargs;
                                        continue; // resolve the new target in the inner loop
                                    }
                                    done => return done,
                                }
                            }
                            // The first invocation of a live escape continuation consumes
                            // it before minting `Eval::Escape`; reused or stale → E340.
                            Value::Cont(c) => return self.invoke_cont(&c, argv, span),
                            other => {
                                return Eval::Error(self.rt(
                                    RuntimeCode::E301,
                                    span,
                                    format!(
                                        "attempt to call a non-procedure: {}",
                                        other.write_repr()
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    /// Evaluate a `begin`/body sequence. Leading contiguous internal `define`s form a
    /// `letrec*` scope: a fresh child frame is pushed (rebinding `*env`), the defined
    /// names are pre-bound to the `Uninitialized` sentinel, then their inits are
    /// evaluated and assigned **sequentially** (a forward read of a not-yet-assigned
    /// name → E321). The remaining exprs run L→R with the last in tail position.
    fn enter_begin(&mut self, mut es: Vec<CoreExpr>, env: &mut Env) -> BeginStep {
        let n_defs = es
            .iter()
            .take_while(|e| matches!(e.kind, CoreKind::Define { .. }))
            .count();
        if n_defs > 0 {
            let child = env.child();
            let rest = es.split_off(n_defs); // `es` now holds only the leading defines
            for e in &es {
                if let CoreKind::Define { name, .. } = &e.kind {
                    child.bind_uninit(name.clone());
                }
            }
            for e in es {
                if let CoreKind::Define { name, value } = e.kind {
                    match self.eval1(*value, &child) {
                        Ok(v) => child.assign_local(&name, v),
                        Err(sig) => return BeginStep::Done(sig),
                    }
                }
            }
            *env = child;
            es = rest;
            if es.is_empty() {
                // A body of only defines (degenerate) → zero values.
                return BeginStep::Done(Eval::Ok(zero()));
            }
        }
        // Non-final exprs run in a discard context (any arity OK, §5); last is tail.
        let last = es.pop().expect("begin has at least one expression");
        for e in es {
            if let Err(sig) = self.eval_discard(e, env) {
                return BeginStep::Done(sig);
            }
        }
        BeginStep::Tail(last)
    }

    /// Bind a call's arguments into a fresh child of the closure's captured env,
    /// collecting any dotted rest into a fresh proper list. Arity mismatch → E302.
    fn bind_call(&self, c: &Rc<ClosureData>, args: Vec<Value>, span: Span) -> Result<Env, Eval> {
        let n_fixed = c.formals.fixed.len();
        let env = c.env.child();
        match &c.formals.rest {
            None => {
                if args.len() != n_fixed {
                    return Err(Eval::Error(self.rt(
                        RuntimeCode::E302,
                        span,
                        format!(
                            "arity mismatch: expected {} argument(s), got {}",
                            n_fixed,
                            args.len()
                        ),
                    )));
                }
                for (id, v) in c.formals.fixed.iter().zip(args) {
                    env.bind_value(id.clone(), v);
                }
            }
            Some(rest_id) => {
                if args.len() < n_fixed {
                    return Err(Eval::Error(self.rt(
                        RuntimeCode::E302,
                        span,
                        format!(
                            "arity mismatch: expected at least {} argument(s), got {}",
                            n_fixed,
                            args.len()
                        ),
                    )));
                }
                let mut it = args.into_iter();
                for id in &c.formals.fixed {
                    env.bind_value(id.clone(), it.next().unwrap());
                }
                let rest_list = Value::list(it.collect::<Vec<_>>().into_iter());
                env.bind_value(rest_id.clone(), rest_list);
            }
        }
        Ok(env)
    }

    // ── bounded sub-evaluation in the two value contexts (§5) ─────────────────────

    /// Single-value context (call operand, `if` test, `let`/`letrec`/`set!`/`define`
    /// RHS, a `values` argument): exactly one value unwraps; 0 or ≥2 → E320. Returns
    /// the value, or the propagating signal to `return`.
    fn eval1(&mut self, expr: CoreExpr, env: &Env) -> Result<Value, Eval> {
        let span = expr.span;
        match self.eval(expr, env.clone()) {
            Eval::Ok(Outcome::One(v)) => Ok(v),
            Eval::Ok(Outcome::Many(mut vs)) if vs.len() == 1 => Ok(vs.pop().unwrap()),
            Eval::Ok(Outcome::Many(_)) => Err(Eval::Error(self.rt(
                RuntimeCode::E320,
                span,
                "a single value is required here, but the expression produced zero or multiple values",
            ))),
            // An internal `TailApply` is resolved inside the trampoline and never flows
            // out of `eval`; reaching here would break the §4 invariant.
            Eval::TailApply { .. } => unreachable!("eval never yields Eval::TailApply"),
            other => Err(other), // Error / Escape: propagate
        }
    }

    /// Discard context (non-final body/`begin` expr): any arity is accepted (§5).
    fn eval_discard(&mut self, expr: CoreExpr, env: &Env) -> Result<(), Eval> {
        match self.eval(expr, env.clone()) {
            Eval::Ok(_) => Ok(()),
            Eval::TailApply { .. } => unreachable!("eval never yields Eval::TailApply"),
            other => Err(other), // Error / Escape: propagate
        }
    }

    // ── ★ HOF apply capability (§1 of the R5 task) ────────────────────────────────

    /// **Apply a *value* procedure to already-evaluated arguments**, reusing the
    /// evaluator's own call machinery and threading the [`Eval`] signal — the one new
    /// mechanism the R5 higher-order procedures (`map`/`filter`/`reduce`) need.
    ///
    /// A primitive's R3 ABI gives it `&mut Interp`, so a builtin can call this to invoke
    /// an arbitrary procedure value the user passed in:
    /// - a [`Value::Closure`] gets a fresh frame via [`Interp::bind_call`] (arity →
    ///   E302, dotted rest collected) and its body is evaluated through the bounded,
    ///   stack-growing [`Interp::eval`] (this is a *non-tail* call, so it correctly
    ///   counts against the recursion bound);
    /// - a [`Value::Primitive`] is called directly;
    /// - anything else → E301 (apply non-procedure), exactly like a source-level call.
    ///
    /// An `Eval::Error`/`Eval::Escape` returned by the applied procedure is returned
    /// as-is, so it propagates straight out of the host HOF (no host control-flow
    /// tricks — the same by-value threading the rest of the evaluator uses, which is
    /// what keeps it backend-portable).
    pub fn apply(&mut self, f: &Value, args: Vec<Value>, span: Span) -> Eval {
        // Dispatch boundary (v1.2, §8). A CATCHABLE fault born right HERE — a closure
        // arity mismatch, a primitive fault, a non-procedure call, a stale continuation —
        // never crosses an `eval` boundary, so the `eval`-level [`Interp::settle`] would
        // miss it: a caller that is a stack manager (`with-exception-handler` truncating
        // its handler, `dynamic-wind` running its `after`) would clean up FIRST and the
        // fault would settle too late (wrong handler / wrong `dynamic-wind` order). So we
        // settle at the fault site, before returning to any such caller. `settle` no-ops
        // on anything already dispatched, escaping, or non-catchable, so wrapping every
        // apply is idempotent with the `eval`-boundary settle (a closure body has already
        // been settled by its own `eval`, and comes back as Ok / Escape / dispatched).
        let out = self.apply_inner(f, args, span);
        self.settle(out)
    }

    fn apply_inner(&mut self, f: &Value, args: Vec<Value>, span: Span) -> Eval {
        #[cfg(feature = "scored-native-contract")]
        if self.contract_observer.is_some()
            && !matches!(f, Value::Primitive(_))
            && args.iter().any(|value| matches!(value, Value::Decision(_)))
        {
            return Eval::Error(self.rt(
                RuntimeCode::ProfileEscape,
                span,
                "decision value reached an application operand boundary",
            ));
        }
        match f {
            Value::Closure(c) => {
                let new_env = match self.bind_call(c, args, span) {
                    Ok(e) => e,
                    Err(sig) => return sig,
                };
                self.eval((*c.body).clone(), new_env)
            }
            // A primitive may return an `Eval::TailApply` (`call-with-values` or
            // `apply`, handing off the call). On the HOST apply path
            // there is no caller tail slot to forward it into, so we RESOLVE it here.
            // This resolution is bounded (a plain `self.apply` re-entry counts against
            // the recursion limit like any non-tail call) — host `apply` is already a
            // non-tail context, so we do not need TCO here, only to ensure a `TailApply`
            // never leaks out of `apply` to a HOF / `eval1` / `run_str`.
            Value::Primitive(p) => {
                #[cfg(feature = "scored-native-contract")]
                if let Some(observer) = self.contract_observer.as_mut() {
                    if let Err(fault) = observer.primitive_call() {
                        return Eval::Error(self.rt(
                            RuntimeCode::ReferenceBudgetExhausted,
                            span,
                            format!(
                                "reference evaluator {:?} budget exhausted after {} steps at depth {}",
                                fault.kind, fault.steps_used, fault.depth
                            ),
                        ));
                    }
                }
                #[cfg(feature = "scored-native-contract")]
                if args.iter().any(|value| matches!(value, Value::Decision(_))) {
                    return Eval::Error(self.rt(
                        RuntimeCode::ProfileEscape,
                        span,
                        "decision value reached a primitive operand boundary",
                    ));
                }
                match (p.func)(self, &args, span) {
                    Eval::TailApply { f: nf, args: nargs } => self.apply(&nf, nargs, span),
                    done => done,
                }
            }
            // An escape continuation `k` reached via the host apply path (e.g. passed to
            // `map`/`call-with-values`); same one-shot gate as a source-level call (§9).
            Value::Cont(c) => self.invoke_cont(c, args, span),
            other => Eval::Error(self.rt(
                RuntimeCode::E301,
                span,
                format!("attempt to call a non-procedure: {}", other.write_repr()),
            )),
        }
    }

    /// Invoke an escape continuation `k` (§9). The single gate for BOTH call paths (a
    /// source-level `(k v…)` in [`Interp::eval_loop`] and a host [`Interp::apply`])
    /// requires a live owner and an unused continuation. The first accepted invocation
    /// marks `k` used BEFORE returning the unwinding [`Eval::Escape`]. Reuse during an
    /// in-flight unwind and invocation after the owner exits both produce E340.
    /// Implemented purely via the threaded [`Eval::Escape`] signal — no host unwinding —
    /// so the model ports to external backend (§1/§9).
    fn invoke_cont(&self, cont: &Continuation, args: Vec<Value>, span: Span) -> Eval {
        if self.live_tags.contains(&cont.tag) && !cont.used.replace(true) {
            Eval::Escape {
                tag: cont.tag,
                vals: into_outcome(args),
            }
        } else {
            Eval::Error(self.rt(
                RuntimeCode::E340,
                span,
                ESCAPE_CONTINUATION_INACTIVE_MESSAGE,
            ))
        }
    }

    /// [`Interp::apply`] in a single-value context (the per-element call of a HOF): the
    /// procedure must yield exactly one value; 0 or ≥2 → E320 (mirrors [`Interp::eval1`]).
    /// Returns the value, or the propagating signal to `return`.
    fn apply1(&mut self, f: &Value, args: Vec<Value>, span: Span) -> Result<Value, Eval> {
        match self.apply(f, args, span) {
            Eval::Ok(Outcome::One(v)) => Ok(v),
            Eval::Ok(Outcome::Many(mut vs)) if vs.len() == 1 => Ok(vs.pop().unwrap()),
            Eval::Ok(Outcome::Many(_)) => Err(Eval::Error(self.rt(
                RuntimeCode::E320,
                span,
                "a single value is required here, but the procedure produced zero or multiple values",
            ))),
            // `apply` resolves any `TailApply` before returning, so it cannot reach here.
            Eval::TailApply { .. } => unreachable!("apply never yields Eval::TailApply"),
            other => Err(other), // Error / Escape: propagate
        }
    }

    // ── builtins (R5: the v1 stdlib + the canonical-name/alias policy, §10) ───────
    // R4 installed the exact numeric tower (§2). R5 completes the v1 builtin set with
    // the R7RS-CANONICAL names plus the docs' friendly ALIASES (so every published
    // snippet runs verbatim) plus the W3xx-warning DEPRECATED third spellings. Every
    // entry below is tagged canonical / alias / deprecated.
    //
    // Canonicalization rule (§10): an *alias* binds the SAME primitive value as its
    // canonical name, so `(eq? car first)` is #t (a real alias, not a copy). A
    // *deprecated* alias binds a thin wrapper that emits a W3xx warning then delegates.
    fn install_builtins(&self) {
        // ── pairs / lists ──
        self.register("cons", prim_cons); // canonical
        self.register("car", prim_car); // canonical
        self.register("cdr", prim_cdr); // canonical
        self.register("first", prim_car); // alias → car
        self.register("rest", prim_cdr); // alias → cdr
        self.register("list-first", prim_list_first); // DEPRECATED (W331) → car
        self.register("list-rest", prim_list_rest); // DEPRECATED (W331) → cdr
        self.register("pair?", prim_pair_q); // canonical
        self.register("null?", prim_null_q); // canonical
        self.register("empty?", prim_null_q); // alias → null?
        self.register("list?", prim_list_q); // canonical (total)
        self.register("length", prim_length); // canonical
        self.register("append", prim_append); // canonical (also a hidden intrinsic)
        self.register("reverse", prim_reverse); // canonical
        self.register("list", prim_list); // canonical (constructor)
        self.register("make-list", prim_make_list); // k copies of a fill (default 0)
        self.register("list-ref", prim_list_ref); // canonical
        self.register("nth", prim_list_ref); // alias → list-ref (same arg order)
        self.register("list-tail", prim_list_tail); // canonical (shared k-th cdr)
        self.register("list-copy", prim_list_copy); // canonical (shallow spine copy)
        for &(name, f) in CXR_PRIMS {
            self.register(name, f); // caar..cddddr (2-deep base + 3/4-deep cxr extension)
        }
        self.register("map", prim_map); // canonical (HOF)
        self.register("filter", prim_filter); // canonical (HOF)
        self.register("any?", prim_any_p); // checked profile extension (strict bool, short-circuit)
        self.register("all?", prim_all_p); // checked profile extension (strict bool, short-circuit)
        self.register("reduce", prim_reduce); // canonical (HOF, left fold)
        self.register("fold-left", prim_reduce); // alias → reduce (R6RS name; (f acc elem) left fold)
        self.register("fold-right", prim_fold_right); // canonical (HOF, right fold)
        self.register("for-each", prim_for_each); // canonical (HOF; map for effect)
        self.register("member", prim_member); // canonical (equal?)
        self.register("memv", prim_memv); // canonical (eqv?)
        self.register("memq", prim_memq); // = memv in v1 (eq? = eqv?, §6)
        self.register("assoc", prim_assoc); // canonical (equal?)
        self.register("assv", prim_assv); // canonical (eqv?)
        self.register("assq", prim_assq); // = assv in v1 (eq? = eqv?, §6)

        // ── equality / booleans ──
        self.register("eqv?", prim_eqv); // canonical
        self.register("eq?", prim_eq); // = eqv? in v1 (§6)
        self.register("equal?", prim_equal); // canonical (deep, cycle-safe)
        self.register("==", prim_equal); // alias → equal?
        self.register("!=", prim_not_equal); // alias → (not (equal? a b))
        self.register("not", prim_not); // canonical (and/or are special forms)

        // ── the exact numeric tower (§2, installed R4) ──
        self.register("+", prim_add);
        self.register("-", prim_sub);
        self.register("*", prim_mul);
        self.register("/", prim_div);
        self.register("modulo", prim_modulo); // canonical
        self.register("%", prim_percent); // DEPRECATED (W330) → modulo
        self.register("quotient", prim_quotient); // canonical
        self.register("remainder", prim_remainder); // canonical
        self.register("floor-quotient", prim_floor_quotient); // floored quotient (toward -inf)
        self.register("floor-remainder", prim_floor_remainder); // = modulo
        self.register("truncate-quotient", prim_truncate_quotient); // = quotient
        self.register("truncate-remainder", prim_truncate_remainder); // = remainder
        self.register("floor/", prim_floor_div); // 2 values: floor-quotient, floor-remainder
        self.register("truncate/", prim_truncate_div); // 2 values: quotient, remainder
        self.register("abs", prim_abs);
        self.register("square", prim_square); // canonical (z*z, exactness-preserving)
        self.register("floor", prim_floor); // canonical (toward -inf)
        self.register("ceiling", prim_ceiling); // canonical (toward +inf)
        self.register("round", prim_round); // canonical (half-to-even)
        self.register("truncate", prim_truncate); // canonical (toward 0)
        self.register("gcd", prim_gcd); // canonical (variadic, non-negative; (gcd)=0)
        self.register("lcm", prim_lcm); // canonical (variadic, non-negative; (lcm)=1)
        self.register("expt", prim_expt); // canonical (exact-integer exponent)
        self.register("exact-integer-sqrt", prim_exact_integer_sqrt); // floor int sqrt + remainder (2 values)
        self.register("min", prim_min);
        self.register("max", prim_max);
        self.register("=", prim_num_eq);
        self.register("<", prim_lt);
        self.register(">", prim_gt);
        self.register("<=", prim_le);
        self.register(">=", prim_ge);
        self.register("exact", prim_exact);
        self.register("inexact", prim_inexact);
        self.register("inexact->exact", prim_exact); // R7RS long-name alias
        self.register("exact->inexact", prim_inexact); // R7RS long-name alias
        self.register("number?", prim_number_q);
        self.register("integer?", prim_integer_q);
        self.register("exact-integer?", prim_exact_integer_q); // exact integer only
        self.register("rational?", prim_rational_q); // ≡ number? in v1 (finite real tower, no complex)
        self.register("real?", prim_real_q); // ≡ number? in v1
        self.register("complex?", prim_complex_q); // ≡ number? in v1
        self.register("exact?", prim_exact_q);
        self.register("inexact?", prim_inexact_q);
        self.register("zero?", prim_zero_q);
        self.register("positive?", prim_positive_q);
        self.register("negative?", prim_negative_q);
        self.register("even?", prim_even_q);
        self.register("odd?", prim_odd_q);

        // ── strings ──
        self.register("string-append", prim_string_append);
        self.register("make-string", prim_make_string); // k copies of a char (default #\space)
        self.register("string-length", prim_string_length);
        self.register("substring", prim_substring);
        self.register("string-copy", prim_string_copy); // substring with optional [start end]
        self.register("string-ref", prim_string_ref); // canonical (character index)
        self.register("string->list", prim_string_to_list);
        self.register("string->vector", prim_string_to_vector); // fresh mutable char-vector
        self.register("list->string", prim_list_to_string);
        self.register("string->symbol", prim_string_to_symbol);
        self.register("symbol->string", prim_symbol_to_string);
        self.register("string->number", prim_string_to_number);
        self.register("number->string", prim_number_to_string); // shares the §2 formatter
        self.register("string=?", prim_string_eq); // canonical (lexicographic, Unicode scalar)
        self.register("string<?", prim_string_lt);
        self.register("string>?", prim_string_gt);
        self.register("string<=?", prim_string_le);
        self.register("string>=?", prim_string_ge);
        self.register("string-ci=?", prim_string_ci_eq); // case-insensitive (fold ≈ full lowercase)
        self.register("string-ci<?", prim_string_ci_lt);
        self.register("string-ci>?", prim_string_ci_gt);
        self.register("string-ci<=?", prim_string_ci_le);
        self.register("string-ci>=?", prim_string_ci_ge);
        self.register("string-map", prim_string_map); // canonical (single-string HOF → fresh string)
        self.register("string-for-each", prim_string_for_each); // canonical (single-string, for effect)
        self.register("string-upcase", prim_string_upcase); // Unicode full uppercasing
        self.register("string-downcase", prim_string_downcase); // Unicode full lowercasing
        self.register("string-foldcase", prim_string_foldcase); // case fold (≈ full lowercase, v1)

        // ── chars ──
        self.register("char?", prim_char_q);
        self.register("char->integer", prim_char_to_integer);
        self.register("integer->char", prim_integer_to_char);
        self.register("char=?", prim_char_eq); // canonical (Unicode scalar order)
        self.register("char<?", prim_char_lt);
        self.register("char>?", prim_char_gt);
        self.register("char<=?", prim_char_le);
        self.register("char>=?", prim_char_ge);
        self.register("char-ci=?", prim_char_ci_eq); // case-insensitive (fold ≈ simple lowercase)
        self.register("char-ci<?", prim_char_ci_lt);
        self.register("char-ci>?", prim_char_ci_gt);
        self.register("char-ci<=?", prim_char_ci_le);
        self.register("char-ci>=?", prim_char_ci_ge);
        self.register("char-alphabetic?", prim_char_alphabetic); // Unicode Alphabetic
        self.register("char-numeric?", prim_char_numeric); // v1: ASCII decimal digit
        self.register("char-whitespace?", prim_char_whitespace); // Unicode White_Space
        self.register("char-upper-case?", prim_char_upper_case); // Unicode Uppercase
        self.register("char-lower-case?", prim_char_lower_case); // Unicode Lowercase
        self.register("char-upcase", prim_char_upcase); // Unicode simple uppercase (single char)
        self.register("char-downcase", prim_char_downcase); // Unicode simple lowercase (single char)
        self.register("char-foldcase", prim_char_foldcase); // case fold (≈ simple lowercase, v1)
        self.register("boolean=?", prim_boolean_eq); // canonical (≥2 booleans, all equal)
        self.register("symbol=?", prim_symbol_eq); // canonical (≥2 symbols, equal by name)

        // ── vectors ──
        self.register("make-vector", prim_make_vector);
        self.register("vector", prim_vector);
        self.register("vector-ref", prim_vector_ref);
        self.register("vector-set!", prim_vector_set);
        self.register("vector-length", prim_vector_length);
        self.register("vector->list", prim_vector_to_list);
        self.register("vector->string", prim_vector_to_string); // chars in range → fresh string
        self.register("vector-copy", prim_vector_copy); // canonical (fresh mutable [start end] slice)
        self.register("vector-map", prim_vector_map); // canonical (single-vector HOF → fresh vector)
        self.register("vector-for-each", prim_vector_for_each); // canonical (single-vector, for effect)
        self.register("list->vector", prim_list_to_vector); // also a hidden intrinsic

        // ── bytevectors (immutable in v1) ──
        self.register("make-bytevector", prim_make_bytevector);
        self.register("bytevector", prim_bytevector);
        self.register("bytevector-length", prim_bytevector_length);
        self.register("bytevector-u8-ref", prim_bytevector_u8_ref);

        // ── symbols ──
        self.register("symbol?", prim_symbol_q);

        // ── remaining total type predicates ──
        self.register("string?", prim_string_q);
        self.register("boolean?", prim_boolean_q);
        self.register("procedure?", prim_procedure_q);
        self.register("vector?", prim_vector_q);
        self.register("bytevector?", prim_bytevector_q);

        // ── I/O (§11) ──
        self.register("display", prim_display);
        self.register("write", prim_write);
        self.register("newline", prim_newline);
        self.register("println", prim_println); // = display + newline

        // ── control + errors (R6, §8/§9) + multiple-values sink (§5) ──
        self.register("error", prim_error); // user (error …) → E330
                                            // v1.2 recoverable error handling (§8): the procedural core over `Eval::Error`.
        self.register("raise", prim_raise); // non-continuable raise of any object → E331 uncaught
        self.register("raise-continuable", prim_raise_continuable); // continuable raise (handler in place)
        self.register("with-exception-handler", prim_with_exception_handler);
        self.register("error-object?", prim_error_object_p);
        self.register("error-object-message", prim_error_object_message);
        self.register("error-object-irritants", prim_error_object_irritants);
        self.register("call/cc", prim_call_cc); // escape-only continuation
        self.register("call-with-current-continuation", prim_call_cc); // R7RS long name
        self.register("dynamic-wind", prim_dynamic_wind); // before/thunk/after cleanup
        self.register("values", prim_values); // multiple-values producer (first-class; mirrors the core node)
        self.register("call-with-values", prim_call_with_values); // multiple-values sink
        self.register("apply", prim_apply); // HOF; tail-applies proc to spread args + final list
    }

    fn register(&self, name: &str, func: PrimFn) {
        let p = Value::Primitive(Primitive {
            name: Rc::from(name),
            func,
        });
        self.global.define(Ident::User(Rc::from(name)), p);
    }
}

/// The result of [`Interp::enter_begin`]: either a tail expr to keep looping on, or a
/// finished signal (an error/escape, or a degenerate defines-only body's zero values).
enum BeginStep {
    Tail(CoreExpr),
    Done(Eval),
}

// ─────────────────────────────────────────────────────────────────────────────
// Intrinsics (§7.1 + checked profile) -- desugared cond/case/quasiquote depend on
// the hidden subset; the profile lowering path also uses intrinsic refs for its
// closed builtin surface. Resolved directly here, never via the lexical env.
// ─────────────────────────────────────────────────────────────────────────────

/// Map an [`Intrinsic`] to its primitive value.
fn intrinsic_value(i: Intrinsic) -> Value {
    let (name, func): (&str, PrimFn) = match i {
        Intrinsic::Cons => ("cons", prim_cons),
        Intrinsic::Append => ("append", prim_append),
        Intrinsic::ListToVector => ("list->vector", prim_list_to_vector),
        Intrinsic::Eqv => ("eqv?", prim_eqv),
        Intrinsic::Add => ("+", prim_add),
        Intrinsic::Sub => ("-", prim_sub),
        Intrinsic::Mul => ("*", prim_mul),
        Intrinsic::Div => ("/", prim_div),
        Intrinsic::Modulo => ("modulo", prim_modulo),
        Intrinsic::NumEq => ("=", prim_num_eq),
        Intrinsic::Lt => ("<", prim_lt),
        Intrinsic::Gt => (">", prim_gt),
        Intrinsic::Le => ("<=", prim_le),
        Intrinsic::Ge => (">=", prim_ge),
        Intrinsic::Equal => ("equal?", prim_equal),
        Intrinsic::Assoc => ("assoc", prim_assoc),
        Intrinsic::Assv => ("assv", prim_assv),
        Intrinsic::Member => ("member", prim_member),
        Intrinsic::Memv => ("memv", prim_memv),
        Intrinsic::Not => ("not", prim_not),
        Intrinsic::StringEq => ("string=?", prim_string_eq),
        Intrinsic::StringLt => ("string<?", prim_string_lt),
        Intrinsic::StringAppend => ("string-append", prim_string_append),
        Intrinsic::NumberToString => ("number->string", prim_number_to_string),
        Intrinsic::NullP => ("null?", prim_null_q),
        Intrinsic::PairP => ("pair?", prim_pair_q),
        Intrinsic::Car => ("car", prim_car),
        Intrinsic::Cdr => ("cdr", prim_cdr),
        Intrinsic::List => ("list", prim_list),
        Intrinsic::Length => ("length", prim_length),
        Intrinsic::ListP => ("list?", prim_list_q),
        Intrinsic::StringP => ("string?", prim_string_q),
        Intrinsic::NumberP => ("number?", prim_number_q),
        Intrinsic::BooleanP => ("boolean?", prim_boolean_q),
        Intrinsic::SymbolP => ("symbol?", prim_symbol_q),
        Intrinsic::Min => ("min", prim_min),
        Intrinsic::Max => ("max", prim_max),
        Intrinsic::Abs => ("abs", prim_abs),
        Intrinsic::Quotient => ("quotient", prim_quotient),
        Intrinsic::Remainder => ("remainder", prim_remainder),
        Intrinsic::Floor => ("floor", prim_floor),
        Intrinsic::Ceiling => ("ceiling", prim_ceiling),
        Intrinsic::Round => ("round", prim_round),
        Intrinsic::Truncate => ("truncate", prim_truncate),
        Intrinsic::Map => ("map", prim_map),
        Intrinsic::Filter => ("filter", prim_filter),
        Intrinsic::Reduce => ("reduce", prim_reduce),
        Intrinsic::FoldLeft => ("fold-left", prim_reduce),
        Intrinsic::FoldRight => ("fold-right", prim_fold_right),
        Intrinsic::Apply => ("apply", prim_apply),
        Intrinsic::Values => ("values", prim_values),
        Intrinsic::CallWithValues => ("call-with-values", prim_call_with_values),
        Intrinsic::AnyP => ("any?", prim_any_p),
        Intrinsic::AllP => ("all?", prim_all_p),
    };
    Value::Primitive(Primitive {
        name: Rc::from(name),
        func,
    })
}

/// `eqv?` per §6: exactness-sensitive on numbers (so `(eqv? 2 2.0) → #f`, and `-0.0`
/// differs from `0.0` via [`crate::value::Finite`]'s bitwise eq), value-equal on the
/// other atoms, and **identity** on every aggregate / procedure / continuation.
fn eqv(a: &Value, b: &Value) -> bool {
    use Value::*;
    match (a, b) {
        (Bool(x), Bool(y)) => x == y,
        (Int(x), Int(y)) => x == y,
        (Rational(x), Rational(y)) => x == y,
        (Real(x), Real(y)) => x == y, // Finite: bitwise (−0.0 ≠ 0.0)
        (Char(x), Char(y)) => x == y,
        (Sym(x), Sym(y)) => x == y, // interned name equality
        (Nil, Nil) => true,
        (Str(x), Str(y)) => Rc::ptr_eq(x, y),
        (Pair(x), Pair(y)) => Rc::ptr_eq(x, y),
        (Vector(x), Vector(y)) => Rc::ptr_eq(x, y),
        (Bytevector(x), Bytevector(y)) => Rc::ptr_eq(x, y),
        (Closure(x), Closure(y)) => Rc::ptr_eq(x, y),
        (Primitive(x), Primitive(y)) => x.ptr_eq(y),
        (Cont(x), Cont(y)) => Rc::ptr_eq(x, y),
        (ErrorObject(x), ErrorObject(y)) => Rc::ptr_eq(x, y),
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Primitive implementations (intrinsics + BOOTSTRAP set).
// ─────────────────────────────────────────────────────────────────────────────

fn arity_error(it: &Interp, name: &str, span: Span, expected: &str, got: usize) -> Eval {
    Eval::Error(it.rt(
        RuntimeCode::E302,
        span,
        format!("{name}: arity mismatch, expected {expected}, got {got}"),
    ))
}

fn type_error(it: &Interp, name: &str, span: Span, expected: &str, v: &Value) -> Eval {
    Eval::Error(it.rt(
        RuntimeCode::E312,
        span,
        format!("{name}: expected {expected}, got {}", v.write_repr()),
    ))
}

/// Classify every argument as a numeric operand (§2 tower); any non-number → E312.
fn classify_nums(it: &Interp, name: &str, span: Span, args: &[Value]) -> Result<Vec<Num>, Eval> {
    let mut out = Vec::with_capacity(args.len());
    for a in args {
        match number::num_of(a) {
            Some(n) => out.push(n),
            None => return Err(type_error(it, name, span, "a number", a)),
        }
    }
    Ok(out)
}

/// Map an arithmetic [`AErr`] to the spec's runtime fault (§2/§8): `DivZero → E313`,
/// `NotFinite → E314`, `NotInteger → E312`.
fn aerr_to_eval(it: &Interp, name: &str, span: Span, e: AErr) -> Eval {
    let (code, msg): (RuntimeCode, String) = match e {
        AErr::DivZero => (RuntimeCode::E313, format!("{name}: division by zero")),
        AErr::NotFinite => (
            RuntimeCode::E314,
            format!("{name}: inexact result is not finite (overflow)"),
        ),
        AErr::NotInteger => (RuntimeCode::E312, format!("{name}: expected an integer")),
    };
    Eval::Error(it.rt(code, span, msg))
}

/// Finish a numeric op: a produced value → one outcome; an [`AErr`] → the mapped fault.
fn finish(it: &Interp, name: &str, span: Span, r: Result<Value, AErr>) -> Eval {
    match r {
        Ok(v) => Eval::Ok(Outcome::One(v)),
        Err(e) => aerr_to_eval(it, name, span, e),
    }
}

/// A one-argument numeric predicate that requires a number (non-number → E312).
fn num_predicate(
    it: &mut Interp,
    name: &str,
    args: &[Value],
    span: Span,
    f: fn(&Num) -> bool,
) -> Eval {
    if args.len() != 1 {
        return arity_error(it, name, span, "1 argument", args.len());
    }
    match number::num_of(&args[0]) {
        Some(n) => Eval::Ok(Outcome::One(Value::Bool(f(&n)))),
        None => type_error(it, name, span, "a number", &args[0]),
    }
}

/// A comparison-chain prim (`= < > <= >=`): ≥2 args (§2 — 0/1-arg → E302), all numbers.
fn cmp_chain(it: &mut Interp, name: &str, args: &[Value], span: Span, op: CmpOp) -> Eval {
    if args.len() < 2 {
        return arity_error(it, name, span, "at least 2 arguments", args.len());
    }
    let nums = match classify_nums(it, name, span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    Eval::Ok(Outcome::One(Value::Bool(number::compare(&nums, op))))
}

// ── the four hidden intrinsics ────────────────────────────────────────────────

fn prim_cons(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "cons", span, "2 arguments", args.len());
    }
    Eval::Ok(Outcome::One(Value::cons(args[0].clone(), args[1].clone())))
}

/// `append`: every argument but the last must be a proper list; the last becomes the
/// tail (any value). Zero args → `()`.
fn prim_append(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() {
        return Eval::Ok(Outcome::One(Value::Nil));
    }
    let mut acc = args[args.len() - 1].clone();
    for arg in args[..args.len() - 1].iter().rev() {
        let mut elems = Vec::new();
        let mut cur = arg.clone();
        loop {
            match cur {
                Value::Nil => break,
                Value::Pair(p) => {
                    elems.push(p.car.clone());
                    cur = p.cdr.clone();
                }
                other => return type_error(it, "append", span, "a proper list", &other),
            }
        }
        for e in elems.into_iter().rev() {
            acc = Value::cons(e, acc);
        }
    }
    Eval::Ok(Outcome::One(acc))
}

fn prim_list_to_vector(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "list->vector", span, "1 argument", args.len());
    }
    let mut elems = Vec::new();
    let mut cur = args[0].clone();
    loop {
        match cur {
            Value::Nil => break,
            Value::Pair(p) => {
                elems.push(p.car.clone());
                cur = p.cdr.clone();
            }
            other => return type_error(it, "list->vector", span, "a proper list", &other),
        }
    }
    Eval::Ok(Outcome::One(Value::vector(elems)))
}

fn prim_eqv(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "eqv?", span, "2 arguments", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(eqv(&args[0], &args[1]))))
}

// ── BOOTSTRAP list basics + predicates ────────────────────────────────────────

fn prim_car(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "car", span, "1 argument", args.len());
    }
    match &args[0] {
        Value::Pair(p) => Eval::Ok(Outcome::One(p.car.clone())),
        other => Eval::Error(it.rt(
            RuntimeCode::E310,
            span,
            format!("car: expected a pair, got {}", other.write_repr()),
        )),
    }
}

fn prim_cdr(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "cdr", span, "1 argument", args.len());
    }
    match &args[0] {
        Value::Pair(p) => Eval::Ok(Outcome::One(p.cdr.clone())),
        other => Eval::Error(it.rt(
            RuntimeCode::E310,
            span,
            format!("cdr: expected a pair, got {}", other.write_repr()),
        )),
    }
}

/// Apply a fixed `car`/`cdr` access path (the a/d letters of a `c…r` name, innermost = rightmost) to
/// `v`. Each step requires a pair; a non-pair at ANY step → E310, exactly like `car`/`cdr`.
fn cxr(it: &Interp, name: &str, path: &str, v: Value, span: Span) -> Eval {
    let mut cur = v;
    for ch in path.chars().rev() {
        match cur {
            Value::Pair(p) => {
                cur = if ch == 'a' {
                    p.car.clone()
                } else {
                    p.cdr.clone()
                }
            }
            other => {
                return Eval::Error(it.rt(
                    RuntimeCode::E310,
                    span,
                    format!("{name}: expected a pair, got {}", other.write_repr()),
                ))
            }
        }
    }
    Eval::Ok(Outcome::One(cur))
}

/// Generate the `c…r` composition accessors. The path is the letters between `c` and `r` (ASCII), and
/// `cxr` applies them right-to-left so `cadr` = `(car (cdr x))`.
macro_rules! cxr_prims {
    ($($n:ident => $lit:literal),* $(,)?) => {
        $(
            fn $n(it: &mut Interp, args: &[Value], span: Span) -> Eval {
                if args.len() != 1 {
                    return arity_error(it, $lit, span, "1 argument", args.len());
                }
                cxr(it, $lit, &$lit[1..$lit.len() - 1], args[0].clone(), span)
            }
        )*
        /// The full `caar`..`cddddr` set: the 2-deep are R7RS `(scheme base)`, the 3- and 4-deep are
        /// the `(scheme cxr)` extension (included for convenience).
        const CXR_PRIMS: &[(&str, PrimFn)] = &[ $( ($lit, $n) ),* ];
    };
}

cxr_prims! {
    prim_caar => "caar", prim_cadr => "cadr", prim_cdar => "cdar", prim_cddr => "cddr",
    prim_caaar => "caaar", prim_caadr => "caadr", prim_cadar => "cadar", prim_caddr => "caddr",
    prim_cdaar => "cdaar", prim_cdadr => "cdadr", prim_cddar => "cddar", prim_cdddr => "cdddr",
    prim_caaaar => "caaaar", prim_caaadr => "caaadr", prim_caadar => "caadar", prim_caaddr => "caaddr",
    prim_cadaar => "cadaar", prim_cadadr => "cadadr", prim_caddar => "caddar", prim_cadddr => "cadddr",
    prim_cdaaar => "cdaaar", prim_cdaadr => "cdaadr", prim_cdadar => "cdadar", prim_cdaddr => "cdaddr",
    prim_cddaar => "cddaar", prim_cddadr => "cddadr", prim_cdddar => "cdddar", prim_cddddr => "cddddr",
}

fn prim_pair_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "pair?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(matches!(args[0], Value::Pair(_)))))
}

fn prim_null_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "null?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(matches!(args[0], Value::Nil))))
}

fn prim_not(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "not", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(matches!(
        args[0],
        Value::Bool(false)
    ))))
}

// ── the exact numeric tower (§2): arithmetic ───────────────────────────────────

fn prim_add(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    let nums = match classify_nums(it, "+", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "+", span, number::add(&nums))
}

fn prim_gcd(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    let nums = match classify_nums(it, "gcd", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "gcd", span, number::gcd(&nums))
}

fn prim_lcm(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    let nums = match classify_nums(it, "lcm", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "lcm", span, number::lcm(&nums))
}

/// `expt` — `(expt base exp)` with an exact-integer exponent (general expt excluded, §2). The
/// base may be any number; the exponent must be an exact integer (a float/rational exp → E312).
fn prim_expt(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "expt", span, "2 arguments", args.len());
    }
    let base = match number::num_of(&args[0]) {
        Some(n) => n,
        None => return type_error(it, "expt", span, "a number", &args[0]),
    };
    let exp = match want_exact_int(it, "expt", span, &args[1]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    finish(it, "expt", span, number::expt(&base, exp))
}

fn prim_mul(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    let nums = match classify_nums(it, "*", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "*", span, number::mul(&nums))
}

fn prim_sub(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() {
        return arity_error(it, "-", span, "at least 1 argument", 0);
    }
    let mut nums = match classify_nums(it, "-", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    // SCORED-MUTATION-SITE M06: reverse only reference-side subtraction.
    if cfg!(scored_mutant = "M06") {
        nums.reverse();
    }
    finish(it, "-", span, number::sub(&nums))
}

fn prim_div(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() {
        return arity_error(it, "/", span, "at least 1 argument", 0);
    }
    let nums = match classify_nums(it, "/", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "/", span, number::div(&nums))
}

fn prim_modulo(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "modulo", span, "2 arguments", args.len());
    }
    let nums = match classify_nums(it, "modulo", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "modulo", span, number::modulo(&nums[0], &nums[1]))
}

fn prim_quotient(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "quotient", span, "2 arguments", args.len());
    }
    let nums = match classify_nums(it, "quotient", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "quotient", span, number::quotient(&nums[0], &nums[1]))
}

fn prim_remainder(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "remainder", span, "2 arguments", args.len());
    }
    let nums = match classify_nums(it, "remainder", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "remainder", span, number::remainder(&nums[0], &nums[1]))
}

/// A single-value integer-division op over the numeric tower (e.g. `number::floor_quotient`).
type IntDiv1Op = fn(&Num, &Num) -> Result<Value, AErr>;
/// A two-value integer-division op (e.g. `number::floor_div` / `number::truncate_div`).
type IntDiv2Op = fn(&Num, &Num) -> Result<(Value, Value), AErr>;

/// A 2-arg integer-division primitive returning ONE value (floor-quotient / floor-remainder /
/// truncate-quotient / truncate-remainder): arity 2 → else E302; classify → E312; `op` computes it.
fn int_div1(it: &mut Interp, name: &str, args: &[Value], span: Span, op: IntDiv1Op) -> Eval {
    if args.len() != 2 {
        return arity_error(it, name, span, "2 arguments", args.len());
    }
    let nums = match classify_nums(it, name, span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, name, span, op(&nums[0], &nums[1]))
}

/// A 2-arg integer-division primitive returning TWO values (floor/ / truncate/): the quotient and
/// remainder together (via [`into_outcome`]). Same arity/type/zero-divisor faults as [`int_div1`].
fn int_div2(it: &mut Interp, name: &str, args: &[Value], span: Span, op: IntDiv2Op) -> Eval {
    if args.len() != 2 {
        return arity_error(it, name, span, "2 arguments", args.len());
    }
    let nums = match classify_nums(it, name, span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    match op(&nums[0], &nums[1]) {
        Ok((q, r)) => Eval::Ok(into_outcome(vec![q, r])),
        Err(e) => aerr_to_eval(it, name, span, e),
    }
}

fn prim_floor_quotient(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    int_div1(it, "floor-quotient", args, span, number::floor_quotient)
}

/// `floor-remainder` is exactly `modulo` (floored remainder, sign of divisor) — distinct prim so
/// diagnostics name the called proc.
fn prim_floor_remainder(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    int_div1(it, "floor-remainder", args, span, number::modulo)
}

/// `truncate-quotient` is exactly `quotient` (truncated, toward zero).
fn prim_truncate_quotient(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    int_div1(it, "truncate-quotient", args, span, number::quotient)
}

/// `truncate-remainder` is exactly `remainder` (sign of dividend).
fn prim_truncate_remainder(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    int_div1(it, "truncate-remainder", args, span, number::remainder)
}

fn prim_floor_div(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    int_div2(it, "floor/", args, span, number::floor_div)
}

fn prim_truncate_div(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    int_div2(it, "truncate/", args, span, number::truncate_div)
}

fn prim_abs(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "abs", span, "1 argument", args.len());
    }
    let nums = match classify_nums(it, "abs", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "abs", span, number::abs(&nums[0]))
}

/// `square` — `(square z)` = `z * z` (exactness-preserving). Non-number → E312.
fn prim_square(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "square", span, "1 argument", args.len());
    }
    let nums = match classify_nums(it, "square", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "square", span, number::square(&nums[0]))
}

/// `exact-integer-sqrt` — `(exact-integer-sqrt k)` returns TWO values `s` and `r` with
/// `s = floor(sqrt(k))` and `r = k - s²` (so `s² ≤ k < (s+1)²`). `k` must be an EXACT non-negative
/// integer: a non-integer/inexact `k` → E312 (`want_exact_int`), a negative `k` → E312. This is
/// exact integer arithmetic (the transcendental `sqrt` family stays excluded, §2).
fn prim_exact_integer_sqrt(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "exact-integer-sqrt", span, "1 argument", args.len());
    }
    let k = match want_exact_int(it, "exact-integer-sqrt", span, &args[0]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    if k.sign() == num_bigint::Sign::Minus {
        return type_error(
            it,
            "exact-integer-sqrt",
            span,
            "a non-negative integer",
            &args[0],
        );
    }
    let s = k.sqrt(); // inherent BigInt::sqrt — truncated (floor) principal root; panics on negative
    let r = k - &s * &s;
    Eval::Ok(into_outcome(vec![Value::Int(s), Value::Int(r)]))
}

fn prim_floor(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "floor", span, "1 argument", args.len());
    }
    let nums = match classify_nums(it, "floor", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "floor", span, number::floor(&nums[0]))
}

fn prim_ceiling(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "ceiling", span, "1 argument", args.len());
    }
    let nums = match classify_nums(it, "ceiling", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "ceiling", span, number::ceiling(&nums[0]))
}

fn prim_round(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "round", span, "1 argument", args.len());
    }
    let nums = match classify_nums(it, "round", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "round", span, number::round(&nums[0]))
}

fn prim_truncate(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "truncate", span, "1 argument", args.len());
    }
    let nums = match classify_nums(it, "truncate", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "truncate", span, number::truncate(&nums[0]))
}

fn prim_min(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() {
        return arity_error(it, "min", span, "at least 1 argument", 0);
    }
    let nums = match classify_nums(it, "min", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "min", span, number::minmax(&nums, false))
}

fn prim_max(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() {
        return arity_error(it, "max", span, "at least 1 argument", 0);
    }
    let nums = match classify_nums(it, "max", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "max", span, number::minmax(&nums, true))
}

// ── comparison chains (§2): ≥2 args, pairwise, mixed compared EXACTLY ───────────

fn prim_num_eq(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    cmp_chain(it, "=", args, span, CmpOp::Eq)
}

fn prim_lt(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    cmp_chain(it, "<", args, span, CmpOp::Lt)
}

fn prim_gt(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    cmp_chain(it, ">", args, span, CmpOp::Gt)
}

fn prim_le(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    cmp_chain(it, "<=", args, span, CmpOp::Le)
}

fn prim_ge(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    cmp_chain(it, ">=", args, span, CmpOp::Ge)
}

// ── exactness crossing (§2) ────────────────────────────────────────────────────

fn prim_exact(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "exact", span, "1 argument", args.len());
    }
    let nums = match classify_nums(it, "exact", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    Eval::Ok(Outcome::One(number::to_exact(&nums[0])))
}

fn prim_inexact(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "inexact", span, "1 argument", args.len());
    }
    let nums = match classify_nums(it, "inexact", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    finish(it, "inexact", span, number::to_inexact(&nums[0]))
}

// ── numeric predicates (§2) ────────────────────────────────────────────────────

/// `number?` — a total type predicate (a non-number is `#f`, never an error).
fn prim_number_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "number?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(
        number::num_of(&args[0]).is_some(),
    )))
}

/// `integer?` — a total type predicate: exact integers and integral inexact reals
/// (e.g. `3.0`) are `#t`; everything else (incl. non-numbers) is `#f`.
fn prim_integer_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "integer?", span, "1 argument", args.len());
    }
    let is_int = match &args[0] {
        Value::Int(_) => true,
        Value::Real(f) => {
            let x = f.get();
            x == x.trunc() // finite by invariant
        }
        _ => false,
    };
    Eval::Ok(Outcome::One(Value::Bool(is_int)))
}

/// `exact-integer?` — total: #t ONLY for an exact integer (`Value::Int`); a rational, an inexact real
/// (even integral like `3.0`), and non-numbers are #f.
fn prim_exact_integer_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "exact-integer?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(matches!(&args[0], Value::Int(_)))))
}

/// `rational?` — total. In v1 the tower is exact int / exact rational / FINITE real (no complex, no
/// inf/NaN), so every number is a rational real → this collapses to `number?`.
fn prim_rational_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "rational?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(
        number::num_of(&args[0]).is_some(),
    )))
}

/// `real?` — total; every number is a real in v1 (no complex) → collapses to `number?`.
fn prim_real_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "real?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(
        number::num_of(&args[0]).is_some(),
    )))
}

/// `complex?` — total; every number is complex in R7RS, and v1 has only reals → collapses to `number?`.
fn prim_complex_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "complex?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(
        number::num_of(&args[0]).is_some(),
    )))
}

fn prim_exact_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    num_predicate(it, "exact?", args, span, number::is_exact)
}

fn prim_inexact_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    num_predicate(it, "inexact?", args, span, number::is_inexact)
}

fn prim_zero_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    num_predicate(it, "zero?", args, span, number::is_zero)
}

fn prim_positive_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    num_predicate(it, "positive?", args, span, number::is_positive)
}

fn prim_negative_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    num_predicate(it, "negative?", args, span, number::is_negative)
}

/// `even?` — requires an integer (exact or inexact); a non-integer → E312.
fn prim_even_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "even?", span, "1 argument", args.len());
    }
    let nums = match classify_nums(it, "even?", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    match number::is_even(&nums[0]) {
        Ok(b) => Eval::Ok(Outcome::One(Value::Bool(b))),
        Err(e) => aerr_to_eval(it, "even?", span, e),
    }
}

/// `odd?` — requires an integer (exact or inexact); a non-integer → E312.
fn prim_odd_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "odd?", span, "1 argument", args.len());
    }
    let nums = match classify_nums(it, "odd?", span, args) {
        Ok(n) => n,
        Err(e) => return e,
    };
    match number::is_odd(&nums[0]) {
        Ok(b) => Eval::Ok(Outcome::One(Value::Bool(b))),
        Err(e) => aerr_to_eval(it, "odd?", span, e),
    }
}

// ── number → string (§2): shares the pinned canonical formatter ─────────────────

/// Resolve an optional radix argument (default 10) for `number->string`/`string->number`. Must be
/// one of `2`/`8`/`10`/`16` (R7RS) → that value as a `u32`, else E312.
fn want_radix(it: &Interp, name: &str, span: Span, arg: Option<&Value>) -> Result<u32, Eval> {
    let v = match arg {
        None => return Ok(10),
        Some(v) => v,
    };
    use num_traits::ToPrimitive;
    let i = want_exact_int(it, name, span, v)?;
    match i.to_u32() {
        Some(r @ (2 | 8 | 10 | 16)) => Ok(r),
        _ => Err(type_error(it, name, span, "a radix of 2, 8, 10, or 16", v)),
    }
}

/// Parse a SIGNED integer string in `radix` (used for `string->number` with a non-decimal radix).
/// The digits are pre-validated (optional leading `+`/`-`, then ≥1 char each a valid digit in
/// `radix`) so that `_`, radix prefixes like `#x`, and out-of-range digits are rejected — num-bigint's
/// `from_str_radix` would otherwise silently SKIP `_`. Returns `None` for any invalid/non-integer string.
fn parse_int_radix(s: &str, radix: u32) -> Option<num_bigint::BigInt> {
    let body = s.strip_prefix(['+', '-']).unwrap_or(s);
    if body.is_empty() || !body.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    use num_traits::Num;
    num_bigint::BigInt::from_str_radix(s, radix).ok()
}

fn prim_number_to_string(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() || args.len() > 2 {
        return arity_error(it, "number->string", span, "1 or 2 arguments", args.len());
    }
    let radix = match want_radix(it, "number->string", span, args.get(1)) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if radix == 10 {
        let s = match &args[0] {
            Value::Int(i) => i.to_string(),
            Value::Rational(r) => format!("{}/{}", r.numer(), r.denom()),
            Value::Real(f) => crate::value::format_real(f.get()),
            other => return type_error(it, "number->string", span, "a number", other),
        };
        return Eval::Ok(Outcome::One(Value::Str(Rc::from(s.as_str()))));
    }
    // A non-decimal radix (2/8/16) formats an EXACT INTEGER only (lowercase digits, leading '-').
    match &args[0] {
        Value::Int(i) => {
            let s = i.to_str_radix(radix);
            Eval::Ok(Outcome::One(Value::Str(Rc::from(s.as_str()))))
        }
        other => type_error(
            it,
            "number->string",
            span,
            "an exact integer (a non-decimal radix only formats exact integers)",
            other,
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// R5 stdlib: shared helpers + the canonical/alias/deprecated builtin set (§10/§11).
// Diagnostics (§task 3): wrong type to a list/string/vector/char op → E312; OOB index
// → E311; car/cdr/first/rest/length of a non-pair/improper list → E310; arity → E302.
// ─────────────────────────────────────────────────────────────────────────────

/// Build an `E311` (index out of range) fault.
fn e311(it: &Interp, span: Span, msg: String) -> Eval {
    Eval::Error(it.rt(RuntimeCode::E311, span, msg))
}

/// Collect a proper list's elements into a `Vec`. An improper/non-list value raises
/// `code` (E310 for `length`, E312 for the other list ops). A v1 list spine is pairs
/// only (pairs are immutable → never cyclic), so this always terminates.
fn list_elems(
    it: &Interp,
    name: &str,
    span: Span,
    code: RuntimeCode,
    v: &Value,
) -> Result<Vec<Value>, Eval> {
    let mut elems = Vec::new();
    let mut cur = v.clone();
    loop {
        match cur {
            Value::Nil => break,
            Value::Pair(p) => {
                elems.push(p.car.clone());
                cur = p.cdr.clone();
            }
            other => {
                return Err(Eval::Error(it.rt(
                    code,
                    span,
                    format!("{name}: expected a proper list, got {}", other.write_repr()),
                )));
            }
        }
    }
    Ok(elems)
}

/// Require an exact integer argument; an inexact / rational / non-number → E312.
fn want_exact_int<'a>(
    it: &Interp,
    name: &str,
    span: Span,
    v: &'a Value,
) -> Result<&'a num_bigint::BigInt, Eval> {
    match v {
        Value::Int(i) => Ok(i),
        other => Err(type_error(it, name, span, "an exact integer", other)),
    }
}

/// Require a string argument; a non-string → E312.
fn want_str<'a>(it: &Interp, name: &str, span: Span, v: &'a Value) -> Result<&'a str, Eval> {
    match v {
        Value::Str(s) => Ok(s),
        other => Err(type_error(it, name, span, "a string", other)),
    }
}

/// Require a byte: an EXACT integer in 0..=255 (the same gate the reader applies to `#u8(…)`
/// elements via `to_u8`). A non-integer OR an out-of-range value → E312 — a value-domain
/// fault like `integer->char`, NOT an index/count (E311).
fn want_byte(it: &Interp, name: &str, span: Span, v: &Value) -> Result<u8, Eval> {
    use num_traits::ToPrimitive;
    match v {
        Value::Int(i) => i
            .to_u8()
            .ok_or_else(|| type_error(it, name, span, "a byte (exact integer 0..=255)", v)),
        other => Err(type_error(
            it,
            name,
            span,
            "a byte (exact integer 0..=255)",
            other,
        )),
    }
}

/// Map an exact integer to an in-range index `0 ≤ k < len`, else E311.
fn index_in_range(
    it: &Interp,
    name: &str,
    span: Span,
    i: &num_bigint::BigInt,
    len: usize,
) -> Result<usize, Eval> {
    use num_traits::ToPrimitive;
    match i.to_usize() {
        Some(k) if k < len => Ok(k),
        _ => Err(e311(
            it,
            span,
            format!("{name}: index {i} out of range (length {len})"),
        )),
    }
}

/// Map an exact integer to a non-negative size that fits `usize` (a count, not an
/// index), else E311.
fn as_count(it: &Interp, name: &str, span: Span, i: &num_bigint::BigInt) -> Result<usize, Eval> {
    use num_traits::ToPrimitive;
    i.to_usize()
        .ok_or_else(|| e311(it, span, format!("{name}: invalid size {i}")))
}

// ── equality (§6): eq? = eqv? in v1; equal? deep + cycle-safe; ==/!= aliases ────

fn prim_eq(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "eq?", span, "2 arguments", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(eqv(&args[0], &args[1]))))
}

fn prim_equal(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "equal?", span, "2 arguments", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(equal(&args[0], &args[1]))))
}

/// `!=` = `(not (equal? a b))` (§10).
fn prim_not_equal(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "!=", span, "2 arguments", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(!equal(&args[0], &args[1]))))
}

/// `equal?` (§6): deep structural equality — pairs (car+cdr), vectors (elementwise),
/// strings (char=), bytevectors, atoms via `eqv?` (so `(equal? 2 2.0) → #f`),
/// procedures by identity. **Cycle-safe and stack-safe**: an explicit work stack (no
/// host recursion → no overflow on deep data) plus a visited-set of aggregate
/// pointer-pairs, so a back-edge to an already-seen pair is co-inductively assumed
/// equal and the comparison terminates (§10). Each distinct `(ptr_a, ptr_b)` pair is
/// still compared once, so no real inequality is ever masked.
fn equal(a: &Value, b: &Value) -> bool {
    let mut work: Vec<(Value, Value)> = vec![(a.clone(), b.clone())];
    let mut visited: HashSet<(usize, usize)> = HashSet::new();
    while let Some((x, y)) = work.pop() {
        match (&x, &y) {
            (Value::Pair(p), Value::Pair(q)) => {
                if Rc::ptr_eq(p, q) {
                    continue;
                }
                let key = (Rc::as_ptr(p) as usize, Rc::as_ptr(q) as usize);
                if !visited.insert(key) {
                    continue; // already comparing these two nodes (cycle / shared) → assume equal
                }
                work.push((p.car.clone(), q.car.clone()));
                work.push((p.cdr.clone(), q.cdr.clone()));
            }
            (Value::Vector(v), Value::Vector(w)) => {
                if Rc::ptr_eq(v, w) {
                    continue;
                }
                let key = (Rc::as_ptr(v) as usize, Rc::as_ptr(w) as usize);
                if !visited.insert(key) {
                    continue;
                }
                let bv = v.items.borrow();
                let bw = w.items.borrow();
                if bv.len() != bw.len() {
                    return false;
                }
                for (e, f) in bv.iter().zip(bw.iter()) {
                    work.push((e.clone(), f.clone()));
                }
            }
            (Value::Str(s), Value::Str(t)) => {
                if **s != **t {
                    return false;
                }
            }
            (Value::Bytevector(s), Value::Bytevector(t)) => {
                if **s != **t {
                    return false;
                }
            }
            // Atoms (numbers w/ exactness, chars, syms, nil), procedures/conts, and any
            // cross-type mismatch (pair vs vector, …) → `eqv?` (which is #f for a mismatch).
            _ => {
                if !eqv(&x, &y) {
                    return false;
                }
            }
        }
    }
    true
}

// ── pairs / lists (§10) ─────────────────────────────────────────────────────────

/// `list?` — a TOTAL predicate (never errors): walks the spine, `#t` iff it ends in
/// `()` (pairs are immutable in v1 → the spine cannot be cyclic, so this terminates).
fn prim_list_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "list?", span, "1 argument", args.len());
    }
    let mut cur = args[0].clone();
    let ok = loop {
        match cur {
            Value::Nil => break true,
            Value::Pair(p) => cur = p.cdr.clone(),
            _ => break false,
        }
    };
    Eval::Ok(Outcome::One(Value::Bool(ok)))
}

/// `length` — proper list only; an improper/non-list value → E310 (per §task 3).
fn prim_length(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "length", span, "1 argument", args.len());
    }
    match list_elems(it, "length", span, RuntimeCode::E310, &args[0]) {
        Ok(elems) => Eval::Ok(Outcome::One(Value::int(elems.len()))),
        Err(e) => e,
    }
}

/// `reverse` — a fresh reversed proper list; improper/non-list → E312.
fn prim_reverse(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "reverse", span, "1 argument", args.len());
    }
    match list_elems(it, "reverse", span, RuntimeCode::E312, &args[0]) {
        Ok(mut elems) => {
            elems.reverse();
            Eval::Ok(Outcome::One(Value::list(elems.into_iter())))
        }
        Err(e) => e,
    }
}

/// `list` — the n-ary list constructor.
fn prim_list(_it: &mut Interp, args: &[Value], _span: Span) -> Eval {
    Eval::Ok(Outcome::One(Value::list(args.iter().cloned())))
}

/// `list-ref` (and its alias `nth`): `(list-ref lst k)`; improper → E312, OOB → E311.
fn prim_list_ref(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "list-ref", span, "2 arguments", args.len());
    }
    let elems = match list_elems(it, "list-ref", span, RuntimeCode::E312, &args[0]) {
        Ok(e) => e,
        Err(e) => return e,
    };
    let i = match want_exact_int(it, "list-ref", span, &args[1]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    match index_in_range(it, "list-ref", span, i, elems.len()) {
        Ok(k) => Eval::Ok(Outcome::One(elems[k].clone())),
        Err(e) => e,
    }
}

/// `list-tail` — `(list-tail lst k)`: the sublist after dropping the first `k` elements (the
/// k-th cdr; SHARED structure, not a copy). `k` an exact non-negative integer (non-int → E312,
/// negative/huge → E311). A list shorter than `k` (a cdr step lands on a non-pair) → E311;
/// `k`=0 returns `lst` unchanged (even a non-pair).
fn prim_list_tail(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "list-tail", span, "2 arguments", args.len());
    }
    let k_i = match want_exact_int(it, "list-tail", span, &args[1]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let k = match as_count(it, "list-tail", span, k_i) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let mut cur = args[0].clone();
    for _ in 0..k {
        match cur {
            Value::Pair(p) => cur = p.cdr.clone(),
            _ => return e311(it, span, format!("list-tail: index {k} out of range")),
        }
    }
    Eval::Ok(Outcome::One(cur))
}

/// `list-copy` — `(list-copy obj)`: a shallow copy of the list spine (fresh pairs, shared cars).
/// Total over values: a proper list copies to a fresh proper list, an improper list keeps its
/// final atom, and a non-pair is returned unchanged (R7RS).
fn prim_list_copy(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "list-copy", span, "1 argument", args.len());
    }
    let mut cars = Vec::new();
    let mut cur = args[0].clone();
    let terminal = loop {
        match cur {
            Value::Pair(p) => {
                cars.push(p.car.clone());
                cur = p.cdr.clone();
            }
            other => break other,
        }
    };
    let mut acc = terminal;
    for car in cars.into_iter().rev() {
        acc = Value::cons(car, acc);
    }
    Eval::Ok(Outcome::One(acc))
}

// ── the higher-order procedures (§task 1): apply a user proc, thread the signal ──

/// `map` — `(map f lst)`: apply `f` to each element, collect a fresh list. Each call
/// is a single-value context (0/≥2 values → E320). Errors/escapes from `f` propagate.
fn prim_map(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(
            it,
            "map",
            span,
            "2 arguments (a procedure and a list)",
            args.len(),
        );
    }
    let f = args[0].clone();
    let elems = match list_elems(it, "map", span, RuntimeCode::E312, &args[1]) {
        Ok(e) => e,
        Err(e) => return e,
    };
    let mut out = Vec::with_capacity(elems.len());
    for e in elems {
        match it.apply1(&f, vec![e], span) {
            Ok(v) => out.push(v),
            Err(sig) => return sig,
        }
    }
    Eval::Ok(Outcome::One(Value::list(out.into_iter())))
}

/// `filter` — `(filter p lst)`: keep elements for which `p` returns a truthy value.
fn prim_filter(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(
            it,
            "filter",
            span,
            "2 arguments (a predicate and a list)",
            args.len(),
        );
    }
    let p = args[0].clone();
    let elems = match list_elems(it, "filter", span, RuntimeCode::E312, &args[1]) {
        Ok(e) => e,
        Err(e) => return e,
    };
    let mut out = Vec::new();
    for e in elems {
        match it.apply1(&p, vec![e.clone()], span) {
            Ok(v) => {
                if is_truthy(&v) {
                    out.push(e);
                }
            }
            Err(sig) => return sig,
        }
    }
    Eval::Ok(Outcome::One(Value::list(out.into_iter())))
}

/// `any?` — checked profile extension `(any? p lst)`: left-to-right short-circuit,
/// returning strict `#t`/`#f` rather than the predicate's original truthy value.
fn prim_any_p(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(
            it,
            "any?",
            span,
            "2 arguments (a predicate and a list)",
            args.len(),
        );
    }
    let p = args[0].clone();
    let elems = match list_elems(it, "any?", span, RuntimeCode::E312, &args[1]) {
        Ok(e) => e,
        Err(e) => return e,
    };
    for e in elems {
        match it.apply1(&p, vec![e], span) {
            Ok(Value::Bool(true)) => return Eval::Ok(Outcome::One(Value::Bool(true))),
            Ok(Value::Bool(false)) => {}
            Ok(other) => return type_error(it, "any?", span, "a boolean predicate result", &other),
            Err(sig) => return sig,
        }
    }
    Eval::Ok(Outcome::One(Value::Bool(false)))
}

/// `all?` — checked profile extension `(all? p lst)`: left-to-right short-circuit,
/// returning strict `#t`/`#f`.
fn prim_all_p(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(
            it,
            "all?",
            span,
            "2 arguments (a predicate and a list)",
            args.len(),
        );
    }
    let p = args[0].clone();
    let elems = match list_elems(it, "all?", span, RuntimeCode::E312, &args[1]) {
        Ok(e) => e,
        Err(e) => return e,
    };
    for e in elems {
        match it.apply1(&p, vec![e], span) {
            Ok(Value::Bool(false)) => return Eval::Ok(Outcome::One(Value::Bool(false))),
            Ok(Value::Bool(true)) => {}
            Ok(other) => return type_error(it, "all?", span, "a boolean predicate result", &other),
            Err(sig) => return sig,
        }
    }
    Eval::Ok(Outcome::One(Value::Bool(true)))
}

/// `for-each` — `(for-each f lst)`: apply `f` to each element LEFT-TO-RIGHT for EFFECT,
/// discard the results, return unspecified (zero values). Unlike `map`, the per-element call
/// is a DISCARD context ([`Interp::apply`], any arity) — so `(for-each display lst)` works even
/// though `display` yields zero values (whereas `map`'s single-value `apply1` would fault E320).
/// Errors/escapes from `f` propagate; a non-list/improper second arg → E312.
fn prim_for_each(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(
            it,
            "for-each",
            span,
            "2 arguments (a procedure and a list)",
            args.len(),
        );
    }
    let f = args[0].clone();
    let elems = match list_elems(it, "for-each", span, RuntimeCode::E312, &args[1]) {
        Ok(e) => e,
        Err(e) => return e,
    };
    for e in elems {
        match it.apply(&f, vec![e], span) {
            Eval::Ok(_) => {}  // result discarded (run for effect)
            sig => return sig, // Error / Escape propagate
        }
    }
    Eval::Ok(zero()) // unspecified → zero values (§0.3), like display
}

/// `reduce` — left fold `(reduce f init lst)` with `f` called as `(f acc elem)`
/// left-to-right; an empty list returns `init`.
fn prim_reduce(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 3 {
        return arity_error(
            it,
            "reduce",
            span,
            "3 arguments (a procedure, an init, and a list)",
            args.len(),
        );
    }
    let f = args[0].clone();
    let mut acc = args[1].clone();
    let elems = match list_elems(it, "reduce", span, RuntimeCode::E312, &args[2]) {
        Ok(e) => e,
        Err(e) => return e,
    };
    for e in elems {
        acc = match it.apply1(&f, vec![acc, e], span) {
            Ok(v) => v,
            Err(sig) => return sig,
        };
    }
    Eval::Ok(Outcome::One(acc))
}

/// `fold-right` — right fold `(fold-right f init lst)` with `f` called as `(f elem acc)`,
/// processing elements RIGHT-to-left so the result is `(f e1 (f e2 (f e3 init)))`; an empty
/// list returns `init`. (`fold-left` is a real alias of `reduce`, which is the left fold.)
/// Collects the spine first then iterates in reverse, so it stays iterative (no host
/// recursion) and a long list cannot overflow the stack.
fn prim_fold_right(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 3 {
        return arity_error(
            it,
            "fold-right",
            span,
            "3 arguments (a procedure, an init, and a list)",
            args.len(),
        );
    }
    let f = args[0].clone();
    let mut acc = args[1].clone();
    let elems = match list_elems(it, "fold-right", span, RuntimeCode::E312, &args[2]) {
        Ok(e) => e,
        Err(e) => return e,
    };
    for e in elems.into_iter().rev() {
        acc = match it.apply1(&f, vec![e, acc], span) {
            Ok(v) => v,
            Err(sig) => return sig,
        };
    }
    Eval::Ok(Outcome::One(acc))
}

// ── list search (§10): member/assoc families share a cmp fn (like eq?/eqv?) ──────

/// `(member obj list)` family: return the FIRST sublist (the `Pair` itself, so the result
/// shares the list's `Rc` and is `eq?` to that tail) whose car satisfies `cmp`, else `#f`.
/// Iterative spine walk (no host recursion); the search STOPS at the first match, so junk
/// after a match is never inspected. An unmatched improper/non-list tail → E312 (the §10
/// list-op fault used by reverse/list-ref/map/filter/reduce, not length's E310).
fn member_impl(
    it: &mut Interp,
    name: &str,
    args: &[Value],
    span: Span,
    cmp: fn(&Value, &Value) -> bool,
) -> Eval {
    if args.len() != 2 {
        return arity_error(it, name, span, "2 arguments", args.len());
    }
    let mut cur = args[1].clone();
    loop {
        match cur {
            Value::Nil => return Eval::Ok(Outcome::One(Value::Bool(false))),
            Value::Pair(p) => {
                if cmp(&p.car, &args[0]) {
                    return Eval::Ok(Outcome::One(Value::Pair(p)));
                }
                cur = p.cdr.clone();
            }
            other => return type_error(it, name, span, "a proper list", &other),
        }
    }
}

/// `(assoc obj alist)` family: return the FIRST entry pair whose car satisfies `cmp`, else
/// `#f`. Each entry must be a pair; a non-pair entry that is reached → E312. Stops at the
/// first match (a bad entry AFTER the match is never seen); an unmatched improper/non-list
/// alist tail → E312.
fn assoc_impl(
    it: &mut Interp,
    name: &str,
    args: &[Value],
    span: Span,
    cmp: fn(&Value, &Value) -> bool,
) -> Eval {
    if args.len() != 2 {
        return arity_error(it, name, span, "2 arguments", args.len());
    }
    let mut cur = args[1].clone();
    loop {
        match cur {
            Value::Nil => return Eval::Ok(Outcome::One(Value::Bool(false))),
            Value::Pair(p) => {
                match &p.car {
                    Value::Pair(entry) => {
                        if cmp(&entry.car, &args[0]) {
                            return Eval::Ok(Outcome::One(p.car.clone()));
                        }
                    }
                    other => {
                        return type_error(
                            it,
                            name,
                            span,
                            "an association list (each entry a pair)",
                            other,
                        )
                    }
                }
                cur = p.cdr.clone();
            }
            other => return type_error(it, name, span, "an association list", &other),
        }
    }
}

fn prim_member(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    member_impl(it, "member", args, span, equal)
}

fn prim_memv(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    member_impl(it, "memv", args, span, eqv)
}

fn prim_memq(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    // eq? ≡ eqv? in v1 (§6), so memq shares memv's comparison.
    member_impl(it, "memq", args, span, eqv)
}

fn prim_assoc(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    assoc_impl(it, "assoc", args, span, equal)
}

fn prim_assv(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    assoc_impl(it, "assv", args, span, eqv)
}

fn prim_assq(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    // eq? ≡ eqv? in v1 (§6), so assq shares assv's comparison.
    assoc_impl(it, "assq", args, span, eqv)
}

// ── deprecated aliases (W3xx warn, then delegate to the canonical primitive) ─────

fn prim_percent(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    it.warn(
        WarnCode::W330,
        span,
        "`%` is a deprecated alias of `modulo` — prefer `modulo`",
    );
    prim_modulo(it, args, span)
}

fn prim_list_first(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    it.warn(
        WarnCode::W331,
        span,
        "`list-first` is a deprecated alias of `first` (car) — prefer `first`",
    );
    prim_car(it, args, span)
}

fn prim_list_rest(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    it.warn(
        WarnCode::W331,
        span,
        "`list-rest` is a deprecated alias of `rest` (cdr) — prefer `rest`",
    );
    prim_cdr(it, args, span)
}

// ── strings (§10; immutable in v1 — no string-set!) ─────────────────────────────

fn prim_string_append(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    let mut s = String::new();
    for a in args {
        match want_str(it, "string-append", span, a) {
            Ok(t) => s.push_str(t),
            Err(e) => return e,
        }
    }
    Eval::Ok(Outcome::One(Value::Str(Rc::from(s.as_str()))))
}

fn prim_string_length(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "string-length", span, "1 argument", args.len());
    }
    match want_str(it, "string-length", span, &args[0]) {
        Ok(s) => Eval::Ok(Outcome::One(Value::int(s.chars().count()))),
        Err(e) => e,
    }
}

/// `substring` — `(substring s start end)`, character indices, `0 ≤ start ≤ end ≤ len`;
/// any out-of-range bound → E311.
fn prim_substring(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 3 {
        return arity_error(it, "substring", span, "3 arguments", args.len());
    }
    let s = match want_str(it, "substring", span, &args[0]) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let start_i = match want_exact_int(it, "substring", span, &args[1]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let end_i = match want_exact_int(it, "substring", span, &args[2]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    use num_traits::ToPrimitive;
    let start = match start_i.to_usize() {
        Some(k) if k <= len => k,
        _ => {
            return e311(
                it,
                span,
                format!("substring: start {start_i} out of range (length {len})"),
            )
        }
    };
    let end = match end_i.to_usize() {
        Some(k) if k <= len => k,
        _ => {
            return e311(
                it,
                span,
                format!("substring: end {end_i} out of range (length {len})"),
            )
        }
    };
    if start > end {
        return e311(
            it,
            span,
            format!("substring: start {start} is past end {end}"),
        );
    }
    let sub: String = chars[start..end].iter().collect();
    Eval::Ok(Outcome::One(Value::Str(Rc::from(sub.as_str()))))
}

/// `string-ref` — `(string-ref s k)`: the character at CHARACTER index `k` (0-based, matching
/// `string-length`/`substring`, NOT a byte offset). Non-string → E312; non-integer `k` → E312;
/// out-of-range `k` → E311 (like `vector-ref`).
fn prim_string_ref(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "string-ref", span, "2 arguments", args.len());
    }
    let s = match want_str(it, "string-ref", span, &args[0]) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let chars: Vec<char> = s.chars().collect();
    let i = match want_exact_int(it, "string-ref", span, &args[1]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    match index_in_range(it, "string-ref", span, i, chars.len()) {
        Ok(k) => Eval::Ok(Outcome::One(Value::Char(chars[k]))),
        Err(e) => e,
    }
}

fn prim_string_to_list(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "string->list", span, "1 argument", args.len());
    }
    match want_str(it, "string->list", span, &args[0]) {
        Ok(s) => Eval::Ok(Outcome::One(Value::list(s.chars().map(Value::Char)))),
        Err(e) => e,
    }
}

/// `string->vector` — `(string->vector s [start [end]])`: a fresh MUTABLE vector of the characters
/// of `s` in the half-open range `[start, end)` (start defaults 0, end the length; bounds inclusive
/// of the length, like `substring`/`vector-copy`). Non-string → E312; a non-integer/out-of-range
/// bound or start > end → E311.
fn prim_string_to_vector(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() || args.len() > 3 {
        return arity_error(it, "string->vector", span, "1 to 3 arguments", args.len());
    }
    let chars: Vec<char> = match want_str(it, "string->vector", span, &args[0]) {
        Ok(s) => s.chars().collect(),
        Err(e) => return e,
    };
    let len = chars.len();
    use num_traits::ToPrimitive;
    let start = if args.len() >= 2 {
        let i = match want_exact_int(it, "string->vector", span, &args[1]) {
            Ok(i) => i,
            Err(e) => return e,
        };
        match i.to_usize() {
            Some(k) if k <= len => k,
            _ => {
                return e311(
                    it,
                    span,
                    format!("string->vector: start {i} out of range (length {len})"),
                )
            }
        }
    } else {
        0
    };
    let end = if args.len() == 3 {
        let i = match want_exact_int(it, "string->vector", span, &args[2]) {
            Ok(i) => i,
            Err(e) => return e,
        };
        match i.to_usize() {
            Some(k) if k <= len => k,
            _ => {
                return e311(
                    it,
                    span,
                    format!("string->vector: end {i} out of range (length {len})"),
                )
            }
        }
    } else {
        len
    };
    if start > end {
        return e311(
            it,
            span,
            format!("string->vector: start {start} is past end {end}"),
        );
    }
    Eval::Ok(Outcome::One(Value::vector(
        chars[start..end].iter().map(|c| Value::Char(*c)).collect(),
    )))
}

/// `string-copy` — `(string-copy s [start [end]])`: a fresh string with the characters of `s` in the
/// half-open range `[start, end)` (start defaults 0, end the length; CHARACTER indices, bounds
/// inclusive of the length, like `substring`). Non-string → E312; a non-integer/out-of-range bound
/// or start > end → E311. The result is always a freshly allocated string (observable via `eq?`).
fn prim_string_copy(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() || args.len() > 3 {
        return arity_error(it, "string-copy", span, "1 to 3 arguments", args.len());
    }
    let chars: Vec<char> = match want_str(it, "string-copy", span, &args[0]) {
        Ok(s) => s.chars().collect(),
        Err(e) => return e,
    };
    let len = chars.len();
    use num_traits::ToPrimitive;
    let start = if args.len() >= 2 {
        let i = match want_exact_int(it, "string-copy", span, &args[1]) {
            Ok(i) => i,
            Err(e) => return e,
        };
        match i.to_usize() {
            Some(k) if k <= len => k,
            _ => {
                return e311(
                    it,
                    span,
                    format!("string-copy: start {i} out of range (length {len})"),
                )
            }
        }
    } else {
        0
    };
    let end = if args.len() == 3 {
        let i = match want_exact_int(it, "string-copy", span, &args[2]) {
            Ok(i) => i,
            Err(e) => return e,
        };
        match i.to_usize() {
            Some(k) if k <= len => k,
            _ => {
                return e311(
                    it,
                    span,
                    format!("string-copy: end {i} out of range (length {len})"),
                )
            }
        }
    } else {
        len
    };
    if start > end {
        return e311(
            it,
            span,
            format!("string-copy: start {start} is past end {end}"),
        );
    }
    let sub: String = chars[start..end].iter().collect();
    Eval::Ok(Outcome::One(Value::Str(Rc::from(sub.as_str()))))
}

/// `make-string` — `(make-string k [char])`: a string of `k` copies of `char`. The default fill is
/// `#\space` (R7RS leaves it unspecified; the reference pins it for determinism, like `make-vector`).
/// `k` an exact non-negative count (non-int → E312, negative/huge → E311); a non-char fill → E312.
fn prim_make_string(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() || args.len() > 2 {
        return arity_error(it, "make-string", span, "1 or 2 arguments", args.len());
    }
    let k_i = match want_exact_int(it, "make-string", span, &args[0]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let k = match as_count(it, "make-string", span, k_i) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let fill = if args.len() == 2 {
        match want_char(it, "make-string", span, &args[1]) {
            Ok(c) => c,
            Err(e) => return e,
        }
    } else {
        ' '
    };
    let s = fill.to_string().repeat(k);
    Eval::Ok(Outcome::One(Value::Str(Rc::from(s.as_str()))))
}

/// `string-upcase` — `(string-upcase s)`: `s` with the Unicode FULL uppercasing algorithm
/// (`str::to_uppercase`). The result may change length (e.g. "ß" → "SS"). Unicode-table based, so
/// deterministic (not libc/locale dependent). Always a freshly allocated string. Non-string → E312.
fn prim_string_upcase(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "string-upcase", span, "1 argument", args.len());
    }
    match want_str(it, "string-upcase", span, &args[0]) {
        Ok(s) => Eval::Ok(Outcome::One(Value::Str(Rc::from(
            s.to_uppercase().as_str(),
        )))),
        Err(e) => e,
    }
}

/// `string-downcase` — `(string-downcase s)`: `s` with the Unicode FULL lowercasing algorithm
/// (`str::to_lowercase`, including context-sensitive final-sigma and length-changing mappings like
/// `İ` → `i` + combining dot). Deterministic; always freshly allocated. Non-string → E312.
fn prim_string_downcase(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "string-downcase", span, "1 argument", args.len());
    }
    match want_str(it, "string-downcase", span, &args[0]) {
        Ok(s) => Eval::Ok(Outcome::One(Value::Str(Rc::from(
            s.to_lowercase().as_str(),
        )))),
        Err(e) => e,
    }
}

/// `string-foldcase` — `(string-foldcase s)`: the case-folded string (the fold `string-ci…?` use).
/// v1 folds via full lowercase (`str::to_lowercase`), so it is a functional twin of `string-downcase`
/// here; true Unicode full case-folding (e.g. "ß" → "ss") is a v2 refinement. Always a fresh string.
fn prim_string_foldcase(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "string-foldcase", span, "1 argument", args.len());
    }
    match want_str(it, "string-foldcase", span, &args[0]) {
        Ok(s) => Eval::Ok(Outcome::One(Value::Str(Rc::from(
            s.to_lowercase().as_str(),
        )))),
        Err(e) => e,
    }
}

fn prim_list_to_string(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "list->string", span, "1 argument", args.len());
    }
    let elems = match list_elems(it, "list->string", span, RuntimeCode::E312, &args[0]) {
        Ok(e) => e,
        Err(e) => return e,
    };
    let mut s = String::new();
    for e in &elems {
        match e {
            Value::Char(c) => s.push(*c),
            other => return type_error(it, "list->string", span, "a list of characters", other),
        }
    }
    Eval::Ok(Outcome::One(Value::Str(Rc::from(s.as_str()))))
}

fn prim_string_to_symbol(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "string->symbol", span, "1 argument", args.len());
    }
    match want_str(it, "string->symbol", span, &args[0]) {
        Ok(s) => Eval::Ok(Outcome::One(Value::Sym(Rc::from(s)))),
        Err(e) => e,
    }
}

fn prim_symbol_to_string(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "symbol->string", span, "1 argument", args.len());
    }
    match &args[0] {
        Value::Sym(s) => Eval::Ok(Outcome::One(Value::Str(s.clone()))),
        other => type_error(it, "symbol->string", span, "a symbol", other),
    }
}

/// `string->number` — parse per the §2 grammar: a valid token → the number; a
/// grammar-matching but non-finite real (e.g. `"1e9999"`) → E314 (§2 finite check); any
/// other unparsable string → `#f`.
fn prim_string_to_number(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() || args.len() > 2 {
        return arity_error(it, "string->number", span, "1 or 2 arguments", args.len());
    }
    let s = match want_str(it, "string->number", span, &args[0]) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let radix = match want_radix(it, "string->number", span, args.get(1)) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if radix == 10 {
        return match parse_number_token(s) {
            NumberParse::Number(v) => Eval::Ok(Outcome::One(v)),
            NumberParse::NotANumber => Eval::Ok(Outcome::One(Value::Bool(false))),
            NumberParse::NotFinite => Eval::Error(it.rt(
                RuntimeCode::E314,
                span,
                format!("string->number: inexact result is not finite: {s:?}"),
            )),
        };
    }
    // A non-decimal radix (2/8/16) parses a signed integer only; anything else → #f (NOT an error).
    // v1 does not honor an in-string radix prefix (e.g. "#xff") when a radix arg is given → #f.
    let v = match parse_int_radix(s, radix) {
        Some(i) => Value::Int(i),
        None => Value::Bool(false),
    };
    Eval::Ok(Outcome::One(v))
}

// ── chars (§10) ─────────────────────────────────────────────────────────────────

fn prim_char_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "char?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(matches!(args[0], Value::Char(_)))))
}

fn prim_char_to_integer(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "char->integer", span, "1 argument", args.len());
    }
    match &args[0] {
        Value::Char(c) => Eval::Ok(Outcome::One(Value::int(*c as u32))),
        other => type_error(it, "char->integer", span, "a character", other),
    }
}

/// `integer->char` — a code point in `0..=#x10FFFF`, excluding surrogates; an
/// out-of-range / surrogate value → a clean E312 (§10 "a clean error").
fn prim_integer_to_char(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "integer->char", span, "1 argument", args.len());
    }
    let i = match want_exact_int(it, "integer->char", span, &args[0]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    use num_traits::ToPrimitive;
    match i.to_u32().and_then(char::from_u32) {
        Some(c) => Eval::Ok(Outcome::One(Value::Char(c))),
        None => type_error(
            it,
            "integer->char",
            span,
            "a Unicode scalar value (0..=#x10FFFF, not a surrogate)",
            &args[0],
        ),
    }
}

/// Extract a [`char`] operand, or E312 (`char` is `Copy`, returned by value).
fn want_char(it: &Interp, name: &str, span: Span, v: &Value) -> Result<char, Eval> {
    match v {
        Value::Char(c) => Ok(*c),
        other => Err(type_error(it, name, span, "a character", other)),
    }
}

/// A variadic character comparison chain (`char=? char<? char>? char<=? char>=?`),
/// pairwise left-to-right over Unicode scalar order (Rust `char` ordering IS codepoint
/// order, matching `char->integer`). Mirrors the numeric [`cmp_chain`]: ≥2 args (else E302),
/// every operand classified to a `char` up front (a non-char in ANY position → E312, even
/// when an earlier pair already settles the result).
fn char_cmp_chain(it: &mut Interp, name: &str, args: &[Value], span: Span, op: CmpOp) -> Eval {
    if args.len() < 2 {
        return arity_error(it, name, span, "at least 2 arguments", args.len());
    }
    let mut chars = Vec::with_capacity(args.len());
    for a in args {
        match want_char(it, name, span, a) {
            Ok(c) => chars.push(c),
            Err(e) => return e,
        }
    }
    let ok = chars.windows(2).all(|w| match op {
        CmpOp::Eq => w[0] == w[1],
        CmpOp::Lt => w[0] < w[1],
        CmpOp::Gt => w[0] > w[1],
        CmpOp::Le => w[0] <= w[1],
        CmpOp::Ge => w[0] >= w[1],
    });
    Eval::Ok(Outcome::One(Value::Bool(ok)))
}

fn prim_char_eq(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_cmp_chain(it, "char=?", args, span, CmpOp::Eq)
}

fn prim_char_lt(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_cmp_chain(it, "char<?", args, span, CmpOp::Lt)
}

fn prim_char_gt(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_cmp_chain(it, "char>?", args, span, CmpOp::Gt)
}

fn prim_char_le(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_cmp_chain(it, "char<=?", args, span, CmpOp::Le)
}

fn prim_char_ge(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_cmp_chain(it, "char>=?", args, span, CmpOp::Ge)
}

/// A variadic case-INSENSITIVE character comparison chain (`char-ci=?` …): like [`char_cmp_chain`]
/// but each operand is folded via [`simple_foldcase_approx`] first (ASCII-exact; see that fn for the
/// known v1 divergences). ≥2 args (else E302); a non-char in ANY position → E312.
fn char_ci_cmp_chain(it: &mut Interp, name: &str, args: &[Value], span: Span, op: CmpOp) -> Eval {
    if args.len() < 2 {
        return arity_error(it, name, span, "at least 2 arguments", args.len());
    }
    let mut chars = Vec::with_capacity(args.len());
    for a in args {
        match want_char(it, name, span, a) {
            Ok(c) => chars.push(simple_foldcase_approx(c)),
            Err(e) => return e,
        }
    }
    let ok = chars.windows(2).all(|w| match op {
        CmpOp::Eq => w[0] == w[1],
        CmpOp::Lt => w[0] < w[1],
        CmpOp::Gt => w[0] > w[1],
        CmpOp::Le => w[0] <= w[1],
        CmpOp::Ge => w[0] >= w[1],
    });
    Eval::Ok(Outcome::One(Value::Bool(ok)))
}

fn prim_char_ci_eq(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_ci_cmp_chain(it, "char-ci=?", args, span, CmpOp::Eq)
}

fn prim_char_ci_lt(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_ci_cmp_chain(it, "char-ci<?", args, span, CmpOp::Lt)
}

fn prim_char_ci_gt(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_ci_cmp_chain(it, "char-ci>?", args, span, CmpOp::Gt)
}

fn prim_char_ci_le(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_ci_cmp_chain(it, "char-ci<=?", args, span, CmpOp::Le)
}

fn prim_char_ci_ge(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_ci_cmp_chain(it, "char-ci>=?", args, span, CmpOp::Ge)
}

/// A 1-argument character classification predicate (`char-alphabetic?` etc.): REQUIRES a character
/// (a non-char → E312, unlike the total `char?`), returns the boolean Unicode classification.
fn char_pred(it: &mut Interp, name: &str, args: &[Value], span: Span, f: fn(char) -> bool) -> Eval {
    if args.len() != 1 {
        return arity_error(it, name, span, "1 argument", args.len());
    }
    match want_char(it, name, span, &args[0]) {
        Ok(c) => Eval::Ok(Outcome::One(Value::Bool(f(c)))),
        Err(e) => e,
    }
}

fn prim_char_alphabetic(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_pred(it, "char-alphabetic?", args, span, char::is_alphabetic)
}

/// `char-numeric?` — v1 recognizes ASCII decimal digits `#\0`..`#\9` only. Rust std has no Unicode
/// decimal-digit (`Nd`) test, and `char::is_numeric` is too broad (it also matches `Nl`/`No`, so e.g.
/// `¾`/`①` would wrongly count). Full Unicode `Nd` is deferred to v2; this avoids false positives.
fn prim_char_numeric(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_pred(it, "char-numeric?", args, span, |c| c.is_ascii_digit())
}

fn prim_char_whitespace(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_pred(it, "char-whitespace?", args, span, char::is_whitespace)
}

fn prim_char_upper_case(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_pred(it, "char-upper-case?", args, span, char::is_uppercase)
}

fn prim_char_lower_case(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_pred(it, "char-lower-case?", args, span, char::is_lowercase)
}

/// The Unicode SIMPLE uppercase of `c` (a single char). Rust std exposes only the FULL mapping
/// (`char::to_uppercase`, an iterator that may yield >1 char); the simple mapping is the single char
/// of the full mapping, or `c` itself when the full mapping expands (e.g. `ß`→"SS" ⇒ simple is `ß`).
/// Every char whose full uppercase expands has simple-uppercase == itself, so this is exact.
fn simple_upcase(c: char) -> char {
    let mut u = c.to_uppercase();
    match (u.next(), u.next()) {
        (Some(x), None) => x,
        _ => c,
    }
}

/// The Unicode SIMPLE lowercase of `c` (a single char). Like [`simple_upcase`], but `U+0130` `İ` is
/// the one char whose simple lowercase (`i`) differs from the collapse of its full lowercase
/// (`i` + combining dot above) — handled explicitly so the result matches the Unicode simple table.
fn simple_downcase(c: char) -> char {
    if c == '\u{0130}' {
        return 'i';
    }
    let mut l = c.to_lowercase();
    match (l.next(), l.next()) {
        (Some(x), None) => x,
        _ => c,
    }
}

/// A v1 APPROXIMATION of Unicode simple case folding (used by the `char-ci` family; `string-ci` folds
/// via the full `str::to_lowercase` instead). True case folding needs the Unicode CaseFolding table
/// (not in std); we delegate to simple
/// lowercase. This is EXACT for ASCII and the common Latin range, but DIVERGES from true folding for
/// a handful of chars where folding ≠ lowercasing — e.g. `µ` U+00B5 (folds to `μ`), the long s `ſ`
/// (→ `s`), and the Greek final sigma `ς` (→ `σ`). Those cases compare case-SENSITIVELY here; exact
/// folding is a v2 refinement. Named distinctly so it is never conflated with `char-downcase`.
fn simple_foldcase_approx(c: char) -> char {
    simple_downcase(c)
}

/// A 1-argument character case converter (`char-upcase`/`char-downcase`): requires a character
/// (a non-char → E312) and returns the SIMPLE single-char case mapping.
fn char_case(it: &mut Interp, name: &str, args: &[Value], span: Span, f: fn(char) -> char) -> Eval {
    if args.len() != 1 {
        return arity_error(it, name, span, "1 argument", args.len());
    }
    match want_char(it, name, span, &args[0]) {
        Ok(c) => Eval::Ok(Outcome::One(Value::Char(f(c)))),
        Err(e) => e,
    }
}

fn prim_char_upcase(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_case(it, "char-upcase", args, span, simple_upcase)
}

fn prim_char_downcase(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_case(it, "char-downcase", args, span, simple_downcase)
}

/// `char-foldcase` — `(char-foldcase c)`: the case-folded character (the fold `char-ci…?` use, via
/// [`simple_foldcase_approx`]; ASCII-exact, with the documented v1 divergences from true folding).
fn prim_char_foldcase(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    char_case(it, "char-foldcase", args, span, simple_foldcase_approx)
}

/// `boolean=?` — `(boolean=? b1 b2 ...)`: #t iff all operands are booleans AND all equal. ≥2 args
/// (else E302); a non-boolean in ANY position → E312 (type-checked up front, like `char=?`).
fn prim_boolean_eq(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() < 2 {
        return arity_error(it, "boolean=?", span, "at least 2 arguments", args.len());
    }
    let mut vals = Vec::with_capacity(args.len());
    for a in args {
        match a {
            Value::Bool(b) => vals.push(*b),
            other => return type_error(it, "boolean=?", span, "a boolean", other),
        }
    }
    Eval::Ok(Outcome::One(Value::Bool(
        vals.windows(2).all(|w| w[0] == w[1]),
    )))
}

/// `symbol=?` — `(symbol=? s1 s2 ...)`: #t iff all operands are symbols AND all equal (by name —
/// `Value::Sym` is the symbol's name). ≥2 args (else E302); a non-symbol in ANY position → E312.
fn prim_symbol_eq(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() < 2 {
        return arity_error(it, "symbol=?", span, "at least 2 arguments", args.len());
    }
    let mut names = Vec::with_capacity(args.len());
    for a in args {
        match a {
            Value::Sym(s) => names.push(s.as_ref()),
            other => return type_error(it, "symbol=?", span, "a symbol", other),
        }
    }
    Eval::Ok(Outcome::One(Value::Bool(
        names.windows(2).all(|w| w[0] == w[1]),
    )))
}

/// A variadic string comparison chain (`string=? string<? string>? string<=? string>=?`),
/// pairwise left-to-right, LEXICOGRAPHIC by Unicode scalar. Rust `&str` byte-ordering IS
/// scalar-lexicographic order for valid UTF-8, and `Value::Str` is always validated UTF-8, so
/// the operands compare directly — no char-by-char loop, no normalization (R7RS compares the
/// raw scalar sequences). Mirrors [`char_cmp_chain`]: ≥2 args (else E302), every operand
/// classified to a string up front (a non-string in ANY position → E312).
fn str_cmp_chain(it: &mut Interp, name: &str, args: &[Value], span: Span, op: CmpOp) -> Eval {
    if args.len() < 2 {
        return arity_error(it, name, span, "at least 2 arguments", args.len());
    }
    let mut strs = Vec::with_capacity(args.len());
    for a in args {
        match want_str(it, name, span, a) {
            Ok(s) => strs.push(s),
            Err(e) => return e,
        }
    }
    let ok = strs.windows(2).all(|w| match op {
        CmpOp::Eq => w[0] == w[1],
        CmpOp::Lt => w[0] < w[1],
        CmpOp::Gt => w[0] > w[1],
        CmpOp::Le => w[0] <= w[1],
        CmpOp::Ge => w[0] >= w[1],
    });
    Eval::Ok(Outcome::One(Value::Bool(ok)))
}

fn prim_string_eq(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    str_cmp_chain(it, "string=?", args, span, CmpOp::Eq)
}

fn prim_string_lt(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    str_cmp_chain(it, "string<?", args, span, CmpOp::Lt)
}

fn prim_string_gt(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    str_cmp_chain(it, "string>?", args, span, CmpOp::Gt)
}

fn prim_string_le(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    str_cmp_chain(it, "string<=?", args, span, CmpOp::Le)
}

fn prim_string_ge(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    str_cmp_chain(it, "string>=?", args, span, CmpOp::Ge)
}

/// A variadic case-INSENSITIVE string comparison chain (`string-ci=?` …): like [`str_cmp_chain`] but
/// each operand is folded via `str::to_lowercase` (full lowercase, = `string-downcase`'s mapping) — a
/// documented v1 approximation of Unicode case folding (ASCII-exact; e.g. `"ß"` vs `"SS"` compares
/// case-sensitively here, a v2 refinement). ≥2 args (else E302); a non-string in any position → E312.
fn str_ci_cmp_chain(it: &mut Interp, name: &str, args: &[Value], span: Span, op: CmpOp) -> Eval {
    if args.len() < 2 {
        return arity_error(it, name, span, "at least 2 arguments", args.len());
    }
    let mut strs: Vec<String> = Vec::with_capacity(args.len());
    for a in args {
        match want_str(it, name, span, a) {
            Ok(s) => strs.push(s.to_lowercase()),
            Err(e) => return e,
        }
    }
    let ok = strs.windows(2).all(|w| match op {
        CmpOp::Eq => w[0] == w[1],
        CmpOp::Lt => w[0] < w[1],
        CmpOp::Gt => w[0] > w[1],
        CmpOp::Le => w[0] <= w[1],
        CmpOp::Ge => w[0] >= w[1],
    });
    Eval::Ok(Outcome::One(Value::Bool(ok)))
}

fn prim_string_ci_eq(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    str_ci_cmp_chain(it, "string-ci=?", args, span, CmpOp::Eq)
}

fn prim_string_ci_lt(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    str_ci_cmp_chain(it, "string-ci<?", args, span, CmpOp::Lt)
}

fn prim_string_ci_gt(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    str_ci_cmp_chain(it, "string-ci>?", args, span, CmpOp::Gt)
}

fn prim_string_ci_le(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    str_ci_cmp_chain(it, "string-ci<=?", args, span, CmpOp::Le)
}

fn prim_string_ci_ge(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    str_ci_cmp_chain(it, "string-ci>=?", args, span, CmpOp::Ge)
}

/// `string-map` — `(string-map proc s)`: a fresh string whose char i is `(proc s[i])`. Single-string
/// (like `map`/`vector-map`); each call is a single-value context (0/≥2 values → E320) and the result
/// MUST be a character (a non-char → E312). The chars are snapshot before any call.
fn prim_string_map(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(
            it,
            "string-map",
            span,
            "2 arguments (a procedure and a string)",
            args.len(),
        );
    }
    let f = args[0].clone();
    let chars: Vec<char> = match want_str(it, "string-map", span, &args[1]) {
        Ok(s) => s.chars().collect(),
        Err(e) => return e,
    };
    let mut out = String::with_capacity(chars.len());
    for c in chars {
        match it.apply1(&f, vec![Value::Char(c)], span) {
            Ok(Value::Char(rc)) => out.push(rc),
            Ok(other) => {
                return type_error(
                    it,
                    "string-map",
                    span,
                    "a character from the procedure",
                    &other,
                )
            }
            Err(sig) => return sig,
        }
    }
    Eval::Ok(Outcome::One(Value::Str(Rc::from(out.as_str()))))
}

/// `string-for-each` — `(string-for-each proc s)`: apply `proc` to each char left-to-right for EFFECT
/// (discard context); result is unspecified (zero values). Single-string, char-snapshot like
/// [`prim_string_map`].
fn prim_string_for_each(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(
            it,
            "string-for-each",
            span,
            "2 arguments (a procedure and a string)",
            args.len(),
        );
    }
    let f = args[0].clone();
    let chars: Vec<char> = match want_str(it, "string-for-each", span, &args[1]) {
        Ok(s) => s.chars().collect(),
        Err(e) => return e,
    };
    for c in chars {
        match it.apply(&f, vec![Value::Char(c)], span) {
            Eval::Ok(_) => {}  // result discarded (run for effect)
            sig => return sig, // Error / Escape propagate
        }
    }
    Eval::Ok(zero())
}

// ── vectors (§10; the one mutable aggregate — vector-set! only) ──────────────────

/// `make-vector` — `(make-vector k [fill])`. Default fill is the exact integer `0`
/// (R7RS leaves it unspecified; the reference pins it for determinism). Mutable.
fn prim_make_vector(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() || args.len() > 2 {
        return arity_error(it, "make-vector", span, "1 or 2 arguments", args.len());
    }
    let k_i = match want_exact_int(it, "make-vector", span, &args[0]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let k = match as_count(it, "make-vector", span, k_i) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let fill = if args.len() == 2 {
        args[1].clone()
    } else {
        Value::int(0)
    };
    Eval::Ok(Outcome::One(Value::vector(vec![fill; k])))
}

/// `make-list` — `(make-list k [fill])`: a freshly allocated proper list of `k` copies of `fill`.
/// The default fill is the exact integer `0` (R7RS leaves it unspecified; pinned for determinism,
/// like `make-vector`). `k` an exact non-negative count (non-int → E312, negative/huge → E311).
fn prim_make_list(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() || args.len() > 2 {
        return arity_error(it, "make-list", span, "1 or 2 arguments", args.len());
    }
    let k_i = match want_exact_int(it, "make-list", span, &args[0]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let k = match as_count(it, "make-list", span, k_i) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let fill = if args.len() == 2 {
        args[1].clone()
    } else {
        Value::int(0)
    };
    Eval::Ok(Outcome::One(Value::list(vec![fill; k].into_iter())))
}

/// `vector` — the n-ary (mutable) vector constructor.
fn prim_vector(_it: &mut Interp, args: &[Value], _span: Span) -> Eval {
    Eval::Ok(Outcome::One(Value::vector(args.to_vec())))
}

fn prim_vector_ref(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "vector-ref", span, "2 arguments", args.len());
    }
    let data = match &args[0] {
        Value::Vector(d) => d,
        other => return type_error(it, "vector-ref", span, "a vector", other),
    };
    let i = match want_exact_int(it, "vector-ref", span, &args[1]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let items = data.items.borrow();
    match index_in_range(it, "vector-ref", span, i, items.len()) {
        Ok(k) => Eval::Ok(Outcome::One(items[k].clone())),
        Err(e) => e,
    }
}

/// `vector-set!` — mutate in place; a non-vector OR an **immutable (quoted) vector** →
/// E312 (§10); OOB → E311; yields zero values (§0.3 "unspecified").
fn prim_vector_set(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 3 {
        return arity_error(it, "vector-set!", span, "3 arguments", args.len());
    }
    let data = match &args[0] {
        Value::Vector(d) => d,
        other => return type_error(it, "vector-set!", span, "a vector", other),
    };
    if !data.mutable {
        return Eval::Error(it.rt(
            RuntimeCode::E312,
            span,
            "vector-set!: cannot mutate an immutable (quoted/literal) vector",
        ));
    }
    let i = match want_exact_int(it, "vector-set!", span, &args[1]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let len = data.items.borrow().len();
    match index_in_range(it, "vector-set!", span, i, len) {
        Ok(k) => {
            data.items.borrow_mut()[k] = args[2].clone();
            Eval::Ok(zero())
        }
        Err(e) => e,
    }
}

fn prim_vector_length(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "vector-length", span, "1 argument", args.len());
    }
    match &args[0] {
        Value::Vector(d) => Eval::Ok(Outcome::One(Value::int(d.items.borrow().len()))),
        other => type_error(it, "vector-length", span, "a vector", other),
    }
}

fn prim_vector_to_list(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "vector->list", span, "1 argument", args.len());
    }
    match &args[0] {
        Value::Vector(d) => Eval::Ok(Outcome::One(Value::list(d.items.borrow().iter().cloned()))),
        other => type_error(it, "vector->list", span, "a vector", other),
    }
}

/// `vector->string` — `(vector->string v [start [end]])`: a fresh string of the characters of `v` in
/// the half-open range `[start, end)` (bounds like `vector-copy`). Every element IN RANGE must be a
/// character (a non-char → E312); elements outside the range are not inspected. Non-vector → E312;
/// a non-integer/out-of-range bound or start > end → E311.
fn prim_vector_to_string(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() || args.len() > 3 {
        return arity_error(it, "vector->string", span, "1 to 3 arguments", args.len());
    }
    let data = match &args[0] {
        Value::Vector(d) => d,
        other => return type_error(it, "vector->string", span, "a vector", other),
    };
    let items = data.items.borrow();
    let len = items.len();
    use num_traits::ToPrimitive;
    let start = if args.len() >= 2 {
        let i = match want_exact_int(it, "vector->string", span, &args[1]) {
            Ok(i) => i,
            Err(e) => return e,
        };
        match i.to_usize() {
            Some(k) if k <= len => k,
            _ => {
                return e311(
                    it,
                    span,
                    format!("vector->string: start {i} out of range (length {len})"),
                )
            }
        }
    } else {
        0
    };
    let end = if args.len() == 3 {
        let i = match want_exact_int(it, "vector->string", span, &args[2]) {
            Ok(i) => i,
            Err(e) => return e,
        };
        match i.to_usize() {
            Some(k) if k <= len => k,
            _ => {
                return e311(
                    it,
                    span,
                    format!("vector->string: end {i} out of range (length {len})"),
                )
            }
        }
    } else {
        len
    };
    if start > end {
        return e311(
            it,
            span,
            format!("vector->string: start {start} is past end {end}"),
        );
    }
    let mut out = String::with_capacity(end - start);
    for v in &items[start..end] {
        match v {
            Value::Char(c) => out.push(*c),
            other => {
                return type_error(it, "vector->string", span, "a vector of characters", other)
            }
        }
    }
    Eval::Ok(Outcome::One(Value::Str(Rc::from(out.as_str()))))
}

/// `vector-copy` — `(vector-copy v [start [end]])`: a freshly allocated, MUTABLE vector holding
/// the elements of `v` in the half-open range `[start, end)` (start defaults to 0, end to the
/// length). The input is only read — never mutated — so copying an immutable (quoted) vector
/// yields a mutable copy. A non-vector OR a non-integer bound → E312; an out-of-range bound
/// (negative or > len) or start > end → E311. Bounds are inclusive of the length
/// (`0 ≤ start ≤ end ≤ len`), like `substring`.
fn prim_vector_copy(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() || args.len() > 3 {
        return arity_error(it, "vector-copy", span, "1 to 3 arguments", args.len());
    }
    let data = match &args[0] {
        Value::Vector(d) => d,
        other => return type_error(it, "vector-copy", span, "a vector", other),
    };
    let items = data.items.borrow();
    let len = items.len();
    use num_traits::ToPrimitive;
    let start = if args.len() >= 2 {
        let i = match want_exact_int(it, "vector-copy", span, &args[1]) {
            Ok(i) => i,
            Err(e) => return e,
        };
        match i.to_usize() {
            Some(k) if k <= len => k,
            _ => {
                return e311(
                    it,
                    span,
                    format!("vector-copy: start {i} out of range (length {len})"),
                )
            }
        }
    } else {
        0
    };
    let end = if args.len() == 3 {
        let i = match want_exact_int(it, "vector-copy", span, &args[2]) {
            Ok(i) => i,
            Err(e) => return e,
        };
        match i.to_usize() {
            Some(k) if k <= len => k,
            _ => {
                return e311(
                    it,
                    span,
                    format!("vector-copy: end {i} out of range (length {len})"),
                )
            }
        }
    } else {
        len
    };
    if start > end {
        return e311(
            it,
            span,
            format!("vector-copy: start {start} is past end {end}"),
        );
    }
    Eval::Ok(Outcome::One(Value::vector(items[start..end].to_vec())))
}

/// `vector-map` — `(vector-map proc v)`: a fresh MUTABLE vector whose element i is `(proc v[i])`.
/// Single-vector (consistent with the list `map`); each call is a single-value context (0/≥2
/// values → E320). The elements are SNAPSHOT before any call (the borrow is dropped) so the proc
/// may safely read or `vector-set!` the same vector without a re-entrant `RefCell` panic.
fn prim_vector_map(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(
            it,
            "vector-map",
            span,
            "2 arguments (a procedure and a vector)",
            args.len(),
        );
    }
    let f = args[0].clone();
    let items: Vec<Value> = match &args[1] {
        Value::Vector(d) => d.items.borrow().iter().cloned().collect(),
        other => return type_error(it, "vector-map", span, "a vector", other),
    };
    let mut out = Vec::with_capacity(items.len());
    for e in items {
        match it.apply1(&f, vec![e], span) {
            Ok(v) => out.push(v),
            Err(sig) => return sig,
        }
    }
    Eval::Ok(Outcome::One(Value::vector(out)))
}

/// `vector-for-each` — `(vector-for-each proc v)`: apply `proc` to each element left-to-right for
/// EFFECT (discard context, so a zero-value proc like `display` is fine); result is unspecified
/// (zero values). Single-vector, and snapshot-before-apply like [`prim_vector_map`].
fn prim_vector_for_each(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(
            it,
            "vector-for-each",
            span,
            "2 arguments (a procedure and a vector)",
            args.len(),
        );
    }
    let f = args[0].clone();
    let items: Vec<Value> = match &args[1] {
        Value::Vector(d) => d.items.borrow().iter().cloned().collect(),
        other => return type_error(it, "vector-for-each", span, "a vector", other),
    };
    for e in items {
        match it.apply(&f, vec![e], span) {
            Eval::Ok(_) => {}  // result discarded (run for effect)
            sig => return sig, // Error / Escape propagate
        }
    }
    Eval::Ok(zero()) // unspecified → zero values (§0.3)
}

// ── bytevectors (§12; immutable read accessors in v1 — no bytevector-u8-set!) ─────

/// `(make-bytevector k [byte])` — a k-length bytevector filled with `byte` (default the
/// exact integer 0, mirroring `make-vector`). `k` an exact non-negative count; `byte` 0..=255.
fn prim_make_bytevector(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() || args.len() > 2 {
        return arity_error(it, "make-bytevector", span, "1 or 2 arguments", args.len());
    }
    let k_i = match want_exact_int(it, "make-bytevector", span, &args[0]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let k = match as_count(it, "make-bytevector", span, k_i) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let fill = if args.len() == 2 {
        match want_byte(it, "make-bytevector", span, &args[1]) {
            Ok(b) => b,
            Err(e) => return e,
        }
    } else {
        0u8
    };
    Eval::Ok(Outcome::One(Value::Bytevector(Rc::new(vec![fill; k]))))
}

/// `(bytevector byte …)` — a bytevector from the given bytes (each 0..=255); zero args → `#u8()`.
fn prim_bytevector(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    let mut bytes = Vec::with_capacity(args.len());
    for a in args {
        match want_byte(it, "bytevector", span, a) {
            Ok(b) => bytes.push(b),
            Err(e) => return e,
        }
    }
    Eval::Ok(Outcome::One(Value::Bytevector(Rc::new(bytes))))
}

/// `(bytevector-length bv)` — the number of bytes; a non-bytevector → E312.
fn prim_bytevector_length(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "bytevector-length", span, "1 argument", args.len());
    }
    match &args[0] {
        Value::Bytevector(b) => Eval::Ok(Outcome::One(Value::int(b.len()))),
        other => type_error(it, "bytevector-length", span, "a bytevector", other),
    }
}

/// `(bytevector-u8-ref bv k)` — the byte at index `k` as an exact integer; non-bytevector or
/// non-integer `k` → E312, out-of-range `k` → E311 (mirrors `vector-ref`).
fn prim_bytevector_u8_ref(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(it, "bytevector-u8-ref", span, "2 arguments", args.len());
    }
    let bytes = match &args[0] {
        Value::Bytevector(b) => b,
        other => return type_error(it, "bytevector-u8-ref", span, "a bytevector", other),
    };
    let i = match want_exact_int(it, "bytevector-u8-ref", span, &args[1]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    match index_in_range(it, "bytevector-u8-ref", span, i, bytes.len()) {
        Ok(k) => Eval::Ok(Outcome::One(Value::int(bytes[k]))),
        Err(e) => e,
    }
}

// ── total type predicates (§10) — all total (never error on the value) ───────────

fn prim_symbol_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "symbol?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(matches!(args[0], Value::Sym(_)))))
}

fn prim_string_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "string?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(matches!(args[0], Value::Str(_)))))
}

fn prim_boolean_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "boolean?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(matches!(args[0], Value::Bool(_)))))
}

fn prim_vector_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "vector?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(matches!(
        args[0],
        Value::Vector(_)
    ))))
}

fn prim_bytevector_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "bytevector?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(matches!(
        args[0],
        Value::Bytevector(_)
    ))))
}

/// `procedure?` — closures, primitives, and (R6) continuations are procedures.
fn prim_procedure_q(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "procedure?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(matches!(
        args[0],
        Value::Closure(_) | Value::Primitive(_) | Value::Cont(_)
    ))))
}

// ── I/O (§11): display/write/newline/println — buffered, return zero values ──────

fn prim_display(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "display", span, "1 argument", args.len());
    }
    let s = args[0].display_repr();
    it.output.push_str(&s);
    Eval::Ok(zero())
}

fn prim_write(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "write", span, "1 argument", args.len());
    }
    let s = args[0].write_repr();
    it.output.push_str(&s);
    Eval::Ok(zero())
}

fn prim_newline(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if !args.is_empty() {
        return arity_error(it, "newline", span, "0 arguments", args.len());
    }
    it.output.push('\n');
    Eval::Ok(zero())
}

/// `println` = `(begin (display x) (newline))` (§11).
fn prim_println(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "println", span, "1 argument", args.len());
    }
    let s = args[0].display_repr();
    it.output.push_str(&s);
    it.output.push('\n');
    Eval::Ok(zero())
}

// ─────────────────────────────────────────────────────────────────────────────
// R6: the error procedure (§8), escape-only call/cc + dynamic-wind (§9), and the
// call-with-values multiple-values sink (§5).
// ─────────────────────────────────────────────────────────────────────────────

/// `(error message irritant…)` (§8) → an **E330** runtime fault that propagates as
/// [`Eval::Error`] to the top level and aborts (v1 has no catching — only a `call/cc`
/// catches its own tagged escape, never an error). The message is the first argument
/// (a string is used raw; any other value is rendered via `write`); the remaining
/// arguments are the irritants, rendered via `write` by [`RuntimeError`]'s `Display`
/// in the deterministic `CODE file:line:col message irritant…` format (§8).
fn prim_error(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.is_empty() {
        return arity_error(it, "error", span, "at least 1 argument (a message)", 0);
    }
    let message = match &args[0] {
        Value::Str(s) => s.to_string(),
        other => other.write_repr(),
    };
    let irritants = args[1..].to_vec();
    let eo = Value::ErrorObject(Rc::new(crate::value::ErrorObj {
        message: message.as_str().into(),
        irritants: irritants.clone(),
    }));
    // A raw, non-continuable `E330` fault carrying the error object as its condition. The
    // `eval` boundary ([`Interp::settle`]) dispatches it to the current handler in place;
    // uncaught it renders as the established `E330` (message + irritants), unchanged.
    Eval::Error(RuntimeError {
        code: RuntimeCode::E330,
        file: it.file.clone(),
        span,
        message,
        irritants,
        condition: Some(Box::new(eo)),
        dispatched: false,
        continuable: false,
    })
}

/// `(call/cc proc)` — escape-only, one-shot **upward** continuation (§9), implemented
/// via the threaded [`Eval::Escape`] signal (NOT host unwinding → backend-portable).
///
/// Mint a FRESH unique tag, mark it live (its frame is now on the stack), and call
/// `proc` with a one-argument escape procedure `k` = [`Value::Cont`] carrying the tag.
/// Invoking `(k v…)` returns `Eval::Escape{tag, vals}` (see [`Interp::invoke_cont`]),
/// which unwinds outward; THIS frame catches the matching tag and returns `(values v…)`.
/// A non-matching escape — or an error, or a normal return — propagates unchanged
/// (so errors are never caught, §8, and an outer `call/cc`'s escape passes through).
///
/// The tag is removed from the live set the instant this frame returns, by ANY path
/// (caught here, propagated, or `proc` returned normally) — so a `k` captured and
/// invoked after this returns is no longer live → E340.
fn prim_call_cc(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "call/cc", span, "1 argument (a procedure)", args.len());
    }
    let proc = args[0].clone();
    // Mint a fresh, never-reused tag and enter this frame's dynamic extent.
    let tag = it.next_tag;
    it.next_tag += 1;
    it.live_tags.insert(tag);
    let k = Value::Cont(Rc::new(Continuation {
        tag,
        used: FlagCell::new(false),
    }));

    let result = it.apply(&proc, vec![k], span);

    // Leaving the frame: its extent ends now (whether we caught, propagate, or proc
    // returned), so the tag is no longer live (a later `(k …)` → E340).
    it.live_tags.remove(&tag);

    match result {
        // Our own escape: catch it and return its values (`(values v…)`, §9).
        Eval::Escape { tag: t, vals } if t == tag => Eval::Ok(vals),
        // Normal return, an error, or some OTHER frame's escape: propagate unchanged.
        other => other,
    }
}

/// `(dynamic-wind before thunk after)` (§9): run `(before)`, then `(thunk)`, then
/// `(after)`; the result is the thunk's value(s). On an escape OR error propagating
/// through `thunk`, the pending `(after)` still runs (cleanup) and then the signal
/// continues outward; `before` never re-runs (escape-only ⇒ no re-entry). Nested winds
/// nest as nested primitive calls, so their `after`s run innermost-first on unwind.
///
/// **Precedence (§9):** if `after` itself raises/escapes while a signal is already in
/// flight (from `thunk`), the NEW signal REPLACES the in-flight one. `before`/`after`
/// run in discard context (any arity — only their signal matters, the outcome is
/// dropped); if `before` itself signals, the wind is never established (no `after`).
fn prim_dynamic_wind(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 3 {
        return arity_error(
            it,
            "dynamic-wind",
            span,
            "3 arguments (before, thunk, after)",
            args.len(),
        );
    }
    let before = args[0].clone();
    let thunk = args[1].clone();
    let after = args[2].clone();

    // `before` establishes the wind; if it signals, the wind never starts → no `after`.
    match it.apply(&before, vec![], span) {
        Eval::Ok(_) => {}
        signal => return signal,
    }

    // The wind is established: capture the thunk's outcome/signal, then ALWAYS run
    // `after` (cleanup), even when `thunk` escaped or errored.
    let thunk_result = it.apply(&thunk, vec![], span);
    let after_result = it.apply(&after, vec![], span);

    match after_result {
        // `after` completed cleanly → the thunk's outcome (or its in-flight signal) stands.
        Eval::Ok(_) => thunk_result,
        // `after` itself signalled → it REPLACES whatever was in flight (precedence, §9).
        signal => signal,
    }
}

/// `(with-exception-handler handler thunk)` (v1.2, §8): install `handler` as the
/// current exception handler for the dynamic extent of `(thunk)`, then run `(thunk)`.
/// This is a PURE STACK MANAGER — it does not catch anything itself. Every catchable
/// fault (a user `raise`/`error` or an intrinsic `E3xx`, but NOT the recursion-limit
/// resource bound) is dispatched to the current handler at the `eval` boundary, IN
/// PLACE at the fault site (R7RS non-unwinding), by [`Interp::settle`] — with the
/// handler suppressed while it runs, so the handler's OWN faults reach the outer handler
/// and never re-enter itself. A handler is expected to escape its `raise` (e.g. via the
/// continuation `guard` captures); a non-continuable raise whose handler RETURNS is the
/// `E332` violation (a `raise-continuable` handler may return a value — `settle` makes
/// it the value of the raising call). We always pop our handler on EVERY exit
/// (return / escape / error).
fn prim_with_exception_handler(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(
            it,
            "with-exception-handler",
            span,
            "2 arguments (handler, thunk)",
            args.len(),
        );
    }
    let handler = args[0].clone();
    let thunk = args[1].clone();
    let base = it.handlers.len();
    it.handlers.push(handler);
    let r = it.apply(&thunk, vec![], span);
    it.handlers.truncate(base);
    r
}

/// `(raise obj)` (v1.2, §8): signal `obj` as a NON-continuable exception. The fault is
/// returned raw; the `eval` boundary ([`Interp::settle`]) dispatches it to the current
/// handler IN PLACE (at the raise point). Uncaught it surfaces as `E331`, with `obj`
/// rendered into the message and kept as the condition so a top-level diagnostic shows
/// what was raised. `obj` may be any value.
fn prim_raise(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "raise", span, "1 argument (a condition)", args.len());
    }
    let obj = args[0].clone();
    let mut re = it.rt(
        RuntimeCode::E331,
        span,
        format!("raised: {}", obj.write_repr()),
    );
    re.condition = Some(Box::new(obj));
    Eval::Error(re)
}

/// `(raise-continuable obj)` (v1.2, §8): like `raise`, but CONTINUABLE — if the handler
/// returns value(s) those become this call's value(s) (see [`Interp::settle`]). Uncaught
/// → `E331`.
fn prim_raise_continuable(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(
            it,
            "raise-continuable",
            span,
            "1 argument (a condition)",
            args.len(),
        );
    }
    let obj = args[0].clone();
    let mut re = it.rt(
        RuntimeCode::E331,
        span,
        format!("raised: {}", obj.write_repr()),
    );
    re.condition = Some(Box::new(obj));
    re.continuable = true;
    Eval::Error(re)
}

/// `(error-object? obj)` (v1.2): #t iff `obj` is an error object (made by `error` or
/// caught from an intrinsic fault).
fn prim_error_object_p(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "error-object?", span, "1 argument", args.len());
    }
    Eval::Ok(Outcome::One(Value::Bool(matches!(
        args[0],
        Value::ErrorObject(_)
    ))))
}

/// `(error-object-message obj)` (v1.2): the message string of an error object.
fn prim_error_object_message(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "error-object-message", span, "1 argument", args.len());
    }
    match &args[0] {
        Value::ErrorObject(e) => Eval::Ok(Outcome::One(Value::Str(e.message.clone()))),
        other => type_error(it, "error-object-message", span, "an error object", other),
    }
}

/// `(error-object-irritants obj)` (v1.2): a fresh list of an error object's irritants.
fn prim_error_object_irritants(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 1 {
        return arity_error(it, "error-object-irritants", span, "1 argument", args.len());
    }
    match &args[0] {
        Value::ErrorObject(e) => Eval::Ok(Outcome::One(Value::list(e.irritants.iter().cloned()))),
        other => type_error(it, "error-object-irritants", span, "an error object", other),
    }
}

/// `values` as a **first-class procedure** (§5): produce its already-evaluated
/// arguments as a multiple-values [`Outcome`] via [`into_outcome`] — exactly 1 collapses
/// to [`Outcome::One`], 0 → `Many([])`, ≥2 → `Many` — which is IDENTICAL to what the
/// dedicated `(values …)` core-form node ([`CoreKind::Values`]) yields (it, too, ends in
/// `into_outcome`). The literal `(values …)` FORM still normalizes to the core node; this
/// primitive backs a *bare* `values` reference, so it can be passed around / stored / used
/// as the consumer or producer of `call-with-values`. Both paths evaluate each operand in
/// a single-value context (the node via [`Interp::eval1`]; this prim via the `App`-operand
/// `eval1` before it is called), so they are observably the same. The single-value-context
/// discipline (E320) still applies wherever a resulting `Many` lands in a one-value
/// position (enforced by [`Interp::eval1`]/[`Interp::apply1`]).
fn prim_values(_it: &mut Interp, args: &[Value], _span: Span) -> Eval {
    Eval::Ok(into_outcome(args.to_vec()))
}

/// `(call-with-values producer consumer)` (§5): call `(producer)` with 0 args, capture
/// ALL its values (the producer continuation accepts any arity, §5), then apply
/// `consumer` to them — arity must match (incl. a dotted rest), else E302 (raised by
/// [`Interp::bind_call`]). The consumer's outcome is the result (any arity flows out).
///
/// ★ **Tail-transparency (§4).** The consumer call is the tail of `call-with-values`, so
/// it must inherit the CALLER'S tail position — otherwise a `call-with-values`-driven
/// self loop (e.g. an accumulator that recurses *through* `call-with-values`) would grow
/// the host stack one frame per hop and hit `recursion-limit` at ~10_000 iterations,
/// violating "§4 TCO through call-with-values". A primitive cannot perform a tail call
/// itself (it runs *below* the trampoline, so `it.apply(consumer, …)` is a stack-growing
/// `Interp::eval`). Instead we hand the consumer call back to the trampoline as an
/// `Eval::TailApply`: the `App` `Primitive` arm in [`Interp::eval_loop`] resolves it in
/// the caller's tail slot (real TCO), while the host [`Interp::apply`] path resolves it
/// bounded. The producer call STAYS here (it is the producer continuation — a discard
/// context that accepts any arity, §5 — not a tail position), and only its captured
/// values are forwarded.
fn prim_call_with_values(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() != 2 {
        return arity_error(
            it,
            "call-with-values",
            span,
            "2 arguments (a producer and a consumer)",
            args.len(),
        );
    }
    let producer = args[0].clone();
    let consumer = args[1].clone();

    let values = match it.apply(&producer, vec![], span) {
        Eval::Ok(Outcome::One(v)) => vec![v],
        Eval::Ok(Outcome::Many(vs)) => vs,
        signal => return signal, // producer escaped/errored → propagate
    };
    // Tail-apply hand-off (NOT `it.apply` — that would be a non-tail, stack-growing
    // call): the trampoline performs the consumer call in the caller's tail slot.
    Eval::TailApply {
        f: consumer,
        args: values,
    }
}

/// `(apply proc a1 … aN last-list)` — call `proc` with `a1..aN` followed by the ELEMENTS of
/// `last-list` (a proper list, else E312). ≥2 args (else E302); a non-procedure `proc` faults
/// E301 when the hand-off resolves; the callee's own arity is enforced by the callee. Like
/// [`prim_call_with_values`], it returns an [`Eval::TailApply`] so the call is a PROPER TAIL
/// CALL — the `App` `Primitive` arm of [`Interp::eval_loop`] re-resolves it in the caller's
/// tail slot, so `(apply loop …)` in tail position loops with no host-stack growth.
fn prim_apply(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    if args.len() < 2 {
        return arity_error(
            it,
            "apply",
            span,
            "at least 2 arguments (a procedure and a final list)",
            args.len(),
        );
    }
    let proc = args[0].clone();
    let mut call_args: Vec<Value> = args[1..args.len() - 1].to_vec();
    match list_elems(it, "apply", span, RuntimeCode::E312, &args[args.len() - 1]) {
        Ok(elems) => call_args.extend(elems),
        Err(e) => return e,
    }
    Eval::TailApply {
        f: proc,
        args: call_args,
    }
}

#[cfg(feature = "scored-native-contract")]
fn contract_decision(
    it: &mut Interp,
    args: &[Value],
    span: Span,
    decision: crate::value::Decision,
    name: &str,
) -> Eval {
    if !args.is_empty() {
        return arity_error(it, name, span, "0", args.len());
    }
    it.contract_decisions_created += 1;
    Eval::Ok(Outcome::One(Value::Decision(decision)))
}

#[cfg(feature = "scored-native-contract")]
fn prim_decision_approve(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    contract_decision(
        it,
        args,
        span,
        crate::value::Decision::Approve,
        "decision-approve",
    )
}

#[cfg(feature = "scored-native-contract")]
fn prim_decision_deny(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    contract_decision(
        it,
        args,
        span,
        crate::value::Decision::Deny,
        "decision-deny",
    )
}

#[cfg(feature = "scored-native-contract")]
fn prim_decision_review(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    contract_decision(
        it,
        args,
        span,
        crate::value::Decision::Review,
        "decision-review",
    )
}

#[cfg(feature = "scored-native-contract")]
fn prim_decision_invalid_input(it: &mut Interp, args: &[Value], span: Span) -> Eval {
    contract_decision(
        it,
        args,
        span,
        crate::value::Decision::InvalidInput,
        "decision-invalid-input",
    )
}
