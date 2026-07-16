//! Core AST — the post-normalization intermediate representation (Round 2).
//!
//! The R2 normalizer ([`crate::normalize`]) turns the reader's spanned surface
//! [`Syntax`](crate::syntax::Syntax) into this **Core AST**: the small, explicit
//! set of forms that survive normalization (LISPEX.md §5 / LISPEX-RUNTIME.md §7).
//! Every derived form (`cond`/`case`/`let*`/`and`/`or`/`when`/`unless`/`do`/named
//! `let`/quasiquote) has already been desugared away, so R3's evaluator only ever
//! interprets the variants below.
//!
//! ## Design (maps cleanly onto a future external backend recursive `enum`)
//!
//! - **Spans on every node.** [`CoreExpr`] is `{ kind, span }`; every synthesized
//!   node copies a relevant source [`Span`] from its origin form, so R3 can point
//!   runtime call-site faults (`E3xx`) at source even for desugared code.
//! - **Identifiers are an [`Ident`] enum** — `User(name)` for a source identifier,
//!   `Temp(n)` for a hygienic fresh identifier minted by an expansion. The two are
//!   *different enum variants*, so a `Temp` can NEVER collide with any source name
//!   regardless of spelling: this is the unshadowable "reserved namespace" required
//!   by §7.1. Temp numbering comes from a deterministic counter, so output is
//!   reproducible (same input → same AST, same temp numbers).
//! - **Hidden intrinsics are an [`Intrinsic`] enum**, referenced by a dedicated
//!   [`CoreKind::Intrinsic`] node (only ever in operator position). Desugarings
//!   that need `cons`/`append`/`list->vector`/`eqv?` emit the *intrinsic node*,
//!   NOT a [`CoreKind::Var`] of the surface name — so a program that rebinds
//!   `cons`/`append`/`eqv?`/… cannot change the meaning of a desugared
//!   `cond`/`case`/quasiquote. R3/R5 resolve an intrinsic node directly to its
//!   primitive (never via the lexical environment).
//! - `call/cc` / `call-with-values` / `dynamic-wind` are NOT special-cased: they
//!   normalize to ordinary [`CoreKind::App`] of a [`CoreKind::Var`] head that R6
//!   binds as a primitive. Only `values` keeps a dedicated node ([`CoreKind::Values`])
//!   since it is the multiple-values producer (an evaluation *outcome*, §5/§7).
//!
//! The [`CoreExpr::sexpr`] pretty-printer renders a span-free s-expression that the
//! R2 tests assert against (and which makes hygiene visible: an intrinsic prints as
//! `#<intrinsic:cons>` and a temp as `#:t0`, neither of which a reader can produce).

use std::rc::Rc;

use crate::reader::Span;
use crate::value::Value;

/// A Core identifier.
///
/// `User` is a source-written name (resolved by lexical lookup in R3); `Temp` is a
/// hygienic identifier minted by an expansion (e.g. the `t` in `or`'s
/// `(let ((t e1)) (if t t …))`, or the loop name in `do`). Because `Temp` is a
/// distinct variant, it cannot be captured or shadowed by any source identifier —
/// the §7.1 unshadowable temp namespace, enforced by the type system rather than by
/// name munging.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Ident {
    /// A source identifier (its interned name).
    User(Rc<str>),
    /// A fresh, unshadowable identifier from an expansion (deterministic counter).
    Temp(u32),
}

/// An intrinsic primitive referenced by desugarings or by the checked profile
/// (never user-shadowable inside that profile).
///
/// R2 expansions need the hidden quasiquote/case intrinsics (`cons`/`append`/
/// `list->vector`/`eqv?`). The checked profile later reuses the same enum for its
/// closed builtin surface, while keeping source-profile admission separate from
/// the hidden intrinsic set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intrinsic {
    /// Pair constructor (quasiquote list/dotted spine).
    Cons,
    /// List concatenation (quasiquote `unquote-splicing`).
    Append,
    /// List → vector (quasiquote of a vector template).
    ListToVector,
    /// `eqv?` comparator (the `case` key test, §0.1 sign-off — NOT `equal?`).
    Eqv,
    /// checked profile `+`.
    Add,
    /// checked profile `-`.
    Sub,
    /// checked profile `*`.
    Mul,
    /// checked profile `/`.
    Div,
    /// checked profile `modulo`.
    Modulo,
    /// checked profile `=`.
    NumEq,
    /// checked profile `<`.
    Lt,
    /// checked profile `>`.
    Gt,
    /// checked profile `<=`.
    Le,
    /// checked profile `>=`.
    Ge,
    /// checked profile `equal?`.
    Equal,
    /// checked profile `assoc` (`equal?` key comparison).
    Assoc,
    /// checked profile `assv` (`eqv?` key comparison).
    Assv,
    /// checked profile `member` (`equal?` element comparison).
    Member,
    /// checked profile `memv` (`eqv?` element comparison).
    Memv,
    /// checked profile `not`.
    Not,
    /// checked profile `string=?`.
    StringEq,
    /// checked profile `string<?`.
    StringLt,
    /// checked profile `string-append`.
    StringAppend,
    /// checked profile `number->string`.
    NumberToString,
    /// checked profile `null?`.
    NullP,
    /// checked profile `pair?`.
    PairP,
    /// checked profile `car`.
    Car,
    /// checked profile `cdr`.
    Cdr,
    /// checked profile `list`.
    List,
    /// checked profile `length`.
    Length,
    /// checked profile `list?`.
    ListP,
    /// checked profile `string?`.
    StringP,
    /// checked profile `number?`.
    NumberP,
    /// checked profile `boolean?`.
    BooleanP,
    /// checked profile `symbol?`.
    SymbolP,
    /// checked profile `min`.
    Min,
    /// checked profile `max`.
    Max,
    /// checked profile `abs`.
    Abs,
    /// checked profile `quotient`.
    Quotient,
    /// checked profile `remainder`.
    Remainder,
    /// checked profile `floor`.
    Floor,
    /// checked profile `ceiling`.
    Ceiling,
    /// checked profile `round`.
    Round,
    /// checked profile `truncate`.
    Truncate,
    /// checked profile `map`.
    Map,
    /// checked profile `filter`.
    Filter,
    /// checked profile `reduce`.
    Reduce,
    /// checked profile `fold-left`.
    FoldLeft,
    /// checked profile `fold-right`.
    FoldRight,
    /// checked profile `apply`.
    Apply,
    /// checked profile `values`.
    Values,
    /// checked profile `call-with-values`.
    CallWithValues,
    /// checked profile-only `any?`.
    AnyP,
    /// checked profile-only `all?`.
    AllP,
}

impl Intrinsic {
    /// The canonical surface name the intrinsic mirrors (for display only).
    pub fn name(self) -> &'static str {
        match self {
            Intrinsic::Cons => "cons",
            Intrinsic::Append => "append",
            Intrinsic::ListToVector => "list->vector",
            Intrinsic::Eqv => "eqv?",
            Intrinsic::Add => "+",
            Intrinsic::Sub => "-",
            Intrinsic::Mul => "*",
            Intrinsic::Div => "/",
            Intrinsic::Modulo => "modulo",
            Intrinsic::NumEq => "=",
            Intrinsic::Lt => "<",
            Intrinsic::Gt => ">",
            Intrinsic::Le => "<=",
            Intrinsic::Ge => ">=",
            Intrinsic::Equal => "equal?",
            Intrinsic::Assoc => "assoc",
            Intrinsic::Assv => "assv",
            Intrinsic::Member => "member",
            Intrinsic::Memv => "memv",
            Intrinsic::Not => "not",
            Intrinsic::StringEq => "string=?",
            Intrinsic::StringLt => "string<?",
            Intrinsic::StringAppend => "string-append",
            Intrinsic::NumberToString => "number->string",
            Intrinsic::NullP => "null?",
            Intrinsic::PairP => "pair?",
            Intrinsic::Car => "car",
            Intrinsic::Cdr => "cdr",
            Intrinsic::List => "list",
            Intrinsic::Length => "length",
            Intrinsic::ListP => "list?",
            Intrinsic::StringP => "string?",
            Intrinsic::NumberP => "number?",
            Intrinsic::BooleanP => "boolean?",
            Intrinsic::SymbolP => "symbol?",
            Intrinsic::Min => "min",
            Intrinsic::Max => "max",
            Intrinsic::Abs => "abs",
            Intrinsic::Quotient => "quotient",
            Intrinsic::Remainder => "remainder",
            Intrinsic::Floor => "floor",
            Intrinsic::Ceiling => "ceiling",
            Intrinsic::Round => "round",
            Intrinsic::Truncate => "truncate",
            Intrinsic::Map => "map",
            Intrinsic::Filter => "filter",
            Intrinsic::Reduce => "reduce",
            Intrinsic::FoldLeft => "fold-left",
            Intrinsic::FoldRight => "fold-right",
            Intrinsic::Apply => "apply",
            Intrinsic::Values => "values",
            Intrinsic::CallWithValues => "call-with-values",
            Intrinsic::AnyP => "any?",
            Intrinsic::AllP => "all?",
        }
    }

    /// Closed intrinsic name set accepted by Meaning Graph law.
    pub fn by_name(name: &str) -> Option<Intrinsic> {
        match name {
            "cons" => Some(Intrinsic::Cons),
            "append" => Some(Intrinsic::Append),
            "list->vector" => Some(Intrinsic::ListToVector),
            "eqv?" => Some(Intrinsic::Eqv),
            "+" => Some(Intrinsic::Add),
            "-" => Some(Intrinsic::Sub),
            "*" => Some(Intrinsic::Mul),
            "/" => Some(Intrinsic::Div),
            "modulo" => Some(Intrinsic::Modulo),
            "=" => Some(Intrinsic::NumEq),
            "<" => Some(Intrinsic::Lt),
            ">" => Some(Intrinsic::Gt),
            "<=" => Some(Intrinsic::Le),
            ">=" => Some(Intrinsic::Ge),
            "equal?" => Some(Intrinsic::Equal),
            "assoc" => Some(Intrinsic::Assoc),
            "assv" => Some(Intrinsic::Assv),
            "member" => Some(Intrinsic::Member),
            "memv" => Some(Intrinsic::Memv),
            "not" => Some(Intrinsic::Not),
            "string=?" => Some(Intrinsic::StringEq),
            "string<?" => Some(Intrinsic::StringLt),
            "string-append" => Some(Intrinsic::StringAppend),
            "number->string" => Some(Intrinsic::NumberToString),
            "null?" => Some(Intrinsic::NullP),
            "pair?" => Some(Intrinsic::PairP),
            "car" => Some(Intrinsic::Car),
            "cdr" => Some(Intrinsic::Cdr),
            "list" => Some(Intrinsic::List),
            "length" => Some(Intrinsic::Length),
            "list?" => Some(Intrinsic::ListP),
            "string?" => Some(Intrinsic::StringP),
            "number?" => Some(Intrinsic::NumberP),
            "boolean?" => Some(Intrinsic::BooleanP),
            "symbol?" => Some(Intrinsic::SymbolP),
            "min" => Some(Intrinsic::Min),
            "max" => Some(Intrinsic::Max),
            "abs" => Some(Intrinsic::Abs),
            "quotient" => Some(Intrinsic::Quotient),
            "remainder" => Some(Intrinsic::Remainder),
            "floor" => Some(Intrinsic::Floor),
            "ceiling" => Some(Intrinsic::Ceiling),
            "round" => Some(Intrinsic::Round),
            "truncate" => Some(Intrinsic::Truncate),
            "map" => Some(Intrinsic::Map),
            "filter" => Some(Intrinsic::Filter),
            "reduce" => Some(Intrinsic::Reduce),
            "fold-left" => Some(Intrinsic::FoldLeft),
            "fold-right" => Some(Intrinsic::FoldRight),
            "apply" => Some(Intrinsic::Apply),
            "values" => Some(Intrinsic::Values),
            "call-with-values" => Some(Intrinsic::CallWithValues),
            "any?" => Some(Intrinsic::AnyP),
            "all?" => Some(Intrinsic::AllP),
            _ => None,
        }
    }

    /// Source names admitted as checked profile builtins in v1.2.10.
    ///
    /// This intentionally excludes `list->vector`: it remains a hidden
    /// normalizer intrinsic for quasiquote, but vectors are outside the checked
    /// source profile for v1.3 unless a later slice changes that boundary.
    pub fn profile_by_name(name: &str) -> Option<Intrinsic> {
        match name {
            "list->vector" => None,
            _ => Intrinsic::by_name(name),
        }
    }
}

/// A `lambda` parameter list: fixed parameters plus an optional dotted/variadic
/// rest parameter (`(x y . rest)` → `fixed = [x, y]`, `rest = Some(rest)`).
#[derive(Clone, Debug, PartialEq)]
pub struct Formals {
    pub fixed: Vec<Ident>,
    pub rest: Option<Ident>,
}

/// One `let`/`letrec` binding: a name and its initializer expression.
#[derive(Clone, Debug, PartialEq)]
pub struct Binding {
    pub name: Ident,
    pub init: CoreExpr,
}

/// The surviving core forms (LISPEX.md §5 / LISPEX-RUNTIME.md §7).
#[derive(Clone, Debug, PartialEq)]
pub enum CoreKind {
    /// Variable reference.
    Var(Ident),
    /// A literal / `quote`d datum — an immutable [`Value`] (self-evaluating
    /// literals are normalized to this too).
    Quote(Value),
    /// `(if test then else)` — always 3-arm (else mandatory, §7).
    If(Box<CoreExpr>, Box<CoreExpr>, Box<CoreExpr>),
    /// `(lambda (formals) body)` — `body` is a single expr (a `Begin` when the
    /// source body had several expressions).
    Lambda {
        formals: Formals,
        body: Box<CoreExpr>,
    },
    /// Application: operator first, then operands (L→R eval is R3's job).
    App {
        op: Box<CoreExpr>,
        args: Vec<CoreExpr>,
    },
    /// `(begin e1 … en)`, n ≥ 1.
    Begin(Vec<CoreExpr>),
    /// `(set! id expr)`.
    Set { target: Ident, value: Box<CoreExpr> },
    /// `(define id expr)` (function-define sugar already lowered to a `lambda`).
    Define { name: Ident, value: Box<CoreExpr> },
    /// `(let ((id init) …) body)` — parallel binding.
    Let {
        bindings: Vec<Binding>,
        body: Box<CoreExpr>,
    },
    /// `(letrec ((id init) …) body)` — recursive binding.
    Letrec {
        bindings: Vec<Binding>,
        body: Box<CoreExpr>,
    },
    /// `(values e*)` — the multiple-values producer (0..N).
    Values(Vec<CoreExpr>),
    /// A hidden intrinsic reference (operator position only; unshadowable).
    Intrinsic(Intrinsic),
    /// `(guard (var clause…) body…)` (v1.2, §8): evaluate `body`; on a CATCHABLE fault
    /// bind `var` to the condition and run the `cond`-style `clauses`, reraising the
    /// original fault when none match and there is no `else`. A fixed surface form
    /// (NOT a user macro) normalized to this node — the procedural `guard` over the
    /// `Eval::Error` signal.
    Guard {
        var: Ident,
        clauses: Vec<GuardClause>,
        else_body: Option<Box<CoreExpr>>,
        body: Box<CoreExpr>,
    },
}

/// One clause of a [`CoreKind::Guard`]: a test and the body it runs when the test is
/// true (a `Begin` when the source clause had several body expressions).
#[derive(Clone, Debug, PartialEq)]
pub struct GuardClause {
    pub test: CoreExpr,
    pub body: CoreExpr,
}

/// A spanned Core node.
#[derive(Clone, Debug, PartialEq)]
pub struct CoreExpr {
    pub kind: CoreKind,
    pub span: Span,
}

impl CoreExpr {
    pub fn new(kind: CoreKind, span: Span) -> CoreExpr {
        CoreExpr { kind, span }
    }

    /// Render a **span-free** s-expression for tests / debugging. Hygienic temps
    /// print as `#:tN` and intrinsics as `#<intrinsic:NAME>`, so a desugaring's use
    /// of unshadowable names is directly visible (and asserted) in the output.
    pub fn sexpr(&self) -> String {
        crate::canonical::canonical_expr_string(self)
            .expect("source-derived CoreExpr should be canonically serializable")
    }
}
