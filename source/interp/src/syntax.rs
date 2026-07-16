//! Spanned surface syntax tree — the reader's output (the R1 → R2 seam).
//!
//! The reader produces [`Syntax`] nodes, NOT plain [`Value`] datums: every node
//! (atoms AND compound list/vector nodes, recursively) carries its source
//! [`Span`]. R2's hygienic normalizer consumes this tree and can therefore point
//! `E110`/`E130`/`E3xx` diagnostics and runtime call-site faults at source.
//!
//! Two distinct shapes, on purpose:
//! - [`Value`] is the **runtime data** type (LISPEX-RUNTIME.md §1).
//! - [`Syntax`] is the **reader/parser output**; it mirrors the datum shapes but
//!   adds spans and keeps the compound structure explicit ([`SyntaxKind::List`],
//!   [`SyntaxKind::DottedList`], [`SyntaxKind::Vector`]) so a normalizer can
//!   pattern-match it ergonomically.
//!
//! [`Syntax::to_value`] strips the spans and yields the plain runtime `Value`
//! (used wherever the program treats a datum as literal data — `quote`, vector
//! and bytevector literals, etc.).

use std::rc::Rc;

use num_bigint::BigInt;
use num_rational::BigRational;

use crate::reader::Span;
use crate::value::{Finite, Value};

/// A surface-syntax node: a datum shape plus the source span it was read from.
#[derive(Clone, Debug, PartialEq)]
pub struct Syntax {
    pub node: SyntaxKind,
    pub span: Span,
}

/// The datum shapes the reader can produce, with compound nodes holding spanned
/// children (so the whole tree is spanned, recursively).
#[derive(Clone, Debug, PartialEq)]
pub enum SyntaxKind {
    Bool(bool),
    /// Exact integer (§2). Rationals that reduce to an integer arrive here.
    Int(BigInt),
    /// Exact rational; INVARIANT q > 1, lowest terms, sign on the numerator.
    Rational(BigRational),
    /// Inexact real; always [`Finite`] (§2).
    Real(Finite),
    Char(char),
    /// Interned symbol name (case-sensitive, §12).
    Sym(Rc<str>),
    Str(Rc<str>),
    /// The empty list `()`.
    Nil,
    /// A proper list `(a b c)`.
    List(Vec<Syntax>),
    /// A dotted/improper list `(a b . tail)` (`items` is non-empty).
    DottedList(Vec<Syntax>, Box<Syntax>),
    /// A vector literal `#(…)`.
    Vector(Vec<Syntax>),
    /// A bytevector literal `#u8(…)`; elements are lexical bytes 0..=255 (§12).
    Bytevector(Vec<u8>),
}

impl Syntax {
    pub fn new(node: SyntaxKind, span: Span) -> Syntax {
        Syntax { node, span }
    }

    /// Extract the plain runtime [`Value`], dropping all spans. Used wherever a
    /// datum is treated as literal data (`quote`, vector/bytevector literals).
    pub fn to_value(&self) -> Value {
        match &self.node {
            SyntaxKind::Bool(b) => Value::Bool(*b),
            SyntaxKind::Int(i) => Value::Int(i.clone()),
            // Route through the checked constructor so the q>1 / demote-to-Int
            // invariant holds even if a node were built by hand.
            SyntaxKind::Rational(r) => Value::rational(r.clone()),
            SyntaxKind::Real(f) => Value::Real(*f),
            SyntaxKind::Char(c) => Value::Char(*c),
            SyntaxKind::Sym(s) => Value::Sym(s.clone()),
            SyntaxKind::Str(s) => Value::Str(s.clone()),
            SyntaxKind::Nil => Value::Nil,
            SyntaxKind::List(items) => Value::list(items.iter().map(Syntax::to_value)),
            SyntaxKind::DottedList(items, tail) => {
                Value::list_with_tail(items.iter().map(Syntax::to_value), tail.to_value())
            }
            // A `#(…)` literal is quoted/self-evaluating data → IMMUTABLE (§10:
            // mutating quoted data is E312).
            SyntaxKind::Vector(items) => {
                Value::vector_literal(items.iter().map(Syntax::to_value).collect())
            }
            SyntaxKind::Bytevector(bytes) => Value::Bytevector(Rc::new(bytes.clone())),
        }
    }
}
