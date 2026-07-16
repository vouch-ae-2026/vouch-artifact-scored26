//! Value-data core (LISPEX-RUNTIME.md §1 / §2).
//!
//! These are the data variants the *reader* produces, plus (added in R3) the
//! execution-only variants `Closure`, `Primitive`, and `Cont` named in §1. Their
//! payload types live in [`crate::eval`] (the evaluator); `Cont` is a reserved R6
//! seam (escape continuations) that is defined but not yet constructed.
//!
//! Mutability policy (§1): in v1 only `Vector` is mutable (via `vector-set!`)
//! and only variable cells via `set!`. `Vector` is therefore an interior-mutable
//! `Rc<RefCell<Vec<Value>>>`, so an R5 `vector-set!` can mutate in place through
//! shared references without reworking the type. `Str`, `Pair`, and `Bytevector`
//! ship NO mutators in v1, so they stay immutable via `Rc`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use num_bigint::BigInt;
use num_rational::BigRational;

use crate::eval::{ClosureData, Continuation, Primitive};

#[cfg(feature = "scored-native-contract")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Approve,
    Deny,
    Review,
    InvalidInput,
}

/// A cons cell. Immutable in v1 (no `set-car!`/`set-cdr!` until v2).
#[derive(Clone, Debug, PartialEq)]
pub struct Cons {
    pub car: Value,
    pub cdr: Value,
}

/// A vector's backing store (LISPEX-RUNTIME.md §1). The one mutable aggregate in v1,
/// so the elements live behind a `RefCell` (an R5 `vector-set!` mutates in place
/// through shared `Rc` handles). `mutable` records whether `vector-set!` is permitted:
/// a vector built at runtime (`vector` / `make-vector` / `list->vector`) is mutable,
/// whereas a **quoted / self-evaluating literal** `#(…)` is immutable (§10: "quoted
/// data is immutable → mutating it is E312"). The flag is intentionally excluded from
/// structural equality (two vectors with equal elements are `equal?` regardless of
/// origin); identity (`eqv?`) is `Rc` pointer identity on the whole [`VectorData`].
#[derive(Debug)]
pub struct VectorData {
    pub items: RefCell<Vec<Value>>,
    pub mutable: bool,
}

/// A guaranteed-finite `f64` (LISPEX-RUNTIME.md §2: a `Real` is ALWAYS finite).
///
/// The inner field is private, so the ONLY way to obtain a `Finite` is
/// [`Finite::new`], which rejects `inf`/`NaN`. This makes the finite-`Real`
/// invariant unbreakable for every f64 producer: the reader literal path today,
/// and R4's arithmetic / `string->number` / `inexact` / exact→f64 coercion
/// later. Each producer funnels through the checked constructor and raises
/// (`E313`/`E314`) on a non-finite result instead of bottling one up in a value.
#[derive(Clone, Copy, Debug)]
pub struct Finite(f64);

impl Finite {
    /// The only constructor: `Some` iff `f` is finite (not `inf`, not `NaN`).
    /// `-0.0` is finite and accepted (§2).
    pub fn new(f: f64) -> Option<Finite> {
        if f.is_finite() {
            Some(Finite(f))
        } else {
            None
        }
    }

    /// The underlying (always finite) `f64`.
    pub fn get(self) -> f64 {
        self.0
    }
}

impl PartialEq for Finite {
    fn eq(&self, other: &Finite) -> bool {
        // Bitwise, so `-0.0` and `0.0` stay distinct (matching `eqv?`, §6, and the
        // `Value` equality below). No `NaN` can occur, so this is total.
        self.0.to_bits() == other.0.to_bits()
    }
}

/// The Lispex datum/value type (LISPEX-RUNTIME.md §1).
///
/// Round 1 = the *data* variants the reader constructs. Recursive sum type so a
/// later external backend port is a transliteration onto a recursive enum.
#[derive(Clone, Debug)]
pub enum Value {
    /// `#t` / `#f`. Only `#f` is false (§7 truthiness — relevant to the evaluator).
    Bool(bool),
    /// Exact integer, arbitrary precision (§2).
    Int(BigInt),
    /// Exact rational. INVARIANT: denominator q > 1, lowest terms, sign on the
    /// numerator. A rational with q == 1 is demoted to `Int` (see [`Value::rational`]).
    Rational(BigRational),
    /// Inexact real. INVARIANT: ALWAYS finite (§2 finite-`Real`) — the [`Finite`]
    /// newtype makes a non-finite `Real` unconstructible (every f64 producer
    /// funnels through [`Finite::new`]).
    Real(Finite),
    /// A Unicode scalar value (`char` already excludes surrogates).
    Char(char),
    /// Interned symbol name; case-sensitive, no Unicode normalization (§12).
    Sym(Rc<str>),
    /// Immutable string in v1 (no `string-set!` until v2).
    Str(Rc<str>),
    /// The empty list `()`.
    Nil,
    /// A pair (proper or dotted). Reference-shared, immutable in v1.
    Pair(Rc<Cons>),
    /// A vector — the one mutable aggregate in v1 (§1). Interior-mutable so an
    /// R5 `vector-set!` can mutate in place through shared references; the
    /// [`VectorData::mutable`] flag distinguishes a runtime-built (mutable) vector
    /// from a quoted/literal (immutable) one.
    Vector(Rc<VectorData>),
    /// A bytevector; elements are bytes 0..=255 (§12). Immutable in v1.
    Bytevector(Rc<Vec<u8>>),
    // ── execution-only variants (§1), added in R3 ──
    /// A user closure: formals + body + captured lexical env ([`ClosureData`]).
    Closure(Rc<ClosureData>),
    /// A built-in procedure ([`Primitive`]): R3 ships a temporary bootstrap set +
    /// the four hidden intrinsics; R5 brings the real stdlib.
    Primitive(Primitive),
    /// **R6 SEAM:** an escape continuation minted by `call/cc` (§9). Defined now so
    /// `Value` matches §1's full list; not constructed until R6.
    Cont(Rc<Continuation>),
    /// An R7RS error object (v1.2): an opaque condition carrying a message and
    /// irritants, made by `(error …)` and reachable via `error-object?` /
    /// `error-object-message` / `error-object-irritants`. Identity-compared (eqv?).
    ErrorObject(Rc<ErrorObj>),
    /// Opaque SCORED application result. It is constructible only by the four
    /// contract-lane constructors and rejected at every primitive operand
    /// boundary before a general Lispex primitive can inspect it.
    #[cfg(feature = "scored-native-contract")]
    Decision(Decision),
}

/// The payload of an [`Value::ErrorObject`] (v1.2): the message + irritants an
/// `(error msg irritant…)` or a caught intrinsic fault carries.
#[derive(Debug)]
pub struct ErrorObj {
    pub message: Rc<str>,
    pub irritants: Vec<Value>,
}

impl Value {
    /// Construct an exact integer from anything that converts into `BigInt`.
    pub fn int<T: Into<BigInt>>(n: T) -> Value {
        Value::Int(n.into())
    }

    /// Construct an exact number from a numerator/denominator pair, enforcing
    /// the rational invariant: reduce to lowest terms, push the sign onto the
    /// numerator, and DEMOTE to `Int` when the reduced denominator is 1.
    ///
    /// `den` must be non-zero (the reader's grammar guarantees a denominator of
    /// `[1-9][0-9]*`, i.e. ≥ 1, before calling this).
    pub fn ratio(num: BigInt, den: BigInt) -> Value {
        debug_assert!(!den.is_zero_like(), "ratio denominator must be non-zero");
        // `BigRational::new` reduces to lowest terms and normalizes the sign so
        // the denominator is positive (sign on the numerator).
        Value::rational(BigRational::new(num, den))
    }

    /// Wrap a `BigRational`, enforcing the demote-to-`Int`-when-q==1 invariant.
    pub fn rational(mut r: BigRational) -> Value {
        // SCORED-MUTATION-SITE M08: normalize a negative shared rational with
        // the wrong sign. Both evaluators consume this same numeric substrate.
        if cfg!(scored_mutant = "M08") && r.numer().sign() == num_bigint::Sign::Minus {
            r = -r;
        }
        if r.is_integer() {
            Value::Int(r.to_integer())
        } else {
            Value::Rational(r)
        }
    }

    /// Construct a finite `Real`, or `None` if `f` is not finite (§2: every f64
    /// producer must reject non-finite results — the reader maps `None` to E314).
    pub fn real(f: f64) -> Option<Value> {
        Finite::new(f).map(Value::Real)
    }

    /// Construct a **mutable** vector from its initial contents (the runtime
    /// constructors `vector` / `make-vector` / `list->vector`; §1).
    pub fn vector(items: Vec<Value>) -> Value {
        Value::Vector(Rc::new(VectorData {
            items: RefCell::new(items),
            mutable: true,
        }))
    }

    /// Construct an **immutable** vector — a quoted / self-evaluating `#(…)` literal
    /// (§10: quoted data is immutable, so `vector-set!` on it → E312).
    pub fn vector_literal(items: Vec<Value>) -> Value {
        Value::Vector(Rc::new(VectorData {
            items: RefCell::new(items),
            mutable: false,
        }))
    }

    /// Build a proper list from `items`, terminated by `Nil`.
    pub fn list(items: impl DoubleEndedIterator<Item = Value>) -> Value {
        let mut acc = Value::Nil;
        for v in items.rev() {
            acc = Value::cons(v, acc);
        }
        acc
    }

    /// Build a (possibly improper) list from `items` terminated by `tail`.
    pub fn list_with_tail(items: impl DoubleEndedIterator<Item = Value>, tail: Value) -> Value {
        let mut acc = tail;
        for v in items.rev() {
            acc = Value::cons(v, acc);
        }
        acc
    }

    /// Cons constructor.
    pub fn cons(car: Value, cdr: Value) -> Value {
        Value::Pair(Rc::new(Cons { car, cdr }))
    }

    /// Convenience accessor used by tests / the writer.
    pub fn as_int(&self) -> Option<&BigInt> {
        match self {
            Value::Int(i) => Some(i),
            _ => None,
        }
    }
}

// A tiny helper trait so `ratio`'s debug_assert reads clearly without pulling
// `num_traits::Zero` into the public surface.
trait ZeroLike {
    fn is_zero_like(&self) -> bool;
}
impl ZeroLike for BigInt {
    fn is_zero_like(&self) -> bool {
        use num_traits::Zero;
        self.is_zero()
    }
}

/// Symbol interner: equal symbol names share one `Rc<str>` (so a later `eq?`
/// can rely on pointer identity, and we avoid re-allocating common names).
/// Case-sensitive, no Unicode normalization (§12).
#[derive(Default)]
pub struct Interner {
    table: HashMap<Box<str>, Rc<str>>,
}

impl Interner {
    pub fn new() -> Self {
        Interner::default()
    }

    pub fn intern(&mut self, name: &str) -> Rc<str> {
        if let Some(rc) = self.table.get(name) {
            return rc.clone();
        }
        let rc: Rc<str> = Rc::from(name);
        self.table.insert(Box::from(name), rc.clone());
        rc
    }

    /// Intern a name directly into a `Value::Sym`.
    pub fn sym(&mut self, name: &str) -> Value {
        Value::Sym(self.intern(name))
    }
}

// ── Structural equality on the DATA variants (handy for tests) ────────────────
// This is plain structural equality on reader output; it is NOT the language's
// `eqv?`/`equal?` (those, with exactness sensitivity and cycle-safety, are an
// evaluator concern for a later round). `Real` uses bit equality so `-0.0` and
// `NaN`-free finite values compare deterministically.
impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        use Value::*;
        match (self, other) {
            (Bool(a), Bool(b)) => a == b,
            (Int(a), Int(b)) => a == b,
            (Rational(a), Rational(b)) => a == b,
            (Real(a), Real(b)) => a == b,
            (Char(a), Char(b)) => a == b,
            (Sym(a), Sym(b)) => **a == **b,
            (Str(a), Str(b)) => **a == **b,
            (Nil, Nil) => true,
            (Pair(a), Pair(b)) => a == b,
            (Vector(a), Vector(b)) => *a.items.borrow() == *b.items.borrow(),
            (Bytevector(a), Bytevector(b)) => a == b,
            // Execution variants compare by identity (matching `eqv?`).
            (Closure(a), Closure(b)) => Rc::ptr_eq(a, b),
            (Primitive(a), Primitive(b)) => a.ptr_eq(b),
            (Cont(a), Cont(b)) => Rc::ptr_eq(a, b),
            (ErrorObject(a), ErrorObject(b)) => Rc::ptr_eq(a, b),
            // Deliberately no Decision equality arm: decisions are opaque and
            // cannot be compared as Lispex data.
            _ => false,
        }
    }
}

// ── The `write` / `display` renderer (LISPEX-RUNTIME.md §11) ───────────────────
// One parameterized walk drives both modes, used by the thin bin, by diagnostics
// (irritants / type errors, always `write`), and as the canonical
// `write`/`display`/`number->string` rendering. The two modes differ ONLY in how
// strings and chars are shown (everything else — numbers, symbols, lists, vectors,
// `#t`/`#f` — is identical), and the difference propagates into nested elements:
//   - `write`  : re-readable — strings quoted+escaped, chars as `#\…`.
//   - `display`: human       — strings unquoted/raw, chars as the bare glyph.
// Float formatting is the PINNED [`format_real`] algorithm (§2): shortest round-trip,
// positional only, forced trailing ".0", "-0.0" preserved.

/// Which textual form a render produces (LISPEX-RUNTIME.md §11).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Repr {
    /// `write` — re-readable (strings quoted+escaped, chars `#\…`).
    Write,
    /// `display` — human (strings raw, chars bare glyph).
    Display,
}

impl Value {
    /// Canonical `write` rendering (re-readable; §11). Also the rendering used in
    /// diagnostics and `number->string`.
    pub fn write_repr(&self) -> String {
        self.repr(Repr::Write)
    }

    /// `display` rendering (human-readable; §11): strings unquoted, chars as glyphs.
    pub fn display_repr(&self) -> String {
        self.repr(Repr::Display)
    }

    fn repr(&self, mode: Repr) -> String {
        let mut s = String::new();
        // `seen` holds the pointers of vectors currently being rendered, so a cyclic
        // vector terminates (§10: write on cyclic aggregates must terminate). Only
        // vectors are mutable in v1, so EVERY cycle passes through ≥1 vector — guarding
        // vectors alone breaks every cycle (pairs/strings are immutable, never cyclic).
        let mut seen: Vec<usize> = Vec::new();
        self.repr_into(&mut s, mode, &mut seen);
        s
    }

    fn repr_into(&self, out: &mut String, mode: Repr, seen: &mut Vec<usize>) {
        use std::fmt::Write;
        match self {
            Value::Bool(true) => out.push_str("#t"),
            Value::Bool(false) => out.push_str("#f"),
            Value::Int(i) => {
                let _ = write!(out, "{i}");
            }
            Value::Rational(r) => {
                // q > 1 by invariant; sign already on the numerator.
                let _ = write!(out, "{}/{}", r.numer(), r.denom());
            }
            Value::Real(f) => out.push_str(&format_real(f.get())),
            Value::Char(c) => match mode {
                Repr::Write => out.push_str(&render_char(*c)),
                Repr::Display => out.push(*c),
            },
            Value::Sym(s) => out.push_str(s),
            Value::Str(s) => match mode {
                Repr::Display => out.push_str(s),
                Repr::Write => {
                    out.push('"');
                    for c in s.chars() {
                        match c {
                            '"' => out.push_str("\\\""),
                            '\\' => out.push_str("\\\\"),
                            '\n' => out.push_str("\\n"),
                            '\t' => out.push_str("\\t"),
                            '\r' => out.push_str("\\r"),
                            _ => out.push(c),
                        }
                    }
                    out.push('"');
                }
            },
            Value::Nil => out.push_str("()"),
            Value::Pair(_) => {
                out.push('(');
                let mut cur = self.clone();
                let mut first = true;
                loop {
                    match cur {
                        Value::Pair(ref p) => {
                            if !first {
                                out.push(' ');
                            }
                            first = false;
                            p.car.repr_into(out, mode, seen);
                            cur = p.cdr.clone();
                        }
                        Value::Nil => break,
                        other => {
                            out.push_str(" . ");
                            other.repr_into(out, mode, seen);
                            break;
                        }
                    }
                }
                out.push(')');
            }
            Value::Vector(data) => {
                let ptr = Rc::as_ptr(data) as usize;
                if seen.contains(&ptr) {
                    // A back-edge into a vector still being rendered → a cycle. Emit a
                    // deterministic marker and stop (§10 "must terminate").
                    out.push_str("#(...)");
                    return;
                }
                seen.push(ptr);
                out.push_str("#(");
                for (i, v) in data.items.borrow().iter().enumerate() {
                    if i > 0 {
                        out.push(' ');
                    }
                    v.repr_into(out, mode, seen);
                }
                out.push(')');
                seen.pop();
            }
            Value::Bytevector(bytes) => {
                out.push_str("#u8(");
                for (i, b) in bytes.iter().enumerate() {
                    if i > 0 {
                        out.push(' ');
                    }
                    let _ = write!(out, "{b}");
                }
                out.push(')');
            }
            Value::Closure(_) => out.push_str("#<procedure>"),
            Value::Primitive(p) => {
                out.push_str("#<primitive ");
                out.push_str(&p.name);
                out.push('>');
            }
            Value::Cont(_) => out.push_str("#<continuation>"),
            Value::ErrorObject(_) => out.push_str("#<error-object>"),
            #[cfg(feature = "scored-native-contract")]
            Value::Decision(_) => out.push_str("#<decision>"),
        }
    }
}

fn render_char(c: char) -> String {
    match c {
        ' ' => "#\\space".to_string(),
        '\n' => "#\\newline".to_string(),
        '\t' => "#\\tab".to_string(),
        '\r' => "#\\return".to_string(),
        '\0' => "#\\null".to_string(),
        c if (c as u32) < 0x20 || (c as u32) == 0x7f => format!("#\\x{:x}", c as u32),
        c => format!("#\\{c}"),
    }
}

/// **★ The PINNED canonical f64 formatter (LISPEX-RUNTIME.md §2).**
///
/// Canonical algorithm = **Ryū shortest-round-trip → positional reconstruction.**
/// One deterministic algorithm shared by `number->string` / `display` / `write`, so the
/// Rust reference interpreter and a future **external backend** port agree **byte-for-byte** (the
/// same parity concern as the corresponding external implementation — do NOT rely on either language's
/// default float printing). `f` is finite (the `Real` invariant). The
/// `golden_float_vector` test below is the cross-impl conformance pin.
///
/// ## Algorithm (explicit, so it can be re-implemented verbatim)
///
/// 1. **Sign.** Take the sign from the sign *bit* (`is_sign_negative`), so `-0.0` keeps
///    its `-`. Work on the magnitude `|f|`.
/// 2. **Shortest digits.** Generate the *shortest* decimal digit string that round-trips
///    to `|f|`, with round-to-nearest, ties-to-even — the unique minimal representation.
///    This is the published **Ryū** algorithm (the `ryu` crate; see [`shortest_digits`]).
///    Ryū is a NAMED, fully-specified algorithm — an external backend port re-implements *that*
///    algorithm to get byte-identical digits, rather than depending on any language's
///    unspecified default float printing. The result is the bare significant-digit string
///    `D` (no leading/trailing zeros) and the base-10 exponent `E` of `D`'s leading digit.
/// 3. **Decimal point position.** `point = E + 1` = how many of `D`'s digits lie to the
///    LEFT of the decimal point. With `L = len(D)`:
///    - `point ≤ 0`  → `"0." + ("0" × −point) + D`     (pure fraction, e.g. `1e-7` → `0.0000001`)
///    - `point ≥ L`  → `D + ("0" × (point − L)) + ".0"` (integral, e.g. `1e30` → `1000…0.0`)
///    - otherwise    → `D[..point] + "." + D[point..]`  (e.g. `1234.5`)
/// 4. **Sign prefix.** Prepend `-` if negative.
///
/// POSITIONAL only (never scientific/exponent), always a trailing `.0` when integral,
/// ASCII throughout. Examples: `3.0→"3.0"`, `0.5→"0.5"`, `1.0/3.0→"0.3333333333333333"`,
/// `1e30→"1000000000000000000000000000000.0"`, `1e-7→"0.0000001"`, `-0.0→"-0.0"`.
pub fn format_real(f: f64) -> String {
    let neg = f.is_sign_negative();
    // Step 2: Ryū shortest digits of the magnitude (`f.abs()` maps -0.0 → 0.0 so the
    // sign is handled exactly once, above).
    let (digits, exp) = shortest_digits(f.abs());
    let len = digits.len() as i64;
    let point = exp + 1; // digits to the left of the decimal point

    let mut s = String::new();
    if neg {
        s.push('-');
    }
    if point <= 0 {
        s.push_str("0.");
        for _ in 0..(-point) {
            s.push('0');
        }
        s.push_str(&digits);
    } else if point >= len {
        s.push_str(&digits);
        for _ in 0..(point - len) {
            s.push('0');
        }
        s.push_str(".0");
    } else {
        let p = point as usize;
        s.push_str(&digits[..p]);
        s.push('.');
        s.push_str(&digits[p..]);
    }
    s
}

/// **Ryū shortest-round-trip digit generation** (step 2 of [`format_real`]).
///
/// Returns the bare significant-digit string `D` (no leading/trailing zeros) and the
/// base-10 exponent `E` of `D`'s leading digit, i.e. the value equals
/// `0.D[0] D[1]… × 10^(E+1)` (the leading digit `D[0]` has place value `10^E`). `f` must
/// be a non-negative, finite `f64`.
///
/// The digits come from the published **Ryū** algorithm (deterministic, shortest
/// round-trip, round-to-nearest ties-to-even) via the `ryu` crate — a NAMED algorithm a
/// external backend port re-implements verbatim, NOT Rust's unspecified default float printing
/// (LISPEX-RUNTIME.md §2). Ryū's *textual* output picks fixed (`"D.D…"`) or scientific
/// (`"D.D…e±N"`) notation by its own heuristic; that choice is irrelevant here — we
/// re-normalize either form to `(D, E)`, so only Ryū's (unique, shortest, ties-to-even)
/// *digits* are load-bearing.
fn shortest_digits(f: f64) -> (String, i64) {
    debug_assert!(f.is_finite() && !f.is_sign_negative());
    let mut buf = ryu::Buffer::new();
    let s = buf.format_finite(f); // shortest; "D[.D…]" or "D[.D…]e±N" (always lowercase 'e')

    // Split the mantissa from the optional base-10 exponent.
    let (mantissa, e_exp) = match s.split_once('e') {
        Some((m, e)) => (m, e.parse::<i64>().expect("ryu exponent is an integer")),
        None => (s, 0),
    };
    // Split the mantissa around its (optional) decimal point and concatenate every digit.
    let (int_part, frac_part) = match mantissa.split_once('.') {
        Some((i, fr)) => (i, fr),
        None => (mantissa, ""),
    };
    let mut all = String::with_capacity(int_part.len() + frac_part.len());
    all.push_str(int_part);
    all.push_str(frac_part);
    // value = (all as a base-10 integer) × 10^scale.
    let scale = e_exp - frac_part.len() as i64;
    let total = all.len() as i64;

    // Drop leading zeros; each one lowers the leading-digit exponent by a place.
    let lead_zeros = all.bytes().take_while(|&b| b == b'0').count() as i64;
    if lead_zeros == total {
        // The magnitude is zero (ryu emits e.g. "0.0"): canonical digit "0", exponent 0,
        // which reconstructs to "0.0" (and "-0.0" once the sign bit is applied).
        return ("0".to_string(), 0);
    }
    // Exponent of the leading (most-significant) nonzero digit.
    let exp = scale + total - 1 - lead_zeros;
    // Bare significant digits: strip the leading zeros AND any trailing zeros (`all` is
    // ASCII, so byte-slicing == char-slicing). After leading strip the first byte is
    // nonzero, so trim_end never empties the string.
    let digits = all[lead_zeros as usize..].trim_end_matches('0').to_string();
    (digits, exp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use num_traits::Signed;

    #[test]
    fn rational_demotes_to_int_when_denominator_is_one() {
        // 42/7 == 6  -> Int(6)
        let v = Value::ratio(BigInt::from(42), BigInt::from(7));
        assert_eq!(v, Value::Int(BigInt::from(6)));
    }

    #[test]
    fn rational_reduces_to_lowest_terms() {
        // 6/4 -> 3/2
        let v = Value::ratio(BigInt::from(6), BigInt::from(4));
        match v {
            Value::Rational(r) => {
                assert_eq!(*r.numer(), BigInt::from(3));
                assert_eq!(*r.denom(), BigInt::from(2));
            }
            other => panic!("expected rational, got {other:?}"),
        }
    }

    #[test]
    fn rational_puts_sign_on_numerator_and_keeps_denominator_positive() {
        // 1 / -2 -> -1/2 (denominator stays positive)
        let v = Value::ratio(BigInt::from(1), BigInt::from(-2));
        match v {
            Value::Rational(r) => {
                assert_eq!(*r.numer(), BigInt::from(-1));
                assert_eq!(*r.denom(), BigInt::from(2));
                assert!(r.denom().is_positive());
            }
            other => panic!("expected rational, got {other:?}"),
        }
    }

    #[test]
    fn real_rejects_non_finite() {
        assert!(Value::real(f64::INFINITY).is_none());
        assert!(Value::real(f64::NEG_INFINITY).is_none());
        assert!(Value::real(f64::NAN).is_none());
        assert!(Value::real(-0.0).is_some());
        assert!(Value::real(1.5).is_some());
        // The `Finite` newtype is the ONLY door to a `Real`, and it is shut to
        // every non-finite f64 (the unbreakable §2 invariant).
        assert!(Finite::new(f64::INFINITY).is_none());
        assert!(Finite::new(f64::NEG_INFINITY).is_none());
        assert!(Finite::new(f64::NAN).is_none());
        assert_eq!(Finite::new(2.5).map(Finite::get), Some(2.5));
        assert!(Finite::new(-0.0).unwrap().get().is_sign_negative());
    }

    #[test]
    fn vector_is_interior_mutable() {
        // The shared `Rc<RefCell<…>>` lets an R5 `vector-set!` mutate in place and
        // be observed through an aliasing handle (the §1 "one mutable aggregate").
        let v = Value::vector(vec![Value::int(1), Value::int(2)]);
        let alias = v.clone();
        match &v {
            Value::Vector(data) => data.items.borrow_mut()[0] = Value::int(99),
            other => panic!("expected vector, got {other:?}"),
        }
        assert_eq!(v, Value::vector(vec![Value::int(99), Value::int(2)]));
        assert_eq!(alias, v); // alias sees the mutation through the shared cell
    }

    #[test]
    fn interner_shares_rc_for_equal_names() {
        let mut it = Interner::new();
        let a = it.intern("foo");
        let b = it.intern("foo");
        assert!(Rc::ptr_eq(&a, &b));
        let c = it.intern("bar");
        assert!(!Rc::ptr_eq(&a, &c));
    }

    #[test]
    fn list_builders() {
        let mut it = Interner::new();
        let lst = Value::list([it.sym("a"), Value::int(1)].into_iter());
        // (a 1) == (a . (1 . ()))
        assert_eq!(
            lst,
            Value::cons(it.sym("a"), Value::cons(Value::int(1), Value::Nil))
        );
    }

    // ── ★ GOLDEN FLOAT VECTOR (LISPEX-RUNTIME.md §2) ──────────────────────────────
    // Pins the canonical f64 formatter byte-for-byte. The Rust impl AND a future external backend
    // port must reproduce EVERY string below (integers, fractions, subnormals, very
    // large/small, -0.0, round-trip-hard 0.1/0.3, the f64 extremes).
    #[test]
    fn golden_float_vector() {
        // Cases small enough to write out literally.
        let fixed: &[(f64, &str)] = &[
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (3.0, "3.0"),
            (10.0, "10.0"),
            (12.0, "12.0"),
            (100.0, "100.0"),
            (-2.5, "-2.5"),
            (0.5, "0.5"),
            (0.1, "0.1"),
            (0.2, "0.2"),
            (0.3, "0.3"),
            (-0.001, "-0.001"),
            (0.0625, "0.0625"),
            (1234.5, "1234.5"),
            (1.0 / 3.0, "0.3333333333333333"),
            (2.0 / 3.0, "0.6666666666666666"),
            (1e-7, "0.0000001"),
            (1.5e-10, "0.00000000015"),
            (9007199254740992.0, "9007199254740992.0"),
            (123456789012345.0, "123456789012345.0"),
        ];
        for (f, want) in fixed {
            assert_eq!(&format_real(*f), want, "format_real({f:?})");
        }

        // Big positional expansions (built independently so the assertion is meaningful).
        assert_eq!(format_real(1e21), format!("1{}.0", "0".repeat(21)));
        assert_eq!(format_real(1e30), format!("1{}.0", "0".repeat(30)));
        assert_eq!(format_real(1e308), format!("1{}.0", "0".repeat(308)));
        // smallest positive subnormal: 5 × 10^-324, i.e. 323 leading fraction zeros.
        assert_eq!(format_real(5e-324), format!("0.{}5", "0".repeat(323)));
        // f64::MIN_POSITIVE = 2.2250738585072014e-308 (17 sig digits, 307 leading zeros).
        assert_eq!(
            format_real(f64::MIN_POSITIVE),
            format!("0.{}22250738585072014", "0".repeat(307))
        );

        // Never scientific, always exactly one '.', ASCII only.
        for (f, _) in fixed {
            let s = format_real(*f);
            assert!(!s.contains('e') && !s.contains('E'), "no exponent in {s}");
            assert_eq!(s.matches('.').count(), 1, "exactly one dot in {s}");
            assert!(s.is_ascii(), "ascii only: {s}");
        }
    }
}
