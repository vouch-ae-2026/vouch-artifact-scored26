//! The exact numeric tower (LISPEX-RUNTIME.md §2) — **pure, `Interp`-free**.
//!
//! R4 replaces R3's temporary integer-only bootstrap arithmetic with the full
//! exact tower the spec pins:
//!
//! - exact integer = [`BigInt`] (arbitrary precision, never overflows),
//! - exact rational = [`BigRational`] (normalized: lowest terms, q > 1, sign on the
//!   numerator, q == 1 demotes to `Int` — enforced by [`Value::rational`]),
//! - inexact real = `f64`, **always finite** (the [`crate::value::Finite`] invariant).
//!
//! **Contagion (§2):** `exact ⊕ exact → exact`; if *any* operand is inexact, ALL
//! operands are coerced to `f64` and the operation runs in IEEE-754 → inexact. The
//! exact→f64 coercion is itself a finite-checked f64 producer ([`AErr::NotFinite`] →
//! `E314`), so e.g. `(+ 1e400-as-exact 1.0)` (a huge exact coerced for contagion)
//! faults rather than smuggling an `inf` into a `Value`.
//!
//! This module is deliberately free of host control flow: every fallible operation
//! returns an explicit [`AErr`] (the evaluator maps it to a [`RuntimeError`]), and the
//! arithmetic itself is plain data — so a later **external backend** port is a transliteration
//! onto a recursive enum + BigInt + `while`-fold. The one host dependency is the
//! shortest-float **digit generation** used by the formatter (see [`crate::value`]),
//! which is uniquely determined (shortest round-trip, ties-to-even) and therefore
//! reproducible in any language.

use num_bigint::BigInt;
use num_integer::Integer;
use num_rational::BigRational;
use num_traits::{One, Signed, ToPrimitive, Zero};

use crate::value::{Finite, Value};

/// A numeric operand classified out of a [`Value`] (§2 tower).
#[derive(Clone, Debug)]
pub enum Num {
    /// Exact integer.
    Int(BigInt),
    /// Exact non-integer rational (q > 1, lowest terms, sign on the numerator).
    Rat(BigRational),
    /// Inexact real. INVARIANT: ALWAYS finite — the payload is the [`Finite`] newtype,
    /// whose private field forces every constructor through the checked [`Finite::new`]
    /// door, so a non-finite `Num::Real` is unconstructible even at the embedder level
    /// (§2 finite-`Real`). Read the underlying `f64` with `f.get()`.
    Real(Finite),
}

/// An arithmetic fault, mapped by the evaluator to a runtime [`crate::error::RuntimeCode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AErr {
    /// Division (or `modulo`) by zero — `E313`. Covers exact `0` *and* inexact `0.0`/`-0.0`.
    DivZero,
    /// An inexact result is not finite (overflow), or an exact→f64 coercion overflowed
    /// — `E314`.
    NotFinite,
    /// A primitive that requires an integer got a non-integer (`modulo`, `quotient`,
    /// `remainder`, `gcd`, `lcm`, `even?`, `odd?`) — `E312`.
    NotInteger,
}

/// Which comparison a [`compare`] chain applies, pairwise left-to-right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Lt,
    Gt,
    Le,
    Ge,
}

// ── classification & coercions ────────────────────────────────────────────────

/// Classify a [`Value`] as a numeric operand, or `None` for a non-number.
pub fn num_of(v: &Value) -> Option<Num> {
    match v {
        Value::Int(i) => Some(Num::Int(i.clone())),
        Value::Rational(r) => Some(Num::Rat(r.clone())),
        Value::Real(f) => Some(Num::Real(*f)),
        _ => None,
    }
}

fn is_real(n: &Num) -> bool {
    matches!(n, Num::Real(_))
}

/// Convert a [`Num`] back to a [`Value`] without changing its exactness (demoting an
/// integral rational, never producing a non-finite `Real`).
fn num_to_value(n: &Num) -> Value {
    match n {
        Num::Int(i) => Value::Int(i.clone()),
        Num::Rat(r) => Value::rational(r.clone()),
        // A `Num::Real` carries a `Finite`, so this re-wrap is always valid.
        Num::Real(f) => Value::Real(*f),
    }
}

/// Coerce a [`Num`] to `f64` for the contagion (inexact) path, finite-checking the
/// exact→f64 conversion (§2: that coercion is a finite-checked f64 producer).
fn to_f64_checked(n: &Num) -> Result<f64, AErr> {
    let f = match n {
        Num::Real(f) => f.get(),
        Num::Int(i) => i.to_f64().unwrap_or(f64::INFINITY),
        Num::Rat(r) => r.to_f64().unwrap_or(f64::INFINITY),
    };
    if f.is_finite() {
        Ok(f)
    } else {
        Err(AErr::NotFinite)
    }
}

/// An exact operand as a `BigRational` (for exact rational arithmetic / comparison).
fn to_ratio(n: &Num) -> BigRational {
    match n {
        Num::Int(i) => BigRational::from_integer(i.clone()),
        Num::Rat(r) => r.clone(),
        // Used only on the EXACT path, where no `Real` is present.
        Num::Real(_) => unreachable!("to_ratio on an inexact operand"),
    }
}

/// The **exact** rational value of any operand, converting an inexact `f64` to its
/// *true* dyadic rational (§2: mixed exact/inexact are compared EXACTLY — no
/// double-rounding). Used by the comparison chain and by `min`/`max` selection.
pub fn to_exact_ratio(n: &Num) -> BigRational {
    match n {
        Num::Int(i) => BigRational::from_integer(i.clone()),
        Num::Rat(r) => r.clone(),
        Num::Real(f) => exact_ratio_of_f64(f.get()),
    }
}

/// The exact integer value of an operand, or `None` if it is not an integer (a
/// non-integral rational, or a non-integral inexact real). An *inexact* integer like
/// `3.0` IS an integer here (§2: `modulo`/`quotient`/`remainder`/`gcd`/`lcm` accept it →
/// inexact result).
fn to_integer(n: &Num) -> Option<BigInt> {
    match n {
        Num::Int(i) => Some(i.clone()),
        Num::Rat(_) => None,
        Num::Real(f) => real_to_integer(f.get()),
    }
}

// ── f64 ⇄ exact decoding (the `exact`/`inexact` crossing, §2) ──────────────────

/// Decode a finite `f64` into `(negative, mantissa, exp)` with value
/// `(-1)^negative · mantissa · 2^exp` (mantissa a non-negative integer). Handles
/// normals and subnormals; `0.0`/`-0.0` decode to mantissa 0.
fn decode_f64(f: f64) -> (bool, u64, i64) {
    let bits = f.to_bits();
    let neg = (bits >> 63) & 1 == 1;
    let raw_exp = ((bits >> 52) & 0x7ff) as i64;
    let frac = bits & ((1u64 << 52) - 1);
    if raw_exp == 0 {
        // Subnormal (or zero): no implicit leading 1; value = frac · 2^(-1074).
        (neg, frac, -1074)
    } else {
        // Normal: implicit leading 1; bias 1023, minus 52 fraction bits → −1075.
        (neg, frac | (1u64 << 52), raw_exp - 1075)
    }
}

/// `exact` of a finite `f64` → its **true** dyadic rational as a `BigRational`
/// (`(exact 0.5) → 1/2`, `(exact 0.1) → 3602879701896397/36028797018963968`).
pub fn exact_ratio_of_f64(f: f64) -> BigRational {
    if f == 0.0 {
        // covers +0.0 and −0.0
        return BigRational::zero();
    }
    let (neg, mantissa, exp) = decode_f64(f);
    let mut num = BigInt::from(mantissa);
    if neg {
        num = -num;
    }
    if exp >= 0 {
        BigRational::from_integer(num << (exp as usize))
    } else {
        let den = BigInt::one() << ((-exp) as usize);
        BigRational::new(num, den)
    }
}

/// `exact` of a finite `f64` → a [`Value`] (`Int` when the dyadic rational is integral,
/// else `Rational`).
pub fn exact_of_f64(f: f64) -> Value {
    Value::rational(exact_ratio_of_f64(f))
}

/// The exact integer value of a finite `f64`, or `None` if it is not integral.
fn real_to_integer(f: f64) -> Option<BigInt> {
    let r = exact_ratio_of_f64(f);
    if r.is_integer() {
        Some(r.to_integer())
    } else {
        None
    }
}

// ── arithmetic (+ − * /) — variadic, with contagion (§2) ───────────────────────

/// `+` : identity `0`, variadic. Exact stays exact; any inexact → IEEE-754 sum.
pub fn add(nums: &[Num]) -> Result<Value, AErr> {
    if nums.iter().any(is_real) {
        let mut acc = 0.0f64;
        for n in nums {
            acc += to_f64_checked(n)?;
        }
        return Value::real(acc).ok_or(AErr::NotFinite);
    }
    if nums.iter().all(|n| matches!(n, Num::Int(_))) {
        let mut acc = BigInt::zero();
        for n in nums {
            if let Num::Int(i) = n {
                acc += i;
            }
        }
        Ok(Value::Int(acc))
    } else {
        let mut acc = BigRational::zero();
        for n in nums {
            acc += to_ratio(n);
        }
        Ok(Value::rational(acc))
    }
}

/// `*` : identity `1`, variadic. Exact stays exact; any inexact → IEEE-754 product.
pub fn mul(nums: &[Num]) -> Result<Value, AErr> {
    if nums.iter().any(is_real) {
        let mut acc = 1.0f64;
        for n in nums {
            acc *= to_f64_checked(n)?;
        }
        return Value::real(acc).ok_or(AErr::NotFinite);
    }
    if nums.iter().all(|n| matches!(n, Num::Int(_))) {
        let mut acc = BigInt::one();
        for n in nums {
            if let Num::Int(i) = n {
                acc *= i;
            }
        }
        Ok(Value::Int(acc))
    } else {
        let mut acc = BigRational::one();
        for n in nums {
            acc *= to_ratio(n);
        }
        Ok(Value::rational(acc))
    }
}

/// `-` : `(- z)` negates, `(- a b …)` left-folds subtraction. Caller guarantees ≥ 1
/// operand (`(-)` with 0 args is an arity error raised by the prim).
pub fn sub(nums: &[Num]) -> Result<Value, AErr> {
    debug_assert!(!nums.is_empty());
    if nums.iter().any(is_real) {
        let vals: Vec<f64> = nums.iter().map(to_f64_checked).collect::<Result<_, _>>()?;
        let r = if vals.len() == 1 {
            -vals[0]
        } else {
            let mut acc = vals[0];
            for v in &vals[1..] {
                acc -= v;
            }
            acc
        };
        return Value::real(r).ok_or(AErr::NotFinite);
    }
    if nums.iter().all(|n| matches!(n, Num::Int(_))) {
        let ints: Vec<&BigInt> = nums
            .iter()
            .map(|n| match n {
                Num::Int(i) => i,
                _ => unreachable!(),
            })
            .collect();
        let acc = if ints.len() == 1 {
            -ints[0].clone()
        } else {
            let mut acc = ints[0].clone();
            for i in &ints[1..] {
                acc -= *i;
            }
            acc
        };
        Ok(Value::Int(acc))
    } else {
        let rs: Vec<BigRational> = nums.iter().map(to_ratio).collect();
        let acc = if rs.len() == 1 {
            -rs[0].clone()
        } else {
            let mut acc = rs[0].clone();
            for r in &rs[1..] {
                acc -= r;
            }
            acc
        };
        Ok(Value::rational(acc))
    }
}

/// `/` : `(/ z)` is the reciprocal, `(/ a b …)` left-folds division. `(/ x 0)` AND
/// `(/ x 0.0)` → [`AErr::DivZero`] (`E313`; never an `inf`). Caller guarantees ≥ 1
/// operand. Exact division stays exact (`(/ 1 3) → 1/3`, `(/ 10 5) → 2`).
pub fn div(nums: &[Num]) -> Result<Value, AErr> {
    debug_assert!(!nums.is_empty());
    if nums.iter().any(is_real) {
        let vals: Vec<f64> = nums.iter().map(to_f64_checked).collect::<Result<_, _>>()?;
        let r = if vals.len() == 1 {
            if vals[0] == 0.0 {
                return Err(AErr::DivZero);
            }
            1.0 / vals[0]
        } else {
            let mut acc = vals[0];
            for d in &vals[1..] {
                if *d == 0.0 {
                    return Err(AErr::DivZero);
                }
                acc /= d;
            }
            acc
        };
        return Value::real(r).ok_or(AErr::NotFinite);
    }
    // Exact path: division generally leaves the integers, so accumulate as a rational.
    let rs: Vec<BigRational> = nums.iter().map(to_ratio).collect();
    let acc = if rs.len() == 1 {
        if rs[0].is_zero() {
            return Err(AErr::DivZero);
        }
        rs[0].recip()
    } else {
        let mut acc = rs[0].clone();
        for d in &rs[1..] {
            if d.is_zero() {
                return Err(AErr::DivZero);
            }
            acc /= d;
        }
        acc
    };
    Ok(Value::rational(acc))
}

/// `modulo` (§2): sign-of-divisor, exactly 2 integer operands (an *inexact* integer
/// like `3.0` is allowed → inexact result). Zero divisor → [`AErr::DivZero`]; a
/// non-integer operand → [`AErr::NotInteger`].
pub fn modulo(a: &Num, b: &Num) -> Result<Value, AErr> {
    let ai = to_integer(a).ok_or(AErr::NotInteger)?;
    let bi = to_integer(b).ok_or(AErr::NotInteger)?;
    if bi.is_zero() {
        return Err(AErr::DivZero);
    }
    // `mod_floor` is the floored remainder → it carries the sign of the divisor.
    let r = ai.mod_floor(&bi);
    if is_real(a) || is_real(b) {
        let f = r.to_f64().unwrap_or(f64::INFINITY);
        Value::real(f).ok_or(AErr::NotFinite)
    } else {
        Ok(Value::Int(r))
    }
}

/// `quotient` (§2): truncated integer division — rounds the exact quotient TOWARD ZERO
/// (contrast [`modulo`]'s floored division). Exactly 2 integer operands (an *inexact*
/// integer like `6.0` is allowed → inexact result). Zero divisor → [`AErr::DivZero`]; a
/// non-integer operand → [`AErr::NotInteger`]. Unlike the bounded [`modulo`]/[`remainder`]
/// result, an *inexact* quotient can overflow f64 → [`AErr::NotFinite`] (`E314`). With
/// [`remainder`] it satisfies `n = d·(quotient n d) + (remainder n d)`.
pub fn quotient(a: &Num, b: &Num) -> Result<Value, AErr> {
    let ai = to_integer(a).ok_or(AErr::NotInteger)?;
    let bi = to_integer(b).ok_or(AErr::NotInteger)?;
    if bi.is_zero() {
        return Err(AErr::DivZero);
    }
    // Native BigInt `/` truncates toward zero (vs `modulo`'s floored `mod_floor`).
    let q = &ai / &bi;
    if is_real(a) || is_real(b) {
        let f = q.to_f64().unwrap_or(f64::INFINITY);
        Value::real(f).ok_or(AErr::NotFinite)
    } else {
        Ok(Value::Int(q))
    }
}

/// `remainder` (§2): the remainder of *truncated* division — it carries the sign of the
/// DIVIDEND `a` (contrast [`modulo`], whose remainder carries the sign of the divisor; the
/// two agree only when the operands share a sign). Exactly 2 integer operands (an *inexact*
/// integer is allowed → inexact result). Zero divisor → [`AErr::DivZero`]; a non-integer
/// operand → [`AErr::NotInteger`].
pub fn remainder(a: &Num, b: &Num) -> Result<Value, AErr> {
    let ai = to_integer(a).ok_or(AErr::NotInteger)?;
    let bi = to_integer(b).ok_or(AErr::NotInteger)?;
    if bi.is_zero() {
        return Err(AErr::DivZero);
    }
    // Native BigInt `%` carries the sign of the dividend (vs `modulo`'s `mod_floor`).
    let r = &ai % &bi;
    if is_real(a) || is_real(b) {
        let f = r.to_f64().unwrap_or(f64::INFINITY);
        Value::real(f).ok_or(AErr::NotFinite)
    } else {
        Ok(Value::Int(r))
    }
}

/// Wrap an exact integer result back into a [`Value`], applying contagion: inexact iff an operand
/// was (the f64 coercion is finite-checked → [`AErr::NotFinite`]). Shared by the floored/truncated
/// integer-division family.
fn int_or_real(n: BigInt, inexact: bool) -> Result<Value, AErr> {
    if inexact {
        Value::real(n.to_f64().unwrap_or(f64::INFINITY)).ok_or(AErr::NotFinite)
    } else {
        Ok(Value::Int(n))
    }
}

/// `floor-quotient` (§2): the FLOORED quotient `⌊n/d⌋` (rounds toward −∞; contrast [`quotient`]'s
/// toward-zero). 2 integer operands; zero divisor → [`AErr::DivZero`]; non-integer → [`AErr::NotInteger`].
pub fn floor_quotient(a: &Num, b: &Num) -> Result<Value, AErr> {
    let ai = to_integer(a).ok_or(AErr::NotInteger)?;
    let bi = to_integer(b).ok_or(AErr::NotInteger)?;
    if bi.is_zero() {
        return Err(AErr::DivZero);
    }
    int_or_real(ai.div_floor(&bi), is_real(a) || is_real(b))
}

/// `floor/` (§2): both results of floored division — `(⌊n/d⌋, n − d·⌊n/d⌋)` (the remainder is
/// [`modulo`], sign of the divisor). 2 integer operands; zero divisor → E313; non-integer → E312.
pub fn floor_div(a: &Num, b: &Num) -> Result<(Value, Value), AErr> {
    let ai = to_integer(a).ok_or(AErr::NotInteger)?;
    let bi = to_integer(b).ok_or(AErr::NotInteger)?;
    if bi.is_zero() {
        return Err(AErr::DivZero);
    }
    let (q, r) = ai.div_mod_floor(&bi);
    let inexact = is_real(a) || is_real(b);
    Ok((int_or_real(q, inexact)?, int_or_real(r, inexact)?))
}

/// `truncate/` (§2): both results of truncated division — `(quotient, remainder)` (the remainder
/// carries the sign of the dividend). 2 integer operands; zero divisor → E313; non-integer → E312.
pub fn truncate_div(a: &Num, b: &Num) -> Result<(Value, Value), AErr> {
    let ai = to_integer(a).ok_or(AErr::NotInteger)?;
    let bi = to_integer(b).ok_or(AErr::NotInteger)?;
    if bi.is_zero() {
        return Err(AErr::DivZero);
    }
    let inexact = is_real(a) || is_real(b);
    Ok((
        int_or_real(&ai / &bi, inexact)?,
        int_or_real(&ai % &bi, inexact)?,
    ))
}

// ── abs / min / max ────────────────────────────────────────────────────────────

/// `abs` (exact-safe across the tower). `abs(-0.0) = 0.0`.
pub fn abs(n: &Num) -> Result<Value, AErr> {
    match n {
        Num::Int(i) => Ok(Value::Int(i.abs())),
        Num::Rat(r) => Ok(Value::rational(r.abs())),
        Num::Real(f) => Value::real(f.get().abs()).ok_or(AErr::NotFinite),
    }
}

/// `square` — `z * z`, exactness-preserving (an exact operand stays exact, an inexact one stays
/// inexact); an inexact square that overflows to non-finite → [`AErr::NotFinite`] (E314).
pub fn square(n: &Num) -> Result<Value, AErr> {
    match n {
        Num::Int(i) => Ok(Value::Int(i * i)),
        Num::Rat(r) => Ok(Value::rational(r * r)),
        Num::Real(f) => Value::real(f.get() * f.get()).ok_or(AErr::NotFinite),
    }
}

// ── rounding (§2): one real → integer-valued, SAME exactness; an Int returns itself ──

/// `floor` — the largest integer ≤ `n`, with `n`'s exactness (exact `Int` from an exact
/// operand, inexact `Real` from an inexact one).
pub fn floor(n: &Num) -> Result<Value, AErr> {
    match n {
        Num::Int(i) => Ok(Value::Int(i.clone())),
        Num::Rat(r) => Ok(Value::Int(r.floor().to_integer())),
        Num::Real(f) => Value::real(f.get().floor()).ok_or(AErr::NotFinite),
    }
}

/// `ceiling` — the smallest integer ≥ `n` (exactness-preserving, like [`floor`]).
pub fn ceiling(n: &Num) -> Result<Value, AErr> {
    match n {
        Num::Int(i) => Ok(Value::Int(i.clone())),
        Num::Rat(r) => Ok(Value::Int(r.ceil().to_integer())),
        Num::Real(f) => Value::real(f.get().ceil()).ok_or(AErr::NotFinite),
    }
}

/// `truncate` — `n` rounded TOWARD ZERO (exactness-preserving).
pub fn truncate(n: &Num) -> Result<Value, AErr> {
    match n {
        Num::Int(i) => Ok(Value::Int(i.clone())),
        Num::Rat(r) => Ok(Value::Int(r.trunc().to_integer())),
        Num::Real(f) => Value::real(f.get().trunc()).ok_or(AErr::NotFinite),
    }
}

/// `round` — `n` to the nearest integer, ties to EVEN (banker's rounding), exactness-
/// preserving. ⚠ Do NOT use `BigRational::round()` (it rounds half AWAY from zero) nor
/// `f64::round()` (also half-away): the exact path hand-rolls half-to-even on numer/denom,
/// and the inexact path uses `f64::round_ties_even()`.
pub fn round(n: &Num) -> Result<Value, AErr> {
    match n {
        Num::Int(i) => Ok(Value::Int(i.clone())),
        Num::Rat(r) => {
            let d = r.denom(); // > 0 (normalized)
            let q = r.numer().div_floor(d); // floor
            let rem = r.numer().mod_floor(d); // 0 ≤ rem < d
            let twice = &rem + &rem; // 2·rem, compared to d to find the nearer integer
            let rounded = match twice.cmp(d) {
                std::cmp::Ordering::Less => q,
                std::cmp::Ordering::Greater => q + BigInt::one(),
                // exact half → round to the EVEN neighbour
                std::cmp::Ordering::Equal => {
                    if q.is_even() {
                        q
                    } else {
                        q + BigInt::one()
                    }
                }
            };
            Ok(Value::Int(rounded))
        }
        Num::Real(f) => Value::real(f.get().round_ties_even()).ok_or(AErr::NotFinite),
    }
}

// ── gcd / lcm (§2): variadic integer folds, always NON-NEGATIVE ──────────────────

/// `gcd` — variadic greatest common divisor over integers, always NON-NEGATIVE; identity `0`
/// ((gcd)→0). Integer-domain (an inexact integer like `4.0` is allowed → inexact result via the
/// same contagion as [`modulo`]); a non-integer operand → [`AErr::NotInteger`].
pub fn gcd(nums: &[Num]) -> Result<Value, AErr> {
    let mut acc = BigInt::zero();
    for n in nums {
        acc = acc.gcd(&to_integer(n).ok_or(AErr::NotInteger)?);
    }
    if nums.iter().any(is_real) {
        let f = acc.to_f64().unwrap_or(f64::INFINITY);
        Value::real(f).ok_or(AErr::NotFinite)
    } else {
        Ok(Value::Int(acc))
    }
}

/// `lcm` — variadic least common multiple over integers, always NON-NEGATIVE; identity `1`
/// ((lcm)→1); a `0` operand makes the result `0`. Integer-domain with the same contagion as [`gcd`].
pub fn lcm(nums: &[Num]) -> Result<Value, AErr> {
    let mut acc = BigInt::one();
    for n in nums {
        acc = acc.lcm(&to_integer(n).ok_or(AErr::NotInteger)?);
    }
    if nums.iter().any(is_real) {
        let f = acc.to_f64().unwrap_or(f64::INFINITY);
        Value::real(f).ok_or(AErr::NotFinite)
    } else {
        Ok(Value::Int(acc))
    }
}

/// `expt` — `(expt base exp)` with an EXACT-INTEGER exponent (`exp` is supplied as a `BigInt`;
/// the caller rejects float/rational exponents). The general/transcendental `expt` is excluded
/// from v1 (§2). Contagion: an inexact base → inexact result, an exact base → exact result (the
/// exponent is always exact, so the result's exactness follows the base). `exp == 0` → `1`
/// carrying the base's exactness; a negative exponent → the reciprocal (exact → rational);
/// `0 ^ 0` → `1`; an exact `0 ^ negative` → [`AErr::DivZero`] (E313), while an inexact
/// `0.0 ^ negative` overflows to `+inf` and is rejected as non-finite (E314).
///
/// A base of magnitude 0 or 1 (`0`, `1`, `-1`, `0.0`, `1.0`, `-1.0`) yields a result that is
/// representable for ANY exponent, so it is resolved BEFORE the exponent is narrowed to a
/// machine integer. For any other base, an exponent magnitude beyond the machine-integer limit
/// (`i32::MAX` inexact / `u32::MAX` exact — an astronomically large power) is reported as the
/// overflow fault E314; this is an implementation bound, documented in LISPEX-RUNTIME.md §2.
pub fn expt(base: &Num, exp: &BigInt) -> Result<Value, AErr> {
    // exp == 0 → 1, carrying the base's exactness (contagion).
    if exp.is_zero() {
        return if is_real(base) {
            Value::real(1.0).ok_or(AErr::NotFinite)
        } else {
            Ok(Value::Int(BigInt::one()))
        };
    }
    // inexact base → f64 integer-power path (contagion).
    if is_real(base) {
        let b = to_f64_checked(base)?;
        // Trivial-magnitude bases are representable for any exponent — resolve them before the
        // i32 narrowing so a huge exponent does not spuriously fault a finite result.
        if b == 1.0 {
            return Value::real(1.0).ok_or(AErr::NotFinite); // 1.0 ^ n = 1.0
        }
        if b == -1.0 {
            let v = if exp.is_even() { 1.0 } else { -1.0 };
            return Value::real(v).ok_or(AErr::NotFinite);
        }
        if b == 0.0 {
            // 0.0 ^ positive = 0.0; 0.0 ^ negative = +inf → non-finite (E314).
            return if exp.is_negative() {
                Err(AErr::NotFinite)
            } else {
                Value::real(0.0).ok_or(AErr::NotFinite)
            };
        }
        let e = exp.to_i32().ok_or(AErr::NotFinite)?; // |exp| > i32::MAX → overflow (E314)
        return Value::real(b.powi(e)).ok_or(AErr::NotFinite);
    }
    // exact base. The trivial integer bases 0/1/-1 are the only exact values whose result is
    // representable for any exponent (and 0 is the only one whose reciprocal would divide by
    // zero); resolve them before the pow. A `Num::Rat` is never 0/±1 (q > 1), so only `Int`.
    if let Num::Int(i) = base {
        if i.is_zero() {
            return if exp.is_negative() {
                Err(AErr::DivZero) // exact 0 ^ negative
            } else {
                Ok(Value::Int(BigInt::zero())) // 0 ^ positive
            };
        }
        if i.is_one() {
            return Ok(Value::Int(BigInt::one())); // 1 ^ n = 1
        }
        if *i == -BigInt::one() {
            let v = if exp.is_even() {
                BigInt::one()
            } else {
                -BigInt::one()
            };
            return Ok(Value::Int(v)); // (-1) ^ n = ±1 by parity
        }
    }
    // general exact non-zero base (|int| > 1, or a rational), exp != 0 →
    // p^|e| / q^|e|, reciprocated when the exponent is negative.
    let r = to_ratio(base); // BigRational, denominator > 0
    let mag = exp.abs().to_u32().ok_or(AErr::NotFinite)?; // |exp| > u32::MAX → overflow (E314)
    let p = r.numer().pow(mag); // inherent BigInt::pow(u32)
    let q = r.denom().pow(mag);
    let result = if exp.is_negative() {
        BigRational::new(q, p) // (q/p)^mag — reciprocal
    } else {
        BigRational::new(p, q)
    };
    Ok(Value::rational(result)) // demotes an integral rational to Int
}

/// `min`/`max` (`want_max` selects `max`). Selection compares EXACTLY across the tower;
/// with **inexactness contagion** (R7RS): if any operand is inexact the result is
/// inexact, even when the selected extremum is an exact operand. Caller guarantees ≥ 1
/// operand. On ties the first operand wins.
pub fn minmax(nums: &[Num], want_max: bool) -> Result<Value, AErr> {
    debug_assert!(!nums.is_empty());
    let inexact = nums.iter().any(is_real);
    let mut best_idx = 0;
    let mut best_r = to_exact_ratio(&nums[0]);
    for (i, n) in nums.iter().enumerate().skip(1) {
        let r = to_exact_ratio(n);
        let take = if want_max { r > best_r } else { r < best_r };
        if take {
            best_r = r;
            best_idx = i;
        }
    }
    let best = &nums[best_idx];
    if inexact && !is_real(best) {
        let f = to_f64_checked(best)?;
        Value::real(f).ok_or(AErr::NotFinite)
    } else {
        Ok(num_to_value(best))
    }
}

// ── comparison chains (§2): ≥2 args, pairwise, mixed compared EXACTLY ───────────

/// A variadic comparison chain (`= < > <= >=`). Caller guarantees ≥ 2 operands. Mixed
/// exact/inexact operands are compared EXACTLY (each `f64` → its true dyadic rational),
/// so e.g. `(= 1/3 0.3333333333333333) → #f` and `(= 0.0 -0.0) → #t`.
pub fn compare(nums: &[Num], op: CmpOp) -> bool {
    debug_assert!(nums.len() >= 2);
    let rs: Vec<BigRational> = nums.iter().map(to_exact_ratio).collect();
    rs.windows(2).all(|w| match op {
        CmpOp::Eq => w[0] == w[1],
        CmpOp::Lt => w[0] < w[1],
        CmpOp::Gt => w[0] > w[1],
        // SCORED-MUTATION-SITE M07: shared inclusive comparisons reject equality.
        CmpOp::Le if cfg!(scored_mutant = "M07") => w[0] < w[1],
        CmpOp::Ge if cfg!(scored_mutant = "M07") => w[0] > w[1],
        CmpOp::Le => w[0] <= w[1],
        CmpOp::Ge => w[0] >= w[1],
    })
}

// ── exactness crossing: exact / inexact (§2) ───────────────────────────────────

/// `exact` / `inexact->exact`: exact operands pass through; an inexact real becomes its
/// true dyadic rational.
pub fn to_exact(n: &Num) -> Value {
    match n {
        Num::Real(f) => exact_of_f64(f.get()),
        _ => num_to_value(n),
    }
}

/// `inexact` / `exact->inexact`: inexact passes through; an exact operand becomes the
/// nearest `f64` (round-to-nearest-even), finite-checked (`(inexact <huge>)` → `E314`).
pub fn to_inexact(n: &Num) -> Result<Value, AErr> {
    let f = to_f64_checked(n)?;
    Value::real(f).ok_or(AErr::NotFinite)
}

// ── numeric predicates (§2) ────────────────────────────────────────────────────

/// `zero?` — numerically zero (covers exact `0` and `±0.0`).
pub fn is_zero(n: &Num) -> bool {
    match n {
        Num::Int(i) => i.is_zero(),
        Num::Rat(_) => false, // a normalized rational is never zero (0 demotes to Int)
        Num::Real(f) => f.get() == 0.0,
    }
}

/// `positive?` — numerically > 0 (`+0.0` is not positive).
pub fn is_positive(n: &Num) -> bool {
    match n {
        Num::Int(i) => i.is_positive(),
        Num::Rat(r) => r.is_positive(),
        Num::Real(f) => f.get() > 0.0,
    }
}

/// `negative?` — numerically < 0 (`-0.0` is not negative).
pub fn is_negative(n: &Num) -> bool {
    match n {
        Num::Int(i) => i.is_negative(),
        Num::Rat(r) => r.is_negative(),
        Num::Real(f) => f.get() < 0.0,
    }
}

/// `exact?` — an exact (integer/rational) number.
pub fn is_exact(n: &Num) -> bool {
    !is_real(n)
}

/// `inexact?` — an inexact (real) number.
pub fn is_inexact(n: &Num) -> bool {
    is_real(n)
}

/// `even?` — requires an integer (exact or inexact); non-integer → [`AErr::NotInteger`].
pub fn is_even(n: &Num) -> Result<bool, AErr> {
    to_integer(n).map(|i| i.is_even()).ok_or(AErr::NotInteger)
}

/// `odd?` — requires an integer (exact or inexact); non-integer → [`AErr::NotInteger`].
pub fn is_odd(n: &Num) -> Result<bool, AErr> {
    to_integer(n).map(|i| i.is_odd()).ok_or(AErr::NotInteger)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(n: i64) -> Num {
        Num::Int(BigInt::from(n))
    }
    fn real(f: f64) -> Num {
        Num::Real(Finite::new(f).expect("test real is finite"))
    }

    #[test]
    fn exact_dyadic_of_known_floats() {
        // (exact 0.5) → 1/2
        assert_eq!(
            exact_of_f64(0.5),
            Value::ratio(BigInt::from(1), BigInt::from(2))
        );
        // (exact 0.1) → 3602879701896397/36028797018963968
        match exact_of_f64(0.1) {
            Value::Rational(r) => {
                assert_eq!(r.numer().to_string(), "3602879701896397");
                assert_eq!(r.denom().to_string(), "36028797018963968");
            }
            other => panic!("expected rational, got {other:?}"),
        }
        // (exact 3.0) → 3 (integral dyadic demotes to Int)
        assert_eq!(exact_of_f64(3.0), Value::int(3));
        assert_eq!(exact_of_f64(-0.0), Value::int(0));
    }

    #[test]
    fn contagion_makes_results_inexact() {
        // (+ 1 2.0) → 3.0
        assert_eq!(
            add(&[int(1), real(2.0)]).unwrap(),
            Value::real(3.0).unwrap()
        );
        // (* 1/2 4) → 2 (exact)
        let half = Num::Rat(BigRational::new(BigInt::from(1), BigInt::from(2)));
        assert_eq!(mul(&[half, int(4)]).unwrap(), Value::int(2));
    }

    #[test]
    fn mixed_comparison_is_exact_not_rounded() {
        // (= 1/3 0.3333333333333333) → #f (the f64 is not exactly 1/3)
        let third = Num::Rat(BigRational::new(BigInt::from(1), BigInt::from(3)));
        assert!(!compare(&[third, real(0.3333333333333333)], CmpOp::Eq));
        // (= 0.0 -0.0) → #t
        assert!(compare(&[real(0.0), real(-0.0)], CmpOp::Eq));
    }

    #[test]
    fn division_and_zero() {
        // (/ 1 3) → 1/3
        assert_eq!(
            div(&[int(1), int(3)]).unwrap(),
            Value::ratio(BigInt::from(1), BigInt::from(3))
        );
        // (/ 10 5) → 2
        assert_eq!(div(&[int(10), int(5)]).unwrap(), Value::int(2));
        // (/ x 0) and (/ x 0.0) → DivZero
        assert_eq!(div(&[int(1), int(0)]), Err(AErr::DivZero));
        assert_eq!(div(&[real(1.0), real(0.0)]), Err(AErr::DivZero));
        assert_eq!(div(&[int(1), real(0.0)]), Err(AErr::DivZero));
    }

    #[test]
    fn overflow_is_e314() {
        // huge * huge in f64 → inf → NotFinite (E314)
        assert_eq!(mul(&[real(1e300), real(1e300)]), Err(AErr::NotFinite));
    }

    #[test]
    fn quotient_remainder_truncate_toward_zero() {
        // Truncated (toward-zero) division: quotient rounds toward zero and remainder
        // carries the sign of the DIVIDEND — the load-bearing contrast with `modulo`'s
        // floored `mod_floor` (which carries the sign of the divisor).
        assert_eq!(quotient(&int(7), &int(3)).unwrap(), Value::int(2));
        assert_eq!(quotient(&int(-7), &int(3)).unwrap(), Value::int(-2));
        assert_eq!(quotient(&int(7), &int(-3)).unwrap(), Value::int(-2));
        assert_eq!(quotient(&int(-7), &int(-3)).unwrap(), Value::int(2));
        assert_eq!(remainder(&int(7), &int(3)).unwrap(), Value::int(1));
        assert_eq!(remainder(&int(-7), &int(3)).unwrap(), Value::int(-1));
        assert_eq!(remainder(&int(7), &int(-3)).unwrap(), Value::int(1));
        assert_eq!(remainder(&int(-7), &int(-3)).unwrap(), Value::int(-1));
        // zero divisor → DivZero (both procedures).
        assert_eq!(quotient(&int(7), &int(0)), Err(AErr::DivZero));
        assert_eq!(remainder(&int(7), &int(0)), Err(AErr::DivZero));
        // a non-integral operand → NotInteger; an inexact integer → inexact result.
        let half = Num::Rat(BigRational::new(BigInt::from(1), BigInt::from(2)));
        assert_eq!(remainder(&int(5), &half), Err(AErr::NotInteger));
        assert_eq!(
            quotient(&real(7.0), &int(2)).unwrap(),
            Value::real(3.0).unwrap()
        );
    }
}
