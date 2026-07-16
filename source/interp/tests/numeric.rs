//! Numeric-tower conformance tests (Round 4) — the full exact int/rational/real tower,
//! contagion, arithmetic/comparison/predicates, the exact/inexact crossing, and the
//! pinned canonical float formatter (LISPEX-RUNTIME.md §2 / §6).
//!
//! Strategy mirrors `tests/eval.rs`: drive the whole pipeline via [`Interp::run_str`]
//! and assert on the [`Outcome`] (or [`RuntimeCode`] on failure).

use lispex::{BigInt, Interp, Outcome, RunError, RuntimeCode, Value};

// ── helpers ───────────────────────────────────────────────────────────────────

fn run(src: &str) -> Outcome {
    let mut it = Interp::new();
    it.run_str(src, "t.lx")
        .unwrap_or_else(|e| panic!("unexpected error for `{src}`: {e:?}"))
}

fn run_one(src: &str) -> Value {
    match run(src) {
        Outcome::One(v) => v,
        other => panic!("expected one value for `{src}`, got {other:?}"),
    }
}

/// Canonical `write` rendering of a single result (numbers go through the pinned formatter).
fn run_repr(src: &str) -> String {
    run_one(src).write_repr()
}

/// A single `Value::Str` result's contents (for `number->string`).
fn run_string(src: &str) -> String {
    match run_one(src) {
        Value::Str(s) => s.to_string(),
        other => panic!("expected a string for `{src}`, got {other:?}"),
    }
}

fn run_bool(src: &str) -> bool {
    match run_one(src) {
        Value::Bool(b) => b,
        other => panic!("expected a boolean for `{src}`, got {other:?}"),
    }
}

fn run_err(src: &str) -> RuntimeCode {
    let mut it = Interp::new();
    match it.run_str(src, "t.lx") {
        Err(RunError::Runtime(e)) => e.code,
        other => panic!("expected a runtime error for `{src}`, got {other:?}"),
    }
}

// ── contagion (§2): exact ⊕ exact → exact; any inexact → IEEE-754 inexact ────────

#[test]
fn arithmetic_identities_and_folds() {
    assert_eq!(run_repr("(+)"), "0");
    assert_eq!(run_repr("(*)"), "1");
    assert_eq!(run_repr("(+ 1 2 3)"), "6");
    assert_eq!(run_repr("(* 2 3 4)"), "24");
    assert_eq!(run_repr("(- 5)"), "-5"); // unary negate
    assert_eq!(run_repr("(- 10 3 2)"), "5"); // left fold
    assert_eq!(run_err("(-)"), RuntimeCode::E302); // 0 args
    assert_eq!(run_err("(/)"), RuntimeCode::E302); // 0 args
}

#[test]
fn contagion_exactness() {
    // exact stays exact
    assert_eq!(run_repr("(+ 1/3 1/6)"), "1/2");
    assert_eq!(run_repr("(* 1/2 4)"), "2"); // demotes to Int
    assert_eq!(run_repr("(+ 1 2)"), "3");
    // any inexact → inexact
    assert_eq!(run_repr("(+ 1 2.0)"), "3.0");
    assert_eq!(run_repr("(- 5 1.0)"), "4.0");
    assert_eq!(run_repr("(* 2 1.5)"), "3.0");
    assert_eq!(run_repr("(+ 1/2 0.5)"), "1.0");
}

// ── division (§2) ───────────────────────────────────────────────────────────────

#[test]
fn division_exact_and_demote() {
    assert_eq!(run_repr("(/ 1 3)"), "1/3");
    assert_eq!(run_repr("(/ 10 5)"), "2"); // demote
    assert_eq!(run_repr("(/ 12 2 3)"), "2"); // left fold
    assert_eq!(run_repr("(/ 2)"), "1/2"); // reciprocal
    assert_eq!(run_repr("(/ 1)"), "1");
    assert_eq!(run_repr("(/ 1.0 3)"), "0.3333333333333333"); // inexact
}

#[test]
fn division_by_zero_is_e313_exact_and_inexact() {
    assert_eq!(run_err("(/ 1 0)"), RuntimeCode::E313);
    assert_eq!(run_err("(/ 1 0.0)"), RuntimeCode::E313); // NOT inf
    assert_eq!(run_err("(/ 1.0 0)"), RuntimeCode::E313);
    assert_eq!(run_err("(/ 0)"), RuntimeCode::E313); // reciprocal of 0
}

// ── modulo (§2): sign-of-divisor, 2 integer args ────────────────────────────────

#[test]
fn modulo_sign_of_divisor() {
    assert_eq!(run_repr("(modulo 7 3)"), "1");
    assert_eq!(run_repr("(modulo -7 3)"), "2");
    assert_eq!(run_repr("(modulo 7 -3)"), "-2");
    assert_eq!(run_repr("(modulo -7 -3)"), "-1");
    // inexact integer operand → inexact result
    assert_eq!(run_repr("(modulo 7.0 3)"), "1.0");
}

#[test]
fn modulo_faults() {
    assert_eq!(run_err("(modulo 7 0)"), RuntimeCode::E313); // zero divisor
    assert_eq!(run_err("(modulo 7)"), RuntimeCode::E302); // arity
    assert_eq!(run_err("(modulo 7 3 2)"), RuntimeCode::E302); // arity
    assert_eq!(run_err("(modulo 7 2.5)"), RuntimeCode::E312); // non-integer
    assert_eq!(run_err("(modulo 1/2 3)"), RuntimeCode::E312); // rational not integer
}

// ── quotient / remainder (§2): truncated division; remainder = sign-of-dividend ──

#[test]
fn quotient_remainder_truncate_toward_zero() {
    // quotient truncates toward zero — all four sign quadrants.
    assert_eq!(run_repr("(quotient 7 3)"), "2");
    assert_eq!(run_repr("(quotient -7 3)"), "-2");
    assert_eq!(run_repr("(quotient 7 -3)"), "-2");
    assert_eq!(run_repr("(quotient -7 -3)"), "2");
    // remainder carries the sign of the DIVIDEND.
    assert_eq!(run_repr("(remainder 7 3)"), "1");
    assert_eq!(run_repr("(remainder -7 3)"), "-1");
    assert_eq!(run_repr("(remainder 7 -3)"), "1");
    assert_eq!(run_repr("(remainder -7 -3)"), "-1");
    // contrast pins: `modulo` is sign-of-divisor on the very same operands.
    assert_eq!(run_repr("(modulo -7 3)"), "2");
    assert_eq!(run_repr("(modulo 7 -3)"), "-2");
    // an exact divisor that divides evenly → exact 0 remainder.
    assert_eq!(run_repr("(remainder 6 3)"), "0");
    assert_eq!(run_repr("(quotient -6 3)"), "-2");
}

#[test]
fn quotient_remainder_inexact_contagion() {
    // an inexact integer operand → inexact result (mirror of `modulo_sign_of_divisor`).
    assert_eq!(run_repr("(quotient 7.0 2)"), "3.0");
    assert_eq!(run_repr("(remainder 7.0 2)"), "1.0");
    assert_eq!(run_repr("(quotient 7 2.0)"), "3.0");
    assert_eq!(run_repr("(remainder -7.0 3)"), "-1.0");
    assert_eq!(run_repr("(remainder -6.0 3)"), "0.0"); // +0.0, never -0.0
}

#[test]
fn quotient_remainder_division_identity() {
    // n = d*(quotient n d) + (remainder n d), across sign combinations.
    assert_eq!(run_repr("(+ (* 3 (quotient -7 3)) (remainder -7 3))"), "-7");
    assert_eq!(run_repr("(+ (* -3 (quotient 7 -3)) (remainder 7 -3))"), "7");
    assert_eq!(
        run_repr("(+ (* -3 (quotient -7 -3)) (remainder -7 -3))"),
        "-7"
    );
}

#[test]
fn quotient_remainder_bignum_stays_exact() {
    // A dividend far past f64 range with an EXACT divisor stays exact (no E314)…
    let big = format!("1{}", "0".repeat(60)); // 10^60
    assert!(run_bool(&format!("(exact? (quotient {big} 7))")));
    assert!(run_bool(&format!("(exact? (remainder {big} 7))")));
    // …and the division identity reconstructs the original exactly (it would diverge if
    // the quotient had been coerced to f64).
    assert_eq!(
        run_repr(&format!("(+ (* 7 (quotient {big} 7)) (remainder {big} 7))")),
        big
    );
    // With an INEXACT divisor only the (small, finite) result is coerced — not E314.
    assert!(run_bool(&format!("(inexact? (quotient {big} 7.0))")));
}

#[test]
fn quotient_remainder_faults() {
    // zero divisor → E313 (exact and inexact zero).
    assert_eq!(run_err("(quotient 7 0)"), RuntimeCode::E313);
    assert_eq!(run_err("(remainder 7 0)"), RuntimeCode::E313);
    assert_eq!(run_err("(quotient 7 0.0)"), RuntimeCode::E313);
    assert_eq!(run_err("(remainder 7.0 0)"), RuntimeCode::E313);
    // arity ≠ 2 → E302.
    assert_eq!(run_err("(quotient 7)"), RuntimeCode::E302);
    assert_eq!(run_err("(quotient 7 3 2)"), RuntimeCode::E302);
    assert_eq!(run_err("(remainder 7)"), RuntimeCode::E302);
    // non-integer / non-number → E312.
    assert_eq!(run_err("(quotient 7 2.5)"), RuntimeCode::E312);
    assert_eq!(run_err("(remainder 1/2 3)"), RuntimeCode::E312);
    assert_eq!(run_err("(quotient 7 'a)"), RuntimeCode::E312);
    // an INEXACT quotient result that overflows f64 → E314 (quotient is unbounded, unlike
    // the bounded modulo/remainder results). 10^400 / 1.0 → 1e400 → inf.
    let huge = format!("1{}", "0".repeat(400));
    assert_eq!(
        run_err(&format!("(quotient {huge} 1.0)")),
        RuntimeCode::E314
    );
}

// ── comparisons (§2): ≥2 args, pairwise, mixed compared EXACTLY ─────────────────

#[test]
fn comparison_chains() {
    assert!(run_bool("(< 1 2 3)"));
    assert!(!run_bool("(< 1 3 2)"));
    assert!(run_bool("(> 3 2 1)"));
    assert!(run_bool("(<= 1 1 2)"));
    assert!(run_bool("(>= 3 3 1)"));
    assert!(run_bool("(= 2 2 2)"));
    assert!(!run_bool("(= 2 2 3)"));
}

#[test]
fn comparison_requires_at_least_two_args() {
    // ★ fixes the R3 bootstrap which wrongly accepted 1 arg.
    assert_eq!(run_err("(<)"), RuntimeCode::E302);
    assert_eq!(run_err("(< 5)"), RuntimeCode::E302);
    assert_eq!(run_err("(=)"), RuntimeCode::E302);
    assert_eq!(run_err("(= 5)"), RuntimeCode::E302);
}

#[test]
fn comparison_mixed_exactness_is_exact() {
    // the f64 0.3333333333333333 is NOT exactly 1/3
    assert!(!run_bool("(= 1/3 0.3333333333333333)"));
    assert!(run_bool("(= 1/2 0.5)"));
    assert!(run_bool("(= 0.0 -0.0)")); // numerically equal
    assert!(run_bool("(< 1/2 0.6)"));
    assert!(run_bool("(< 1 1.5 2)"));
}

#[test]
fn comparison_non_number_is_e312() {
    assert_eq!(run_err("(< 1 'a)"), RuntimeCode::E312);
    assert_eq!(run_err("(= 1 \"x\")"), RuntimeCode::E312);
}

// ── abs / min / max ─────────────────────────────────────────────────────────────

#[test]
fn abs_across_tower() {
    assert_eq!(run_repr("(abs -5)"), "5");
    assert_eq!(run_repr("(abs -1/2)"), "1/2");
    assert_eq!(run_repr("(abs -2.5)"), "2.5");
    assert_eq!(run_repr("(abs -0.0)"), "0.0");
}

#[test]
fn min_max_with_contagion() {
    assert_eq!(run_repr("(max 1 2 3)"), "3");
    assert_eq!(run_repr("(min 3 1 2)"), "1");
    // inexactness contagion: an inexact operand → inexact result, even when the
    // selected extremum is exact.
    assert_eq!(run_repr("(max 2 1.0)"), "2.0");
    assert_eq!(run_repr("(min 1 2.0)"), "1.0");
    assert_eq!(run_repr("(max 1 2.0)"), "2.0");
}

// ── exact / inexact crossing (§2) + round-trip ──────────────────────────────────

#[test]
fn exact_of_floats() {
    assert_eq!(run_repr("(exact 0.5)"), "1/2");
    assert_eq!(run_repr("(exact 3.0)"), "3");
    assert_eq!(
        run_repr("(exact 0.1)"),
        "3602879701896397/36028797018963968"
    );
}

#[test]
fn inexact_of_exacts_and_aliases() {
    assert_eq!(run_repr("(inexact 1/2)"), "0.5");
    assert_eq!(run_repr("(inexact 3)"), "3.0");
    // long-name aliases
    assert_eq!(run_repr("(exact->inexact 1/2)"), "0.5");
    assert_eq!(run_repr("(inexact->exact 0.5)"), "1/2");
}

#[test]
fn exact_inexact_round_trip() {
    // exact → inexact → exact recovers the original for dyadic values.
    assert_eq!(run_repr("(exact (inexact 1/2))"), "1/2");
    assert_eq!(run_repr("(inexact (exact 0.25))"), "0.25");
}

#[test]
fn inexact_overflow_is_e314() {
    // 10^400 has no finite f64 → E314 on the exact→f64 coercion.
    let huge = format!("(inexact {}{})", "1", "0".repeat(400));
    assert_eq!(run_err(&huge), RuntimeCode::E314);
}

// ── predicates (§2) ─────────────────────────────────────────────────────────────

#[test]
fn type_predicates_are_total() {
    assert!(run_bool("(number? 1)"));
    assert!(run_bool("(number? 1/2)"));
    assert!(run_bool("(number? 1.5)"));
    assert!(!run_bool("(number? \"x\")"));
    assert!(!run_bool("(number? 'sym)"));

    assert!(run_bool("(integer? 3)"));
    assert!(run_bool("(integer? 3.0)")); // inexact integer
    assert!(!run_bool("(integer? 3.5)"));
    assert!(!run_bool("(integer? 1/2)"));
    assert!(!run_bool("(integer? \"x\")"));

    // exact-integer? — true ONLY for an exact integer.
    assert!(run_bool("(exact-integer? 5)"));
    assert!(!run_bool("(exact-integer? 1/2)"));
    assert!(!run_bool("(exact-integer? 5.0)")); // inexact → #f
    assert!(!run_bool("(exact-integer? 'a)"));
    // rational? / real? / complex? — in v1 every number qualifies (finite real tower, no complex);
    // non-numbers are #f.
    assert!(run_bool("(rational? 5)"));
    assert!(run_bool("(rational? 1/2)"));
    assert!(run_bool("(rational? 2.5)"));
    assert!(!run_bool("(rational? 'a)"));
    assert!(run_bool("(real? 1.5)"));
    assert!(run_bool("(real? 1/3)"));
    assert!(!run_bool("(real? \"x\")"));
    assert!(run_bool("(complex? 5)"));
    assert!(!run_bool("(complex? 'a)"));
    // arity ≠ 1 → E302.
    assert_eq!(run_err("(exact-integer?)"), RuntimeCode::E302);
    assert_eq!(run_err("(real? 1 2)"), RuntimeCode::E302);
}

#[test]
fn exactness_predicates() {
    assert!(run_bool("(exact? 1)"));
    assert!(run_bool("(exact? 1/2)"));
    assert!(!run_bool("(exact? 1.0)"));
    assert!(run_bool("(inexact? 1.0)"));
    assert!(!run_bool("(inexact? 1)"));
    assert_eq!(run_err("(exact? 'x)"), RuntimeCode::E312);
}

#[test]
fn sign_and_zero_predicates() {
    assert!(run_bool("(zero? 0)"));
    assert!(run_bool("(zero? 0.0)"));
    assert!(run_bool("(zero? -0.0)"));
    assert!(!run_bool("(zero? 1/2)"));
    assert!(run_bool("(positive? 3)"));
    assert!(run_bool("(positive? 1/2)"));
    assert!(!run_bool("(positive? 0.0)"));
    assert!(run_bool("(negative? -3)"));
    assert!(run_bool("(negative? -1/2)"));
    assert!(!run_bool("(negative? -0.0)")); // -0.0 is not negative
    assert_eq!(run_err("(zero? 'x)"), RuntimeCode::E312);
}

#[test]
fn parity_predicates_require_integer() {
    assert!(run_bool("(even? 4)"));
    assert!(!run_bool("(even? 3)"));
    assert!(run_bool("(odd? 3)"));
    assert!(run_bool("(even? 4.0)")); // inexact integer allowed
    assert!(run_bool("(odd? 7.0)"));
    assert_eq!(run_err("(even? 2.5)"), RuntimeCode::E312); // non-integer real
    assert_eq!(run_err("(odd? 1/2)"), RuntimeCode::E312); // rational
    assert_eq!(run_err("(even? 'x)"), RuntimeCode::E312); // non-number
}

// ── eqv? numeric upgrade (§6) ────────────────────────────────────────────────────

#[test]
fn eqv_numeric_is_exactness_sensitive() {
    assert!(run_bool("(eqv? 2 2)"));
    assert!(!run_bool("(eqv? 2 2.0)")); // exactness differs
    assert!(run_bool("(eqv? 1/2 1/2)"));
    assert!(run_bool("(eqv? 1/2 2/4)")); // 2/4 normalizes to 1/2
    assert!(run_bool("(eqv? 4 8/2)")); // 8/2 demotes to Int 4
    assert!(!run_bool("(eqv? 0.0 -0.0)")); // distinct finite values
    assert!(run_bool("(eqv? 1.5 1.5)"));
}

// ── the PINNED canonical formatter, end-to-end via number->string + write ───────

#[test]
fn number_to_string_canonical() {
    assert_eq!(run_string("(number->string 42)"), "42");
    assert_eq!(run_string("(number->string -7)"), "-7");
    assert_eq!(run_string("(number->string 1/2)"), "1/2");
    assert_eq!(run_string("(number->string -1/2)"), "-1/2");
    assert_eq!(run_string("(number->string 3.0)"), "3.0");
    assert_eq!(run_string("(number->string 0.5)"), "0.5");
    assert_eq!(run_string("(number->string -0.0)"), "-0.0");
    assert_eq!(run_string("(number->string 1e-7)"), "0.0000001");
    assert_eq!(
        run_string("(number->string (/ 1.0 3))"),
        "0.3333333333333333"
    );
    assert_eq!(
        run_string("(number->string 1e30)"),
        format!("1{}.0", "0".repeat(30))
    );
    assert_eq!(run_err("(number->string 'x)"), RuntimeCode::E312);
}

#[test]
fn number_string_radix() {
    // number->string with a radix (2/8/16) formats an exact integer; radix 10 = default behavior.
    assert_eq!(run_string("(number->string 255 16)"), "ff");
    assert_eq!(run_string("(number->string 255 2)"), "11111111");
    assert_eq!(run_string("(number->string 255 8)"), "377");
    assert_eq!(run_string("(number->string -255 16)"), "-ff");
    assert_eq!(run_string("(number->string 0 16)"), "0");
    assert_eq!(run_string("(number->string 255 10)"), "255");
    assert_eq!(run_string("(number->string 3.5 10)"), "3.5"); // radix 10 still any number
    assert_eq!(run_string("(number->string 1/2 10)"), "1/2");
    // a non-integer with a non-decimal radix → E312; an invalid radix → E312.
    assert_eq!(run_err("(number->string 3.5 16)"), RuntimeCode::E312);
    assert_eq!(run_err("(number->string 1/2 2)"), RuntimeCode::E312);
    assert_eq!(run_err("(number->string 255 3)"), RuntimeCode::E312);
    assert_eq!(run_err("(number->string)"), RuntimeCode::E302);
    assert_eq!(run_err("(number->string 1 2 3)"), RuntimeCode::E302);

    // string->number with a radix parses a signed integer in that base.
    assert_eq!(run_repr("(string->number \"ff\" 16)"), "255");
    assert_eq!(run_repr("(string->number \"FF\" 16)"), "255"); // uppercase accepted
    assert_eq!(run_repr("(string->number \"+ff\" 16)"), "255");
    assert_eq!(run_repr("(string->number \"-ff\" 16)"), "-255");
    assert_eq!(run_repr("(string->number \"11111111\" 2)"), "255");
    assert_eq!(run_repr("(string->number \"377\" 8)"), "255");
    assert_eq!(run_repr("(string->number \"42\" 10)"), "42"); // radix 10 default grammar
                                                              // round-trip number->string/string->number in base 16.
    assert_eq!(
        run_repr("(string->number (number->string 4095 16) 16)"),
        "4095"
    );
    // invalid in the given base → #f (NOT an error), incl. the underscore / prefix gotchas.
    assert!(!run_bool("(string->number \"xyz\" 16)"));
    assert!(!run_bool("(string->number \"ff\" 10)")); // f not base-10
    assert!(!run_bool("(string->number \"2\" 2)")); // 2 not base-2
    assert!(!run_bool("(string->number \"f_f\" 16)")); // underscore rejected (no silent skip)
    assert!(!run_bool("(string->number \"#xff\" 16)")); // in-string prefix not honored in v1
    assert!(!run_bool("(string->number \"\" 16)"));
    // bad radix / non-string / arity faults.
    assert_eq!(run_err("(string->number \"ff\" 3)"), RuntimeCode::E312);
    assert_eq!(run_err("(string->number 5 16)"), RuntimeCode::E312);
    assert_eq!(run_err("(string->number \"1\" 2 3)"), RuntimeCode::E302);
}

#[test]
fn write_renders_numbers_through_the_formatter() {
    // exact int / rational
    assert_eq!(run_repr("(/ 1 3)"), "1/3");
    assert_eq!(run_repr("(/ -1 2)"), "-1/2");
    // inexact reals (positional, trailing .0, -0.0)
    assert_eq!(run_repr("3.0"), "3.0");
    assert_eq!(run_repr("0.5"), "0.5");
    assert_eq!(run_repr("(/ 1.0 3)"), "0.3333333333333333");
    assert_eq!(run_repr("(- 0.0 0.0)"), "0.0");
}

// ── exact bignum stays exact; f64 overflow → E314 ───────────────────────────────

#[test]
fn huge_factorial_stays_exact() {
    // (fact 50) computed by the evaluator must be the exact 50! (no overflow, no float).
    let src = "
        (define (fact n) (if (= n 0) 1 (* n (fact (- n 1)))))
        (fact 50)";
    let mut expected = BigInt::from(1);
    for k in 1..=50u32 {
        expected *= BigInt::from(k);
    }
    match run_one(src) {
        Value::Int(i) => assert_eq!(i, expected),
        other => panic!("expected an exact integer, got {other:?}"),
    }
}

#[test]
fn f64_overflow_in_arithmetic_is_e314() {
    assert_eq!(run_err("(* 1e308 1e308)"), RuntimeCode::E314);
    assert_eq!(run_err("(* 1e200 1e200)"), RuntimeCode::E314); // 1e400 → inf
                                                               // division overflow (finite / tiny) → inf → E314
    assert_eq!(run_err("(/ 1e308 1e-308)"), RuntimeCode::E314);
}

// ── rounding (§2): floor/ceiling/round/truncate — round is half-to-EVEN ──────────

#[test]
fn rounding_over_the_tower() {
    // exact rational → exact Int, in the right direction.
    assert_eq!(run_repr("(floor 7/2)"), "3");
    assert_eq!(run_repr("(ceiling 7/2)"), "4");
    assert_eq!(run_repr("(truncate 7/2)"), "3");
    assert_eq!(run_repr("(floor -7/2)"), "-4");
    assert_eq!(run_repr("(ceiling -7/2)"), "-3");
    assert_eq!(run_repr("(truncate -7/2)"), "-3"); // toward zero
                                                   // Int input → identity (exact).
    assert_eq!(run_repr("(floor 5)"), "5");
    assert_eq!(run_repr("(round -5)"), "-5");
    // inexact real → inexact, exactness preserved.
    assert_eq!(run_repr("(floor 3.5)"), "3.0");
    assert_eq!(run_repr("(ceiling 3.5)"), "4.0");
    assert_eq!(run_repr("(truncate -3.5)"), "-3.0");
    assert_eq!(run_repr("(floor -3.5)"), "-4.0");
    assert_eq!(run_repr("(floor 5.0)"), "5.0");
    // exactness boundary: exact Int vs inexact Real for the same magnitude.
    assert_eq!(run_repr("(truncate 7/2)"), "3");
    assert_eq!(run_repr("(truncate 3.5)"), "3.0");
}

#[test]
fn round_is_half_to_even() {
    // EXACT ties round to the EVEN neighbour (NOT half-away: 5/2 would be 3 under half-away).
    assert_eq!(run_repr("(round 1/2)"), "0");
    assert_eq!(run_repr("(round 3/2)"), "2");
    assert_eq!(run_repr("(round 5/2)"), "2"); // killer vs half-away (→3)
    assert_eq!(run_repr("(round 7/2)"), "4");
    assert_eq!(run_repr("(round -1/2)"), "0"); // exact → plain 0 (no -0)
    assert_eq!(run_repr("(round -3/2)"), "-2");
    assert_eq!(run_repr("(round -5/2)"), "-2");
    // exact non-ties.
    assert_eq!(run_repr("(round 1/3)"), "0");
    assert_eq!(run_repr("(round 2/3)"), "1");
    // INEXACT ties round to even (round_ties_even, NOT f64::round which gives 1.0/3.0).
    assert_eq!(run_repr("(round 0.5)"), "0.0"); // killer vs f64::round (→1.0)
    assert_eq!(run_repr("(round 1.5)"), "2.0");
    assert_eq!(run_repr("(round 2.5)"), "2.0"); // killer vs f64::round (→3.0)
    assert_eq!(run_repr("(round 3.5)"), "4.0");
    assert_eq!(run_repr("(round -2.5)"), "-2.0");
    // inexact non-ties.
    assert_eq!(run_repr("(round 2.4)"), "2.0");
    assert_eq!(run_repr("(round 2.6)"), "3.0");
}

#[test]
fn rounding_negative_zero_and_faults() {
    // inexact results landing on zero from the negative side keep the -0.0 sign bit.
    assert_eq!(run_repr("(round -0.5)"), "-0.0"); // ties to even = 0, sign preserved
    assert_eq!(run_repr("(truncate -0.5)"), "-0.0"); // toward zero
    assert_eq!(run_repr("(ceiling -0.5)"), "-0.0"); // toward +inf
    assert_eq!(run_repr("(floor -0.5)"), "-1.0"); // toward -inf
                                                  // a non-number / non-real arg → E312.
    assert_eq!(run_err("(floor \"x\")"), RuntimeCode::E312);
    assert_eq!(run_err("(round 'sym)"), RuntimeCode::E312);
    // arity ≠ 1 → E302.
    assert_eq!(run_err("(floor)"), RuntimeCode::E302);
    assert_eq!(run_err("(round 1 2)"), RuntimeCode::E302);
}

// ── gcd / lcm (§2): variadic integer folds, always non-negative ──────────────────

#[test]
fn gcd_lcm_variadic() {
    // identities and the non-negative result.
    assert_eq!(run_repr("(gcd)"), "0");
    assert_eq!(run_repr("(lcm)"), "1");
    assert_eq!(run_repr("(gcd 7)"), "7");
    assert_eq!(run_repr("(gcd 12 8)"), "4");
    assert_eq!(run_repr("(gcd 12 8 6)"), "2");
    assert_eq!(run_repr("(gcd 0 5)"), "5");
    assert_eq!(run_repr("(gcd 0 0)"), "0");
    assert_eq!(run_repr("(lcm 4 6)"), "12");
    assert_eq!(run_repr("(lcm 3 5 7)"), "105");
    assert_eq!(run_repr("(lcm 4 0)"), "0"); // any 0 → 0
                                            // signs: gcd/lcm are always non-negative regardless of input signs.
    assert_eq!(run_repr("(gcd 12 -8)"), "4");
    assert_eq!(run_repr("(gcd -12 -8)"), "4");
    assert_eq!(run_repr("(lcm -4 6)"), "12");
    assert_eq!(run_repr("(lcm -4 -6)"), "12");
    // contagion: any inexact integer operand → inexact result.
    assert_eq!(run_repr("(gcd 12.0 8)"), "4.0");
    assert_eq!(run_repr("(lcm 4.0 6)"), "12.0");
    assert_eq!(run_repr("(lcm -4.0 6)"), "12.0");
}

#[test]
fn gcd_lcm_faults() {
    // a non-integer / non-number operand → E312.
    assert_eq!(run_err("(gcd 1/2)"), RuntimeCode::E312);
    assert_eq!(run_err("(gcd 2.5)"), RuntimeCode::E312);
    assert_eq!(run_err("(lcm \"x\")"), RuntimeCode::E312);
    assert_eq!(run_err("(gcd 'a)"), RuntimeCode::E312);
}

// ── expt (§2): exact-integer exponent only; the general/transcendental expt is excluded ──

#[test]
fn expt_exact_integer_powers() {
    // positive exponent, exact base → exact result.
    assert_eq!(run_repr("(expt 2 10)"), "1024");
    assert_eq!(run_repr("(expt 5 1)"), "5");
    assert_eq!(run_repr("(expt -2 3)"), "-8");
    assert_eq!(run_repr("(expt -2 2)"), "4");
    // anything ^ 0 is 1 (exact base → exact 1), including 0 ^ 0.
    assert_eq!(run_repr("(expt 2 0)"), "1");
    assert_eq!(run_repr("(expt 0 0)"), "1");
    assert_eq!(run_repr("(expt 0 5)"), "0");
    // bignum result stays EXACT (no f64 coercion).
    assert_eq!(run_repr("(expt 2 64)"), "18446744073709551616");
    assert!(run_bool("(exact? (expt 2 64))"));
}

#[test]
fn expt_negative_exponent_is_reciprocal() {
    // negative exponent → exact reciprocal (rational), demoting to Int only when integral.
    assert_eq!(run_repr("(expt 2 -1)"), "1/2");
    assert_eq!(run_repr("(expt 2 -3)"), "1/8");
    assert_eq!(run_repr("(expt -2 -1)"), "-1/2");
    // rational base, both signs.
    assert_eq!(run_repr("(expt 1/2 3)"), "1/8");
    assert_eq!(run_repr("(expt 1/2 -1)"), "2"); // reciprocal demotes to an integer
    assert_eq!(run_repr("(expt 2/3 2)"), "4/9");
    assert_eq!(run_repr("(expt 3/2 -2)"), "4/9");
}

#[test]
fn expt_contagion_and_inexact() {
    // an inexact base → inexact result (contagion); an exact base stays exact.
    assert_eq!(run_repr("(expt 2.0 3)"), "8.0");
    assert_eq!(run_repr("(expt 2.0 0)"), "1.0"); // inexact base → inexact 1
    assert_eq!(run_repr("(expt 2.0 -1)"), "0.5"); // inexact negative power
    assert_eq!(run_repr("(expt 0.0 0)"), "1.0");
}

#[test]
fn expt_zero_to_negative_is_faulted() {
    // exact 0 ^ negative → E313 (division by zero); inexact 0.0 ^ negative → +inf → E314.
    assert_eq!(run_err("(expt 0 -1)"), RuntimeCode::E313);
    assert_eq!(run_err("(expt 0.0 -1)"), RuntimeCode::E314);
}

#[test]
fn expt_faults() {
    // the exponent must be an EXACT integer — a float (even integral) or rational → E312.
    assert_eq!(run_err("(expt 2 1.0)"), RuntimeCode::E312);
    assert_eq!(run_err("(expt 2 2.5)"), RuntimeCode::E312);
    assert_eq!(run_err("(expt 2 1/2)"), RuntimeCode::E312);
    assert_eq!(run_err("(expt 2 'a)"), RuntimeCode::E312); // non-number exponent
    assert_eq!(run_err("(expt \"x\" 2)"), RuntimeCode::E312); // non-number base
                                                              // arity ≠ 2 → E302.
    assert_eq!(run_err("(expt 2)"), RuntimeCode::E302);
    assert_eq!(run_err("(expt 2 3 4)"), RuntimeCode::E302);
}

#[test]
fn square_exactness_and_contagion() {
    assert_eq!(run_repr("(square 5)"), "25");
    assert_eq!(run_repr("(square -3)"), "9");
    assert_eq!(run_repr("(square 0)"), "0");
    assert_eq!(run_repr("(square 1/2)"), "1/4");
    assert_eq!(run_repr("(square 2/3)"), "4/9");
    assert_eq!(run_repr("(square 2.5)"), "6.25");
    assert_eq!(run_repr("(square 3.0)"), "9.0"); // inexact stays inexact
    assert_eq!(run_repr("(square 1000000)"), "1000000000000"); // exact (10^6)^2 = 10^12
                                                               // an inexact square that overflows to non-finite → E314.
    assert_eq!(run_err("(square 1e200)"), RuntimeCode::E314);
    assert_eq!(run_err("(square \"x\")"), RuntimeCode::E312);
    assert_eq!(run_err("(square)"), RuntimeCode::E302);
    assert_eq!(run_err("(square 1 2)"), RuntimeCode::E302);
}

#[test]
fn exact_integer_sqrt_floor_and_remainder() {
    // two values s, r with s = floor(sqrt(k)) and r = k - s² (so s² ≤ k < (s+1)²).
    assert_eq!(
        run_repr("(call-with-values (lambda () (exact-integer-sqrt 17)) list)"),
        "(4 1)"
    );
    assert_eq!(
        run_repr("(call-with-values (lambda () (exact-integer-sqrt 16)) list)"),
        "(4 0)"
    );
    assert_eq!(
        run_repr("(call-with-values (lambda () (exact-integer-sqrt 0)) list)"),
        "(0 0)"
    );
    assert_eq!(
        run_repr("(call-with-values (lambda () (exact-integer-sqrt 1)) list)"),
        "(1 0)"
    );
    // exact bignum (no f64 precision loss): sqrt(10^12) = 10^6 exactly.
    assert_eq!(
        run_repr("(call-with-values (lambda () (exact-integer-sqrt (* 1000000 1000000))) list)"),
        "(1000000 0)"
    );
    // faults: negative → E312 (domain), inexact/non-integer → E312, arity → E302.
    assert_eq!(run_err("(exact-integer-sqrt -1)"), RuntimeCode::E312);
    assert_eq!(run_err("(exact-integer-sqrt 4.0)"), RuntimeCode::E312); // inexact
    assert_eq!(run_err("(exact-integer-sqrt 2.5)"), RuntimeCode::E312);
    assert_eq!(run_err("(exact-integer-sqrt 1/2)"), RuntimeCode::E312); // rational
    assert_eq!(run_err("(exact-integer-sqrt)"), RuntimeCode::E302);
    assert_eq!(run_err("(exact-integer-sqrt 1 2)"), RuntimeCode::E302);
}

#[test]
fn floor_truncate_division_family() {
    // floor-quotient FLOORS (toward -inf); contrast quotient which truncates (toward 0).
    assert_eq!(run_repr("(floor-quotient 7 2)"), "3");
    assert_eq!(run_repr("(floor-quotient -7 2)"), "-4");
    assert_eq!(run_repr("(floor-quotient 7 -2)"), "-4");
    assert_eq!(run_repr("(floor-quotient -7 -2)"), "3");
    assert_eq!(run_repr("(quotient -7 2)"), "-3"); // contrast: truncated
                                                   // floor-remainder == modulo (sign of divisor); truncate-* == quotient/remainder.
    assert_eq!(run_repr("(floor-remainder -7 2)"), "1");
    assert_eq!(run_repr("(floor-remainder 7 -2)"), "-1");
    assert_eq!(run_repr("(truncate-quotient -7 2)"), "-3");
    assert_eq!(run_repr("(truncate-remainder -7 2)"), "-1");
    // floor/ and truncate/ return TWO values (quotient, remainder).
    assert_eq!(
        run_repr("(call-with-values (lambda () (floor/ -7 2)) list)"),
        "(-4 1)"
    );
    assert_eq!(
        run_repr("(call-with-values (lambda () (truncate/ -7 2)) list)"),
        "(-3 -1)"
    );
    assert_eq!(
        run_repr("(call-with-values (lambda () (floor/ 7 2)) list)"),
        "(3 1)"
    );
    // division identity n = d*q + r for both.
    assert_eq!(
        run_repr("(call-with-values (lambda () (floor/ -7 2)) (lambda (q r) (+ (* 2 q) r)))"),
        "-7"
    );
    // contagion: an inexact operand → inexact results.
    assert_eq!(run_repr("(floor-quotient 7.0 2)"), "3.0");
    assert_eq!(
        run_repr("(call-with-values (lambda () (floor/ 7.0 2)) list)"),
        "(3.0 1.0)"
    );
}

#[test]
fn floor_truncate_division_faults() {
    // zero divisor → E313; non-integer → E312; arity ≠ 2 → E302.
    assert_eq!(run_err("(floor-quotient 7 0)"), RuntimeCode::E313);
    assert_eq!(run_err("(floor/ 7 0)"), RuntimeCode::E313);
    assert_eq!(run_err("(truncate/ 7 0)"), RuntimeCode::E313);
    assert_eq!(run_err("(floor-remainder 7 0)"), RuntimeCode::E313);
    assert_eq!(run_err("(floor-quotient 7 2.5)"), RuntimeCode::E312);
    assert_eq!(run_err("(truncate/ 1/2 3)"), RuntimeCode::E312);
    assert_eq!(run_err("(floor-quotient 7)"), RuntimeCode::E302);
    assert_eq!(run_err("(floor/ 7 2 3)"), RuntimeCode::E302);
    // an UNBOUNDED inexact floored quotient can overflow f64 → E314 (like quotient).
    assert_eq!(
        run_err("(floor-quotient (expt 10 400) 1.0)"),
        RuntimeCode::E314
    );
}

#[test]
fn expt_unit_base_parity() {
    // base ±1 isolates pure sign parity (independent of magnitude), for both signs of exponent.
    assert_eq!(run_repr("(expt -1 2)"), "1");
    assert_eq!(run_repr("(expt -1 3)"), "-1");
    assert_eq!(run_repr("(expt -1 100)"), "1");
    assert_eq!(run_repr("(expt -1 -1)"), "-1"); // reciprocal of -1 is -1
    assert_eq!(run_repr("(expt -1 -2)"), "1");
    assert_eq!(run_repr("(expt 1 -5)"), "1");
    assert_eq!(run_repr("(expt -1.0 2)"), "1.0"); // inexact powi parity
    assert_eq!(run_repr("(expt -1.0 3)"), "-1.0");
}

#[test]
fn expt_negative_rational_base_reciprocal_sign() {
    // a NEGATIVE rational base with a negative exponent: the reciprocal swap places a negative
    // value into the denominator slot, which BigRational::new must normalize onto the numerator.
    assert_eq!(run_repr("(expt -3/2 -1)"), "-2/3");
    assert_eq!(run_repr("(expt -3/2 -2)"), "4/9"); // even → positive
    assert_eq!(run_repr("(expt -2/3 -1)"), "-3/2");
}

#[test]
fn expt_inexact_overflow_and_zero() {
    // a finite inexact base whose integer power overflows to ±inf → E314 (finite-Real invariant).
    assert_eq!(run_err("(expt 1e200 3)"), RuntimeCode::E314);
    assert_eq!(run_err("(expt 1e308 2)"), RuntimeCode::E314);
    // inexact 0.0 ^ positive stays inexact 0.0 (distinct path from the exact 0 ^ positive → 0).
    assert_eq!(run_repr("(expt 0.0 5)"), "0.0");
    assert!(run_bool("(inexact? (expt 0.0 5))"));
}

#[test]
fn expt_huge_exponent_trivial_is_exact_others_cap() {
    // A base of magnitude 0 or 1 is representable for ANY exponent, so even an exponent past the
    // machine-integer limit returns the exact/finite value rather than spuriously overflowing.
    assert_eq!(run_repr("(expt 1 5000000000)"), "1"); // exp > u32::MAX
    assert_eq!(run_repr("(expt -1 5000000000)"), "1"); // even
    assert_eq!(run_repr("(expt -1 5000000001)"), "-1"); // odd
    assert_eq!(run_repr("(expt 1 -5000000000)"), "1");
    assert_eq!(run_repr("(expt 0 5000000000)"), "0");
    assert_eq!(run_repr("(expt 1.0 3000000000)"), "1.0"); // exp > i32::MAX (inexact)
    assert_eq!(run_repr("(expt -1.0 3000000000)"), "1.0"); // even
    assert_eq!(run_repr("(expt 0.0 3000000000)"), "0.0");
    // any OTHER base with an exponent past the machine-integer limit → the E314 overflow bound.
    assert_eq!(run_err("(expt 2 4294967296)"), RuntimeCode::E314); // exact, exp > u32::MAX
    assert_eq!(run_err("(expt 2.0 3000000000)"), RuntimeCode::E314); // inexact, exp > i32::MAX
    assert_eq!(run_err("(expt 2.0 -3000000000)"), RuntimeCode::E314);
    // a trivial base with an over-limit NEGATIVE exponent still reciprocates cleanly.
    assert_eq!(run_err("(expt 0 -5000000000)"), RuntimeCode::E313); // exact 0 ^ negative
}
