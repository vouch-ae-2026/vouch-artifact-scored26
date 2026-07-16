//! Evaluator core conformance tests (Round 3).
//!
//! Strategy: drive the whole pipeline via [`Interp::run_str`] (read → normalize →
//! evaluate) and assert on the resulting [`Outcome`] (or [`RuntimeCode`] on failure).
//! Covers: every core form, closures (shared-mutable captured cells), `letrec` mutual
//! recursion + the `Uninitialized` sentinel (E321), multiple values + misuse (E320),
//! the four hidden intrinsics via desugared `cond`/`case`/quasiquote, **guaranteed
//! TCO** (deep self + mutual tail recursion; a non-tail recursion hitting the bound),
//! the evaluator-intrinsic faults, and an end-to-end LISPEX.md §15.1 example.

use lispex::{Interp, Outcome, RunError, RuntimeCode, Value};

// ── helpers ───────────────────────────────────────────────────────────────────

/// Run a program (default recursion bound), expecting success; return the last
/// top-level form's outcome.
fn run(src: &str) -> Outcome {
    let mut it = Interp::new();
    it.run_str(src, "t.lx")
        .unwrap_or_else(|e| panic!("unexpected error for `{src}`: {e:?}"))
}

/// Run and expect a single integer result.
fn run_int(src: &str) -> i128 {
    use num_traits::ToPrimitive;
    match run(src) {
        Outcome::One(Value::Int(i)) => i.to_i128().expect("int fits i128"),
        other => panic!("expected one integer for `{src}`, got {other:?}"),
    }
}

/// Run and expect a single value; return its canonical `write` rendering.
fn run_repr(src: &str) -> String {
    match run(src) {
        Outcome::One(v) => v.write_repr(),
        other => panic!("expected one value for `{src}`, got {other:?}"),
    }
}

/// Run and expect a single boolean.
fn run_bool(src: &str) -> bool {
    match run(src) {
        Outcome::One(Value::Bool(b)) => b,
        other => panic!("expected one boolean for `{src}`, got {other:?}"),
    }
}

/// Run, expecting a runtime fault; return its code.
fn run_err(src: &str) -> RuntimeCode {
    let mut it = Interp::new();
    match it.run_str(src, "t.lx") {
        Err(RunError::Runtime(e)) => e.code,
        other => panic!("expected a runtime error for `{src}`, got {other:?}"),
    }
}

/// Run a closure on a thread with a large stack, so deep (non-tail) recursion can
/// reach the *logical* recursion bound without first overflowing the host stack.
fn big_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

// ── core forms ─────────────────────────────────────────────────────────────────

#[test]
fn quote_and_literals() {
    assert_eq!(run_int("5"), 5);
    assert_eq!(run_repr("'(1 2 3)"), "(1 2 3)");
    assert_eq!(run_repr("'foo"), "foo");
    assert!(run_bool("#t"));
    assert!(!run_bool("#f"));
}

#[test]
fn if_truthiness_only_false_is_false() {
    assert_eq!(run_int("(if #t 1 2)"), 1);
    assert_eq!(run_int("(if #f 1 2)"), 2);
    // 0, (), "" and vectors are all truthy (§7).
    assert_eq!(run_int("(if 0 1 2)"), 1);
    assert_eq!(run_int("(if '() 1 2)"), 1);
    assert_eq!(run_int("(if \"\" 1 2)"), 1);
}

#[test]
fn begin_returns_last() {
    assert_eq!(run_int("(begin 1 2 3)"), 3);
}

#[test]
fn lambda_application_and_arith() {
    assert_eq!(run_int("((lambda (x) (+ x 1)) 41)"), 42);
    assert_eq!(run_int("((lambda (x y) (- x y)) 10 3)"), 7);
    assert_eq!(run_int("(- 5)"), -5);
    assert_eq!(run_int("(+)"), 0);
}

#[test]
fn dotted_rest_collects_a_proper_list() {
    assert_eq!(run_repr("((lambda (a . rest) rest) 1 2 3)"), "(2 3)");
    assert_eq!(run_repr("((lambda (a . rest) rest) 1)"), "()");
    assert_eq!(run_repr("((lambda (a b . rest) rest) 1 2 3 4)"), "(3 4)");
}

#[test]
fn let_is_parallel() {
    assert_eq!(run_int("(let ((x 1) (y 2)) (+ x y))"), 3);
    // The inner `y` init sees the OUTER `x` (parallel binding), so y = 1.
    assert_eq!(run_int("(let ((x 1)) (let ((x 2) (y x)) y))"), 1);
}

#[test]
fn define_and_set_and_global_cell_reuse() {
    assert_eq!(run_int("(define x 10) (+ x 5)"), 15);
    assert_eq!(run_int("(define c 0) (set! c 7) c"), 7);
    // A duplicate top-level `define` REASSIGNS the existing global cell, so a closure
    // that captured it earlier sees the new value (§7.8).
    assert_eq!(
        run_int("(define a 1) (define g (lambda () a)) (define a 2) (g)"),
        2
    );
}

#[test]
fn set_and_define_yield_zero_values() {
    assert_eq!(run("(define x 1)"), Outcome::Many(vec![]));
    assert_eq!(run("(define x 1) (set! x 2)"), Outcome::Many(vec![]));
}

// ── closures: shared-mutable captured cell ──────────────────────────────────────

#[test]
fn closure_counter_shares_a_mutable_cell() {
    let src = "
        (define make-counter
          (lambda () (let ((n 0)) (lambda () (set! n (+ n 1)) n))))
        (define c (make-counter))
        (c) (c) (c)";
    assert_eq!(run_int(src), 3);
}

#[test]
fn closures_have_independent_cells() {
    // c2 is untouched by c1's three calls (separate captured `n` cells).
    let src = "
        (define make-counter
          (lambda () (let ((n 0)) (lambda () (set! n (+ n 1)) n))))
        (define c1 (make-counter))
        (define c2 (make-counter))
        (c1) (c1) (c1)
        (c2)";
    assert_eq!(run_int(src), 1);
}

// ── letrec: mutual recursion + the Uninitialized sentinel (E321) ────────────────

#[test]
fn letrec_mutual_recursion() {
    let src = "
        (letrec ((even? (lambda (n) (if (= n 0) #t (odd? (- n 1)))))
                 (odd?  (lambda (n) (if (= n 0) #f (even? (- n 1))))))
          (even? 10))";
    assert!(run_bool(src));
}

#[test]
fn letrec_forward_read_of_uninitialized_is_e321() {
    // `a`'s init reads `b`, whose cell still holds the Uninitialized sentinel.
    assert_eq!(run_err("(letrec ((a b) (b 1)) a)"), RuntimeCode::E321);
}

// ── multiple values + single-value-context misuse (E320) ────────────────────────

#[test]
fn values_outcomes() {
    assert_eq!(
        run("(values 1 2 3)"),
        Outcome::Many(vec![Value::int(1), Value::int(2), Value::int(3)])
    );
    assert_eq!(run("(values)"), Outcome::Many(vec![]));
    // Exactly one value normalizes to a single value.
    assert_eq!(run("(values 5)"), Outcome::One(Value::int(5)));
}

#[test]
fn multiple_values_in_single_value_context_is_e320() {
    assert_eq!(run_err("(+ (values 1 2) 3)"), RuntimeCode::E320); // operand
    assert_eq!(run_err("(if (values) 1 2)"), RuntimeCode::E320); // test (0 values)
    assert_eq!(run_err("(let ((x (values 1 2))) x)"), RuntimeCode::E320); // let RHS
}

// ── the four hidden intrinsics, exercised via desugared forms ────────────────────

#[test]
fn cond_desugaring_evaluates() {
    assert_eq!(run_int("(cond (#f 1) (#t 2) (else 3))"), 2);
    assert_eq!(run_int("(cond (#f 1) (else 9))"), 9);
    // No clause matches and no else → zero values (§0.3).
    assert_eq!(run("(cond (#f 1))"), Outcome::Many(vec![]));
}

#[test]
fn case_desugaring_uses_eqv_intrinsic() {
    // `case` lowers to the hidden `eqv?` intrinsic over the key.
    assert_eq!(run_repr("(case 2 ((1) 'a) ((2 3) 'b) (else 'c))"), "b");
    assert_eq!(run_repr("(case 9 ((1) 'a) ((2 3) 'b) (else 'c))"), "c");
}

#[test]
fn quasiquote_uses_cons_append_listvector_intrinsics() {
    // cons spine + unquote.
    assert_eq!(run_repr("`(1 ,(+ 1 1) 3)"), "(1 2 3)");
    // append intrinsic (unquote-splicing of a quoted list — no user `list` needed).
    assert_eq!(run_repr("`(1 ,@'(2 3) 4)"), "(1 2 3 4)");
    // list->vector intrinsic (vector template).
    assert_eq!(run_repr("`#(1 ,(+ 1 1) 3)"), "#(1 2 3)");
}

#[test]
fn intrinsics_are_immune_to_user_rebinding() {
    // Rebinding `cons`/`eqv?`/`append` must NOT change a desugared form's meaning,
    // because desugarings reference the hidden intrinsic node, not the lexical name.
    assert_eq!(
        run_repr("(define cons (lambda (a b) 'hacked)) `(1 ,(+ 1 1) 3)"),
        "(1 2 3)"
    );
    assert_eq!(
        run_repr("(define eqv? (lambda (a b) #t)) (case 9 ((1) 'a) (else 'c))"),
        "c"
    );
}

// ── ★ guaranteed proper TCO ──────────────────────────────────────────────────────

#[test]
fn tco_deep_self_tail_recursion() {
    // 200_000 tail self-calls: completes with no host-stack growth.
    big_stack(|| {
        let src = "
            (define down
              (lambda (n acc) (if (= n 0) acc (down (- n 1) (+ acc 1)))))
            (down 200000 0)";
        assert_eq!(run_int(src), 200000);
    });
}

#[test]
fn tco_deep_mutual_tail_recursion() {
    // 100_000-deep mutual tail recursion (even?/odd?): the one trampoline loop
    // alternates between the two closures with no stack growth.
    big_stack(|| {
        let src = "
            (letrec ((ev? (lambda (n) (if (= n 0) #t (od? (- n 1)))))
                     (od? (lambda (n) (if (= n 0) #f (ev? (- n 1))))))
              (ev? 100000))";
        assert!(run_bool(src));
    });
}

#[test]
fn non_tail_recursion_hits_the_bound_cleanly() {
    // `(+ n (sum (- n 1)))` keeps the recursive call in OPERAND (non-tail) position,
    // so depth grows ~1 per level and a deep run hits the bound — a clean,
    // diagnosable resource limit, not a host stack overflow.
    big_stack(|| {
        let src = "
            (define sum (lambda (n) (if (= n 0) 0 (+ n (sum (- n 1))))))
            (sum 1000000)";
        let mut it = Interp::new();
        match it.run_str(src, "t.lx") {
            Err(RunError::Runtime(e)) => assert_eq!(e.code, RuntimeCode::RecursionLimit),
            other => panic!("expected RecursionLimit, got {other:?}"),
        }
    });
}

#[test]
fn non_tail_recursion_on_default_stack_faults_cleanly_no_abort() {
    // ⚠ REGRESSION GUARD (the Round-3 host-stack-overflow fix). A deep NON-tail
    // recursion driven through `Interp::new()` on the DEFAULT cargo-test thread (whose
    // stack is only ~2 MiB — NOT the 256 MiB worker the other tests use). Reaching the
    // 10_000 logical bound needs far more host stack than 2 MiB holds, so before the
    // fix this aborted the process (SIGABRT/SIGSEGV host stack overflow) instead of
    // returning. With `stacker` growing the host stack on the heap on demand, the
    // logical bound fires as a clean `RecursionLimit` — the §4 guarantee — on any
    // thread, no big-stack worker required.
    let src = "
        (define sum (lambda (n) (if (= n 0) 0 (+ n (sum (- n 1))))))
        (sum 100000)";
    let mut it = Interp::new(); // DEFAULT bound (10_000), DEFAULT (small) stack.
    match it.run_str(src, "t.lx") {
        Err(RunError::Runtime(e)) => assert_eq!(e.code, RuntimeCode::RecursionLimit),
        other => panic!("expected a clean RecursionLimit (not a host abort), got {other:?}"),
    }
}

#[test]
fn configurable_bound_is_respected() {
    // With a small bound, even a shallow non-tail recursion trips the limit.
    let mut it = Interp::with_limit(200);
    let src = "(define sum (lambda (n) (if (= n 0) 0 (+ n (sum (- n 1)))))) (sum 100000)";
    match it.run_str(src, "t.lx") {
        Err(RunError::Runtime(e)) => assert_eq!(e.code, RuntimeCode::RecursionLimit),
        other => panic!("expected RecursionLimit, got {other:?}"),
    }
}

/// ⚠ LOCKED-PROFILE GUARD. The native non-tail recursion bound is part of the
/// deterministic v1 profile and must stay 10_000. The wasm32 bound is a *separate*,
/// smaller host-resource ceiling (see `eval::CALL_DEPTH_LIMIT`) guarded by
/// `wasm/verify.mjs`, which cargo-test cannot reach. This test compiles for the host
/// (non-wasm), so it pins the native value and fails loudly if anyone edits the const.
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn native_call_depth_limit_is_locked_at_10_000() {
    assert_eq!(lispex::CALL_DEPTH_LIMIT, 10_000);
}

// ── evaluator-intrinsic faults ───────────────────────────────────────────────────

#[test]
fn fault_codes() {
    assert_eq!(run_err("nope"), RuntimeCode::E300); // unbound variable
    assert_eq!(run_err("(5 1)"), RuntimeCode::E301); // apply non-procedure
    assert_eq!(run_err("((lambda (x) x) 1 2)"), RuntimeCode::E302); // too many args
    assert_eq!(run_err("((lambda (x y) x) 1)"), RuntimeCode::E302); // too few args
    assert_eq!(run_err("(set! undefined 1)"), RuntimeCode::E303); // set! on unbound
    assert_eq!(run_err("(car 5)"), RuntimeCode::E310); // pair expected
    assert_eq!(run_err("(+ 1 'x)"), RuntimeCode::E312); // wrong type to primitive
}

// ── end-to-end: LISPEX.md §15.1 named-let `sum` over a quoted list ───────────────

#[test]
fn lispex_15_1_named_let_sum() {
    let src = "
        (define (sum xs)
          (let loop ((xs xs) (acc 0))
            (if (null? xs) acc
                (loop (cdr xs) (+ acc (car xs))))))
        (sum '(1 2 3 4 5))";
    assert_eq!(run_int(src), 15);
}

#[test]
fn named_let_loop_is_tail_recursive_over_a_long_list() {
    // Build a long list with quasiquote-free recursion is awkward; instead sum a
    // range via a tail loop to confirm the named-let idiom is properly TCO'd.
    big_stack(|| {
        let src = "
            (define (count-up n)
              (let loop ((i 0) (acc 0))
                (if (= i n) acc (loop (+ i 1) (+ acc i)))))
            (count-up 100000)";
        // 0+1+...+99999 = 99999*100000/2 = 4999950000
        assert_eq!(run_int(src), 4_999_950_000);
    });
}
