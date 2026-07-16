//! R6 control-flow + error-model conformance tests (LISPEX-RUNTIME.md §5/§8/§9):
//! the user `(error …)` procedure → E330, escape-only `call/cc` (via the threaded
//! `Eval::Escape` signal) with its E340 consumed/out-of-extent fault, cleanup `dynamic-wind`
//! (cleanup-on-escape, before-runs-once, after-replaces-in-flight precedence), and the
//! `call-with-values` multiple-values sink.
//!
//! Strategy mirrors `tests/stdlib.rs`: drive the whole pipeline via [`Interp::run_str`]
//! and assert on the [`Outcome`] (or the [`RuntimeCode`] / full [`RuntimeError`] on a
//! fault, or the buffered I/O output used to observe before/thunk/after ordering).

use lispex::{Interp, Outcome, RunError, RuntimeCode, RuntimeError, Value};

// ── helpers ───────────────────────────────────────────────────────────────────

fn run(src: &str) -> Outcome {
    let mut it = Interp::new();
    it.run_str(src, "ctrl.lx")
        .unwrap_or_else(|e| panic!("unexpected error for `{src}`: {e:?}"))
}

/// Canonical `write` rendering of the (single) last result.
fn run_repr(src: &str) -> String {
    match run(src) {
        Outcome::One(v) => v.write_repr(),
        other => panic!("expected one value for `{src}`, got {other:?}"),
    }
}

fn run_int(src: &str) -> i128 {
    use num_traits::ToPrimitive;
    match run(src) {
        Outcome::One(Value::Int(i)) => i.to_i128().expect("int fits i128"),
        other => panic!("expected one integer for `{src}`, got {other:?}"),
    }
}

/// Run, expecting a runtime fault; return its code.
fn run_err(src: &str) -> RuntimeCode {
    run_err_full(src).code
}

/// Run, expecting a runtime fault; return the full structured fault (for inspecting
/// the E330 message + irritants rendering, §8).
fn run_err_full(src: &str) -> RuntimeError {
    let mut it = Interp::new();
    match it.run_str(src, "ctrl.lx") {
        Err(RunError::Runtime(e)) => e,
        other => panic!("expected a runtime error for `{src}`, got {other:?}"),
    }
}

/// Run (expecting success) and return the buffered display/write output (used to
/// observe before/thunk/after ordering deterministically).
fn run_output(src: &str) -> String {
    let mut it = Interp::new();
    it.run_str(src, "ctrl.lx")
        .unwrap_or_else(|e| panic!("unexpected error for `{src}`: {e:?}"));
    it.take_output()
}

// ── §8: the user (error …) procedure → E330 ─────────────────────────────────────

#[test]
fn error_raises_e330_with_irritants_in_the_message() {
    let e = run_err_full("(error \"boom\" 1 2)");
    assert_eq!(e.code, RuntimeCode::E330);
    assert_eq!(e.message, "boom");
    // Irritants are kept structured and rendered via `write` (§8).
    assert_eq!(e.irritants.len(), 2);
    // The deterministic `CODE file:line:col message irritant…` rendering (§8).
    let rendered = format!("{e}");
    assert_eq!(rendered, "E330 ctrl.lx:1:1 boom 1 2");
}

#[test]
fn error_renders_string_irritants_via_write() {
    // Irritants go through `write`, so a string irritant is quoted/escaped (§8).
    let e = run_err_full("(error \"nope\" \"bad\" 'sym)");
    assert_eq!(e.code, RuntimeCode::E330);
    assert_eq!(format!("{e}"), "E330 ctrl.lx:1:1 nope \"bad\" sym");
}

#[test]
fn error_with_no_arguments_is_arity_e302() {
    assert_eq!(run_err("(error)"), RuntimeCode::E302);
}

#[test]
fn error_aborts_and_is_never_caught_by_call_cc() {
    // v1 has no `guard`; `call/cc` only catches its own tagged escape, never an error,
    // so a `(error …)` inside a `call/cc` propagates straight out (§8).
    assert_eq!(
        run_err("(call/cc (lambda (k) (error \"inside\")))"),
        RuntimeCode::E330
    );
}

// ── §9: escape-only call/cc ──────────────────────────────────────────────────────

#[test]
fn call_cc_returns_proc_value_when_k_unused() {
    // `k` never invoked → the proc's own value is the result.
    assert_eq!(run_int("(call/cc (lambda (k) 42))"), 42);
}

#[test]
fn call_with_current_continuation_long_name_escapes() {
    // the R7RS long spelling is a real alias of call/cc and escapes identically.
    assert_eq!(
        run_int("(call-with-current-continuation (lambda (k) (k 7)))"),
        7
    );
}

#[test]
fn call_cc_early_exit_out_of_a_map_loop() {
    // `k` escapes out of the middle of a `map` traversal, returning a value (§9).
    let src = "(call/cc
                 (lambda (k)
                   (map (lambda (x) (if (= x 3) (k 'found) x)) '(1 2 3 4 5))
                   'fell-through))";
    assert_eq!(run_repr(src), "found");
}

#[test]
fn call_cc_delivers_multiple_values() {
    // `(k 1 2)` → the owning `call/cc` returns `(values 1 2)`, captured downstream.
    let src = "(call-with-values
                 (lambda () (call/cc (lambda (k) (k 1 2))))
                 (lambda (a b) (+ a b)))";
    assert_eq!(run_int(src), 3);
}

#[test]
fn call_cc_non_matching_escape_propagates_to_outer_owner() {
    // An inner `call/cc` does NOT catch the outer `k`'s escape (tag mismatch); it
    // propagates to the outer owner, which returns 100 → (+ 1 100).
    let src = "(+ 1 (call/cc (lambda (outer)
                     (+ 10 (call/cc (lambda (inner)
                              (outer 100)))))))";
    assert_eq!(run_int(src), 101);
}

#[test]
fn call_cc_k_used_after_extent_is_e340() {
    // `k` captured, the `call/cc` returns, THEN `k` is invoked → out of extent → E340
    // (deterministic, never UB; multi-shot re-entry is v2).
    let src = "(define saved #f)
               (call/cc (lambda (k) (set! saved k)))
               (saved 42)";
    assert_eq!(run_err(src), RuntimeCode::E340);
}

#[test]
fn call_cc_k_reinvoked_from_after_is_e340() {
    // The first `(k 1)` consumes this one-shot continuation BEFORE unwinding. Although
    // its owner is still on the stack while `after` runs, `(k 2)` is a reuse and faults
    // E340. That newer fault replaces the in-flight escape (§9 precedence).
    let src = "(call/cc
                 (lambda (k)
                   (dynamic-wind
                     (lambda () 'before)
                     (lambda () (k 1))
                     (lambda () (k 2)))))";
    let error = run_err_full(src);
    assert_eq!(error.code, RuntimeCode::E340);
    assert_eq!(error.message, "escape continuation is no longer active");
}

#[test]
fn dynamic_wind_after_different_escape_replaces_inflight_escape() {
    // `inner` is consumed by the first escape, but `outer` is a distinct, unused live
    // continuation. Invoking it from `after` is valid and its newer escape replaces the
    // inner transfer, so the outer owner receives `second`.
    let src = "(call/cc
                 (lambda (outer)
                   (call/cc
                     (lambda (inner)
                       (dynamic-wind
                         (lambda () 'before)
                         (lambda () (inner 'first))
                         (lambda () (outer 'second)))))
                   'fell-through))";
    assert_eq!(run_repr(src), "second");
}

// ── §9: dynamic-wind ─────────────────────────────────────────────────────────────

#[test]
fn dynamic_wind_normal_order_is_before_thunk_after() {
    let src = "(dynamic-wind
                 (lambda () (display \"B\"))
                 (lambda () (display \"T\") 'result)
                 (lambda () (display \"A\")))";
    assert_eq!(run_output(src), "BTA");
    // The result is the thunk's value.
    assert_eq!(run_repr(src), "result");
}

#[test]
fn dynamic_wind_runs_after_on_escape_then_escapes() {
    // An escape crossing the wind runs the `after` (cleanup) and then the escape
    // continues to its owner; the post-escape thunk code ("X") never runs (§9).
    let src = "(call/cc
                 (lambda (k)
                   (dynamic-wind
                     (lambda () (display \"B\"))
                     (lambda () (display \"T\") (k 'escaped) (display \"X\"))
                     (lambda () (display \"A\")))))";
    assert_eq!(run_output(src), "BTA");
    assert_eq!(run_repr(src), "escaped");
}

#[test]
fn dynamic_wind_before_runs_exactly_once_on_escape() {
    // Escape-only ⇒ no re-entry ⇒ `before` never re-runs (exactly one "B").
    let src = "(call/cc
                 (lambda (k)
                   (dynamic-wind
                     (lambda () (display \"B\"))
                     (lambda () (k 0))
                     (lambda () (display \"A\")))))";
    let out = run_output(src);
    assert_eq!(out.matches('B').count(), 1, "before ran once, got {out:?}");
    assert_eq!(out, "BA");
}

#[test]
fn dynamic_wind_nested_afters_run_innermost_first() {
    // Two nested winds; an escape from the inner thunk runs the inner `after` before
    // the outer `after` (innermost-first on unwind, §9).
    let src = "(call/cc
                 (lambda (k)
                   (dynamic-wind
                     (lambda () (display \"Bo\"))
                     (lambda ()
                       (dynamic-wind
                         (lambda () (display \"Bi\"))
                         (lambda () (k 0))
                         (lambda () (display \"Ai\"))))
                     (lambda () (display \"Ao\")))))";
    // before-outer, before-inner, after-inner, after-outer.
    assert_eq!(run_output(src), "BoBiAiAo");
}

#[test]
fn dynamic_wind_after_error_replaces_inflight_escape() {
    // An `after` that ERRORS while an escape is in flight: the new error REPLACES the
    // escape (precedence, §9), so the whole form faults E330 (the escape's 1 is lost).
    let src = "(call/cc
                 (lambda (k)
                   (dynamic-wind
                     (lambda () #t)
                     (lambda () (k 1))
                     (lambda () (error \"after-failed\")))))";
    assert_eq!(run_err(src), RuntimeCode::E330);
}

#[test]
fn dynamic_wind_after_error_replaces_normal_result() {
    // Even on a NORMAL thunk, an `after` that errors replaces the thunk's value (§9).
    let src = "(dynamic-wind (lambda () #t) (lambda () 'ok) (lambda () (error \"boom\")))";
    assert_eq!(run_err(src), RuntimeCode::E330);
}

#[test]
fn dynamic_wind_before_error_means_no_wind_and_no_after() {
    // If `before` itself signals, the wind is never established: neither thunk nor
    // after run (only "B" prints, then the error propagates).
    let src = "(dynamic-wind
                 (lambda () (display \"B\") (error \"before-failed\"))
                 (lambda () (display \"T\"))
                 (lambda () (display \"A\")))";
    assert_eq!(run_err(src), RuntimeCode::E330);
    assert_eq!(
        run_output(
            "(dynamic-wind
                 (lambda () (display \"B\") 'ok)
                 (lambda () (display \"T\"))
                 (lambda () (display \"A\")))"
        ),
        "BTA"
    ); // sanity: a clean before DOES wind
}

#[test]
fn dynamic_wind_result_can_be_multiple_values() {
    // The thunk's value(s) are the result, including a multiple-values outcome.
    let src = "(call-with-values
                 (lambda () (dynamic-wind (lambda () 0) (lambda () (values 7 8)) (lambda () 0)))
                 (lambda (a b) (* a b)))";
    assert_eq!(run_int(src), 56);
}

// ── §5: call-with-values (the multiple-values sink) ──────────────────────────────

#[test]
fn call_with_values_spec_example() {
    // LISPEX.md §15.1: (call-with-values (lambda () (values 3 1))
    //                                    (lambda (q r) (vector q r))) → #(3 1)
    let src = "(call-with-values (lambda () (values 3 1)) (lambda (q r) (vector q r)))";
    assert_eq!(run_repr(src), "#(3 1)");
}

#[test]
fn call_with_values_basic_arities() {
    // ≥2 values into a variadic consumer.
    assert_eq!(
        run_int("(call-with-values (lambda () (values 1 2 3)) +)"),
        6
    );
    // Exactly one value (producer yields a single value, not a `values` form).
    assert_eq!(
        run_int("(call-with-values (lambda () 5) (lambda (x) (* x x)))"),
        25
    );
    // Zero values into a nullary consumer.
    assert_eq!(
        run_repr("(call-with-values (lambda () (values)) (lambda () 'done))"),
        "done"
    );
}

#[test]
fn call_with_values_consumer_arity_mismatch_is_e302() {
    // The consumer's arity must match the produced count (incl. dotted rest) → E302 (§5).
    assert_eq!(
        run_err("(call-with-values (lambda () (values 1 2)) (lambda (x) x))"),
        RuntimeCode::E302
    );
}

#[test]
fn call_with_values_dotted_rest_consumer() {
    // A dotted-rest consumer collects the trailing produced values into its rest list
    // (the §5 "arity must match incl. dotted rest" path): x=1, rest=(2 3).
    let src =
        "(call-with-values (lambda () (values 1 2 3)) (lambda (x . rest) (+ x (length rest))))";
    assert_eq!(run_int(src), 3);
}

// ── §5: `values` as a first-class procedure (not only the `(values …)` form) ─────

#[test]
fn values_proc_passed_as_consumer_collects_all() {
    // A bare `values` reference resolves to the first-class primitive, so it can be the
    // consumer of `call-with-values`; with `list` it is observable as a proper list.
    assert_eq!(
        run_repr("(call-with-values (lambda () (values 1 2)) list)"),
        "(1 2)"
    );
}

#[test]
fn values_proc_as_consumer_delivers_two_values() {
    // `(call-with-values producer values)` re-delivers the two values; feeding the
    // result into a 2-ary lambda makes the delivery observable (1 + 2 = 3).
    let src = "(call-with-values
                 (lambda () (call-with-values (lambda () (values 1 2)) values))
                 (lambda (a b) (+ a b)))";
    assert_eq!(run_int(src), 3);
}

#[test]
fn values_form_consumer_lambda_still_works() {
    // The classic `(values …)` FORM (a core node) still flows into a matching consumer.
    let src = "(call-with-values (lambda () (values 1 2)) (lambda (a b) (+ a b)))";
    assert_eq!(run_int(src), 3);
}

#[test]
fn values_single_value_context_collapses_to_one() {
    // `(values 5)` in a single-value context collapses to the one value 5 — identical
    // whether reached as the form (core node) or via the first-class primitive.
    assert_eq!(run_int("(values 5)"), 5);
    assert_eq!(
        run_int("(+ 0 (call-with-values (lambda () (values 5)) values))"),
        5
    );
}

#[test]
fn values_proc_passed_as_hof_argument() {
    // `values` passed as an ordinary higher-order argument and applied to many args
    // (in a context that accepts the multiple-values outcome via `call-with-values`).
    let src = "(call-with-values
                 (lambda () ((lambda (f) (f 1 2 3)) values))
                 list)";
    assert_eq!(run_repr(src), "(1 2 3)");
}

#[test]
fn values_proc_zero_values_into_nullary_consumer() {
    // A bare `values` applied to no args is the zero-values outcome (`Many([])`).
    let src = "(call-with-values (lambda () (values)) (lambda () 'done))";
    assert_eq!(run_repr(src), "done");
}

#[test]
fn values_proc_is_procedure_and_eq_to_itself() {
    // It is a real first-class procedure value (so `procedure?` is #t) and aliasing it
    // preserves identity (the same registered primitive).
    assert_eq!(run_repr("(procedure? values)"), "#t");
    assert_eq!(run_repr("(let ((v values)) (eq? v values))"), "#t");
}

// ── ★ §4: call-with-values is TAIL-TRANSPARENT (P0 regression golden) ─────────────

#[test]
fn call_with_values_self_tail_loop_does_not_grow_the_stack() {
    // ⚠ REGRESSION GUARD (the R7 P0 fix). A self-recursive loop whose tail step is a
    // `call-with-values` consumer call. §4 requires TCO "through call-with-values": the
    // consumer call must inherit the caller's tail slot, so this loops in constant host
    // stack. 100_000 hops is 10× the `CALL_DEPTH_LIMIT` (10_000) — BEFORE the fix the
    // consumer ran via a non-tail `Interp::apply`, so each hop grew the host stack and
    // the run faulted `recursion-limit` at ~10k. Run on the DEFAULT (small ~2 MiB)
    // cargo-test stack — no big-stack worker — precisely to prove no growth.
    let src = "
        (define (loop n acc)
          (if (= n 0)
              acc
              (call-with-values
                (lambda () (values (- n 1) (+ acc 1)))
                loop)))
        (loop 100000 0)";
    let mut it = Interp::new(); // DEFAULT bound (10_000), DEFAULT (small) stack.
    match it.run_str(src, "ctrl.lx") {
        Ok(Outcome::One(Value::Int(i))) => {
            use num_traits::ToPrimitive;
            assert_eq!(i.to_i128(), Some(100000), "loop must accumulate 100000");
        }
        other => panic!(
            "call-with-values tail loop should RETURN 100000 (TCO), got {other:?} \
             — a `recursion-limit` here means call-with-values is not tail-transparent"
        ),
    }
}

#[test]
fn call_with_values_self_tail_loop_returns_correct_value_small_bound() {
    // The same loop with a deliberately TINY recursion bound still returns — proof the
    // tail hops cost ZERO logical depth (a non-tail call-with-values would trip the
    // 50-frame bound almost immediately).
    let src = "
        (define (loop n acc)
          (if (= n 0)
              acc
              (call-with-values
                (lambda () (values (- n 1) (+ acc 1)))
                loop)))
        (loop 50000 0)";
    let mut it = Interp::with_limit(50); // a tiny bound a non-tail loop would blow past.
    match it.run_str(src, "ctrl.lx") {
        Ok(Outcome::One(Value::Int(i))) => {
            use num_traits::ToPrimitive;
            assert_eq!(i.to_i128(), Some(50000));
        }
        other => panic!("tail call-with-values must cost no depth, got {other:?}"),
    }
}

// ── the recursion bound stays OUTSIDE the catchable namespace ────────────────────

#[test]
fn recursion_limit_is_not_catchable_by_call_cc() {
    // The recursion bound is a deterministic RESOURCE limit, NOT an E3xx fault and NOT
    // a tag-matched escape, so `call/cc` does not catch it — it propagates (§4/§9).
    let mut it = Interp::with_limit(200);
    let src = "(call/cc (lambda (k)
                 (define (loop n) (+ 1 (loop n)))
                 (loop 0)))";
    match it.run_str(src, "ctrl.lx") {
        Err(RunError::Runtime(e)) => assert_eq!(e.code, RuntimeCode::RecursionLimit),
        other => panic!("expected the non-catchable recursion limit, got {other:?}"),
    }
}

// ── v1.2 recoverable error handling (§8): guard / raise / raise-continuable /
//    with-exception-handler / error objects ─────────────────────────────────────

#[test]
fn guard_catches_error_message_irritants() {
    assert_eq!(
        run_repr(
            "(guard (e (#t (list 'caught (error-object-message e) (error-object-irritants e))))
               (error \"boom\" 1 2))"
        ),
        "(caught \"boom\" (1 2))"
    );
}

#[test]
fn guard_clause_dispatch() {
    assert_eq!(
        run_repr(
            "(guard (e ((symbol? e) (list 'sym e)) ((number? e) (list 'num e)))
               (raise 42))"
        ),
        "(num 42)"
    );
}

#[test]
fn guard_reraises_when_no_clause_matches() {
    // No matching clause and no `else` → the original condition is reraised; uncaught
    // at the top level it renders as E331.
    assert_eq!(
        run_err("(guard (e ((string? e) 'str)) (raise 42))"),
        RuntimeCode::E331
    );
}

#[test]
fn guard_else_catches_intrinsic_fault() {
    // An intrinsic fault (car of a non-pair, E310) is catchable and reads as an error
    // object inside the handler.
    assert_eq!(
        run_repr("(guard (e (else (error-object? e))) (car 5))"),
        "#t"
    );
}

#[test]
fn guard_passes_through_a_normal_result() {
    assert_eq!(run_int("(guard (e (#t 'x)) (+ 1 2))"), 3);
}

#[test]
fn guard_preserves_multiple_values() {
    match run("(guard (e (#t 'x)) (values 1 2))") {
        Outcome::Many(vs) => assert_eq!(vs.len(), 2),
        other => panic!("expected two values, got {other:?}"),
    }
}

#[test]
fn guard_nested_reraise_reaches_outer() {
    assert_eq!(
        run_repr(
            "(guard (e (#t (list 'outer e)))
               (guard (e2 ((string? e2) 'inner)) (raise 'sym)))"
        ),
        "(outer sym)"
    );
}

#[test]
fn raise_uncaught_is_e331() {
    assert_eq!(run_err("(raise 'oops)"), RuntimeCode::E331);
}

#[test]
fn raise_continuable_returns_handler_value() {
    // `with-exception-handler` + `raise-continuable`: the handler runs in place and its
    // value returns INTO the `raise-continuable` call site (1 + 100 = 101).
    assert_eq!(
        run_int(
            "(with-exception-handler (lambda (e) 100)
               (lambda () (+ 1 (raise-continuable 'x))))"
        ),
        101
    );
}

#[test]
fn with_exception_handler_via_callcc_is_a_manual_guard() {
    assert_eq!(
        run_repr(
            "(call/cc (lambda (k)
               (with-exception-handler
                 (lambda (e) (k (error-object-message e)))
                 (lambda () (error \"x\")))))"
        ),
        "\"x\""
    );
}

#[test]
fn error_object_predicate() {
    assert_eq!(run_repr("(error-object? 5)"), "#f");
    assert_eq!(
        run_repr("(error-object? (guard (e (#t e)) (error \"x\")))"),
        "#t"
    );
}

#[test]
fn recursion_limit_is_not_caught_by_guard() {
    let mut it = Interp::new();
    let src = "(guard (e (#t 'caught)) (define (loop n) (+ 1 (loop n))) (loop 0))";
    match it.run_str(src, "ctrl.lx") {
        Err(RunError::Runtime(e)) => assert_eq!(e.code, RuntimeCode::RecursionLimit),
        other => panic!("expected the non-catchable recursion limit, got {other:?}"),
    }
}

#[test]
fn dynamic_wind_after_runs_on_a_caught_unwind() {
    assert_eq!(
        run_output(
            "(guard (e (#t 'done))
               (dynamic-wind (lambda () (display \"[in]\"))
                             (lambda () (error \"x\"))
                             (lambda () (display \"[out]\"))))"
        ),
        "[in][out]"
    );
}

#[test]
fn handler_runs_at_the_raise_point_before_dynamic_wind_after() {
    // R7RS non-unwinding: the handler runs IN PLACE at the `raise`, so it observes the
    // `before` effect but not yet the `after` (which runs as the escape unwinds).
    assert_eq!(
        run_repr(
            "(call/cc (lambda (k)
               (let ((log (list)))
                 (with-exception-handler
                   (lambda (e) (k log))
                   (lambda ()
                     (dynamic-wind (lambda () (set! log (cons 'before log)))
                                   (lambda () (raise 'boom))
                                   (lambda () (set! log (cons 'after log)))))))))"
        ),
        "(before)"
    );
}

#[test]
fn a_handlers_own_raise_goes_to_the_outer_handler_not_itself() {
    // The current handler is suppressed while it runs, so the inner handler sees only
    // `first`; its `(raise 'second)` reaches the OUTER handler, not itself.
    assert_eq!(
        run_repr(
            "(call/cc (lambda (k)
               (let ((seen (list)))
                 (with-exception-handler
                   (lambda (e) (k (list 'outer e seen)))
                   (lambda ()
                     (with-exception-handler
                       (lambda (e) (set! seen (cons e seen)) (raise 'second))
                       (lambda () (raise-continuable 'first))))))))"
        ),
        "(outer second (first))"
    );
}

#[test]
fn guard_catches_a_raise_ahead_of_an_outer_handler() {
    // `guard` installs its own handler, so a `raise` in its body is caught by the guard
    // — not an enclosing `with-exception-handler`.
    assert_eq!(
        run_repr(
            "(with-exception-handler (lambda (e) 'outer)
               (lambda () (guard (e (#t 'inner)) (raise 'x))))"
        ),
        "inner"
    );
}

#[test]
fn wec_catches_a_thunk_arity_fault_born_in_apply() {
    // The fault (E302) is born inside `apply` — the 0-arg thunk call mismatches the
    // 1-arg lambda, BEFORE any thunk body runs. It must still reach the handler the
    // enclosing `with-exception-handler` installed, instead of escaping uncaught past
    // its handler truncate. (Dispatch happens at the apply boundary, not just `eval`.)
    assert_eq!(
        run_repr(
            "(call/cc (lambda (k)
               (with-exception-handler (lambda (e) (k 'caught))
                 (lambda (x) x))))"
        ),
        "caught"
    );
}

#[test]
fn dynamic_wind_after_runs_after_handler_for_a_raw_apply_fault() {
    // The thunk is the primitive `error` invoked with zero args — an arity fault born in
    // `apply`, not in a closure body. The handler must still run at the fault site
    // (observing log = (before)) BEFORE `dynamic-wind` runs its `after`, exactly as it
    // would for a closure-body raise. A regression here prints (after before).
    assert_eq!(
        run_repr(
            "(call/cc (lambda (k)
               (let ((log (list)))
                 (with-exception-handler (lambda (e) (k log))
                   (lambda ()
                     (dynamic-wind
                       (lambda () (set! log (cons 'before log)))
                       error
                       (lambda () (set! log (cons 'after log)))))))))"
        ),
        "(before)"
    );
}

#[test]
fn guard_catches_an_apply_born_thunk_fault() {
    // The guard body is a TAIL-position call whose fault (E302) is born in `apply` — a
    // 0-arg call to a 1-arg lambda, before any body runs. `guard` must catch it like any
    // other condition (the apply-boundary settle reaches the guard's installed handler).
    assert_eq!(
        run_repr("(guard (e (else 'caught)) ((lambda (x) x)))"),
        "caught"
    );
}

#[test]
fn e332_is_offered_to_the_outer_handler() {
    // The inner handler RETURNS from a non-continuable raise → the E332 secondary. It
    // must reach the OUTER handler (which escapes via `k`), never loop on the inner one.
    assert_eq!(
        run_repr(
            "(call/cc (lambda (k)
               (with-exception-handler (lambda (e) (k 'outer-caught))
                 (lambda ()
                   (with-exception-handler (lambda (e) 'returned)
                     (lambda () (raise 'boom)))))))"
        ),
        "outer-caught"
    );
}
