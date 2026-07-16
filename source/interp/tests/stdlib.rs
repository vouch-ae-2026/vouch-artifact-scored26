//! R5 stdlib conformance tests — the v1 builtin set with the canonical-name/alias
//! policy (LISPEX-RUNTIME.md §10), the higher-order procedures with the new apply
//! capability (§1 of the R5 task), deep cycle-safe `equal?` (§6), `display`/`write`
//! (§11), and the W3xx deprecation warnings.
//!
//! Strategy mirrors `tests/eval.rs` / `tests/numeric.rs`: drive the whole pipeline via
//! [`Interp::run_str`] and assert on the [`Outcome`] (or [`RuntimeCode`] on failure,
//! the deprecation [`WarnCode`]s, or the buffered I/O output).

use lispex::{Interp, Outcome, RunError, RuntimeCode, Value, WarnCode};

// ── helpers ───────────────────────────────────────────────────────────────────

fn run(src: &str) -> Outcome {
    let mut it = Interp::new();
    it.run_str(src, "t.lx")
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

/// Run (expecting success) and return the deprecation warning codes emitted.
fn run_warns(src: &str) -> Vec<WarnCode> {
    let mut it = Interp::new();
    it.run_str(src, "t.lx")
        .unwrap_or_else(|e| panic!("unexpected error for `{src}`: {e:?}"));
    it.take_warnings().into_iter().map(|w| w.code).collect()
}

/// Run (expecting success) and return the buffered display/write output.
fn run_output(src: &str) -> String {
    let mut it = Interp::new();
    it.run_str(src, "t.lx")
        .unwrap_or_else(|e| panic!("unexpected error for `{src}`: {e:?}"));
    it.take_output()
}

// ── pairs / lists: canonical names ──────────────────────────────────────────────

#[test]
fn pair_basics() {
    assert_eq!(run_repr("(cons 1 2)"), "(1 . 2)");
    assert_eq!(run_int("(car '(1 2))"), 1);
    assert_eq!(run_repr("(cdr '(1 2))"), "(2)");
    assert!(run_bool("(pair? '(1))"));
    assert!(!run_bool("(pair? '())"));
    assert!(run_bool("(null? '())"));
    assert!(!run_bool("(null? '(1))"));
}

#[test]
fn cxr_composition_accessors() {
    // the 2-deep (scheme base) accessors.
    assert_eq!(run_int("(caar '((1) 2))"), 1);
    assert_eq!(run_int("(cadr '(1 2 3))"), 2);
    assert_eq!(run_repr("(cdar '((1 2) 3))"), "(2)");
    assert_eq!(run_repr("(cddr '(1 2 3))"), "(3)");
    // a sampling of the 3-/4-deep (scheme cxr) extension.
    assert_eq!(run_int("(caddr '(1 2 3))"), 3);
    assert_eq!(run_int("(cadddr '(1 2 3 4))"), 4);
    assert_eq!(run_int("(caddar '((1 2 3) 4))"), 3); // car(cdr(cdr(car x)))
    assert_eq!(run_repr("(cddddr '(1 2 3 4 5))"), "(5)");
    // a non-pair at ANY step → E310 (like car/cdr); arity ≠ 1 → E302.
    assert_eq!(run_err("(cadr '(1))"), RuntimeCode::E310); // cdr → (), then car of () → E310
    assert_eq!(run_err("(caar '(1 2))"), RuntimeCode::E310); // car → 1, then car of 1 → E310
    assert_eq!(run_err("(cadr 5)"), RuntimeCode::E310);
    assert_eq!(run_err("(cadr)"), RuntimeCode::E302);
    assert_eq!(run_err("(cadr '(1) '(2))"), RuntimeCode::E302);
}

#[test]
fn make_list_constructor() {
    assert_eq!(run_repr("(make-list 3 'x)"), "(x x x)");
    assert_eq!(run_repr("(make-list 0 'x)"), "()");
    assert_eq!(run_repr("(make-list 2)"), "(0 0)"); // default fill = 0 (pinned, like make-vector)
    assert_eq!(run_repr("(make-list 0)"), "()");
    // k: non-negative exact integer — negative/huge → E311, non-integer → E312 (make-vector family).
    assert_eq!(run_err("(make-list -1)"), RuntimeCode::E311);
    assert_eq!(run_err("(make-list 2.5 'x)"), RuntimeCode::E312);
    assert_eq!(run_err("(make-list \"x\")"), RuntimeCode::E312);
    assert_eq!(run_err("(make-list)"), RuntimeCode::E302);
    assert_eq!(run_err("(make-list 1 2 3)"), RuntimeCode::E302);
}

#[test]
fn list_predicate_is_total() {
    assert!(run_bool("(list? '(1 2 3))"));
    assert!(run_bool("(list? '())"));
    assert!(!run_bool("(list? '(1 . 2))")); // improper → #f, never an error
    assert!(!run_bool("(list? 5)"));
    assert!(!run_bool("(list? \"abc\")"));
}

#[test]
fn length_append_reverse_list() {
    assert_eq!(run_int("(length '(1 2 3))"), 3);
    assert_eq!(run_int("(length '())"), 0);
    assert_eq!(run_repr("(append '(1 2) '(3 4))"), "(1 2 3 4)");
    assert_eq!(run_repr("(append)"), "()");
    assert_eq!(run_repr("(reverse '(1 2 3))"), "(3 2 1)");
    assert_eq!(run_repr("(list 1 2 3)"), "(1 2 3)"); // R7RS rendering, not (list …)
    assert_eq!(run_repr("(list)"), "()");
}

#[test]
fn list_ref_and_alias() {
    assert_eq!(run_repr("(list-ref '(a b c) 1)"), "b");
    assert_eq!(run_repr("(nth '(a b c) 1)"), "b"); // alias, same arg order
    assert_eq!(run_int("(list-ref '(10 20 30) 0)"), 10);
}

#[test]
fn list_tail_shares_structure() {
    assert_eq!(run_repr("(list-tail '(1 2 3 4) 0)"), "(1 2 3 4)"); // k=0 → lst unchanged
    assert_eq!(run_repr("(list-tail '(1 2 3 4) 2)"), "(3 4)");
    assert_eq!(run_repr("(list-tail '(1 2 3) 3)"), "()"); // k == length → ()
    assert_eq!(run_repr("(list-tail '(1 2 . 3) 2)"), "3"); // improper tail reached
    assert_eq!(run_repr("(list-tail 5 0)"), "5"); // k=0 returns any obj unchanged
                                                  // the returned tail is the SAME spine node (shared Rc → eq?).
    assert!(run_bool(
        "(let ((l '(1 2 3))) (eq? (list-tail l 1) (cdr l)))"
    ));
    // fewer than k elements (a cdr step lands on a non-pair) → E311 (range), not E310.
    assert_eq!(run_err("(list-tail '(1 2 3) 4)"), RuntimeCode::E311);
    assert_eq!(run_err("(list-tail '() 1)"), RuntimeCode::E311);
    assert_eq!(run_err("(list-tail '(1 2 . 3) 3)"), RuntimeCode::E311);
    assert_eq!(run_err("(list-tail 5 1)"), RuntimeCode::E311); // non-pair, k>0
    assert_eq!(run_err("(list-tail '(1) -1)"), RuntimeCode::E311); // negative k
    assert_eq!(run_err("(list-tail '(1) 1.0)"), RuntimeCode::E312); // non-int k
    assert_eq!(run_err("(list-tail '(1))"), RuntimeCode::E302); // arity
}

#[test]
fn list_copy_is_shallow_and_total() {
    assert_eq!(run_repr("(list-copy '(1 2 3))"), "(1 2 3)");
    assert_eq!(run_repr("(list-copy '())"), "()");
    assert_eq!(run_repr("(list-copy '(1 2 . 3))"), "(1 2 . 3)"); // improper preserved
    assert_eq!(run_repr("(list-copy 5)"), "5"); // non-pair returned unchanged (total)
                                                // a fresh spine (not eq? to the input) but the SAME car objects (shared, not deep-copied).
    assert!(run_bool(
        "(let ((l '(1 2 3))) (and (equal? (list-copy l) l) (not (eq? (list-copy l) l))))"
    ));
    assert!(run_bool(
        "(let ((x (list 9))) (eq? (car (list-copy (list x))) x))"
    ));
    assert_eq!(run_err("(list-copy)"), RuntimeCode::E302); // arity
}

// ── member / assoc families (§10): list/alist search — member/assoc by equal?, the ──
//    v/q spellings by eqv? (eq? ≡ eqv? in v1, §6) ─────────────────────────────────

#[test]
fn member_family_search() {
    // returns the matching SUBLIST (not the element), #f when absent, empty → #f.
    assert_eq!(run_repr("(member 2 '(1 2 3))"), "(2 3)");
    assert_eq!(run_repr("(member 1 '(1 2 3))"), "(1 2 3)");
    assert_eq!(run_repr("(member 3 '(1 2 3))"), "(3)");
    assert!(!run_bool("(member 9 '(1 2 3))")); // not found → #f
    assert!(!run_bool("(member 1 '())")); // empty → #f
                                          // member uses equal? (deep); memq/memv use eqv? (identity on pairs).
    assert_eq!(run_repr("(member (list 1) '((0) (1) (2)))"), "((1) (2))");
    assert!(!run_bool("(memq (list 1) '((0) (1) (2)))")); // fresh list, not eqv
                                                          // memv/memq on atoms; eqv? is exactness-sensitive (2.0 ≠ 2).
    assert_eq!(run_repr("(memv 2 '(1 2 3))"), "(2 3)");
    assert!(!run_bool("(memv 2.0 '(1 2 3))"));
    assert_eq!(run_repr("(memq 'b '(a b c))"), "(b c)");
    // the returned sublist is the SAME spine node (shared Rc → eq?).
    assert!(run_bool("(let ((l '(1 2 3))) (eq? (member 2 l) (cdr l)))"));
}

#[test]
fn assoc_family_search() {
    // returns the matching ENTRY pair, #f when absent, empty → #f.
    assert_eq!(run_repr("(assoc 'b '((a 1) (b 2) (c 3)))"), "(b 2)");
    assert_eq!(run_repr("(assq 'a '((a . 1) (b . 2)))"), "(a . 1)"); // dotted entry is a pair
    assert_eq!(run_repr("(assv 2 '((1 . a) (2 . b)))"), "(2 . b)");
    assert!(!run_bool("(assoc 'z '((a 1)))")); // not found → #f
    assert!(!run_bool("(assq 'a '())")); // empty → #f
                                         // assoc uses equal? on the key; assq/assv use eqv?.
    assert_eq!(
        run_repr("(assoc (list 1) '(((1) . x) ((2) . y)))"),
        "((1) . x)"
    );
    assert!(!run_bool("(assq (list 1) '(((1) . x)))"));
    // first match wins.
    assert_eq!(run_repr("(assq 'a '((a . 1) (a . 2)))"), "(a . 1)");
}

#[test]
fn member_assoc_are_distinct_prims_not_aliases() {
    // six separate procedures (NOT aliases): memq and memv are distinct values even
    // though eq? ≡ eqv? makes them behave identically in v1.
    assert!(!run_bool("(eq? memq memv)"));
    assert!(!run_bool("(eq? assq assv)"));
    // …yet they behave identically here.
    assert_eq!(run_repr("(memq 2 '(1 2 3))"), run_repr("(memv 2 '(1 2 3))"));
}

#[test]
fn member_assoc_faults() {
    // non-list / improper (unmatched) 2nd arg → E312 (the reverse/map family, not E310).
    assert_eq!(run_err("(member 1 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(member 9 '(1 2 . 3))"), RuntimeCode::E312);
    // assoc on a non-pair alist entry → E312.
    assert_eq!(run_err("(assq 'a '(1 2 3))"), RuntimeCode::E312);
    assert_eq!(run_err("(assoc 'z '((a 1) 2))"), RuntimeCode::E312);
    // …but a match BEFORE the bad entry succeeds (stop-at-first-match).
    assert_eq!(run_repr("(assq 'a '((a . 1) 2))"), "(a . 1)");
    // arity ≠ 2 → E302 (there is no optional compare argument in v1).
    assert_eq!(run_err("(member 1)"), RuntimeCode::E302);
    assert_eq!(run_err("(member 1 '() equal?)"), RuntimeCode::E302);
    assert_eq!(run_err("(assoc)"), RuntimeCode::E302);
}

// ── fold-left (alias of reduce) / fold-right (§10): the directional folds ─────────

#[test]
fn fold_left_right_directional() {
    // fold-left == reduce: (f acc elem), left-to-right.
    assert_eq!(run_int("(fold-left - 0 '(1 2 3))"), -6); // ((0-1)-2)-3
    assert_eq!(
        run_repr("(fold-left (lambda (acc x) (cons x acc)) '() '(1 2 3))"),
        "(3 2 1)"
    );
    // fold-right: (f elem acc), right-to-left.
    assert_eq!(run_int("(fold-right - 0 '(1 2 3))"), 2); // 1-(2-(3-0))
    assert_eq!(run_repr("(fold-right cons '() '(1 2 3))"), "(1 2 3)"); // identity rebuild
    assert_eq!(
        run_repr("(fold-right (lambda (x acc) (cons (* x 2) acc)) '() '(1 2 3))"),
        "(2 4 6)"
    );
    // empty → init (both); single element.
    assert_eq!(run_int("(fold-left + 99 '())"), 99);
    assert_eq!(run_int("(fold-right + 7 '())"), 7);
    assert_eq!(run_int("(fold-right - 0 '(5))"), 5);
}

#[test]
fn fold_faults_and_signals() {
    // arity != 3 → E302 (single-list only; a 2nd list is rejected as wrong arity).
    assert_eq!(run_err("(fold-left + 0)"), RuntimeCode::E302);
    assert_eq!(
        run_err("(fold-right cons '() '(1) '(2))"),
        RuntimeCode::E302
    );
    // non-list / improper 3rd arg → E312 (no partial fold — list_elems faults first).
    assert_eq!(run_err("(fold-left + 0 5)"), RuntimeCode::E312);
    assert_eq!(
        run_err("(fold-right cons '() '(1 2 . 3))"),
        RuntimeCode::E312
    );
    // a per-element call producing multiple values → E320.
    assert_eq!(
        run_err("(fold-right (lambda (x acc) (values 1 2)) 0 '(1))"),
        RuntimeCode::E320
    );
}

// ── pairs / lists: friendly + deprecated aliases ────────────────────────────────

#[test]
fn aliases_run_identically_to_canonical() {
    // first/rest = car/cdr; empty? = null?; nth = list-ref.
    assert_eq!(run_int("(first '(1 2))"), run_int("(car '(1 2))"));
    assert_eq!(run_repr("(rest '(1 2))"), run_repr("(cdr '(1 2))"));
    assert_eq!(run_bool("(empty? '())"), run_bool("(null? '())"));
    assert_eq!(
        run_repr("(nth '(a b c) 1)"),
        run_repr("(list-ref '(a b c) 1)")
    );
    assert_eq!(
        run_int("(fold-left + 0 '(1 2 3))"),
        run_int("(reduce + 0 '(1 2 3))")
    );
}

#[test]
fn aliases_are_real_aliases_by_identity() {
    // A real alias binds the SAME primitive value, so eq?/eqv? sees identity (§10).
    assert!(run_bool("(eq? car first)"));
    assert!(run_bool("(eq? cdr rest)"));
    assert!(run_bool("(eq? null? empty?)"));
    assert!(run_bool("(eqv? list-ref nth)"));
    assert!(run_bool("(eq? equal? ==)"));
    assert!(run_bool("(eq? reduce fold-left)")); // fold-left = R6RS spelling of reduce
    assert!(run_bool("(eq? call/cc call-with-current-continuation)")); // R7RS long name
}

#[test]
fn deprecated_list_accessors_run_and_warn() {
    assert_eq!(run_int("(list-first '(1 2))"), 1); // behaves as car
    assert_eq!(run_repr("(list-rest '(1 2))"), "(2)"); // behaves as cdr
    assert_eq!(run_warns("(list-first '(1 2))"), vec![WarnCode::W331]);
    assert_eq!(run_warns("(list-rest '(1 2))"), vec![WarnCode::W331]);
}

#[test]
fn deprecated_percent_runs_and_warns() {
    assert_eq!(run_int("(% 7 3)"), 1); // behaves as modulo
    assert_eq!(run_warns("(% 7 3)"), vec![WarnCode::W330]);
    // The canonical `modulo` does NOT warn.
    assert!(run_warns("(modulo 7 3)").is_empty());
}

// ── list diagnostics ────────────────────────────────────────────────────────────

#[test]
fn list_errors() {
    assert_eq!(run_err("(car '())"), RuntimeCode::E310);
    assert_eq!(run_err("(car 5)"), RuntimeCode::E310);
    assert_eq!(run_err("(cdr '())"), RuntimeCode::E310);
    assert_eq!(run_err("(length '(1 2 . 3))"), RuntimeCode::E310); // improper → E310
    assert_eq!(run_err("(length 5)"), RuntimeCode::E310);
    assert_eq!(run_err("(reverse 5)"), RuntimeCode::E312); // non-list to a list op → E312
    assert_eq!(run_err("(list-ref '(a b) 5)"), RuntimeCode::E311); // OOB → E311
    assert_eq!(run_err("(list-ref '(a b) -1)"), RuntimeCode::E311);
    assert_eq!(run_err("(car)"), RuntimeCode::E302); // arity
    assert_eq!(run_err("(cons 1)"), RuntimeCode::E302);
}

// ── higher-order procedures (the new apply capability) ──────────────────────────

#[test]
fn map_filter_reduce_happy() {
    assert_eq!(run_repr("(map (lambda (x) (* x x)) '(1 2 3))"), "(1 4 9)");
    assert_eq!(
        run_repr("(filter (lambda (x) (> x 2)) '(1 2 3 4))"),
        "(3 4)"
    );
    assert_eq!(run_int("(reduce + 0 '(1 2 3 4))"), 10); // left fold over a primitive
    assert_eq!(run_int("(reduce + 0 '())"), 0); // empty → init
                                                // reduce f = (acc elem): build a reversed list to show left-fold order.
    assert_eq!(
        run_repr("(reduce (lambda (acc x) (cons x acc)) '() '(1 2 3))"),
        "(3 2 1)"
    );
    // map over the empty list never calls the proc (so a non-proc is fine here).
    assert_eq!(run_repr("(map car '())"), "()");
}

#[test]
fn map_can_call_a_primitive_procedure() {
    assert_eq!(run_repr("(map car '((1 a) (2 b) (3 c)))"), "(1 2 3)");
}

#[test]
fn hof_errors_propagate_out_of_the_hof() {
    // A closure that faults mid-map → the fault aborts the whole HOF (signal threaded).
    assert_eq!(
        run_err("(map (lambda (x) (car x)) '(1 2 3))"),
        RuntimeCode::E310
    );
    assert_eq!(run_err("(map car '(1 2 3))"), RuntimeCode::E310);
    assert_eq!(
        run_err("(reduce (lambda (acc x) (car x)) 0 '(1))"),
        RuntimeCode::E310
    );
    // Applying a non-procedure inside map → E301.
    assert_eq!(run_err("(map 5 '(1 2))"), RuntimeCode::E301);
    // Arity mismatch when applying the user proc → E302.
    assert_eq!(run_err("(map (lambda (x y) x) '(1 2))"), RuntimeCode::E302);
    // A proc yielding multiple values in the single-value per-element context → E320.
    assert_eq!(
        run_err("(map (lambda (x) (values 1 2)) '(1))"),
        RuntimeCode::E320
    );
    // The HOFs themselves are arity-checked.
    assert_eq!(run_err("(map car)"), RuntimeCode::E302);
    assert_eq!(run_err("(reduce + 0)"), RuntimeCode::E302);
}

// ── equality: eq?/eqv?/equal? + ==/!= ───────────────────────────────────────────

#[test]
fn equality_basics() {
    assert!(run_bool("(eqv? 2 2)"));
    assert!(!run_bool("(eqv? 2 2.0)")); // exactness-sensitive
    assert!(run_bool("(eq? 'a 'a)"));
    assert!(run_bool("(eqv? 1/2 1/2)"));
}

#[test]
fn equal_is_deep_structural() {
    assert!(run_bool("(equal? '(1 2 (3 4)) '(1 2 (3 4)))"));
    assert!(!run_bool("(equal? '(1 2 (3 4)) '(1 2 (3 5)))"));
    assert!(run_bool("(equal? \"abc\" \"abc\")")); // strings by char=
    assert!(!run_bool("(equal? \"abc\" \"abd\")"));
    assert!(run_bool("(equal? (vector 1 2 3) (vector 1 2 3))")); // vectors elementwise
    assert!(!run_bool("(equal? (vector 1 2) (vector 1 2 3))"));
    assert!(!run_bool("(equal? 2 2.0)")); // atoms via eqv? → exactness-sensitive
    assert!(!run_bool("(equal? '(1 2) (vector 1 2))")); // cross-type → #f
                                                        // procedures by identity
    assert!(run_bool("(equal? car car)"));
    assert!(!run_bool("(equal? car cdr)"));
}

#[test]
fn equal_aliases_eqeq_and_bang_eq() {
    assert!(run_bool("(== '(1 2) '(1 2))")); // == aliases equal?
    assert!(!run_bool("(== '(1 2) '(1 3))"));
    assert!(run_bool("(!= '(1 2) '(1 3))")); // != = (not (equal? …))
    assert!(!run_bool("(!= '(1 2) '(1 2))"));
}

#[test]
fn equal_is_cycle_safe_and_terminates() {
    // A self-referential vector (the only way to build a cycle in v1) compared to
    // itself MUST terminate (visited-set / co-induction), not loop forever.
    assert!(run_bool(
        "(define v (make-vector 1 0)) (vector-set! v 0 v) (equal? v v)"
    ));
    // Two distinct but bisimilar self-cycles compare equal and terminate.
    assert!(run_bool(
        "(define a (make-vector 1 0)) (vector-set! a 0 a)
         (define b (make-vector 1 0)) (vector-set! b 0 b)
         (equal? a b)"
    ));
    // A cyclic vector vs a finite one terminates and is unequal.
    assert!(!run_bool(
        "(define v (make-vector 1 0)) (vector-set! v 0 v) (equal? v (make-vector 1 0))"
    ));
}

#[test]
fn not_and_equality_arity() {
    assert!(run_bool("(not #f)"));
    assert!(!run_bool("(not 5)"));
    assert!(!run_bool("(not '())"));
    assert_eq!(run_err("(equal? 1)"), RuntimeCode::E302);
}

// ── strings ─────────────────────────────────────────────────────────────────────

#[test]
fn string_ops() {
    assert_eq!(run_repr("(string-append \"a\" \"b\" \"c\")"), "\"abc\"");
    assert_eq!(run_repr("(string-append)"), "\"\"");
    assert_eq!(run_int("(string-length \"hello\")"), 5);
    assert_eq!(run_repr("(substring \"hello\" 1 4)"), "\"ell\"");
    assert_eq!(run_repr("(substring \"hello\" 0 0)"), "\"\"");
    assert_eq!(run_repr("(substring \"hello\" 0 5)"), "\"hello\"");
    // string-ref: a CHARACTER index (not a byte offset), matching string-length/substring.
    assert_eq!(run_repr("(string-ref \"abc\" 0)"), "#\\a");
    assert_eq!(run_repr("(string-ref \"abc\" 2)"), "#\\c");
    // index 1 of "hαllo" is U+03B1 (α) — proves char-index, not byte-index.
    assert_eq!(
        run_int("(char->integer (string-ref \"h\\x3b1;llo\" 1))"),
        945
    );
}

#[test]
fn string_list_symbol_roundtrips() {
    assert_eq!(run_repr("(string->list \"ab\")"), "(#\\a #\\b)");
    assert_eq!(run_repr("(list->string (list #\\a #\\b))"), "\"ab\"");
    assert_eq!(run_repr("(string->symbol \"foo\")"), "foo");
    assert_eq!(run_repr("(symbol->string 'foo)"), "\"foo\"");
    assert_eq!(
        run_repr("(symbol->string (string->symbol \"xy\"))"),
        "\"xy\""
    );
    assert_eq!(run_repr("(list->string (string->list \"hi\"))"), "\"hi\"");
}

#[test]
fn string_to_number() {
    assert_eq!(run_int("(string->number \"42\")"), 42);
    assert_eq!(run_repr("(string->number \"1/2\")"), "1/2");
    assert_eq!(run_repr("(string->number \"3.5\")"), "3.5");
    assert!(!run_bool("(string->number \"abc\")")); // unparsable → #f
    assert!(!run_bool("(string->number \"\")"));
    assert!(!run_bool("(string->number \"4.2.0\")"));
    // number->string is the inverse for the canonical formatter.
    assert_eq!(run_repr("(number->string 42)"), "\"42\"");
    assert_eq!(run_repr("(number->string 3.5)"), "\"3.5\"");
}

#[test]
fn string_to_number_nonfinite_is_e314() {
    // Matched the real grammar but overflows to non-finite → E314 (§2), not #f.
    assert_eq!(run_err("(string->number \"1e9999\")"), RuntimeCode::E314);
}

#[test]
fn string_errors() {
    assert_eq!(run_err("(string-length 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(string-append \"a\" 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(substring \"hello\" 2 10)"), RuntimeCode::E311); // end OOB
    assert_eq!(run_err("(substring \"hello\" 3 1)"), RuntimeCode::E311); // start > end
    assert_eq!(run_err("(list->string '(1 2))"), RuntimeCode::E312); // non-char element
    assert_eq!(run_err("(symbol->string 5)"), RuntimeCode::E312);
    // string-ref: OOB index → E311; non-string/non-int → E312; arity → E302.
    assert_eq!(run_err("(string-ref \"abc\" 3)"), RuntimeCode::E311);
    assert_eq!(run_err("(string-ref \"\" 0)"), RuntimeCode::E311);
    assert_eq!(run_err("(string-ref \"abc\" -1)"), RuntimeCode::E311);
    assert_eq!(run_err("(string-ref 5 0)"), RuntimeCode::E312);
    assert_eq!(run_err("(string-ref \"abc\" 1.0)"), RuntimeCode::E312);
    assert_eq!(run_err("(string-ref \"abc\")"), RuntimeCode::E302);
}

// ── chars ─────────────────────────────────────────────────────────────────────

#[test]
fn char_ops_and_roundtrip() {
    assert!(run_bool("(char? #\\a)"));
    assert!(!run_bool("(char? 5)"));
    assert_eq!(run_int("(char->integer #\\A)"), 65);
    assert_eq!(run_repr("(integer->char 65)"), "#\\A");
    assert_eq!(run_repr("(integer->char (char->integer #\\z))"), "#\\z");
    assert_eq!(run_int("(char->integer (integer->char 97))"), 97);
}

#[test]
fn char_errors() {
    assert_eq!(run_err("(char->integer 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(integer->char 55296)"), RuntimeCode::E312); // 0xD800 surrogate
    assert_eq!(run_err("(integer->char -1)"), RuntimeCode::E312);
    assert_eq!(run_err("(integer->char 1114112)"), RuntimeCode::E312); // > 0x10FFFF
}

#[test]
fn char_comparison_chains() {
    // equality (variadic chain, all adjacent equal).
    assert!(run_bool("(char=? #\\a #\\a)"));
    assert!(!run_bool("(char=? #\\a #\\b)"));
    assert!(run_bool("(char=? #\\x #\\x #\\x)"));
    assert!(!run_bool("(char=? #\\a #\\b #\\a)"));
    // strict order — Unicode scalar (codepoint) order, pairwise L→R.
    assert!(run_bool("(char<? #\\a #\\b #\\c)"));
    assert!(!run_bool("(char<? #\\a #\\c #\\b)")); // a<c but not c<b
    assert!(!run_bool("(char<? #\\a #\\a)")); // equal is not strictly <
    assert!(run_bool("(char>? #\\c #\\b #\\a)"));
    // non-strict allows equal adjacent.
    assert!(run_bool("(char<=? #\\a #\\a #\\b)"));
    assert!(run_bool("(char>=? #\\c #\\c #\\a)"));
    // uppercase A (65) < lowercase a (97); non-ASCII scalar order (Greek α < β).
    assert!(run_bool("(char<? #\\A #\\a)"));
    assert!(run_bool("(char<? (integer->char 945) (integer->char 946))"));
    assert!(run_bool("(char=? #\\space #\\space)")); // named-char literal flows through
}

#[test]
fn char_comparison_faults() {
    // arity < 2 → E302 (matches the numeric chain; no 1-arg degenerate #t).
    assert_eq!(run_err("(char<?)"), RuntimeCode::E302);
    assert_eq!(run_err("(char>? #\\a)"), RuntimeCode::E302);
    // a non-char operand → E312.
    assert_eq!(run_err("(char<? #\\a 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(char=? #\\a \"a\")"), RuntimeCode::E312);
    // a LATE non-char still faults E312 even when an earlier pair would settle the chain.
    assert_eq!(run_err("(char<? #\\b #\\a 5)"), RuntimeCode::E312);
    // numeric comparators stay numeric-only — chars are not numbers.
    assert_eq!(run_err("(< #\\a #\\b)"), RuntimeCode::E312);
}

#[test]
fn char_ci_comparison_chains() {
    // case-INSENSITIVE: folds each operand (≈ simple lowercase) before comparing.
    assert!(run_bool("(char-ci=? #\\a #\\A)"));
    assert!(run_bool("(char-ci=? #\\A #\\a)"));
    assert!(!run_bool("(char-ci=? #\\a #\\b)"));
    assert!(run_bool("(char-ci=? #\\a #\\a #\\A)")); // variadic
    assert!(run_bool("(char-ci<? #\\a #\\B)")); // a < b case-insensitively (B folds to b)
    assert!(!run_bool("(char-ci<? #\\B #\\a)"));
    assert!(run_bool("(char-ci>=? #\\Z #\\z)"));
    assert!(run_bool("(char-ci>? #\\B #\\a)")); // B folds to b, b > a
    assert!(!run_bool("(char-ci>? #\\a #\\B)"));
    assert!(run_bool("(char-ci<=? #\\a #\\A #\\b)")); // variadic, a == A <= b
    assert!(!run_bool("(char-ci<=? #\\b #\\A)"));
    assert!(run_bool("(char-ci=? #\\5 #\\5)")); // non-letters unaffected
                                                // non-ASCII single-char fold that DOES work (lowercase == fold): é (233) vs É (201).
    assert!(run_bool(
        "(char-ci=? (integer->char 233) (integer->char 201))"
    ));
    // DOCUMENTED v1 approximation (fold ≈ lowercase): these compare case-SENSITIVELY here even
    // though TRUE Unicode case-folding would make them equal — a v2 refinement.
    assert!(!run_bool(
        "(char-ci=? (integer->char 962) (integer->char 963))"
    )); // final ς vs σ
    assert!(!run_bool(
        "(char-ci=? (integer->char 181) (integer->char 956))"
    )); // µ U+00B5 vs μ
        // faults mirror char=?: arity < 2 → E302; a non-char (any position) → E312.
    assert_eq!(run_err("(char-ci=?)"), RuntimeCode::E302);
    assert_eq!(run_err("(char-ci<? #\\a)"), RuntimeCode::E302);
    assert_eq!(run_err("(char-ci=? #\\a 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(char-ci=? #\\a #\\b 5)"), RuntimeCode::E312); // late non-char
}

// ── bytevectors (§12; immutable read accessors in v1) ───────────────────────────

#[test]
fn bytevector_constructors_and_accessors() {
    // constructors round-trip with the #u8 literal.
    assert_eq!(run_repr("(bytevector 1 2 3)"), "#u8(1 2 3)");
    assert_eq!(run_repr("(bytevector)"), "#u8()");
    assert_eq!(run_repr("(bytevector 0 255)"), "#u8(0 255)");
    assert_eq!(run_repr("(make-bytevector 3 7)"), "#u8(7 7 7)");
    assert_eq!(run_repr("(make-bytevector 2)"), "#u8(0 0)"); // default fill 0
    assert_eq!(run_repr("(make-bytevector 0)"), "#u8()");
    assert_eq!(run_repr("(bytevector 4/2)"), "#u8(2)"); // integral exact (4/2 → 2) is a byte
                                                        // accessors.
    assert_eq!(run_int("(bytevector-length #u8(10 20 30))"), 3);
    assert_eq!(run_int("(bytevector-length #u8())"), 0);
    assert_eq!(run_int("(bytevector-length (make-bytevector 4))"), 4);
    assert_eq!(run_int("(bytevector-u8-ref #u8(10 20 30) 0)"), 10);
    assert_eq!(run_int("(bytevector-u8-ref #u8(10 20 30) 1)"), 20);
    assert_eq!(run_int("(bytevector-u8-ref #u8(255) 0)"), 255); // upper byte round-trips
    assert!(run_bool("(integer? (bytevector-u8-ref #u8(5) 0))")); // result is an exact int
                                                                  // predicate (total — never errors on the value).
    assert!(run_bool("(bytevector? #u8(1 2))"));
    assert!(run_bool("(bytevector? (bytevector 1))"));
    assert!(!run_bool("(bytevector? (vector 1 2))"));
    assert!(!run_bool("(bytevector? '(1 2))"));
    assert!(!run_bool("(bytevector? \"ab\")"));
    // equality is already wired: constructor == literal by contents.
    assert!(run_bool("(equal? (bytevector 1 2 3) #u8(1 2 3))"));
}

#[test]
fn bytevector_faults() {
    // byte VALUE out of 0..=255 → E312 (value-domain, like integer->char), both constructors.
    assert_eq!(run_err("(bytevector 256)"), RuntimeCode::E312);
    assert_eq!(run_err("(bytevector -1)"), RuntimeCode::E312);
    assert_eq!(run_err("(make-bytevector 3 256)"), RuntimeCode::E312);
    assert_eq!(run_err("(make-bytevector 3 -1)"), RuntimeCode::E312);
    // a non-integer byte → E312.
    assert_eq!(run_err("(bytevector 1.0)"), RuntimeCode::E312);
    assert_eq!(run_err("(bytevector #\\a)"), RuntimeCode::E312);
    // index out of range → E311; negative count → E311.
    assert_eq!(run_err("(bytevector-u8-ref #u8(1 2) 5)"), RuntimeCode::E311);
    assert_eq!(
        run_err("(bytevector-u8-ref #u8(1 2) -1)"),
        RuntimeCode::E311
    );
    assert_eq!(run_err("(bytevector-u8-ref #u8() 0)"), RuntimeCode::E311);
    assert_eq!(run_err("(make-bytevector -1)"), RuntimeCode::E311);
    // non-int index/count → E312; non-bytevector → E312.
    assert_eq!(run_err("(make-bytevector 1.5)"), RuntimeCode::E312);
    assert_eq!(run_err("(bytevector-u8-ref #u8(1) 0.5)"), RuntimeCode::E312);
    assert_eq!(run_err("(bytevector-length 5)"), RuntimeCode::E312);
    assert_eq!(
        run_err("(bytevector-u8-ref (vector 1) 0)"),
        RuntimeCode::E312
    );
    // arity → E302.
    assert_eq!(run_err("(make-bytevector)"), RuntimeCode::E302);
    assert_eq!(run_err("(make-bytevector 1 2 3)"), RuntimeCode::E302);
    assert_eq!(run_err("(bytevector-length)"), RuntimeCode::E302);
    assert_eq!(run_err("(bytevector-u8-ref #u8(1))"), RuntimeCode::E302);
    // bytevector-u8-set! is genuinely OUT (v1 immutable) → unbound variable.
    assert_eq!(
        run_err("(bytevector-u8-set! #u8(1) 0 9)"),
        RuntimeCode::E300
    );
}

// ── string comparisons (§10): lexicographic by Unicode scalar; string-ci folds (≈ lowercase) ───

#[test]
fn string_comparison_chains() {
    // equality (variadic chain).
    assert!(run_bool("(string=? \"a\" \"a\")"));
    assert!(!run_bool("(string=? \"a\" \"b\")"));
    assert!(run_bool("(string=? \"x\" \"x\" \"x\")"));
    assert!(!run_bool("(string=? \"x\" \"x\" \"y\")"));
    // lexicographic order; the prefix rule (a shorter proper prefix is less).
    assert!(run_bool("(string<? \"a\" \"b\")"));
    assert!(run_bool("(string<? \"ab\" \"abc\")"));
    assert!(!run_bool("(string<? \"abc\" \"ab\")"));
    assert!(run_bool("(string<? \"a\" \"b\" \"c\")"));
    assert!(!run_bool("(string<? \"a\" \"c\" \"b\")")); // mid-chain break
                                                        // uppercase < lowercase by codepoint (Z=90 < a=97).
    assert!(run_bool("(string<? \"Z\" \"a\")"));
    // empty string.
    assert!(run_bool("(string<? \"\" \"a\")"));
    assert!(run_bool("(string=? \"\" \"\")"));
    // > and the non-strict forms (equal adjacent allowed).
    assert!(run_bool("(string>? \"c\" \"a\")"));
    assert!(run_bool("(string<=? \"a\" \"a\" \"b\")"));
    assert!(run_bool("(string>=? \"c\" \"c\" \"a\")"));
    // cross-UTF-8-width scalar order: U+007F < U+0080 < U+0800 (1- vs 2- vs 3-byte).
    assert!(run_bool("(string<? \"\\x7f;\" \"\\x80;\" \"\\x800;\")"));
}

#[test]
fn string_comparison_faults() {
    // arity < 2 → E302.
    assert_eq!(run_err("(string<?)"), RuntimeCode::E302);
    assert_eq!(run_err("(string>? \"a\")"), RuntimeCode::E302);
    // a non-string operand → E312.
    assert_eq!(run_err("(string<? \"a\" 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(string=? \"a\" 'a)"), RuntimeCode::E312);
    // a LATE non-string still faults E312 even when an earlier pair settles the chain.
    assert_eq!(run_err("(string<? \"b\" \"a\" 5)"), RuntimeCode::E312);
    // numeric comparators stay numeric-only — strings are not numbers.
    assert_eq!(run_err("(< \"a\" \"b\")"), RuntimeCode::E312);
}

#[test]
fn string_ci_comparison_chains() {
    // case-INSENSITIVE: folds each operand (≈ full lowercase) before comparing.
    assert!(run_bool("(string-ci=? \"abc\" \"ABC\")"));
    assert!(run_bool("(string-ci=? \"Abc\" \"aBC\")"));
    assert!(!run_bool("(string-ci=? \"abc\" \"abd\")"));
    assert!(run_bool("(string-ci=? \"a\" \"A\" \"a\")")); // variadic
    assert!(run_bool("(string-ci<? \"abc\" \"ABD\")")); // abc < abd case-insensitively
    assert!(!run_bool("(string-ci<? \"B\" \"a\")"));
    assert!(run_bool("(string-ci>=? \"Z\" \"z\")"));
    assert!(run_bool("(string-ci>? \"B\" \"a\")")); // B folds to b, b > a
    assert!(!run_bool("(string-ci>? \"a\" \"B\")"));
    assert!(run_bool("(string-ci<=? \"a\" \"A\" \"b\")")); // variadic, a == A <= b
    assert!(!run_bool("(string-ci<=? \"b\" \"A\")"));
    assert!(run_bool("(string-ci=? \"\" \"\")"));
    // non-ASCII fold that works (lowercase == fold): café vs CAFÉ.
    assert!(run_bool("(string-ci=? \"café\" \"CAFÉ\")"));
    // DOCUMENTED v1 approximation: true Unicode case-folding would make these equal, but the
    // lowercase fold does not ("SS" -> "ss", "ß" -> "ß") — a v2 refinement.
    assert!(!run_bool("(string-ci=? \"ß\" \"SS\")"));
    // faults mirror string=?: arity < 2 → E302; a non-string (any position) → E312.
    assert_eq!(run_err("(string-ci=?)"), RuntimeCode::E302);
    assert_eq!(run_err("(string-ci<? \"a\")"), RuntimeCode::E302);
    assert_eq!(run_err("(string-ci=? \"a\" 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(string-ci=? \"a\" \"b\" 5)"), RuntimeCode::E312); // late non-string
}

// ── apply (§10): variadic application; a proper tail call ────────────────────────

#[test]
fn apply_spread() {
    assert_eq!(run_int("(apply + '(1 2 3))"), 6);
    assert_eq!(run_int("(apply + 1 2 '(3 4))"), 10); // middle args spread before list elems
    assert_eq!(run_repr("(apply list 1 2 '(3 4))"), "(1 2 3 4)");
    assert_eq!(run_int("(apply car '((1 2)))"), 1);
    assert_eq!(run_int("(apply + '())"), 0); // empty final list → proc called with no args
    assert_eq!(run_int("(apply + 1 2 '())"), 3);
    assert_eq!(run_repr("(apply cons 1 '(2))"), "(1 . 2)");
    // multiple values pass through unchanged (apply is a real tail call).
    assert_eq!(
        run_repr("(call-with-values (lambda () (apply values '(1 2 3))) list)"),
        "(1 2 3)"
    );
    // works in a non-tail HOF context too.
    assert_eq!(
        run_repr("(map (lambda (f) (apply f '(1 2))) (list + * -))"),
        "(3 2 -1)"
    );
}

#[test]
fn apply_faults() {
    // the final argument must be a proper list → E312.
    assert_eq!(run_err("(apply + 1 2)"), RuntimeCode::E312); // last arg 2 is not a list
    assert_eq!(run_err("(apply + (cons 1 2))"), RuntimeCode::E312); // improper
                                                                    // a non-procedure operator → E301 (faulted when the hand-off resolves).
    assert_eq!(run_err("(apply 5 '(1 2))"), RuntimeCode::E301);
    // arity < 2 → E302.
    assert_eq!(run_err("(apply +)"), RuntimeCode::E302);
    assert_eq!(run_err("(apply)"), RuntimeCode::E302);
    // the CALLEE's own arity still applies: car of zero args → E302 from car.
    assert_eq!(run_err("(apply car '())"), RuntimeCode::E302);
}

// ── for-each (§10): map for effect; a discard context (zero-value procs OK) ───────

#[test]
fn for_each_effect_and_order() {
    // runs f for EFFECT left-to-right; (for-each display …) works even though display
    // returns ZERO values (discard context — single-value apply1 would wrongly fault E320).
    assert_eq!(run_output("(for-each display '(1 2 3))"), "123");
    assert_eq!(
        run_output("(for-each (lambda (x) (display x)) '(a b c))"),
        "abc"
    );
    // empty list → no calls; returns unspecified (zero values).
    assert_eq!(run_output("(for-each display '())"), "");
    assert_eq!(run("(for-each display '())"), Outcome::Many(vec![]));
    // a single-value-returning proc is fine too (its result is discarded).
    assert_eq!(
        run("(for-each (lambda (x) (+ x 1)) '(1 2 3))"),
        Outcome::Many(vec![])
    );
}

#[test]
fn for_each_faults() {
    // an error from the proc propagates.
    assert_eq!(run_err("(for-each car '(1))"), RuntimeCode::E310);
    // non-list / improper 2nd arg → E312 (collected before any call → no partial effect).
    assert_eq!(run_err("(for-each display 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(for-each display '(1 2 . 3))"), RuntimeCode::E312);
    // arity ≠ 2 → E302.
    assert_eq!(run_err("(for-each display)"), RuntimeCode::E302);
    assert_eq!(run_err("(for-each display '() 'extra)"), RuntimeCode::E302);
}

// ── vectors ─────────────────────────────────────────────────────────────────────

#[test]
fn vector_ops() {
    assert_eq!(run_repr("(vector 1 2 3)"), "#(1 2 3)");
    assert_eq!(run_repr("(vector)"), "#()");
    assert_eq!(run_repr("(make-vector 3 0)"), "#(0 0 0)");
    assert_eq!(run_repr("(make-vector 2)"), "#(0 0)"); // default fill = 0
    assert_eq!(run_int("(vector-ref (vector 10 20 30) 1)"), 20);
    assert_eq!(run_int("(vector-length (vector 1 2 3))"), 3);
    assert_eq!(run_int("(vector-length (vector))"), 0);
    assert_eq!(run_repr("(vector->list (vector 1 2))"), "(1 2)");
    assert_eq!(run_repr("(list->vector '(1 2 3))"), "#(1 2 3)");
    assert_eq!(
        run_repr("(vector->list (list->vector '(1 2 3)))"),
        "(1 2 3)"
    );
}

#[test]
fn vector_set_mutates_a_runtime_vector() {
    assert_eq!(
        run_int("(define v (vector 1 2 3)) (vector-set! v 0 99) (vector-ref v 0)"),
        99
    );
    // vector-set! yields zero values (§0.3).
    assert_eq!(
        run("(define v (vector 1 2 3)) (vector-set! v 1 5)"),
        Outcome::Many(vec![])
    );
}

#[test]
fn vector_errors() {
    assert_eq!(run_err("(vector-ref (vector 1) 5)"), RuntimeCode::E311); // OOB
    assert_eq!(run_err("(vector-ref (vector 1) -1)"), RuntimeCode::E311);
    assert_eq!(run_err("(vector-ref 5 0)"), RuntimeCode::E312); // non-vector
    assert_eq!(run_err("(vector-length 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(vector-set! 5 0 1)"), RuntimeCode::E312);
    // Mutating a quoted/literal (immutable) vector → E312 (§10).
    assert_eq!(run_err("(vector-set! '#(1 2 3) 0 9)"), RuntimeCode::E312);
}

#[test]
fn vector_copy_fresh_subrange() {
    // full copy + optional [start [end]] half-open sub-range.
    assert_eq!(run_repr("(vector-copy (vector 1 2 3))"), "#(1 2 3)");
    assert_eq!(run_repr("(vector-copy (vector 1 2 3) 1)"), "#(2 3)");
    assert_eq!(run_repr("(vector-copy (vector 1 2 3) 1 2)"), "#(2)");
    assert_eq!(run_repr("(vector-copy (vector 1 2 3) 0 0)"), "#()"); // empty range
    assert_eq!(run_repr("(vector-copy (vector 1 2 3) 3)"), "#()"); // start == len ok
    assert_eq!(run_repr("(vector-copy (vector 1 2 3) 3 3)"), "#()");
    // the copy is a fresh, independent, MUTABLE vector — mutating it does not touch the original.
    assert_eq!(
        run_repr("(define v (vector 1 2 3)) (define c (vector-copy v)) (vector-set! c 0 99) (list (vector-ref c 0) (vector-ref v 0))"),
        "(99 1)"
    );
    assert!(!run_bool(
        "(let ((v (vector 1 2))) (eq? (vector-copy v) v))"
    )); // fresh → not eq?
    assert!(run_bool(
        "(let ((v (vector 1 2))) (equal? (vector-copy v) v))"
    )); // equal? structurally
        // copying an IMMUTABLE (quoted/literal) vector yields a MUTABLE copy (R7RS: a immutable, b mutable).
    assert_eq!(
        run_repr("(define c (vector-copy '#(1 8 2 8))) (vector-set! c 0 3) c"),
        "#(3 8 2 8)"
    );
    // the reverse independence direction: mutating the SOURCE must not affect the copy.
    assert_eq!(
        run_repr("(define v (vector 1 2 3)) (define c (vector-copy v)) (vector-set! v 0 99) (list (vector-ref v 0) (vector-ref c 0))"),
        "(99 1)"
    );
    // SHALLOW copy: an aggregate element is shared (eq?), not deep-copied (mirrors list-copy).
    assert!(run_bool(
        "(let ((x (vector 9))) (eq? (vector-ref (vector-copy (vector x)) 0) x))"
    ));
}

#[test]
fn vector_copy_errors() {
    assert_eq!(
        run_err("(vector-copy (vector 1 2 3) 0 5)"),
        RuntimeCode::E311
    ); // end OOB
    assert_eq!(
        run_err("(vector-copy (vector 1 2 3) 2 1)"),
        RuntimeCode::E311
    ); // start > end
    assert_eq!(run_err("(vector-copy (vector 1) -1)"), RuntimeCode::E311); // negative start
    assert_eq!(run_err("(vector-copy 5)"), RuntimeCode::E312); // non-vector
    assert_eq!(run_err("(vector-copy (vector 1) 1.0)"), RuntimeCode::E312); // non-int bound
    assert_eq!(run_err("(vector-copy)"), RuntimeCode::E302); // arity
    assert_eq!(run_err("(vector-copy (vector 1) 0 1 2)"), RuntimeCode::E302); // arity
}

#[test]
fn vector_map_builds_a_fresh_vector() {
    assert_eq!(
        run_repr("(vector-map (lambda (x) (* x x)) (vector 1 2 3))"),
        "#(1 4 9)"
    );
    assert_eq!(run_repr("(vector-map (lambda (x) x) (vector))"), "#()"); // empty → no calls
    assert_eq!(
        run_repr("(vector-map car (vector '(1 a) '(2 b)))"),
        "#(1 2)"
    ); // primitive proc
       // the result is a fresh, MUTABLE vector.
    assert_eq!(
        run_repr("(define r (vector-map (lambda (x) x) (vector 1 2))) (vector-set! r 0 9) r"),
        "#(9 2)"
    );
    // SNAPSHOT semantics: the proc may vector-set! the SAME vector mid-map without panicking, and
    // the mapped result is the entry-time elements (would double-borrow-panic without the snapshot).
    assert_eq!(
        run_repr("(let ((v (vector 1 2 3))) (vector-map (lambda (x) (vector-set! v 1 0) x) v))"),
        "#(1 2 3)"
    );
    // applied strictly LEFT-TO-RIGHT (a side-effecting accumulator ends up reversed).
    assert_eq!(
        run_repr("(define acc '()) (vector-map (lambda (x) (set! acc (cons x acc)) x) (vector 1 2 3)) acc"),
        "(3 2 1)"
    );
}

#[test]
fn vector_map_faults() {
    assert_eq!(run_err("(vector-map 5 (vector 1))"), RuntimeCode::E301); // non-procedure
    assert_eq!(run_repr("(vector-map 5 (vector))"), "#()"); // empty → proc never applied, no error
    assert_eq!(
        run_err("(vector-map (lambda (x y) x) (vector 1))"),
        RuntimeCode::E302
    ); // proc arity
       // a per-element call must yield exactly one value (single-value context): 0 or ≥2 → E320.
    assert_eq!(
        run_err("(vector-map (lambda (x) (values 1 2)) (vector 1))"),
        RuntimeCode::E320
    );
    assert_eq!(
        run_err("(vector-map display (vector 1))"),
        RuntimeCode::E320
    ); // display → 0 values
    assert_eq!(run_err("(vector-map car 5)"), RuntimeCode::E312); // non-vector
    assert_eq!(run_err("(vector-map car)"), RuntimeCode::E302); // arity
    assert_eq!(
        run_err("(vector-map car (vector 1) (vector 2))"),
        RuntimeCode::E302
    ); // single-vector only
       // a per-element fault propagates MID-iteration (element 1 is fine, element 2 faults E310).
    assert_eq!(
        run_err("(vector-map (lambda (x) (car x)) (vector '(1) 2 3))"),
        RuntimeCode::E310
    );
}

#[test]
fn vector_for_each_runs_for_effect() {
    // left-to-right, discard context (display yields zero values — apply1 would wrongly E320).
    assert_eq!(
        run_output("(vector-for-each display (vector 1 2 3))"),
        "123"
    );
    assert_eq!(
        run_output("(vector-for-each (lambda (x) (display x)) (vector 'a 'b))"),
        "ab"
    );
    // empty → no calls; returns unspecified (zero values).
    assert_eq!(run_output("(vector-for-each display (vector))"), "");
    assert_eq!(
        run("(vector-for-each display (vector))"),
        Outcome::Many(vec![])
    );
    assert_eq!(
        run("(vector-for-each (lambda (x) (+ x 1)) (vector 1 2 3))"),
        Outcome::Many(vec![])
    );
    // SNAPSHOT: the proc may vector-set! the same vector mid-iteration without panicking.
    assert_eq!(
        run_int("(define v (vector 1 2 3)) (vector-for-each (lambda (x) (vector-set! v 0 99)) v) (vector-ref v 0)"),
        99
    );
    // applied strictly LEFT-TO-RIGHT (the accumulator ends up reversed).
    assert_eq!(
        run_repr("(define acc '()) (vector-for-each (lambda (x) (set! acc (cons x acc))) (vector 'a 'b 'c)) acc"),
        "(c b a)"
    );
}

#[test]
fn vector_for_each_faults() {
    assert_eq!(run_err("(vector-for-each display 5)"), RuntimeCode::E312); // non-vector
    assert_eq!(run_err("(vector-for-each 5 (vector 1))"), RuntimeCode::E301); // non-procedure
    assert_eq!(run_err("(vector-for-each display)"), RuntimeCode::E302); // arity
    assert_eq!(
        run_err("(vector-for-each display (vector 1) (vector 2))"),
        RuntimeCode::E302
    ); // single-vector
       // a per-element fault propagates MID-iteration (element 1 fine, element 2 faults E310).
    assert_eq!(
        run_err("(vector-for-each (lambda (x) (car x)) (vector '(1) 2 3))"),
        RuntimeCode::E310
    );
}

#[test]
fn boolean_eq_chain() {
    assert!(run_bool("(boolean=? #t #t)"));
    assert!(run_bool("(boolean=? #f #f)"));
    assert!(!run_bool("(boolean=? #t #f)"));
    assert!(run_bool("(boolean=? #t #t #t)")); // variadic
    assert!(!run_bool("(boolean=? #t #t #f)"));
    // a non-boolean in ANY position → E312 (0 is NOT a boolean), type-checked up front.
    assert_eq!(run_err("(boolean=? #t 1)"), RuntimeCode::E312);
    assert_eq!(run_err("(boolean=? 0 0)"), RuntimeCode::E312);
    assert_eq!(run_err("(boolean=? #t #f 0)"), RuntimeCode::E312); // late bad operand
    assert_eq!(run_err("(boolean=? #t)"), RuntimeCode::E302); // arity
    assert_eq!(run_err("(boolean=?)"), RuntimeCode::E302);
}

#[test]
fn symbol_eq_chain() {
    assert!(run_bool("(symbol=? 'a 'a)"));
    assert!(!run_bool("(symbol=? 'a 'b)"));
    assert!(run_bool("(symbol=? 'a 'a 'a)")); // variadic
    assert!(!run_bool("(symbol=? 'a 'a 'b)"));
    assert!(run_bool("(symbol=? (string->symbol \"x\") 'x)")); // equal by name
                                                               // a non-symbol in ANY position → E312 (a string is not a symbol), type-checked up front.
    assert_eq!(run_err("(symbol=? 'a \"a\")"), RuntimeCode::E312);
    assert_eq!(run_err("(symbol=? 'a 1)"), RuntimeCode::E312);
    assert_eq!(run_err("(symbol=? 'a 'b \"x\")"), RuntimeCode::E312); // late bad operand
    assert_eq!(run_err("(symbol=? 'a)"), RuntimeCode::E302); // arity
    assert_eq!(run_err("(symbol=?)"), RuntimeCode::E302);
}

#[test]
fn string_map_builds_a_fresh_string() {
    assert_eq!(run_repr("(string-map (lambda (c) c) \"abc\")"), "\"abc\""); // identity
    assert_eq!(
        run_repr("(string-map (lambda (c) #\\x) \"abc\")"),
        "\"xxx\""
    );
    // shift each char by one codepoint.
    assert_eq!(
        run_repr("(string-map (lambda (c) (integer->char (+ 1 (char->integer c)))) \"abc\")"),
        "\"bcd\""
    );
    assert_eq!(run_repr("(string-map (lambda (c) c) \"\")"), "\"\""); // empty → no calls
                                                                      // applied strictly LEFT-TO-RIGHT (the accumulator ends up reversed).
    assert_eq!(
        run_repr(
            "(define acc '()) (string-map (lambda (c) (set! acc (cons c acc)) c) \"abc\") acc"
        ),
        "(#\\c #\\b #\\a)"
    );
}

#[test]
fn string_map_faults() {
    // the proc MUST return a character — a single non-char result → E312.
    assert_eq!(
        run_err("(string-map (lambda (c) 5) \"a\")"),
        RuntimeCode::E312
    );
    // 0 or ≥2 values per call → E320 (single-value context, before the char check).
    assert_eq!(run_err("(string-map display \"a\")"), RuntimeCode::E320); // display → 0 values
    assert_eq!(
        run_err("(string-map (lambda (c) (values #\\a #\\b)) \"x\")"),
        RuntimeCode::E320
    );
    assert_eq!(run_err("(string-map 5 \"a\")"), RuntimeCode::E301); // non-procedure
    assert_eq!(run_repr("(string-map 5 \"\")"), "\"\""); // empty → proc never applied, no error
    assert_eq!(
        run_err("(string-map (lambda (x y) x) \"a\")"),
        RuntimeCode::E302
    ); // proc arity
    assert_eq!(run_err("(string-map car 5)"), RuntimeCode::E312); // non-string
    assert_eq!(run_err("(string-map car)"), RuntimeCode::E302); // arity
    assert_eq!(run_err("(string-map car \"a\" \"b\")"), RuntimeCode::E302); // single-string
}

#[test]
fn string_for_each_runs_for_effect() {
    assert_eq!(run_output("(string-for-each display \"abc\")"), "abc");
    assert_eq!(
        run_output("(string-for-each (lambda (c) (display c)) \"\")"),
        ""
    );
    assert_eq!(run("(string-for-each display \"\")"), Outcome::Many(vec![]));
    assert_eq!(
        run("(string-for-each (lambda (c) c) \"ab\")"),
        Outcome::Many(vec![])
    );
    // left-to-right order.
    assert_eq!(
        run_repr(
            "(define acc '()) (string-for-each (lambda (c) (set! acc (cons c acc))) \"abc\") acc"
        ),
        "(#\\c #\\b #\\a)"
    );
}

#[test]
fn string_for_each_faults() {
    assert_eq!(run_err("(string-for-each display 5)"), RuntimeCode::E312); // non-string
    assert_eq!(run_err("(string-for-each 5 \"a\")"), RuntimeCode::E301); // non-procedure
    assert_eq!(run_err("(string-for-each display)"), RuntimeCode::E302); // arity
    assert_eq!(
        run_err("(string-for-each display \"a\" \"b\")"),
        RuntimeCode::E302
    ); // single-string
}

#[test]
fn char_classification_predicates() {
    // char-alphabetic? / char-upper-case? / char-lower-case? use the full Unicode property.
    assert!(run_bool("(char-alphabetic? #\\a)"));
    assert!(run_bool("(char-alphabetic? #\\Z)"));
    assert!(!run_bool("(char-alphabetic? #\\0)"));
    assert!(!run_bool("(char-alphabetic? (integer->char 32))")); // space
    assert!(run_bool("(char-upper-case? #\\A)"));
    assert!(!run_bool("(char-upper-case? #\\a)"));
    assert!(!run_bool("(char-upper-case? #\\5)"));
    assert!(run_bool("(char-lower-case? #\\a)"));
    assert!(!run_bool("(char-lower-case? #\\A)"));
    // char-whitespace? — Unicode White_Space.
    assert!(run_bool("(char-whitespace? (integer->char 32))")); // space
    assert!(run_bool("(char-whitespace? (integer->char 9))")); // tab
    assert!(!run_bool("(char-whitespace? #\\a)"));
    // char-numeric? — v1 ASCII decimal digits only.
    assert!(run_bool("(char-numeric? #\\0)"));
    assert!(run_bool("(char-numeric? #\\9)"));
    assert!(!run_bool("(char-numeric? #\\a)"));
    // v1 ASCII scope: non-ASCII Nd and Nl/No are #f (no false positives like ¾/①).
    assert!(!run_bool("(char-numeric? (integer->char 1636))")); // ٤ Arabic-Indic 4 (Nd, deferred)
    assert!(!run_bool("(char-numeric? (integer->char 190))")); // ¾ vulgar fraction (No)
    assert!(!run_bool("(char-numeric? (integer->char 9312))")); // ① circled one (No)
}

#[test]
fn char_classification_faults() {
    // each REQUIRES a character (non-char → E312), unlike the total char? predicate.
    assert_eq!(run_err("(char-alphabetic? 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(char-numeric? \"a\")"), RuntimeCode::E312);
    assert_eq!(run_err("(char-lower-case? 'a)"), RuntimeCode::E312);
    // arity ≠ 1 → E302.
    assert_eq!(run_err("(char-whitespace?)"), RuntimeCode::E302);
    assert_eq!(run_err("(char-upper-case? #\\a #\\b)"), RuntimeCode::E302);
}

#[test]
fn char_upcase_downcase_simple() {
    assert_eq!(run_repr("(char-upcase #\\a)"), "#\\A");
    assert_eq!(run_repr("(char-upcase #\\A)"), "#\\A"); // idempotent
    assert_eq!(run_repr("(char-upcase #\\5)"), "#\\5"); // non-letter unchanged
    assert_eq!(run_repr("(char-downcase #\\A)"), "#\\a");
    assert_eq!(run_repr("(char-downcase #\\a)"), "#\\a");
    assert_eq!(run_repr("(char-downcase #\\5)"), "#\\5");
    // non-ASCII single-char mapping: é (U+00E9=233) ↔ É (U+00C9=201).
    assert_eq!(
        run_int("(char->integer (char-upcase (integer->char 233)))"),
        201
    );
    assert_eq!(
        run_int("(char->integer (char-downcase (integer->char 201)))"),
        233
    );
    // SIMPLE (not full) mapping: ß (U+00DF=223) upcases to itself (full would expand to \"SS\").
    assert_eq!(
        run_int("(char->integer (char-upcase (integer->char 223)))"),
        223
    );
    // İ (U+0130=304) simple-downcases to a single i (105), NOT i + combining dot (the full mapping).
    assert_eq!(
        run_int("(char->integer (char-downcase (integer->char 304)))"),
        105
    );
}

#[test]
fn char_upcase_downcase_faults() {
    assert_eq!(run_err("(char-upcase 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(char-downcase \"a\")"), RuntimeCode::E312);
    assert_eq!(run_err("(char-upcase)"), RuntimeCode::E302);
    assert_eq!(run_err("(char-downcase #\\a #\\b)"), RuntimeCode::E302);
}

#[test]
fn string_to_vector_and_back() {
    // string->vector → a fresh MUTABLE vector of chars, optional [start [end]] sub-range.
    assert_eq!(run_repr("(string->vector \"abc\")"), "#(#\\a #\\b #\\c)");
    assert_eq!(run_repr("(string->vector \"abc\" 1)"), "#(#\\b #\\c)");
    assert_eq!(run_repr("(string->vector \"abc\" 1 2)"), "#(#\\b)");
    assert_eq!(run_repr("(string->vector \"\")"), "#()");
    assert_eq!(run_repr("(string->vector \"abc\" 3)"), "#()"); // start == len
    assert_eq!(
        run_repr("(define v (string->vector \"ab\")) (vector-set! v 0 #\\z) v"),
        "#(#\\z #\\b)"
    ); // fresh + mutable
       // vector->string → a string from the chars in range.
    assert_eq!(
        run_repr("(vector->string (vector #\\a #\\b #\\c))"),
        "\"abc\""
    );
    assert_eq!(
        run_repr("(vector->string (vector #\\a #\\b #\\c) 1)"),
        "\"bc\""
    );
    assert_eq!(
        run_repr("(vector->string (vector #\\a #\\b #\\c) 1 2)"),
        "\"b\""
    );
    assert_eq!(run_repr("(vector->string (vector))"), "\"\"");
    // round-trip (incl. a non-ASCII char) is identity.
    assert_eq!(
        run_repr("(vector->string (string->vector \"héllo\"))"),
        "\"héllo\""
    );
    // a non-char OUTSIDE the selected range does not fault.
    assert_eq!(
        run_repr("(vector->string (vector #\\a #\\b 5) 0 2)"),
        "\"ab\""
    );
}

#[test]
fn string_to_vector_and_back_faults() {
    assert_eq!(run_err("(string->vector 5)"), RuntimeCode::E312); // non-string
    assert_eq!(run_err("(string->vector \"abc\" 0 5)"), RuntimeCode::E311); // end OOB
    assert_eq!(run_err("(string->vector \"abc\" 2 1)"), RuntimeCode::E311); // start > end
    assert_eq!(run_err("(string->vector \"abc\" -1)"), RuntimeCode::E311); // negative
    assert_eq!(run_err("(string->vector \"abc\" 1.0)"), RuntimeCode::E312); // non-int bound
    assert_eq!(run_err("(string->vector)"), RuntimeCode::E302);
    assert_eq!(run_err("(string->vector \"a\" 0 1 2)"), RuntimeCode::E302);
    // vector->string: a non-char element IN range → E312.
    assert_eq!(
        run_err("(vector->string (vector #\\a 5 #\\c))"),
        RuntimeCode::E312
    );
    assert_eq!(run_err("(vector->string 5)"), RuntimeCode::E312); // non-vector
    assert_eq!(
        run_err("(vector->string (vector #\\a) 0 5)"),
        RuntimeCode::E311
    ); // OOB
    assert_eq!(
        run_err("(vector->string (vector #\\a) 1.0)"),
        RuntimeCode::E312
    ); // non-int bound
    assert_eq!(run_err("(vector->string)"), RuntimeCode::E302);
    assert_eq!(
        run_err("(vector->string (vector #\\a) 0 1 2)"),
        RuntimeCode::E302
    );
}

#[test]
fn string_copy_and_make_string() {
    // string-copy: substring with an optional [start [end]]; CHARACTER indices.
    assert_eq!(run_repr("(string-copy \"abc\")"), "\"abc\"");
    assert_eq!(run_repr("(string-copy \"abc\" 1)"), "\"bc\"");
    assert_eq!(run_repr("(string-copy \"abc\" 1 2)"), "\"b\"");
    assert_eq!(run_repr("(string-copy \"abc\" 3)"), "\"\""); // start == len
    assert_eq!(run_repr("(string-copy \"\")"), "\"\"");
    assert_eq!(run_repr("(string-copy \"hαllo\" 1 2)"), "\"α\""); // char index, not byte
                                                                  // the copy is freshly allocated (strings compare by identity under eq?).
    assert!(!run_bool("(let ((s \"abc\")) (eq? s (string-copy s)))"));
    // make-string: k copies of a char, default fill #\space.
    assert_eq!(run_repr("(make-string 3 #\\x)"), "\"xxx\"");
    assert_eq!(run_repr("(make-string 0 #\\x)"), "\"\"");
    assert_eq!(run_repr("(make-string 3)"), "\"   \""); // default fill = space
    assert_eq!(run_repr("(make-string 2 (integer->char 955))"), "\"λλ\""); // multi-byte fill
    assert!(!run_bool("(eq? (make-string 1 #\\x) (make-string 1 #\\x))")); // fresh each call
}

#[test]
fn string_copy_and_make_string_faults() {
    assert_eq!(run_err("(string-copy 5)"), RuntimeCode::E312); // non-string
    assert_eq!(run_err("(string-copy \"abc\" 0 5)"), RuntimeCode::E311); // end OOB
    assert_eq!(run_err("(string-copy \"abc\" 2 1)"), RuntimeCode::E311); // start > end
    assert_eq!(run_err("(string-copy \"abc\" -1)"), RuntimeCode::E311); // negative
    assert_eq!(run_err("(string-copy \"abc\" 1.0)"), RuntimeCode::E312); // non-int bound
    assert_eq!(run_err("(string-copy)"), RuntimeCode::E302);
    assert_eq!(run_err("(string-copy \"a\" 0 1 2)"), RuntimeCode::E302);
    assert_eq!(run_err("(make-string -1)"), RuntimeCode::E311); // negative k
    assert_eq!(run_err("(make-string 2 5)"), RuntimeCode::E312); // non-char fill
    assert_eq!(run_err("(make-string \"x\")"), RuntimeCode::E312); // non-int k
    assert_eq!(run_err("(make-string)"), RuntimeCode::E302);
    assert_eq!(run_err("(make-string 1 #\\a #\\b)"), RuntimeCode::E302);
}

#[test]
fn string_upcase_downcase() {
    assert_eq!(run_repr("(string-upcase \"hello\")"), "\"HELLO\"");
    assert_eq!(
        run_repr("(string-upcase \"Hello World\")"),
        "\"HELLO WORLD\""
    );
    assert_eq!(run_repr("(string-upcase \"123abc\")"), "\"123ABC\"");
    assert_eq!(run_repr("(string-upcase \"\")"), "\"\"");
    assert_eq!(run_repr("(string-downcase \"HELLO\")"), "\"hello\"");
    assert_eq!(run_repr("(string-downcase \"Hello\")"), "\"hello\"");
    // FULL Unicode mapping (not simple/ASCII): uppercasing ß (U+00DF) expands to "SS" (length change).
    assert_eq!(
        run_repr("(string-upcase (list->string (list (integer->char 223))))"),
        "\"SS\""
    );
    // FULL lowercasing also expands: İ (U+0130) → i (105) + combining dot above (775).
    assert_eq!(
        run_repr("(map char->integer (string->list (string-downcase (list->string (list (integer->char 304))))))"),
        "(105 775)"
    );
    // context-sensitive final sigma: ΑΣ → α (945) + FINAL sigma ς (962), not σ (963).
    assert_eq!(
        run_repr("(map char->integer (string->list (string-downcase (list->string (list (integer->char 913) (integer->char 931))))))"),
        "(945 962)"
    );
    // each call returns a FRESH string (strings compare by identity under eq?).
    assert!(!run_bool("(let ((s \"ABC\")) (eq? s (string-upcase s)))"));
    assert!(!run_bool("(let ((s \"abc\")) (eq? s (string-downcase s)))"));
}

#[test]
fn string_upcase_downcase_faults() {
    assert_eq!(run_err("(string-upcase 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(string-downcase 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(string-upcase)"), RuntimeCode::E302);
    assert_eq!(run_err("(string-downcase \"a\" \"b\")"), RuntimeCode::E302);
}

#[test]
fn char_and_string_foldcase() {
    // char-foldcase = the fold char-ci uses (≈ simple lowercase).
    assert_eq!(run_repr("(char-foldcase #\\A)"), "#\\a");
    assert_eq!(run_repr("(char-foldcase #\\a)"), "#\\a");
    assert_eq!(run_repr("(char-foldcase #\\5)"), "#\\5");
    assert_eq!(
        run_int("(char->integer (char-foldcase (integer->char 201)))"),
        233
    ); // É → é
    assert_eq!(
        run_int("(char->integer (char-foldcase (integer->char 181)))"),
        181
    ); // µ stays µ (v1)
       // string-foldcase = the fold string-ci uses (≈ full lowercase); always a fresh string.
    assert_eq!(run_repr("(string-foldcase \"ABC\")"), "\"abc\"");
    assert_eq!(run_repr("(string-foldcase \"Hello\")"), "\"hello\"");
    assert_eq!(run_repr("(string-foldcase \"CAFÉ\")"), "\"café\"");
    assert_eq!(run_repr("(string-foldcase \"\")"), "\"\"");
    assert_eq!(run_repr("(string-foldcase \"ß\")"), "\"ß\""); // v1: stays ß (true fold → "ss")
    assert!(!run_bool("(let ((s \"abc\")) (eq? s (string-foldcase s)))")); // fresh
                                                                           // R7RS identity (holds in v1 incl. the divergent cases): ci=? ≡ =? on the folded operands.
    assert!(run_bool(
        "(eq? (char-ci=? (integer->char 181) (integer->char 956)) (char=? (char-foldcase (integer->char 181)) (char-foldcase (integer->char 956))))"
    ));
    assert!(run_bool(
        "(eq? (string-ci=? \"ß\" \"SS\") (string=? (string-foldcase \"ß\") (string-foldcase \"SS\")))"
    ));
    // faults: 1 arg → E302; non-char/non-string → E312.
    assert_eq!(run_err("(char-foldcase 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(char-foldcase #\\a #\\b)"), RuntimeCode::E302);
    assert_eq!(run_err("(string-foldcase 5)"), RuntimeCode::E312);
    assert_eq!(run_err("(string-foldcase)"), RuntimeCode::E302);
}

// ── total type predicates ────────────────────────────────────────────────────────

#[test]
fn type_predicates() {
    assert!(run_bool("(number? 5)"));
    assert!(!run_bool("(number? \"x\")"));
    assert!(run_bool("(integer? 3.0)"));
    assert!(run_bool("(string? \"x\")"));
    assert!(!run_bool("(string? 'x)"));
    assert!(run_bool("(symbol? 'x)"));
    assert!(!run_bool("(symbol? \"x\")"));
    assert!(run_bool("(char? #\\x)"));
    assert!(run_bool("(boolean? #t)"));
    assert!(!run_bool("(boolean? 0)"));
    assert!(run_bool("(vector? (vector))"));
    assert!(!run_bool("(vector? '(1 2))"));
    assert!(run_bool("(procedure? car)"));
    assert!(run_bool("(procedure? (lambda (x) x))"));
    assert!(!run_bool("(procedure? 5)"));
    assert!(run_bool("(null? '())"));
    assert!(run_bool("(pair? '(1))"));
    assert!(run_bool("(list? '(1 2))"));
}

// ── display / write (§11) ────────────────────────────────────────────────────────

#[test]
fn display_vs_write_difference() {
    // Strings: display unquoted/raw, write quoted+escaped.
    assert_eq!(run_output("(display \"hi\")"), "hi");
    assert_eq!(run_output("(write \"hi\")"), "\"hi\"");
    // Chars: display the bare glyph, write the #\… form.
    assert_eq!(run_output("(display #\\a)"), "a");
    assert_eq!(run_output("(write #\\a)"), "#\\a");
    // The mode propagates into nested elements of a list.
    assert_eq!(run_output("(display '(\"a\" \"b\"))"), "(a b)");
    assert_eq!(run_output("(write '(\"a\" \"b\"))"), "(\"a\" \"b\")");
}

#[test]
fn display_numbers_and_lists() {
    assert_eq!(run_output("(display 42)"), "42");
    assert_eq!(run_output("(display 3.5)"), "3.5"); // pinned formatter
    assert_eq!(run_output("(display '(1 2 3))"), "(1 2 3)"); // R7RS rendering
    assert_eq!(run_output("(display (vector 1 2))"), "#(1 2)");
}

#[test]
fn newline_and_println() {
    assert_eq!(run_output("(newline)"), "\n");
    assert_eq!(run_output("(println 42)"), "42\n");
    assert_eq!(run_output("(println \"hi\")"), "hi\n"); // println uses display semantics
    assert_eq!(
        run_output("(begin (display \"a\") (newline) (display \"b\"))"),
        "a\nb"
    );
}

#[test]
fn io_returns_zero_values() {
    // display/write/newline/println all yield zero values (§11).
    assert_eq!(run("(display 1)"), Outcome::Many(vec![]));
    assert_eq!(run("(write 1)"), Outcome::Many(vec![]));
    assert_eq!(run("(newline)"), Outcome::Many(vec![]));
    // …so a following expression's value is the program result.
    assert_eq!(run_int("(begin (display 7) 9)"), 9);
}

#[test]
fn io_arity_errors() {
    assert_eq!(run_err("(display 1 2)"), RuntimeCode::E302);
    assert_eq!(run_err("(newline 1)"), RuntimeCode::E302);
}
