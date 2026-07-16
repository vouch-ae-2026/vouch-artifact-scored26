//! Hygienic normalizer conformance tests (Round 2).
//!
//! Strategy: normalize source, then assert the produced Core AST via the span-free
//! [`CoreExpr::sexpr`] printer. Self-evaluating literals print as `(quote …)`, a
//! hygienic temp prints as `#:tN`, and a hidden intrinsic prints as
//! `#<intrinsic:NAME>` — so desugaring shape AND hygiene are both directly visible.

use lispex::normalize::{normalize_one, normalize_program};
use lispex::reader::{read_program, ErrCode};

// ── helpers ─────────────────────────────────────────────────────────────────────

/// Normalize a single top-level form to its Core sexpr.
fn n(src: &str) -> String {
    let prog = read_program(src, "t.lx").unwrap_or_else(|d| panic!("read error `{d}` for `{src}`"));
    assert_eq!(
        prog.datums.len(),
        1,
        "expected exactly one datum for `{src}`"
    );
    normalize_one(&prog.datums[0], "t.lx")
        .unwrap_or_else(|d| panic!("normalize error `{d}` for `{src}`"))
        .sexpr()
}

/// Normalize a whole program to a vector of Core sexprs.
fn np(src: &str) -> Vec<String> {
    let prog = read_program(src, "t.lx").unwrap_or_else(|d| panic!("read error `{d}` for `{src}`"));
    normalize_program(&prog.datums, "t.lx")
        .unwrap_or_else(|d| panic!("normalize error `{d}` for `{src}`"))
        .iter()
        .map(|c| c.sexpr())
        .collect()
}

/// Normalize source that READS fine but must FAIL to normalize; return the code.
fn nerr(src: &str) -> ErrCode {
    let prog =
        read_program(src, "t.lx").unwrap_or_else(|d| panic!("read should succeed `{d}` `{src}`"));
    match normalize_program(&prog.datums, "t.lx") {
        Ok(c) => panic!("expected normalize error for `{src}`, got {c:?}"),
        Err(d) => d.code,
    }
}

/// Assert normalization succeeds (shape unimportant).
fn ok(src: &str) {
    let prog = read_program(src, "t.lx").unwrap_or_else(|d| panic!("read error `{d}` `{src}`"));
    normalize_program(&prog.datums, "t.lx")
        .unwrap_or_else(|d| panic!("expected ok for `{src}`, got `{d}`"));
}

// ── core forms pass through ──────────────────────────────────────────────────────

#[test]
fn literals_become_quote() {
    assert_eq!(n("5"), "(quote 5)");
    assert_eq!(n("#t"), "(quote #t)");
    assert_eq!(n("\"hi\""), "(quote \"hi\")");
    assert_eq!(n("#\\a"), "(quote #\\a)");
    assert_eq!(n("1/3"), "(quote 1/3)");
    // vector / bytevector literals self-evaluate (quoted)
    assert_eq!(n("#(1 2)"), "(quote #(1 2))");
    assert_eq!(n("#u8(0 255)"), "(quote #u8(0 255))");
}

#[test]
fn variable_reference() {
    assert_eq!(n("foo"), "foo");
    assert_eq!(n("list->vector"), "list->vector");
}

#[test]
fn quote_form() {
    assert_eq!(n("(quote x)"), "(quote x)");
    assert_eq!(n("(quote (1 2 3))"), "(quote (1 2 3))");
    assert_eq!(n("'x"), "(quote x)"); // reader shorthand
    assert_eq!(n("'()"), "(quote ())");
}

#[test]
fn if_form() {
    assert_eq!(n("(if a b c)"), "(if a b c)");
}

#[test]
fn lambda_form() {
    assert_eq!(n("(lambda (x) x)"), "(lambda (x) x)");
    assert_eq!(n("(lambda () 1)"), "(lambda () (quote 1))");
    assert_eq!(n("(lambda (x y . rest) x)"), "(lambda (x y . rest) x)");
    assert_eq!(n("(lambda (x . rest) x)"), "(lambda (x . rest) x)");
    // multi-expression body wraps in begin
    assert_eq!(n("(lambda (x) a b)"), "(lambda (x) (begin a b))");
}

#[test]
fn begin_set_define() {
    assert_eq!(n("(begin a b)"), "(begin a b)");
    assert_eq!(n("(begin a)"), "a"); // single-element begin collapses
    assert_eq!(n("(set! x 1)"), "(set! x (quote 1))");
    assert_eq!(n("(define x 1)"), "(define x (quote 1))");
}

#[test]
fn define_function_sugar() {
    assert_eq!(
        n("(define (f a b) (+ a b))"),
        "(define f (lambda (a b) (+ a b)))"
    );
    assert_eq!(
        n("(define (f a b) x y)"),
        "(define f (lambda (a b) (begin x y)))"
    );
    assert_eq!(n("(define (f . xs) xs)"), "(define f (lambda (. xs) xs))");
    assert_eq!(n("(define (f a . xs) a)"), "(define f (lambda (a . xs) a))");
}

#[test]
fn internal_define_passes_through_structurally() {
    // R2 decision: an internal `define` is normalized structurally (a Define node
    // inside the body's `begin`); the letrec*-style scoping of internal defines is
    // left to R3. It does NOT error at normalize time.
    assert_eq!(
        n("(lambda (x) (define y 1) (+ x y))"),
        "(lambda (x) (begin (define y (quote 1)) (+ x y)))"
    );
}

#[test]
fn values_is_a_core_node() {
    assert_eq!(n("(values)"), "(values)");
    assert_eq!(n("(values 1 2)"), "(values (quote 1) (quote 2))");
    // bare `values` may be referenced as a procedure
    assert_eq!(n("(map values xs)"), "(map values xs)");
}

#[test]
fn callcc_family_are_plain_applications() {
    // NOT special-cased: ordinary App of a Var head R6 binds as a primitive.
    assert_eq!(n("(call/cc f)"), "(call/cc f)");
    assert_eq!(n("(call-with-values p c)"), "(call-with-values p c)");
    assert_eq!(n("(dynamic-wind a b c)"), "(dynamic-wind a b c)");
}

#[test]
fn application_and_computed_operator() {
    assert_eq!(n("(f 1 2)"), "(f (quote 1) (quote 2))");
    assert_eq!(n("((lambda (x) x) 5)"), "((lambda (x) x) (quote 5))");
    // operator literal is allowed at normalize time (runtime E301 in R3)
    assert_eq!(n("(5 1)"), "((quote 5) (quote 1))");
}

#[test]
fn let_and_letrec() {
    assert_eq!(
        n("(let ((x 1) (y 2)) (+ x y))"),
        "(let ((x (quote 1)) (y (quote 2))) (+ x y))"
    );
    assert_eq!(n("(let () 1)"), "(let () (quote 1))");
    assert_eq!(
        n("(letrec ((f (lambda () 1))) (f))"),
        "(letrec ((f (lambda () (quote 1)))) (f))"
    );
}

// ── derived forms ────────────────────────────────────────────────────────────────

#[test]
fn let_star_nests() {
    assert_eq!(
        n("(let* ((x 1) (y 2)) (+ x y))"),
        "(let ((x (quote 1))) (let ((y (quote 2))) (+ x y)))"
    );
    // zero bindings -> a plain (let () body)
    assert_eq!(n("(let* () body)"), "(let () body)");
    assert_eq!(n("(let* ((x 1)) x)"), "(let ((x (quote 1))) x)");
}

#[test]
fn let_star_zero_binding_keeps_outer_empty_let() {
    // Regression: when the body is ITSELF a `let`, the outer empty `(let () …)`
    // wrapper must survive — wrapping is decided by the binding count, not by
    // inspecting the normalized body's kind.
    assert_eq!(
        n("(let* () (let ((x 1)) x))"),
        "(let () (let ((x (quote 1))) x))"
    );
    assert_eq!(n("(let* () 1)"), "(let () (quote 1))");
    // non-empty let* still right-folds into nested single-binding lets
    assert_eq!(
        n("(let* ((x 1) (y 2)) (+ x y))"),
        "(let ((x (quote 1))) (let ((y (quote 2))) (+ x y)))"
    );
}

#[test]
fn cond_to_nested_if() {
    assert_eq!(
        n("(cond (a 1) (b 2) (else 3))"),
        "(if a (quote 1) (if b (quote 2) (quote 3)))"
    );
    // no else -> fall-through is zero values (§0.3 unspecified = zero values)
    assert_eq!(n("(cond (a 1))"), "(if a (quote 1) (values))");
    // single else
    assert_eq!(n("(cond (else 9))"), "(quote 9)");
    // multi-expr clause body -> begin
    assert_eq!(
        n("(cond (a 1 2) (else 3))"),
        "(if a (begin (quote 1) (quote 2)) (quote 3))"
    );
}

#[test]
fn case_uses_eqv_intrinsic_not_equal() {
    let out = n("(case x ((1) 'a) (else 'b))");
    assert_eq!(
        out,
        "(let ((#:t0 x)) (if (if (#<intrinsic:eqv?> #:t0 (quote 1)) (quote #t) (quote #f)) (quote a) (quote b)))"
    );
    // §0.1 sign-off: the comparator is eqv?, never equal?, and never a user-bound var.
    assert!(out.contains("#<intrinsic:eqv?>"));
    assert!(!out.contains("equal?"));
}

#[test]
fn case_multi_datum_clause_does_not_duplicate_body() {
    let out = n("(case x ((1 2) 'a) (else 'b))");
    assert_eq!(
        out,
        "(let ((#:t0 x)) \
         (if (if (#<intrinsic:eqv?> #:t0 (quote 1)) (quote #t) \
         (if (#<intrinsic:eqv?> #:t0 (quote 2)) (quote #t) (quote #f))) \
         (quote a) (quote b)))"
    );
    // the body `(quote a)` appears exactly once despite two datums
    assert_eq!(out.matches("(quote a)").count(), 1);
}

#[test]
fn and_expands_with_last_operand_in_tail() {
    assert_eq!(n("(and)"), "(quote #t)");
    assert_eq!(n("(and a)"), "a");
    // last operand `c` is in tail (if-branch) position, not wrapped in a temp
    assert_eq!(n("(and a b c)"), "(if a (if b c (quote #f)) (quote #f))");
}

#[test]
fn or_expands_with_last_operand_in_tail() {
    assert_eq!(n("(or)"), "(quote #f)");
    assert_eq!(n("(or a)"), "a");
    // §6.6 single-operand base case: last operand `b` lands in tail position,
    // earlier operands use a fresh temp so they are not re-evaluated.
    assert_eq!(n("(or a b)"), "(let ((#:t0 a)) (if #:t0 #:t0 b))");
    assert_eq!(
        n("(or a b c)"),
        "(let ((#:t0 a)) (if #:t0 #:t0 (let ((#:t1 b)) (if #:t1 #:t1 c))))"
    );
}

#[test]
fn when_unless_use_values_not_not() {
    assert_eq!(n("(when c x y)"), "(if c (begin x y) (values))");
    // unless must NOT go through a user-shadowable `not`
    let out = n("(unless c x)");
    assert_eq!(out, "(if c (values) x)");
    assert!(!out.contains("not"));
}

#[test]
fn named_let_to_letrec() {
    assert_eq!(
        n("(let loop ((i 0)) (loop i))"),
        "(letrec ((loop (lambda (i) (loop i)))) (loop (quote 0)))"
    );
}

#[test]
fn do_to_letrec_loop() {
    assert_eq!(
        n("(do ((i 0 (+ i 1))) ((= i 5) i) (display i))"),
        "(letrec ((#:t0 (lambda (i) \
         (if (= i (quote 5)) i (begin (display i) (#:t0 (+ i (quote 1)))))))) \
         (#:t0 (quote 0)))"
    );
    // step optional -> variable keeps its value; empty result -> zero values
    assert_eq!(
        n("(do ((x 0)) (done))"),
        "(letrec ((#:t0 (lambda (x) (if done (values) (#:t0 x))))) (#:t0 (quote 0)))"
    );
}

// ── quasiquote (§10) ─────────────────────────────────────────────────────────────

#[test]
fn quasiquote_list_with_unquote_and_splice() {
    // `(a ,x ,@ys b)  -> cons/append spine built from hidden intrinsics
    assert_eq!(
        n("`(a ,x ,@ys b)"),
        "(#<intrinsic:cons> (quote a) \
         (#<intrinsic:cons> x \
         (#<intrinsic:append> ys \
         (#<intrinsic:cons> (quote b) (quote ())))))"
    );
}

#[test]
fn quasiquote_plain_is_quote() {
    assert_eq!(n("`a"), "(quote a)");
    assert_eq!(n("`5"), "(quote 5)");
    assert_eq!(
        n("`(a b)"),
        "(#<intrinsic:cons> (quote a) (#<intrinsic:cons> (quote b) (quote ())))"
    );
}

#[test]
fn quasiquote_dotted_tail_unquote() {
    // `(a . ,b) -> (cons 'a b)
    assert_eq!(n("`(a . ,b)"), "(#<intrinsic:cons> (quote a) b)");
}

#[test]
fn quasiquote_vector() {
    // `#(,a ,@bs) -> (list->vector (cons a (append bs '())))
    assert_eq!(
        n("`#(,a ,@bs)"),
        "(#<intrinsic:list->vector> (#<intrinsic:cons> a (#<intrinsic:append> bs (quote ()))))"
    );
}

#[test]
fn quasiquote_nested_reconstructs() {
    // a nested quasiquote increases depth: inner unquote at depth 2 is data.
    let out = n("`(a `(b ,c))");
    // outer spine uses cons; the inner quasiquote/unquote are rebuilt as data
    assert!(out.starts_with("(#<intrinsic:cons> (quote a)"));
    assert!(out.contains("(quote quasiquote)"));
    assert!(out.contains("(quote unquote)"));
}

// ── HYGIENE: user rebinding cannot change desugared meaning ───────────────────────

#[test]
fn hygiene_rebinding_does_not_capture() {
    // Bind every surface name a desugaring might otherwise have used; the expansions
    // inside still reference hidden intrinsics / fresh temps, never these bindings.
    let out = n("(let ((cons 0) (append 0) (list 0) (not 0) (eqv? 0)) \
           (begin (unless flag stop) (case k ((1) 'x) (else 'y)) `(p ,@q)))");
    // case still uses the intrinsic eqv?, not the bound `eqv?`
    assert!(out.contains("#<intrinsic:eqv?>"));
    // quasiquote still uses intrinsic cons/append, not the bound `cons`/`append`
    assert!(out.contains("#<intrinsic:cons>"));
    assert!(out.contains("#<intrinsic:append>"));
    // unless lowered to (if flag (values) stop) — note `not` only appears as the
    // user binding `(not 0)`, never as an application head in the unless expansion.
    assert!(out.contains("(if flag (values) stop)"));
}

#[test]
fn hygiene_user_temp_name_does_not_collide() {
    // A user variable literally named like a temp's *printed* form is still a User
    // ident (distinct enum variant) and never unifies with a hygienic Temp.
    let out = n("(or #t x)");
    // outer temp is #:t0 (the hygienic one); had a user `#:t0` existed it would be
    // a separate User("#:t0"). Determinism: same numbering every run.
    assert_eq!(out, "(let ((#:t0 (quote #t))) (if #:t0 #:t0 x))");
}

// ── E110: binding / using reserved words ─────────────────────────────────────────

#[test]
fn e110_binding_reserved_words() {
    assert_eq!(nerr("(let ((if 1)) if)"), ErrCode::E110);
    assert_eq!(nerr("(lambda (let) let)"), ErrCode::E110);
    assert_eq!(nerr("(define lambda 1)"), ErrCode::E110);
    assert_eq!(nerr("(set! define 1)"), ErrCode::E110);
    assert_eq!(nerr("(letrec ((cond 1)) cond)"), ErrCode::E110);
    assert_eq!(nerr("(let* ((begin 1)) begin)"), ErrCode::E110);
    assert_eq!(nerr("(let loop ((do 1)) do)"), ErrCode::E110);
    assert_eq!(nerr("(define (f when) when)"), ErrCode::E110);
    assert_eq!(nerr("(do ((case 0)) (x))"), ErrCode::E110);
}

#[test]
fn e110_reserved_word_as_value() {
    // a syntactic keyword used as a bare value/argument
    assert_eq!(nerr("(+ 1 if)"), ErrCode::E110);
    assert_eq!(nerr("lambda"), ErrCode::E110);
    assert_eq!(nerr("(define x cond)"), ErrCode::E110);
}

#[test]
fn callcc_family_may_be_bound_or_referenced() {
    // these reserved names are first-class procedures, not syntactic keywords
    ok("(map call/cc xs)");
    ok("(define x dynamic-wind)");
    ok("call-with-values");
}

// ── E120: forbidden macros / reader extensions / multi-binding forms ─────────────

#[test]
fn e120_forbidden_forms() {
    assert_eq!(
        nerr("(define-syntax foo (syntax-rules () ()))"),
        ErrCode::E120
    );
    assert_eq!(nerr("(let-syntax () 1)"), ErrCode::E120);
    assert_eq!(nerr("(letrec-syntax () 1)"), ErrCode::E120);
    assert_eq!(nerr("(syntax-rules () ())"), ErrCode::E120);
    assert_eq!(nerr("(define-values (a b) (values 1 2))"), ErrCode::E120);
    assert_eq!(nerr("(let-values (((a) 1)) a)"), ErrCode::E120);
    assert_eq!(nerr("(let*-values (((a) 1)) a)"), ErrCode::E120);
    assert_eq!(nerr("(define-library (foo))"), ErrCode::E120);
    assert_eq!(nerr("(include \"f.lx\")"), ErrCode::E120);
}

#[test]
fn e120_forbidden_as_symbol() {
    // mentioned as a symbol (not just as a head) is still E120
    assert_eq!(nerr("(foo syntax-rules)"), ErrCode::E120);
    assert_eq!(nerr("define-syntax"), ErrCode::E120);
}

#[test]
fn e120_forbidden_in_binder_positions() {
    // A §11 forbidden name used as a binder/target is E120 (not E110), in every
    // binding position: define target, let binder, lambda formal, set! target.
    assert_eq!(nerr("(define define-syntax 1)"), ErrCode::E120);
    assert_eq!(nerr("(let ((syntax-rules 1)) 2)"), ErrCode::E120);
    assert_eq!(nerr("(lambda (let-syntax) 1)"), ErrCode::E120);
    assert_eq!(nerr("(set! define-values 1)"), ErrCode::E120);
}

// ── E130: malformed derived forms ────────────────────────────────────────────────

#[test]
fn e130_empty_and_malformed() {
    assert_eq!(nerr("()"), ErrCode::E130); // empty application
    assert_eq!(nerr("(cond)"), ErrCode::E130); // empty cond
    assert_eq!(nerr("(if a b)"), ErrCode::E130); // if needs 3 arms
    assert_eq!(nerr("(if a b c d)"), ErrCode::E130);
    assert_eq!(nerr("(quote)"), ErrCode::E130);
    assert_eq!(nerr("(quote a b)"), ErrCode::E130);
    assert_eq!(nerr("(set! x)"), ErrCode::E130);
    assert_eq!(nerr("(begin)"), ErrCode::E130);
}

#[test]
fn e130_bad_bindings_and_formals() {
    assert_eq!(nerr("(let ((x)) x)"), ErrCode::E130); // binding not (id init)
    assert_eq!(nerr("(let ((x 1 2)) x)"), ErrCode::E130);
    assert_eq!(nerr("(let (x) x)"), ErrCode::E130); // binding not a list
    assert_eq!(nerr("(let x x)"), ErrCode::E130); // bindings is a bare non-named atom? -> named-let needs body
    assert_eq!(nerr("(lambda 5 5)"), ErrCode::E130); // formals not a list
    assert_eq!(nerr("(lambda (x x) x)"), ErrCode::E130); // duplicate formal
    assert_eq!(nerr("(lambda (1) 1)"), ErrCode::E130); // non-symbol formal
}

#[test]
fn e130_bad_cond_case_clauses() {
    assert_eq!(nerr("(cond a)"), ErrCode::E130); // clause not a list
    assert_eq!(nerr("(cond (a))"), ErrCode::E130); // clause has no body
    assert_eq!(nerr("(cond (else 1) (a 2))"), ErrCode::E130); // else not last
    assert_eq!(nerr("(cond (a => f) (else 1))"), ErrCode::E130); // => unsupported
    assert_eq!(nerr("(case x)"), ErrCode::E130); // no clauses
    assert_eq!(nerr("(case x ((1)))"), ErrCode::E130); // clause has no body
    assert_eq!(nerr("(case x (1 'a))"), ErrCode::E130); // datums not a list
    assert_eq!(nerr("(case x (else 1) ((2) 'b))"), ErrCode::E130); // else not last
}

#[test]
fn e130_bare_unquote_outside_quasiquote() {
    assert_eq!(nerr(",x"), ErrCode::E130);
    assert_eq!(nerr(",@x"), ErrCode::E130);
    assert_eq!(nerr("(unquote x)"), ErrCode::E130);
    // a bare unquote-splicing at the top of a quasiquote (not in a list) is E130
    assert_eq!(nerr("`,@x"), ErrCode::E130);
}

#[test]
fn e130_bad_do_and_module() {
    assert_eq!(nerr("(do)"), ErrCode::E130);
    assert_eq!(nerr("(do ((i 0 1 2)) (x))"), ErrCode::E130); // spec too long
    assert_eq!(nerr("(do (i) (x))"), ErrCode::E130); // spec not a list
    assert_eq!(nerr("(do () ())"), ErrCode::E130); // empty test clause
    assert_eq!(
        nerr("(begin (module m (export) (import) 1))"),
        ErrCode::E130
    ); // module not top-level
}

// ── module flattening (§3) ───────────────────────────────────────────────────────

#[test]
fn module_header_is_flattened() {
    let out = np("(module foo (export a) (import b) (define a 1) (define c 2))");
    assert_eq!(out, vec!["(define a (quote 1))", "(define c (quote 2))"]);
}

#[test]
fn module_dotted_name_and_no_clauses() {
    let out = np("(module util.string (define a 1))");
    assert_eq!(out, vec!["(define a (quote 1))"]);
}

#[test]
fn module_malformed_export_import_is_e130() {
    // export/import items must be identifiers (§3/§14); non-symbol items are E130,
    // not silently dropped.
    assert_eq!(
        nerr("(module m (export 1) (import 2) (define x 1))"),
        ErrCode::E130
    );
}

#[test]
fn module_valid_export_import_still_flattens() {
    let out = np("(module m (export a) (import b) (define a 1))");
    assert_eq!(out, vec!["(define a (quote 1))"]);
}

// ── determinism ──────────────────────────────────────────────────────────────────

#[test]
fn determinism_same_input_same_ast() {
    let src = "(begin (or a b c) (case k ((1 2) x) (else y)) (do ((i 0 (+ i 1))) ((= i 3)) z))";
    let prog = read_program(src, "t.lx").unwrap();
    let a = normalize_program(&prog.datums, "t.lx").unwrap();
    let b = normalize_program(&prog.datums, "t.lx").unwrap();
    // identical Core AST incl. fresh-temp numbering (sexpr) and full Debug (spans)
    let sa: Vec<String> = a.iter().map(|c| c.sexpr()).collect();
    let sb: Vec<String> = b.iter().map(|c| c.sexpr()).collect();
    assert_eq!(sa, sb);
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
}

// ── spec examples normalize without error ────────────────────────────────────────

#[test]
fn spec_15_1_examples() {
    ok("(define (sum xs) (let loop ((xs xs) (acc 0)) (if (null? xs) acc (loop (cdr xs) (+ acc (car xs))))))");
    ok("(when (> n 0) (display \"positive\"))");
    ok("`(a ,x ,@ys b)");
    ok("(call-with-values (lambda () (values 3 1)) (lambda (q r) (vector q r)))");
    ok("#u8(72 101 108 108 111)");
    ok("#(1 2 3)");
}

#[test]
fn spec_15_2_compat_results_are_valid_lispex() {
    // the §15.2 "after" snippets are ordinary Lispex and must normalize cleanly
    ok("(if (> n 0) (begin (display \"positive\")) (values))");
    ok("(append (list 'a x) ys (list 'b))");
    ok("(call-with-values (lambda () (values 3 1)) (lambda (q r) (vector q r)))");
}

#[test]
fn whole_program_normalizes() {
    let src = "\
(define (fact n) (if (= n 0) 1 (* n (fact (- n 1)))))
(define table #(1 2 3))
(let loop ((i 0)) (when (< i 3) (display i) (loop (+ i 1))))
(cond ((> x 0) 'pos) ((< x 0) 'neg) (else 'zero))";
    let out = np(src);
    assert_eq!(out.len(), 4);
}
