use std::rc::Rc;

use lispex::{
    canonical_program_bytes, normalize_program, read_program, CoreExpr, CoreKind, ErrorObj, Span,
    Value, CANONICAL_FORMAT_TAG,
};

fn canonical_preview(src: &str) -> String {
    let program = read_program(src, "canonical.lspx").expect("reader accepts fixture");
    let core =
        normalize_program(&program.datums, "canonical.lspx").expect("normalizer accepts fixture");
    String::from_utf8(canonical_program_bytes(&core).expect("canonical bytes")).unwrap()
}

#[test]
fn empty_program_canonical_preview_is_tag_only() {
    assert_eq!(canonical_preview(""), format!("{CANONICAL_FORMAT_TAG}\n"));
}

#[test]
fn rest_only_formals_are_representable() {
    assert_eq!(
        canonical_preview("(define (f . args) args)\n"),
        concat!(
            "lispex.core.canonical/v0\n",
            "(define f (lambda (. args) args))\n"
        )
    );
}

#[test]
fn character_writer_layers_are_pinned() {
    assert_eq!(
        canonical_preview("(quote (#\\tab #\\a #\\space #\\delete #\\escape #\\return #\\null))\n"),
        concat!(
            "lispex.core.canonical/v0\n",
            "(quote (#\\tab #\\a #\\space #\\x7f #\\x1b #\\return #\\null))\n"
        )
    );
}

#[test]
fn temp_numbering_is_program_scoped_and_visible() {
    assert_eq!(
        canonical_preview("(or a b)\n(or c d)\n"),
        concat!(
            "lispex.core.canonical/v0\n",
            "(let ((#:t0 a)) (if #:t0 #:t0 b))\n",
            "(let ((#:t1 c)) (if #:t1 #:t1 d))\n"
        )
    );
}

#[test]
fn guard_else_and_ordinaries_are_unambiguous() {
    assert_eq!(
        canonical_preview("(guard (e ((error-object? e) e) (else #f)) (raise e))\n"),
        concat!(
            "lispex.core.canonical/v0\n",
            "(guard (e ((error-object? e) e) (else (quote #f))) (raise e))\n"
        )
    );
}

#[test]
fn intrinsics_are_core_tokens_not_user_variables() {
    assert_eq!(
        canonical_preview("(case x ((1 2) 'small) (else 'other))\n"),
        concat!(
            "lispex.core.canonical/v0\n",
            "(let ((#:t0 x)) (if (if (#<intrinsic:eqv?> #:t0 (quote 1)) ",
            "(quote #t) (if (#<intrinsic:eqv?> #:t0 (quote 2)) ",
            "(quote #t) (quote #f))) (quote small) (quote other)))\n"
        )
    );
}

#[test]
fn canonical_serializer_rejects_execution_only_literals() {
    let expr = CoreExpr::new(
        CoreKind::Quote(Value::ErrorObject(Rc::new(ErrorObj {
            message: Rc::from("boom"),
            irritants: vec![],
        }))),
        Span { line: 1, col: 1 },
    );

    assert!(canonical_program_bytes(&[expr]).is_err());
}

#[test]
fn canonical_serializer_rejects_cyclic_vector_literals() {
    let vector = Value::vector(vec![]);
    let Value::Vector(data) = &vector else {
        unreachable!("Value::vector returns a vector")
    };
    data.items.borrow_mut().push(vector.clone());
    let expr = CoreExpr::new(CoreKind::Quote(vector), Span { line: 1, col: 1 });

    assert!(canonical_program_bytes(&[expr]).is_err());
}
