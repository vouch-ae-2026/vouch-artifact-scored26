//! Reader / lexer conformance tests (Round 1).
//!
//! Covers every datum kind, dotted lists, nested vectors, all comment forms, the
//! pinned number grammar (incl. its rejects), the quote shorthands, header
//! pragmas, and a few LISPEX.md §15.1 example forms (read-only).

use lispex::reader::{read_one, read_program, ErrCode};
use lispex::value::Value;
use lispex::BigInt;
use num_rational::BigRational;

// ── helpers ───────────────────────────────────────────────────────────────────

// The reader now emits a spanned `Syntax` tree; `one`/`values` project it to the
// plain runtime `Value` via `to_value()` so the value-shape assertions below stay
// concise. Span preservation itself is checked by `reader_preserves_spans`.
fn one(src: &str) -> Value {
    read_one(src, "test.lx")
        .map(|s| s.to_value())
        .unwrap_or_else(|d| panic!("expected ok, got `{d}` for `{src}`"))
}

fn values(src: &str) -> Vec<Value> {
    read_program(src, "test.lx")
        .unwrap_or_else(|d| panic!("expected ok, got `{d}` for `{src}`"))
        .datums
        .iter()
        .map(|s| s.to_value())
        .collect()
}

fn err(src: &str) -> ErrCode {
    match read_program(src, "test.lx") {
        Ok(p) => panic!("expected error for `{src}`, got {:?}", p.datums),
        Err(d) => d.code,
    }
}

fn int(n: i64) -> Value {
    Value::Int(BigInt::from(n))
}

fn real(f: f64) -> Value {
    Value::real(f).expect("finite test real")
}

fn sym(name: &str) -> Value {
    Value::Sym(std::rc::Rc::from(name))
}

fn list(items: Vec<Value>) -> Value {
    Value::list(items.into_iter())
}

// ── booleans ──────────────────────────────────────────────────────────────────

#[test]
fn booleans() {
    assert_eq!(one("#t"), Value::Bool(true));
    assert_eq!(one("#f"), Value::Bool(false));
    assert_eq!(one("#true"), Value::Bool(true));
    assert_eq!(one("#false"), Value::Bool(false));
    assert_eq!(err("#tru"), ErrCode::E100);
}

// ── integers ──────────────────────────────────────────────────────────────────

#[test]
fn integers() {
    assert_eq!(one("0"), int(0));
    assert_eq!(one("42"), int(42));
    assert_eq!(one("-7"), int(-7));
    assert_eq!(one("-0"), int(0));
    assert_eq!(
        one("123456789012345678901234567890"),
        Value::Int("123456789012345678901234567890".parse::<BigInt>().unwrap())
    );
}

#[test]
fn integer_rejects() {
    assert_eq!(err("007"), ErrCode::E100); // leading zero
    assert_eq!(err("00"), ErrCode::E100); // leading zero
    assert_eq!(err("#x10"), ErrCode::E100); // radix prefix
    assert_eq!(err("#e1"), ErrCode::E100); // exactness prefix
    assert_eq!(err("12abc"), ErrCode::E100); // digit-led, not a number
    assert_eq!(err("-5x"), ErrCode::E100); // -digit-led, not a number
}

// ── rationals ─────────────────────────────────────────────────────────────────

fn rat(n: i64, d: i64) -> Value {
    Value::Rational(BigRational::new(BigInt::from(n), BigInt::from(d)))
}

#[test]
fn rationals() {
    assert_eq!(one("1/3"), rat(1, 3));
    assert_eq!(one("6/4"), rat(3, 2)); // reduced
    assert_eq!(one("-1/2"), rat(-1, 2)); // sign on numerator (only the numerator may be signed)
    assert_eq!(one("42/7"), int(6)); // demote q==1 -> Int
    assert_eq!(one("0/5"), int(0)); // numerator 0 -> Int(0)
}

#[test]
fn rational_rejects() {
    assert_eq!(err("1/0"), ErrCode::E100); // denominator 0 not allowed
    assert_eq!(err("1/02"), ErrCode::E100); // leading-zero denominator
    assert_eq!(err("1/-2"), ErrCode::E100); // denominator may not be signed
    assert_eq!(err("1/2/3"), ErrCode::E100); // two slashes
}

// ── reals ─────────────────────────────────────────────────────────────────────

#[test]
fn reals() {
    assert_eq!(one("19.99"), real(19.99));
    assert_eq!(one("1.5e3"), real(1500.0));
    assert_eq!(one("-1.5E-3"), real(-0.0015));
    assert_eq!(one("1e10"), real(1e10));
    assert_eq!(one("0.0"), real(0.0));
    // -0.0 exists and is finite (§2)
    match one("-0.0") {
        Value::Real(f) => {
            let f = f.get();
            assert_eq!(f, 0.0);
            assert!(f.is_sign_negative());
        }
        other => panic!("expected real -0.0, got {other:?}"),
    }
}

#[test]
fn real_rejects() {
    assert_eq!(err("1e9999"), ErrCode::E314); // overflow to non-finite
    assert_eq!(err("-1e9999"), ErrCode::E314);
    assert_eq!(err("1."), ErrCode::E100); // no digit after '.'
    assert_eq!(err("1.2.3"), ErrCode::E100); // two dots
    assert_eq!(err("1e"), ErrCode::E100); // empty exponent
}

// ── symbols ───────────────────────────────────────────────────────────────────

#[test]
fn symbols() {
    assert_eq!(one("foo"), sym("foo"));
    assert_eq!(one("list->vector"), sym("list->vector"));
    assert_eq!(one("+"), sym("+"));
    assert_eq!(one("-"), sym("-"));
    assert_eq!(one("->"), sym("->"));
    assert_eq!(one("..."), sym("..."));
    assert_eq!(one("set!"), sym("set!"));
    // case-sensitive (§12)
    assert_ne!(one("Foo"), one("foo"));
    // `+`-led tokens are symbols (the number grammar permits a leading `-` only)
    assert_eq!(one("+5"), sym("+5"));
    // `.`-led non-dot tokens are symbols (grammar requires a digit before `.`)
    assert_eq!(one(".foo"), sym(".foo"));
    assert_eq!(one(".5"), sym(".5"));
}

// ── characters ────────────────────────────────────────────────────────────────

#[test]
fn characters() {
    assert_eq!(one("#\\a"), Value::Char('a'));
    assert_eq!(one("#\\space"), Value::Char(' '));
    assert_eq!(one("#\\newline"), Value::Char('\n'));
    assert_eq!(one("#\\tab"), Value::Char('\t'));
    assert_eq!(one("#\\return"), Value::Char('\r'));
    assert_eq!(one("#\\null"), Value::Char('\0'));
    assert_eq!(one("#\\("), Value::Char('('));
    assert_eq!(one("#\\)"), Value::Char(')'));
    assert_eq!(one("#\\;"), Value::Char(';'));
    assert_eq!(one("#\\1"), Value::Char('1'));
    assert_eq!(one("#\\x"), Value::Char('x')); // bare x = the letter x
    assert_eq!(one("#\\x41"), Value::Char('A')); // hex scalar
    assert_eq!(one("#\\x03B1"), Value::Char('\u{3B1}')); // α
}

#[test]
fn character_rejects() {
    assert_eq!(err("#\\xD800"), ErrCode::E150); // surrogate
    assert_eq!(err("#\\x110000"), ErrCode::E150); // > U+10FFFF
    assert_eq!(err("#\\xFFFFFFFFFF"), ErrCode::E150); // too large for u32
    assert_eq!(err("#\\nosuchname"), ErrCode::E150); // unknown name
}

// A single-char `#\X` requires EOF or a delimiter after it: an alnum start that
// runs into more alnum chars is ONE (invalid) token, not a char then a number.
#[test]
fn character_requires_delimiter() {
    // The reported bug: `#\12` must NOT read as `#\1` then `2`.
    assert_eq!(err("#\\12"), ErrCode::E150); // `#\12` is not a valid char name
    assert_eq!(err("#\\abc"), ErrCode::E150); // `#\abc` unknown name
                                              // …but valid single chars still read (incl. non-alnum punctuation that needs
                                              // no following delimiter beyond not being greedily consumed):
    assert_eq!(one("#\\1"), Value::Char('1'));
    assert_eq!(one("#\\a"), Value::Char('a'));
    assert_eq!(one("#\\;"), Value::Char(';'));
    assert_eq!(one("#\\("), Value::Char('(')); // `#\(` then EOF
    assert_eq!(one("#\\x41"), Value::Char('A')); // hex escape path
                                                 // a single alnum char abutting a delimiter is one char + the next datum:
    assert_eq!(values("#\\1 2"), vec![Value::Char('1'), int(2)]);
    // inside a list a char is delimited by the surrounding parens:
    assert_eq!(one("(#\\a)"), list(vec![Value::Char('a')]));
}

// ── strings ───────────────────────────────────────────────────────────────────

fn s(text: &str) -> Value {
    Value::Str(std::rc::Rc::from(text))
}

#[test]
fn strings() {
    assert_eq!(one("\"hello\""), s("hello"));
    assert_eq!(one("\"\""), s(""));
    assert_eq!(one("\"a\\nb\""), s("a\nb"));
    assert_eq!(one("\"tab\\there\""), s("tab\there"));
    assert_eq!(one("\"q\\\"q\""), s("q\"q")); // escaped quote
    assert_eq!(one("\"back\\\\slash\""), s("back\\slash"));
    assert_eq!(one("\"\\x41;\""), s("A")); // hex escape
    assert_eq!(one("\"\\x3B1;\""), s("\u{3B1}")); // α
}

#[test]
fn string_rejects() {
    assert_eq!(err("\"abc"), ErrCode::E100); // unterminated
    assert_eq!(err("\"\\q\""), ErrCode::E150); // bad escape
    assert_eq!(err("\"\\x41\""), ErrCode::E150); // hex missing ';'
    assert_eq!(err("\"\\x;\""), ErrCode::E150); // empty hex escape
    assert_eq!(err("\"\\xD800;\""), ErrCode::E150); // surrogate via escape
}

// ── lists & dotted lists ───────────────────────────────────────────────────────

#[test]
fn lists() {
    assert_eq!(one("()"), Value::Nil);
    assert_eq!(one("(1 2 3)"), list(vec![int(1), int(2), int(3)]));
    assert_eq!(
        one("(1 (2 3) 4)"),
        list(vec![int(1), list(vec![int(2), int(3)]), int(4)])
    );
    assert_eq!(one("(foo)"), list(vec![sym("foo")]));
}

#[test]
fn dotted_lists() {
    // (1 2 . 3)
    assert_eq!(
        one("(1 2 . 3)"),
        Value::list_with_tail(vec![int(1), int(2)].into_iter(), int(3))
    );
    // (a . b)
    assert_eq!(one("(a . b)"), Value::cons(sym("a"), sym("b")));
    // nested
    assert_eq!(
        one("(a (b . c) . d)"),
        Value::list_with_tail(
            vec![sym("a"), Value::cons(sym("b"), sym("c"))].into_iter(),
            sym("d")
        )
    );
}

#[test]
fn dotted_list_rejects() {
    assert_eq!(err("(a . )"), ErrCode::E140); // no cdr
    assert_eq!(err("(. a)"), ErrCode::E140); // no car
    assert_eq!(err("(a . b c)"), ErrCode::E140); // >1 datum after dot
    assert_eq!(err("(a .)"), ErrCode::E140); // dot then close
}

#[test]
fn list_structural_rejects() {
    assert_eq!(err("(1 2"), ErrCode::E100); // unterminated
    assert_eq!(err(")"), ErrCode::E100); // stray close
    assert_eq!(err("("), ErrCode::E100); // unterminated empty
    assert_eq!(err("[1 2]"), ErrCode::E100); // unsupported bracket
    assert_eq!(err("{}"), ErrCode::E100); // unsupported bracket
    assert_eq!(err("."), ErrCode::E100); // stray dot
}

// ── vectors ─────────────────────────────────────────────────────────────────--

#[test]
fn vectors() {
    assert_eq!(one("#(1 2 3)"), Value::vector(vec![int(1), int(2), int(3)]));
    assert_eq!(one("#()"), Value::vector(vec![]));
    // nested vectors
    assert_eq!(
        one("#(#(1) 2)"),
        Value::vector(vec![Value::vector(vec![int(1)]), int(2)])
    );
    // mixed datum kinds
    assert_eq!(
        one("#(1 #\\a \"s\" foo)"),
        Value::vector(vec![int(1), Value::Char('a'), s("s"), sym("foo")])
    );
}

#[test]
fn vector_rejects() {
    assert_eq!(err("#(1 . 2)"), ErrCode::E100); // dot not allowed in vector
    assert_eq!(err("#(1 2"), ErrCode::E100); // unterminated
}

// ── bytevectors ─────────────────────────────────────────────────────────────--

fn bv(bytes: Vec<u8>) -> Value {
    Value::Bytevector(std::rc::Rc::new(bytes))
}

#[test]
fn bytevectors() {
    assert_eq!(
        one("#u8(72 101 108 108 111)"),
        bv(vec![72, 101, 108, 108, 111])
    );
    assert_eq!(one("#u8()"), bv(vec![]));
    assert_eq!(one("#u8(0 255)"), bv(vec![0, 255]));
}

#[test]
fn bytevector_rejects() {
    assert_eq!(err("#u8(256)"), ErrCode::E100); // out of range
    assert_eq!(err("#u8(-1)"), ErrCode::E100); // out of range
    assert_eq!(err("#u8(1.5)"), ErrCode::E100); // not an integer
    assert_eq!(err("#u8(a)"), ErrCode::E100); // not an integer
    assert_eq!(err("#u8(1 2"), ErrCode::E100); // unterminated
    assert_eq!(err("#u9(1)"), ErrCode::E100); // not #u8(
}

// §12: a `<byte>` is a LEXICAL integer literal, so a rational/real that would
// *normalize* to an in-range int is still rejected — it is not byte syntax.
#[test]
fn bytevector_elements_are_lexical_integers() {
    assert_eq!(err("#u8(4/2)"), ErrCode::E100); // would normalize to 2, but not <byte> syntax
    assert_eq!(err("#u8(1/1)"), ErrCode::E100); // would normalize to 1, but not <byte> syntax
    assert_eq!(err("#u8(2.0)"), ErrCode::E100); // a real, not an integer literal
    assert_eq!(one("#u8(0 255)"), bv(vec![0, 255])); // plain integer literals ok
}

// ── comments ────────────────────────────────────────────────────────────────--

#[test]
fn line_comments() {
    assert_eq!(one("; a comment\n42"), int(42));
    assert_eq!(one("42 ; trailing\n"), int(42));
}

#[test]
fn block_comments() {
    assert_eq!(one("#| block |# 42"), int(42));
    // nestable
    assert_eq!(one("#| a #| b |# c |# 42"), int(42));
    assert_eq!(one("#| #| #| deep |# |# |# 42"), int(42));
}

#[test]
fn block_comment_rejects() {
    assert_eq!(err("#| unterminated"), ErrCode::E100);
    assert_eq!(err("#| a #| b |# still open"), ErrCode::E100);
}

// ── header pragmas ────────────────────────────────────────────────────────────

#[test]
fn header_pragmas() {
    let prog = read_program(";! lispex 1.2\n;! compat: r5rs\n42\n", "test.lx").unwrap();
    assert_eq!(prog.header.version.as_deref(), Some("1.2"));
    assert!(prog.header.compat_r5rs);
    let datums: Vec<Value> = prog.datums.iter().map(|s| s.to_value()).collect();
    assert_eq!(datums, vec![int(42)]);
}

#[test]
fn header_pragma_version_only() {
    let prog = read_program(";! lispex 1.2\n(foo)\n", "test.lx").unwrap();
    assert_eq!(prog.header.version.as_deref(), Some("1.2"));
    assert!(!prog.header.compat_r5rs);
}

// ── quote shorthands ──────────────────────────────────────────────────────────

#[test]
fn quote_shorthands() {
    assert_eq!(one("'x"), list(vec![sym("quote"), sym("x")]));
    assert_eq!(one("`x"), list(vec![sym("quasiquote"), sym("x")]));
    assert_eq!(one(",x"), list(vec![sym("unquote"), sym("x")]));
    assert_eq!(one(",@xs"), list(vec![sym("unquote-splicing"), sym("xs")]));
    // nested
    assert_eq!(
        one("''x"),
        list(vec![sym("quote"), list(vec![sym("quote"), sym("x")])])
    );
    // quoting a list
    assert_eq!(
        one("'(1 2)"),
        list(vec![sym("quote"), list(vec![int(1), int(2)])])
    );
}

#[test]
fn quote_shorthand_rejects() {
    assert_eq!(err("'"), ErrCode::E100); // nothing to quote
    assert_eq!(err(",@"), ErrCode::E100); // nothing to splice
}

// ── multiple top-level datums ─────────────────────────────────────────────────

#[test]
fn multiple_toplevel_datums() {
    assert_eq!(values("1 2 3"), vec![int(1), int(2), int(3)]);

    let prog = read_program("(define x 1)\n(define y 2)\n", "test.lx").unwrap();
    assert_eq!(prog.datums.len(), 2);
}

// ── diagnostic rendering format ───────────────────────────────────────────────

#[test]
fn diagnostic_format() {
    let d = read_program("\n  )", "demo.lx").unwrap_err();
    assert_eq!(d.code, ErrCode::E100);
    let rendered = d.to_string();
    // `CODE file:line:col message`
    assert!(rendered.starts_with("E100 demo.lx:2:3 "), "got: {rendered}");
}

// ── LISPEX.md §15.1 examples: must READ without error ──────────────────────────

#[test]
fn example_named_let_sum() {
    let src = "(define (sum xs)\n  (let loop ((xs xs) (acc 0))\n    (if (null? xs) acc\n        (loop (cdr xs) (+ acc (car xs))))))";
    let prog = read_program(src, "test.lx").unwrap();
    assert_eq!(prog.datums.len(), 1);
}

#[test]
fn example_when() {
    let prog = read_program("(when (> n 0) (display \"positive\"))", "test.lx").unwrap();
    assert_eq!(prog.datums.len(), 1);
}

#[test]
fn example_bytevector_hello() {
    assert_eq!(
        one("#u8(72 101 108 108 111)"),
        bv(vec![72, 101, 108, 108, 111])
    );
}

#[test]
fn example_quasiquote_splice() {
    // `(a ,x ,@ys b)  =>  (quasiquote (a (unquote x) (unquote-splicing ys) b))
    let v = one("`(a ,x ,@ys b)");
    let expected = list(vec![
        sym("quasiquote"),
        list(vec![
            sym("a"),
            list(vec![sym("unquote"), sym("x")]),
            list(vec![sym("unquote-splicing"), sym("ys")]),
            sym("b"),
        ]),
    ]);
    assert_eq!(v, expected);
}

#[test]
fn example_call_with_values() {
    let src = "(call-with-values (lambda () (values 3 1))\n                  (lambda (q r) (vector q r)))";
    let prog = read_program(src, "test.lx").unwrap();
    assert_eq!(prog.datums.len(), 1);
}

// ── a couple of whole-program forms exercising many datum kinds at once ────────

// ── banned reader extensions (E120) ────────────────────────────────────────────

#[test]
fn banned_reader_extensions_are_e120() {
    // `#;` datum comment and `#lang` are reader extensions → immediate E120 (§4).
    assert_eq!(err("#;42"), ErrCode::E120);
    assert_eq!(err("#; (ignored)"), ErrCode::E120);
    assert_eq!(err("#lang racket"), ErrCode::E120);
    assert_eq!(err("#lang"), ErrCode::E120);
    // other unknown `#…` stays the generic E100 (radix/exactness prefixes, etc.)
    assert_eq!(err("#x10"), ErrCode::E100);
    assert_eq!(err("#e1"), ErrCode::E100);
    assert_eq!(err("#langx"), ErrCode::E100); // not exactly `#lang`
}

// ── source spans are preserved in the reader's `Syntax` output ─────────────────

#[test]
fn reader_preserves_spans() {
    use lispex::syntax::SyntaxKind;
    use lispex::Span;

    let s = read_one("  (foo 42)", "test.lx").unwrap();
    assert_eq!(s.span, Span { line: 1, col: 3 }); // the opening `(`
    match &s.node {
        SyntaxKind::List(items) => {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].span, Span { line: 1, col: 4 }); // `foo`
            assert!(matches!(&items[0].node, SyntaxKind::Sym(n) if &**n == "foo"));
            assert_eq!(items[1].span, Span { line: 1, col: 8 }); // `42`
            assert!(matches!(&items[1].node, SyntaxKind::Int(_)));
        }
        other => panic!("expected list, got {other:?}"),
    }

    // line tracking across a newline
    let s2 = read_one("\n  bar", "test.lx").unwrap();
    assert_eq!(s2.span, Span { line: 2, col: 3 });

    // nested compound nodes are spanned too, and `to_value` drops spans while
    // preserving the datum structure.
    let s3 = read_one("(a (b))", "test.lx").unwrap();
    if let SyntaxKind::List(items) = &s3.node {
        assert_eq!(items[1].span, Span { line: 1, col: 4 }); // inner `(b)`
    } else {
        panic!("expected list");
    }
    assert_eq!(s3.to_value(), list(vec![sym("a"), list(vec![sym("b")])]));
}

#[test]
fn mixed_program_reads() {
    let src = r#"
;! lispex 1.2
;; a line comment
#| a #| nested |# block |#
(define greeting "Hello, \x4C;ispEx!")
(define table #(1 2/3 4.5 #\x #t))
(define bytes #u8(1 2 3))
'(quoted list . tail)
`(a ,b ,@cs)
"#;
    let prog = read_program(src, "test.lx").unwrap();
    assert_eq!(prog.header.version.as_deref(), Some("1.2"));
    assert_eq!(prog.datums.len(), 5);
}
