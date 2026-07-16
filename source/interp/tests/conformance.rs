//! R7 — Conformance corpus + harness (LISPEX-RUNTIME.md §13).
//!
//! Three families drive the EXISTING interpreter (this harness changes NO
//! interpreter semantics and does NOT modify the docs):
//!
//!   (A) **Evaluation goldens** — preserved current code blocks in
//!       `content/en/docs/classic/**.mdx` that carry
//!       an expected-result annotation (`;; Result:` / `; Result:` / `;; ⇒` / `; ⇒`,
//!       both trailing and following-line, plus the `NAME ⇒ value` "variable" form).
//!       Runnable fences are ```lispex``` AND ```clojure``` (```text``` is skipped).
//!       A file's runnable fences are concatenated **in document order, at their
//!       original line numbers** (prose blanked out), so blocks that build on each
//!       other (defines reused later) work and every annotation keeps its real
//!       `file:line`.
//!
//!   (B) **Diagnostic negatives** — malformed input → a static `E1xx`/`W3xx` code
//!       (asserted to fire at READ/NORMALIZE, before evaluation) plus the author
//!       runtime-`E3xx` negatives.
//!
//!   (C) **R5RS-compat normalization pairs** — §15.1 surface → normalized Core AST
//!       (the transformer, not the runtime).  ⚠ See the module note below and the
//!       R7 report: the R5RS-compat *toggle* and the W310/W320 warnings are NOT
//!       implemented in the v1 interpreter (R1–R6), so the "compat ON" half of (C)
//!       is recorded as a documented gap rather than silently passed.
//!
//! ★ Comparison strategy (must-fix guard, §13).  An expected annotation is a
//! **restricted expectation language** — literals, quoted data, vectors,
//! bytevectors, `(values …)`, the docs' `(list …)` notation (read as a *list
//! literal*, NOT by calling the interpreter's `list`), and bare error-code tokens
//! (`E312`, …).  It is evaluated **directly in Rust** (no interpreter procedure is
//! ever invoked for the expectation) and compared to the actual outcome BOTH by
//! value (`equal?`, via `Value`'s structural `PartialEq`) AND by canonical `write`
//! string.  Anything outside the restricted language (e.g. an `(append …)`
//! expectation) is marked **SKIP-with-reason**, never silently passed.
//!
//! Documented doc-errors (§0 sign-offs + ones surfaced here) are recorded as
//! explicit **EXCEPTION** entries: the harness asserts the interpreter's *actual*
//! (divergent) behaviour, so the suite is green AND the divergence stays visible.
//! Each carries the doc fix that would let the snippet pass (see the R7 report).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use lispex::{
    normalize_one, read_one, read_program, Eval, Interp, Outcome, RunError, RuntimeCode, Syntax,
    SyntaxKind, Value,
};

// ─────────────────────────────────────────────────────────────────────────────
// Doc file access
// ─────────────────────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("interp/ has a parent (repo root)")
        .to_path_buf()
}

fn doc_text(lang: &str, rel: &str) -> String {
    let p = repo_root()
        .join("content")
        .join(lang)
        .join("docs")
        .join("classic")
        .join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Every en doc (used by the drift guard).
const ALL_DOCS: &[&str] = &[
    "getting-started.mdx",
    "introduction.mdx",
    "reference/core-functions.mdx",
    "reference/functional-library.mdx",
    "reference/list-operations.mdx",
    "reference/operators.mdx",
    "concepts/variables-scope.mdx",
    "concepts/control-flow.mdx",
    "concepts/data-types.mdx",
    "concepts/error-handling.mdx",
    "concepts/functions-closures.mdx",
    "concepts/syntax.mdx",
    "guides/using-map.mdx",
    "guides/first-project.mdx",
    "guides/recursion.mdx",
    "guides/capabilities.mdx",
    "guides/targets.mdx",
    "guides/understanding-closures.mdx",
];

// ─────────────────────────────────────────────────────────────────────────────
// Fenced-block extraction
// ─────────────────────────────────────────────────────────────────────────────

struct Fence {
    lang: String,
    body: String,
}

fn is_fence_marker(line: &str) -> Option<String> {
    line.trim_start()
        .strip_prefix("```")
        .map(|rest| rest.trim().to_string())
}

fn fences(text: &str) -> Vec<Fence> {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if let Some(tag) = is_fence_marker(lines[i]) {
            // `tag` is the opening info string; a closing ``` has an empty tag, but
            // an opening fence with an empty info string is possible too — so we just
            // pair the next ``` as the close.
            let mut body = Vec::new();
            i += 1;
            while i < lines.len() && is_fence_marker(lines[i]).is_none() {
                body.push(lines[i]);
                i += 1;
            }
            out.push(Fence {
                lang: tag,
                body: body.join("\n"),
            });
            i += 1; // skip the closing marker
        } else {
            i += 1;
        }
    }
    out
}

fn is_runnable(lang: &str) -> bool {
    lang == "lispex" || lang == "clojure"
}

/// Build a program string that is line-for-line aligned with `text`, keeping ONLY
/// the lines inside runnable fences and blanking everything else.  Reading this
/// string therefore yields datums whose spans carry the **original** `.mdx` line
/// numbers, and a comment scan over it sees the in-fence annotations at their real
/// lines — so the corpus can key exceptions by `file:line`.
fn assemble_program(text: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out: Vec<String> = vec![String::new(); lines.len()];
    let mut i = 0;
    while i < lines.len() {
        if let Some(tag) = is_fence_marker(lines[i]) {
            let runnable = is_runnable(&tag);
            i += 1;
            while i < lines.len() && is_fence_marker(lines[i]).is_none() {
                if runnable {
                    out[i] = lines[i].to_string();
                }
                i += 1;
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    out.join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// Comment-aware text helpers (line scanner + whole-block code stripper)
// ─────────────────────────────────────────────────────────────────────────────

/// Byte index of the first `;` that starts a line comment (outside a string and not
/// the `;` of a `#\;` char literal), if any.
fn comment_start(line: &str) -> Option<usize> {
    let mut in_str = false;
    let mut it = line.char_indices().peekable();
    while let Some((idx, c)) = it.next() {
        if in_str {
            if c == '\\' {
                it.next();
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '#' => {
                if let Some(&(_, n)) = it.peek() {
                    if n == '\\' {
                        it.next(); // the backslash
                        it.next(); // the char itself (e.g. `;`)
                    }
                }
            }
            ';' => return Some(idx),
            _ => {}
        }
    }
    None
}

/// Executable code of a fence body with all comments removed and whitespace runs
/// collapsed to single spaces — the "is the CODE translation-invariant?" view used
/// by the drift guard (translated comments + alignment differences vanish; a
/// translated string literal or an added/removed form survives).
fn strip_code(body: &str) -> String {
    let chars: Vec<char> = body.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '"' => {
                out.push('"');
                i += 1;
                while i < chars.len() {
                    let c = chars[i];
                    out.push(c);
                    i += 1;
                    if c == '\\' && i < chars.len() {
                        out.push(chars[i]);
                        i += 1;
                    } else if c == '"' {
                        break;
                    }
                }
            }
            '#' if i + 1 < chars.len() && chars[i + 1] == '\\' => {
                out.push('#');
                out.push('\\');
                i += 2;
                if i < chars.len() {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            '#' if i + 1 < chars.len() && chars[i + 1] == '|' => {
                // nestable block comment
                let mut depth = 1;
                i += 2;
                while i < chars.len() && depth > 0 {
                    if chars[i] == '#' && i + 1 < chars.len() && chars[i + 1] == '|' {
                        depth += 1;
                        i += 2;
                    } else if chars[i] == '|' && i + 1 < chars.len() && chars[i + 1] == '#' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            ';' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-datum scanner (used ONLY to slice the first datum out of an expectation
// string, so trailing prose like `(stops at 10)` is ignored).
// ─────────────────────────────────────────────────────────────────────────────

fn is_delim(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '(' | ')' | '[' | ']' | '{' | '}' | '"' | ';' | '\'' | '`' | ','
        )
}

fn skip_string(chars: &[char], mut i: usize) -> usize {
    i += 1; // opening quote
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '"' => return i + 1,
            _ => i += 1,
        }
    }
    i
}

fn skip_char(chars: &[char], mut i: usize) -> usize {
    i += 2; // `#\`
    if i < chars.len() {
        i += 1; // the (possibly delimiter) char
    }
    while i < chars.len() && !is_delim(chars[i]) {
        i += 1; // rest of a named char like `space`
    }
    i
}

/// Return the byte length (in chars) of the first datum starting at `start` (which
/// must already be a non-whitespace char).
fn datum_end(chars: &[char], start: usize) -> usize {
    let mut i = start;
    // quote prefixes
    while i < chars.len() && matches!(chars[i], '\'' | '`' | ',') {
        if chars[i] == ',' && i + 1 < chars.len() && chars[i + 1] == '@' {
            i += 2;
        } else {
            i += 1;
        }
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
    }
    if i >= chars.len() {
        return chars.len();
    }
    // `#(` vector or `#u8(` bytevector → balanced-scan from the `(`.
    if chars[i] == '#' {
        let open = if i + 1 < chars.len() && chars[i + 1] == '(' {
            Some(i + 1)
        } else if chars[i..].starts_with(&['#', 'u', '8', '(']) {
            Some(i + 3)
        } else {
            None
        };
        if let Some(o) = open {
            return scan_balanced(chars, o);
        }
        if i + 1 < chars.len() && chars[i + 1] == '\\' {
            return skip_char(chars, i);
        }
    }
    match chars[i] {
        '(' | '[' | '{' => scan_balanced(chars, i),
        '"' => skip_string(chars, i),
        _ => {
            while i < chars.len() && !is_delim(chars[i]) {
                i += 1;
            }
            i
        }
    }
}

fn scan_balanced(chars: &[char], start: usize) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while i < chars.len() {
        match chars[i] {
            '"' => i = skip_string(chars, i),
            '#' if i + 1 < chars.len() && chars[i + 1] == '\\' => i = skip_char(chars, i),
            ';' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '(' | '[' | '{' => {
                depth += 1;
                i += 1;
            }
            ')' | ']' | '}' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    i
}

fn first_datum(s: &str) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    if i >= chars.len() {
        return None;
    }
    let end = datum_end(&chars, i);
    Some(chars[i..end].iter().collect())
}

// ─────────────────────────────────────────────────────────────────────────────
// Restricted expectation language → expected outcome (evaluated in Rust only).
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Expect {
    /// 0, 1, or many values.
    Vals(Vec<Value>),
    /// A bare error-code token (`E312`, `recursion-limit`, …).
    Err(String),
    /// Not expressible in the restricted language → SKIP-with-reason.
    Unsupported(String),
}

fn is_error_token(name: &str) -> bool {
    if name == "recursion-limit" {
        return true;
    }
    let b = name.as_bytes();
    b.len() == 4 && (b[0] == b'E' || b[0] == b'W') && b[1..].iter().all(u8::is_ascii_digit)
}

/// Build a proper-list `Value` for a `(list …)` expectation WITHOUT calling
/// `Value::list` (the same constructor the interpreter's `list` primitive uses).  An
/// explicit right-fold over `Value::cons` / `Value::Nil` is an INDEPENDENT oracle, so a
/// bug in `Value::list`'s iteration/termination cannot be masked by program and
/// expectation sharing it (the §13 "don't share a broken procedure" rule extended to the
/// list constructor, P3 #8).
fn list_oracle(items: Vec<Value>) -> Value {
    let mut acc = Value::Nil;
    for v in items.into_iter().rev() {
        acc = Value::cons(v, acc);
    }
    acc
}

fn restricted(s: &Syntax) -> Expect {
    match &s.node {
        SyntaxKind::Bool(_)
        | SyntaxKind::Int(_)
        | SyntaxKind::Rational(_)
        | SyntaxKind::Real(_)
        | SyntaxKind::Char(_)
        | SyntaxKind::Str(_)
        | SyntaxKind::Nil
        | SyntaxKind::Vector(_)
        | SyntaxKind::Bytevector(_) => Expect::Vals(vec![s.to_value()]),
        SyntaxKind::Sym(name) => {
            if is_error_token(name) {
                Expect::Err(name.to_string())
            } else {
                Expect::Unsupported(format!(
                    "bare symbol `{name}` in expectation (only error-code tokens allowed)"
                ))
            }
        }
        SyntaxKind::DottedList(..) => Expect::Unsupported("dotted list in expectation".to_string()),
        SyntaxKind::List(items) => {
            let head = match items.first().map(|h| &h.node) {
                Some(SyntaxKind::Sym(h)) => h.to_string(),
                _ => return Expect::Unsupported("non-symbol head in expectation".to_string()),
            };
            match head.as_str() {
                "quote" if items.len() == 2 => Expect::Vals(vec![items[1].to_value()]),
                "list" => match collect_single(&items[1..]) {
                    Ok(vs) => Expect::Vals(vec![list_oracle(vs)]),
                    Err(e) => Expect::Unsupported(e),
                },
                "values" => match collect_single(&items[1..]) {
                    Ok(vs) => Expect::Vals(vs),
                    Err(e) => Expect::Unsupported(e),
                },
                other => Expect::Unsupported(format!(
                    "call form `({other} …)` is not in the restricted expectation language"
                )),
            }
        }
    }
}

fn collect_single(items: &[Syntax]) -> Result<Vec<Value>, String> {
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match restricted(it) {
            Expect::Vals(mut vs) if vs.len() == 1 => out.push(vs.pop().unwrap()),
            Expect::Vals(vs) => {
                return Err(format!(
                    "element produced {} values, need exactly 1",
                    vs.len()
                ))
            }
            Expect::Err(c) => return Err(format!("element is an error token `{c}`")),
            Expect::Unsupported(e) => return Err(e),
        }
    }
    Ok(out)
}

fn expect_from_text(text: &str) -> Expect {
    let Some(fd) = first_datum(text) else {
        return Expect::Unsupported("empty expectation".to_string());
    };
    match read_one(&fd, "<expectation>") {
        Ok(s) => restricted(&s),
        Err(e) => Expect::Unsupported(format!("unreadable expectation `{fd}`: {}", e.code)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Driving the interpreter
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
enum Actual {
    Vals(Vec<Value>),
    Err(String),
}

fn outcome_vals(o: Outcome) -> Vec<Value> {
    match o {
        Outcome::One(v) => vec![v],
        Outcome::Many(vs) => vs,
    }
}

/// Map a top-level [`Eval`] result to the harness [`Actual`]. Factored out of
/// [`eval_datum`] so the (defensively present) `Eval::Escape` arm is directly testable
/// — a live escape that surfaces at top level was used outside its dynamic extent → E340
/// (§9). In practice a live escape is always caught by its owning `call/cc` frame and a
/// stale `(k …)` faults `Eval::Error(E340)` at the call site, so the `Escape` arm here is
/// a belt-and-braces guard; `escape_outcome_maps_to_e340` pins its contract.
fn actual_of_eval(ev: Eval) -> Actual {
    match ev {
        Eval::Ok(o) => Actual::Vals(outcome_vals(o)),
        Eval::Error(e) => Actual::Err(e.code.as_str().to_string()),
        Eval::Escape { .. } => Actual::Err("E340".to_string()),
        // `TailApply` is an internal trampoline hand-off resolved inside `eval`; it can
        // never be the outcome of a top-level form (§4).
        Eval::TailApply { .. } => {
            unreachable!("Eval::TailApply must be resolved inside the trampoline")
        }
    }
}

fn eval_datum(it: &mut Interp, datum: &Syntax, file: &str) -> Actual {
    match normalize_one(datum, file) {
        Err(e) => Actual::Err(e.code.to_string()),
        Ok(core) => actual_of_eval(it.eval_toplevel(core)),
    }
}

fn eval_src(it: &mut Interp, src: &str, file: &str) -> Actual {
    match read_one(src, file) {
        Err(e) => Actual::Err(e.code.to_string()),
        Ok(datum) => eval_datum(it, &datum, file),
    }
}

fn write_join(vs: &[Value]) -> String {
    vs.iter()
        .map(Value::write_repr)
        .collect::<Vec<_>>()
        .join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// Annotation scanning
// ─────────────────────────────────────────────────────────────────────────────

const ARROW: char = '\u{21D2}'; // ⇒

#[derive(Debug)]
enum AnnoKind {
    /// Value of the immediately-preceding top-level form.
    Positional,
    /// Value of evaluating this variable name.
    NamedVar(String),
}

#[derive(Debug)]
struct Anno {
    line: usize,
    kind: AnnoKind,
    expect_text: String,
}

fn looks_like_ident(s: &str) -> bool {
    !s.is_empty()
        && !s.contains(char::is_whitespace)
        && !s.contains('(')
        && !s.contains(')')
        && !s.contains('"')
}

fn scan_annos(assembled: &str) -> Vec<Anno> {
    let mut out = Vec::new();
    for (idx, line) in assembled.split('\n').enumerate() {
        let Some(cpos) = comment_start(line) else {
            continue;
        };
        let body = line[cpos..].trim_start_matches(';');
        let body = body.trim();
        if let Some(rest) = body.strip_prefix("Result:") {
            out.push(Anno {
                line: idx + 1,
                kind: AnnoKind::Positional,
                expect_text: rest.trim().to_string(),
            });
        } else if let Some(api) = body.find(ARROW) {
            let lhs = body[..api].trim();
            let rhs = body[api + ARROW.len_utf8()..].trim();
            let kind = if lhs.is_empty() {
                AnnoKind::Positional
            } else if looks_like_ident(lhs) {
                AnnoKind::NamedVar(lhs.to_string())
            } else {
                AnnoKind::Positional
            };
            out.push(Anno {
                line: idx + 1,
                kind,
                expect_text: rhs.to_string(),
            });
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// (A) Evaluation goldens
// ─────────────────────────────────────────────────────────────────────────────

/// The (A) source files and the pinned number of recognised annotations each one
/// carries (so the corpus cannot silently shrink).
const A_FILES: &[(&str, usize)] = &[
    ("reference/operators.mdx", 54),
    ("reference/core-functions.mdx", 12),
    ("reference/list-operations.mdx", 12),
    ("reference/functional-library.mdx", 8),
    ("concepts/data-types.mdx", 7),
    ("concepts/control-flow.mdx", 8),
    ("concepts/variables-scope.mdx", 8),
    ("concepts/functions-closures.mdx", 6),
    ("guides/recursion.mdx", 3),
    ("guides/understanding-closures.mdx", 2),
    ("guides/using-map.mdx", 1),
    ("introduction.mdx", 1),
];

/// Documented divergences (§0 sign-offs + ones surfaced by this corpus).  Keyed by
/// `(file, line)`; the value is the interpreter's ACTUAL (divergent) outcome, which
/// the harness asserts — so the suite is green AND the divergence stays visible.
fn exception_for(file: &str, line: usize) -> Option<Actual> {
    let code = match (file, line) {
        // §0.2: `=` is numeric-only → comparing strings/lists faults, not `#f`/`#t`.
        ("reference/operators.mdx", 82) => "E312", // (= "hello" "world")  doc: #f
        ("reference/operators.mdx", 83) => "E312", // (= (list 1 2)(list 1 2))  doc: #t
        // `length` is a LIST op; the "longest word" example applies it to a string.
        ("reference/functional-library.mdx", 78) => "E310", // doc: "delightful"
        // `rest`/`cdr` of the empty list faults E310 — it does NOT return `()`.
        ("reference/core-functions.mdx", 50) => "E310", // doc: (list)
        // (recursion.mdx:87 was an EXCEPTION while the tail-factorial helper was bound
        //  with `let` — the self-call was unbound, E300. The doc now uses `letrec`
        //  (R7 doc fix), so the snippet RETURNS 120 and is a normal value golden below.)
        _ => return None,
    };
    Some(Actual::Err(code.to_string()))
}

#[derive(Default)]
struct Tally {
    pass: usize,
    exception: usize,
    skip: usize,
}

#[test]
fn family_a_evaluation_goldens() {
    let mut tally = Tally::default();
    let mut total_annos = 0usize;

    for &(rel, pinned) in A_FILES {
        let text = doc_text("en", rel);
        let assembled = assemble_program(&text);
        let prog = read_program(&assembled, rel).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let mut annos = scan_annos(&assembled);
        assert_eq!(
            annos.len(),
            pinned,
            "{rel}: extracted {} annotations, pinned {pinned} — corpus changed",
            annos.len()
        );
        total_annos += annos.len();

        // Interleave datum-runs and annotation-checks in line order (a positional
        // annotation reads the most recent run; a NamedVar re-reads the variable at
        // that point — so a later redefine cannot retro-actively change it).
        let mut datums: Vec<&Syntax> = prog.datums.iter().collect();
        datums.sort_by_key(|d| d.span.line);
        annos.sort_by_key(|a| a.line);

        let mut it = Interp::new();
        it.set_file(rel);
        let mut di = 0usize;
        let mut last: Option<Actual> = None;

        for anno in &annos {
            while di < datums.len() && datums[di].span.line <= anno.line {
                last = Some(eval_datum(&mut it, datums[di], rel));
                di += 1;
            }
            let actual = match &anno.kind {
                AnnoKind::Positional => last
                    .as_ref()
                    .map(clone_actual)
                    .expect("a positional annotation must follow a form"),
                AnnoKind::NamedVar(name) => eval_src(&mut it, name, rel),
            };

            if let Some(exp_actual) = exception_for(rel, anno.line) {
                assert_eq!(
                    actual, exp_actual,
                    "{rel}:{} EXCEPTION drifted (interp behaviour changed)",
                    anno.line
                );
                tally.exception += 1;
                continue;
            }

            match expect_from_text(&anno.expect_text) {
                Expect::Unsupported(_) => tally.skip += 1,
                Expect::Vals(want) => {
                    assert_pass(rel, anno.line, &want, &actual);
                    tally.pass += 1;
                }
                Expect::Err(code) => {
                    assert_eq!(
                        actual,
                        Actual::Err(code.clone()),
                        "{rel}:{} expected error {code}",
                        anno.line
                    );
                    tally.pass += 1;
                }
            }
        }
        // run any trailing datums for completeness (no-op for checks)
        while di < datums.len() {
            let _ = eval_datum(&mut it, datums[di], rel);
            di += 1;
        }
    }

    // Pinned corpus sizes (family A value-annotations).
    assert_eq!(total_annos, 122, "family-A annotation count changed");
    // R7: recursion.mdx:87 flipped EXCEPTION(E300)→PASS(120) when the doc's tail-factorial
    // helper was rebound from `let` to `letrec` (the self-call is now bound) — so PASS is
    // +1 (78→79) and EXCEPTION is -1 (5→4).
    assert_eq!(tally.pass, 117, "family-A PASS count changed");
    assert_eq!(tally.exception, 4, "family-A EXCEPTION count changed");
    assert_eq!(tally.skip, 1, "family-A SKIP count changed");
}

fn clone_actual(a: &Actual) -> Actual {
    match a {
        Actual::Vals(vs) => Actual::Vals(vs.clone()),
        Actual::Err(c) => Actual::Err(c.clone()),
    }
}

/// Dual comparison (§13): by value (`equal?` via `Value`'s structural `PartialEq`)
/// AND by canonical `write` string.
fn assert_pass(file: &str, line: usize, want: &[Value], actual: &Actual) {
    let Actual::Vals(got) = actual else {
        panic!("{file}:{line} expected values {want:?}, got {actual:?}");
    };
    assert_eq!(
        got, want,
        "{file}:{line} value mismatch: got {got:?}, want {want:?}"
    );
    assert_eq!(
        write_join(got),
        write_join(want),
        "{file}:{line} write-string mismatch"
    );
}

/// first-project.mdx is a build-on file with no per-form annotation; its documented
/// golden is a ```text``` "Expected output" block.  ⚠ That ```text``` block is NOT
/// verified here (it is non-runnable prose — the harness skips ```text``` fences); this
/// test instead pins the program's ACTUAL behaviour, which is an EXCEPTION: it faults
/// **E320** at `(map println report-lines)` (println yields zero values, and `map`'s
/// element-collection is a single-value context → §5), so the documented output is never
/// produced.  Doc fix: print without collecting return values (e.g. a recursive
/// `for-each`-style helper).  The name reflects the assertion (the E320 fault), not the
/// unverified text block.
#[test]
fn family_a_first_project_faults_e320_exception() {
    let rel = "guides/first-project.mdx";
    let text = doc_text("en", rel);
    let assembled = assemble_program(&text);
    let prog = read_program(&assembled, rel).unwrap_or_else(|e| panic!("read {rel}: {e}"));

    let mut it = Interp::new();
    it.set_file(rel);
    let mut first_err: Option<String> = None;
    for d in &prog.datums {
        if let Actual::Err(c) = eval_datum(&mut it, d, rel) {
            first_err = Some(c);
            break;
        }
    }
    assert_eq!(
        first_err.as_deref(),
        Some("E320"),
        "first-project EXCEPTION drifted: expected the program to fault E320"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (B) Diagnostic negatives
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    /// Must fail in the reader.
    Reader,
    /// Reads, but must fail in the normalizer.
    Normalize,
    /// Reads + normalizes, but faults at runtime.
    Runtime,
    /// Reads + normalizes + runs WITHOUT error, emitting a W3xx warning.
    Warning,
}

/// `(program, expected_code, phase)`.  The expected code is what the interpreter
/// ACTUALLY emits (authoritative); where a doc states a different code it is noted
/// in the R7 doc-fix list.
const B_NEGATIVES: &[(&str, &str, Phase)] = &[
    // ── static (must fire before evaluation) ──
    ("(let ((if 1)) if)", "E110", Phase::Normalize),
    ("(define-syntax swap (a))", "E120", Phase::Normalize),
    ("#;(this is a reader extension)", "E120", Phase::Reader),
    ("(cond)", "E130", Phase::Normalize),
    ("(and 1 . 2)", "E130", Phase::Normalize), // doc: "E100/E130"
    ("(a b . c d)", "E140", Phase::Reader),    // doc says E100 → actually E140
    ("(a .)", "E140", Phase::Reader),
    ("\"bad \\x; esc\"", "E150", Phase::Reader),
    ("(+ 1 2", "E100", Phase::Reader),   // unterminated list
    ("#x10", "E100", Phase::Reader),     // radix/exactness prefix banned (§2)
    ("#u8(256)", "E100", Phase::Reader), // bytevector element out of 0..=255
    // ── deprecation warning (runs, but warns) ──
    ("(% 10 3)", "W330", Phase::Warning),
    // ── runtime E3xx ──
    ("(car '())", "E310", Phase::Runtime),
    ("(/ 1 0)", "E313", Phase::Runtime),
    ("(foo)", "E300", Phase::Runtime),
    ("(5 1)", "E301", Phase::Runtime),
    ("(vector-ref (vector) 0)", "E311", Phase::Runtime),
    ("(+ 1 \"x\")", "E312", Phase::Runtime),
    ("(values (values 1 2) 3)", "E320", Phase::Runtime),
    // §8 runtime negatives the original corpus omitted (R7 coverage gap):
    ("(error \"x\")", "E330", Phase::Runtime), // user (error …) abort
    ("(letrec ((a b) (b 1)) a)", "E321", Phase::Runtime), // forward read of an
    // uninitialized letrec var (a's init reads the not-yet-assigned b).
    ("1e9999", "E314", Phase::Reader), // non-finite inexact literal (finite-Real, §2)
];

#[test]
fn family_b_diagnostic_negatives() {
    for &(src, code, phase) in B_NEGATIVES {
        let file = "<negative>";
        let read = read_program(src, file);
        match phase {
            Phase::Reader => {
                let e = read
                    .err()
                    .unwrap_or_else(|| panic!("`{src}` expected reader error {code}, but read OK"));
                assert_eq!(e.code.to_string(), code, "`{src}` reader code");
            }
            Phase::Normalize => {
                let prog =
                    read.unwrap_or_else(|e| panic!("`{src}` expected to READ, but failed: {e}"));
                let e = lispex::normalize_program(&prog.datums, file)
                    .err()
                    .unwrap_or_else(|| {
                        panic!("`{src}` expected normalize error {code}, but normalized OK")
                    });
                assert_eq!(e.code.to_string(), code, "`{src}` normalize code");
            }
            Phase::Runtime => {
                // must read + normalize cleanly, then fault at eval.
                let prog = read.unwrap_or_else(|e| panic!("`{src}` should READ: {e}"));
                lispex::normalize_program(&prog.datums, file)
                    .unwrap_or_else(|e| panic!("`{src}` should NORMALIZE: {e}"));
                let mut it = Interp::new();
                it.set_file(file);
                let actual = eval_src(&mut it, src, file);
                assert_eq!(
                    actual,
                    Actual::Err(code.to_string()),
                    "`{src}` runtime code"
                );
            }
            Phase::Warning => {
                let mut it = Interp::new();
                it.set_file(file);
                let actual = eval_src(&mut it, src, file);
                assert!(
                    matches!(actual, Actual::Vals(_)),
                    "`{src}` should RUN (warning, not error), got {actual:?}"
                );
                let warned = it.take_warnings();
                assert!(
                    warned.iter().any(|w| w.code.as_str() == code),
                    "`{src}` expected warning {code}, got {warned:?}"
                );
            }
        }
    }
    // R7: +3 negatives (E330 user-error, E321 uninitialized-letrec-read, E314 non-finite
    // literal) for §8 codes the original corpus omitted: 19 → 22.
    assert_eq!(B_NEGATIVES.len(), 22, "family-B negative count changed");
}

// ─────────────────────────────────────────────────────────────────────────────
// (C) R5RS-compat normalization pairs (tests the TRANSFORMER, not the runtime).
//
// ⚠ The R5RS-compat *toggle* is NOT implemented in the v1 interpreter:
// `normalize_program`/`normalize_one` take no compat flag and `WarnCode` has no
// W310/W320 (only the runtime W330/W331).  So the spec's "parse with compat OFF
// then ON, assert W310/W320 fire" cannot be exercised — that half is a documented
// GAP (see the R7 report).  These pairs assert the actual (compat-unaware)
// normalization of the §15.1 surface forms, which is the testable core of (C).
// C-EQV in particular pins the §0.1 sign-off: `case` desugars through the hidden
// `eqv?` intrinsic (NOT `equal?`).
// ─────────────────────────────────────────────────────────────────────────────

const C_PAIRS: &[(&str, &str)] = &[
    // when → if + (values)  [matches §15.2 / §12, modulo the begin-wrapper + quote]
    (
        "(when (> n 0) (display \"positive\"))",
        "(if (> n (quote 0)) (display (quote \"positive\")) (values))",
    ),
    // unless → if with the (values) in the then-branch
    (
        "(unless (> n 0) (display \"x\"))",
        "(if (> n (quote 0)) (values) (display (quote \"x\")))",
    ),
    // named let → hygienic letrec loop (§15.1; §15.2 illustrates a let+set! form)
    (
        "(define (sum xs) (let loop ((xs xs) (acc 0)) (if (null? xs) acc (loop (cdr xs) (+ acc (car xs))))))",
        "(define sum (lambda (xs) (letrec ((loop (lambda (xs acc) (if (null? xs) acc (loop (cdr xs) (+ acc (car xs))))))) (loop xs (quote 0)))))",
    ),
    // quasiquote → cons/append via HIDDEN intrinsics (hygiene; §10 / §15.2)
    (
        "`(a ,x ,@ys b)",
        "(#<intrinsic:cons> (quote a) (#<intrinsic:cons> x (#<intrinsic:append> ys (#<intrinsic:cons> (quote b) (quote ())))))",
    ),
    // call-with-values → unchanged core application (§15.1 == §15.2)
    (
        "(call-with-values (lambda () (values 3 1)) (lambda (q r) (vector q r)))",
        "(call-with-values (lambda () (values (quote 3) (quote 1))) (lambda (q r) (vector q r)))",
    ),
    // case → eqv? intrinsic (§0.1: NOT equal?) + fresh temp key binding (§7.1)
    (
        "(case key ((1 2) \"a\") (else \"b\"))",
        "(let ((#:t0 key)) (if (if (#<intrinsic:eqv?> #:t0 (quote 1)) (quote #t) (if (#<intrinsic:eqv?> #:t0 (quote 2)) (quote #t) (quote #f))) (quote \"a\") (quote \"b\")))",
    ),
    // do → fresh-named letrec loop (§6.8)
    (
        "(do ((i 0 (+ i 1))) ((= i 3) i))",
        "(letrec ((#:t0 (lambda (i) (if (= i (quote 3)) i (#:t0 (+ i (quote 1))))))) (#:t0 (quote 0)))",
    ),
    // #u8 stays a bytevector literal in the ONLY (compat-OFF) mode the interp has.
    // Compat-ON would rewrite to a vector + W310 — NOT IMPLEMENTED (documented gap).
    (
        "#u8(72 101 108 108 111)",
        "(quote #u8(72 101 108 108 111))",
    ),
];

#[test]
fn family_c_normalization_pairs() {
    for &(src, want) in C_PAIRS {
        let datum = read_one(src, "<compat>").unwrap_or_else(|e| panic!("read `{src}`: {e}"));
        let core =
            normalize_one(&datum, "<compat>").unwrap_or_else(|e| panic!("normalize `{src}`: {e}"));
        assert_eq!(core.sexpr(), want, "normalization of `{src}`");
    }
    assert_eq!(C_PAIRS.len(), 8, "family-C pair count changed");
}

/// Guard the documented (C) gap so it can't silently appear without the corpus
/// being updated: the compat toggle + W310/W320 are absent in v1.
#[test]
fn family_c_compat_toggle_is_unimplemented() {
    use lispex::WarnCode;
    // Only the runtime deprecation warnings exist; the compat W310/W320 do not.
    assert_eq!(WarnCode::W330.as_str(), "W330");
    assert_eq!(WarnCode::W331.as_str(), "W331");
    // `#u8` is preserved (no compat vector rewrite, no W310).
    let datum = read_one("#u8(1 2 3)", "<g>").unwrap();
    assert_eq!(
        normalize_one(&datum, "<g>").unwrap().sexpr(),
        "(quote #u8(1 2 3))"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Locale drift guard (en is canonical; ko/ru CODE must match modulo comments).
//
// Reality (a finding): the ko/ru fences are NOT byte-identical to en — translators
// localised in-code comments + the `;; Result:`/`;; ⇒` markers + alignment
// whitespace.  The EXECUTABLE code is invariant for 129/137 count-matching runnable
// fences; the remaining drift is REAL and PINNED below (translated string literals
// in getting-started, data-types/ko, and first-project, an en-only `(and 1 . 2)`
// example, a ko/ru-only `'apple` block, and an incomplete ru syntax page).  The
// guard asserts the observed drift set equals the pinned set, so neither new drift
// nor a future fix slips by unnoticed.
// ─────────────────────────────────────────────────────────────────────────────

/// (rel, lang) whose fence COUNT differs from en (structural drift).
const COUNT_DRIFT: &[(&str, &str)] = &[
    ("concepts/data-types.mdx", "ko"), // ko/ru add a `'apple` symbol example
    ("concepts/data-types.mdx", "ru"),
    ("concepts/syntax.mdx", "ru"), // ru page is missing 4 code blocks
];

/// (rel, lang, en_fence_count, other_fence_count) — the EXACT pinned fence counts for
/// every count-drifted file (P2 #4).  Asserting the precise counts means an edit that
/// adds/removes ANY fence in a count-drifted file (en or ko/ru) trips the guard, even
/// though the per-fence index alignment past the structural insertion is ambiguous.
const COUNT_DRIFT_EXPECT: &[(&str, &str, usize, usize)] = &[
    ("concepts/data-types.mdx", "ko", 9, 10), // ko inserts the `'apple` block (mid-doc)
    ("concepts/data-types.mdx", "ru", 9, 10), // ru likewise
    ("concepts/syntax.mdx", "ru", 11, 7),     // ru omits 4 blocks
];

/// (rel, lang, fence_index) of a runnable fence whose CODE differs from en.
const CODE_DRIFT: &[(&str, &str, usize)] = &[
    // en's diagnostics block has an extra `(and 1 . 2)` example ko/ru lack.
    ("concepts/error-handling.mdx", "ko", 2),
    ("concepts/error-handling.mdx", "ru", 2),
    // getting-started: ko localises the hello-world string in the CLI example.
    ("getting-started.mdx", "ko", 4),
    // first-project: string LITERALS (task names, "URGENT: ", headers) are translated.
    ("guides/first-project.mdx", "ko", 0),
    ("guides/first-project.mdx", "ko", 2),
    ("guides/first-project.mdx", "ko", 3),
    ("guides/first-project.mdx", "ru", 0),
    ("guides/first-project.mdx", "ru", 2),
    ("guides/first-project.mdx", "ru", 3),
];

/// Pinned count of index-aligned, code-IDENTICAL runnable fences found in the COMMON
/// PREFIX of the count-drifted files (P2 #4).  In a count-drifted file the extra/missing
/// fence is inserted MID-document, so index alignment only holds up to the first
/// structural divergence; we compare the aligned prefix (so those surviving fences stay
/// drift-checked) and stop at the first divergence.  ⚠ LIMITATION: runnable fences AFTER
/// the first structural divergence in a count-drifted file are NOT code-compared (their
/// index no longer maps to en) — the exact COUNT_DRIFT_EXPECT pin is the guard there.
/// data-types ko: indices 0..=2 align, then the string-literal block is localized → 3.
/// data-types ru: indices 0..=3 align, then the inserted `'apple` block is #4 → 4.
/// syntax ru: indices 0..=5 align (the omission begins at #6) → 6.
const COUNT_DRIFT_PREFIX_IDENTICAL: usize = 3 + 4 + 6;

#[test]
fn locale_code_drift_guard() {
    let mut seen_count: BTreeSet<(&str, &str)> = BTreeSet::new();
    let mut seen_code: BTreeSet<(&str, &str, usize)> = BTreeSet::new();
    let mut identical = 0usize;
    let mut prefix_identical = 0usize;

    for &rel in ALL_DOCS {
        let en = fences(&doc_text("en", rel));
        for lang in ["ko", "ru"] {
            let other = fences(&doc_text(lang, rel));
            if en.len() != other.len() {
                assert!(
                    COUNT_DRIFT.contains(&(rel, lang)),
                    "UNPINNED fence-count drift {rel} {lang}: en={} {lang}={}",
                    en.len(),
                    other.len()
                );
                // Pin the EXACT counts so any fence add/remove (either side) trips here.
                assert!(
                    COUNT_DRIFT_EXPECT.contains(&(rel, lang, en.len(), other.len())),
                    "fence COUNT changed for count-drifted {rel} {lang}: en={} {lang}={} \
                     — update COUNT_DRIFT_EXPECT",
                    en.len(),
                    other.len()
                );
                seen_count.insert((rel, lang));
                // Still drift-check the ALIGNED COMMON PREFIX: the mid-document
                // insertion/omission only breaks alignment from its point on, so every
                // runnable fence before the first divergence is genuinely comparable.
                for (idx, (ef, of)) in en.iter().zip(other.iter()).enumerate() {
                    // Catch a fence-lang drift regardless of runnability (P2 #6 spirit).
                    assert_eq!(ef.lang, of.lang, "{rel} {lang} #{idx} fence-lang drift");
                    if !is_runnable(&ef.lang) {
                        continue;
                    }
                    if strip_code(&ef.body) == strip_code(&of.body) {
                        prefix_identical += 1;
                    } else {
                        // First structural divergence: indices no longer align past here.
                        break;
                    }
                }
                continue;
            }
            assert!(
                !COUNT_DRIFT.contains(&(rel, lang)),
                "{rel} {lang} pinned as count-drift but counts now match — update the pin"
            );
            for (idx, (ef, of)) in en.iter().zip(other.iter()).enumerate() {
                // ★ P2 #6: assert fence-lang equality BEFORE the runnability gate, so a
                // fence-lang drift is caught even when one side is non-runnable.
                assert_eq!(ef.lang, of.lang, "{rel} {lang} #{idx} fence-lang drift");
                if !is_runnable(&ef.lang) {
                    continue;
                }
                let differs = strip_code(&ef.body) != strip_code(&of.body);
                let pinned = CODE_DRIFT.contains(&(rel, lang, idx));
                if differs {
                    assert!(
                        pinned,
                        "UNPINNED code drift {rel} {lang} #{idx}\n  en: {}\n  {lang}: {}",
                        strip_code(&ef.body),
                        strip_code(&of.body)
                    );
                    seen_code.insert((rel, lang, idx));
                } else {
                    assert!(
                        !pinned,
                        "{rel} {lang} #{idx} pinned as code-drift but is now identical — update the pin"
                    );
                    identical += 1;
                }
            }
        }
    }

    // Every pin must have actually been observed (so a doc fix is noticed).
    assert_eq!(
        seen_count.len(),
        COUNT_DRIFT.len(),
        "a pinned count-drift entry was not observed"
    );
    assert_eq!(
        seen_code.len(),
        CODE_DRIFT.len(),
        "a pinned code-drift entry was not observed"
    );
    // Pin the bulk of translation-invariant fences so the guard can't be neutered.
    // 164: current equal-count locale pairs have this many code-identical
    // runnable fences; getting-started.mdx has one localized CLI example.
    assert_eq!(
        identical, 164,
        "count of code-identical runnable fence comparisons changed"
    );
    // Pin the count-drifted files' aligned-prefix drift checks (P2 #4): surviving fences
    // before each structural divergence stay verified.
    assert_eq!(
        prefix_identical, COUNT_DRIFT_PREFIX_IDENTICAL,
        "count-drifted aligned-prefix identical-fence count changed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ★ §4 — Guaranteed proper TCO conformance family (doc-INDEPENDENT goldens).
//
// LISPEX-RUNTIME.md §4 ("TCO goldens (must exist): self, mutual, and through
// if/begin/and/or/cond/case/do/call-with-values"). Each loop below recurses in TAIL
// position THROUGH the named form and runs `DEPTH` (> CALL_DEPTH_LIMIT = 10_000) hops,
// so a missing-TCO regression would surface as a `recursion-limit` fault rather than the
// expected normal return. All run on the DEFAULT (small ~2 MiB) cargo-test stack with
// the DEFAULT bound — TCO means constant host stack AND zero logical depth, so neither
// the host stack nor the 10_000 bound is approached.
// ─────────────────────────────────────────────────────────────────────────────

/// Comfortably past CALL_DEPTH_LIMIT (10_000): a non-TCO version would fault long before.
const TCO_DEPTH: i128 = 50_000;

/// Run `src` (default bound + default small stack) and assert it RETURNS the integer
/// `want` — i.e. it looped via TCO instead of faulting `recursion-limit`. The failure
/// message calls out a recursion-limit specifically, since that is the missing-TCO tell.
fn assert_tco_int(label: &str, src: &str, want: i128) {
    use num_traits::ToPrimitive;
    let mut it = Interp::new();
    match it.run_str(src, "<tco>") {
        Ok(Outcome::One(Value::Int(i))) => assert_eq!(
            i.to_i128(),
            Some(want),
            "{label}: looped but produced the wrong value"
        ),
        Err(RunError::Runtime(e)) if e.code == RuntimeCode::RecursionLimit => panic!(
            "{label}: faulted `recursion-limit` — TCO is BROKEN through this form \
             (a tail recursion of {TCO_DEPTH} must not grow depth)"
        ),
        other => panic!("{label}: expected {want} via TCO, got {other:?}"),
    }
}

/// Same, but the loop returns a symbol sentinel (`done`) — assert its `write` rendering.
fn assert_tco_sym(label: &str, src: &str, want: &str) {
    let mut it = Interp::new();
    match it.run_str(src, "<tco>") {
        Ok(Outcome::One(v)) => assert_eq!(v.write_repr(), want, "{label}: wrong loop result"),
        Err(RunError::Runtime(e)) if e.code == RuntimeCode::RecursionLimit => {
            panic!("{label}: faulted `recursion-limit` — TCO is BROKEN through this form")
        }
        other => panic!("{label}: expected `{want}` via TCO, got {other:?}"),
    }
}

#[test]
fn tco_self_recursion_returns_not_recursion_limit() {
    // The recursive call is the whole `if`-branch tail: pure self-recursion.
    let src = format!(
        "(define (loop n acc) (if (= n 0) acc (loop (- n 1) (+ acc 1)))) (loop {TCO_DEPTH} 0)"
    );
    assert_tco_int("self", &src, TCO_DEPTH);
}

#[test]
fn tco_mutual_recursion_even_odd() {
    // even?/odd? mutual tail recursion: the one trampoline loop alternates the two
    // closures with no growth. `(ev? 50000)` is #t; map it to an int so the helper fits.
    let src = format!(
        "(letrec ((ev? (lambda (n) (if (= n 0) #t (od? (- n 1)))))
                  (od? (lambda (n) (if (= n 0) #f (ev? (- n 1))))))
           (if (ev? {TCO_DEPTH}) 1 0))"
    );
    assert_tco_int("mutual even?/odd?", &src, 1);
}

#[test]
fn tco_through_if() {
    // The tail call sits in an `if` then-branch (and the base case in the else-branch).
    let src =
        format!("(define (loop n) (if (= n 0) 0 (if #t (loop (- n 1)) 999))) (loop {TCO_DEPTH})");
    assert_tco_int("if", &src, 0);
}

#[test]
fn tco_through_begin() {
    // The recursive call is the LAST expr of a `begin` body → tail (§4).
    let src =
        format!("(define (loop n) (begin 1 (if (= n 0) 0 (loop (- n 1))))) (loop {TCO_DEPTH})");
    assert_tco_int("begin", &src, 0);
}

#[test]
fn tco_through_and() {
    // `and`'s LAST operand is in tail position (§4: rely on single-operand expansion).
    let src =
        format!("(define (loop n) (and #t (if (= n 0) 0 (loop (- n 1))))) (loop {TCO_DEPTH})");
    assert_tco_int("and", &src, 0);
}

#[test]
fn tco_through_or() {
    // `or`'s LAST operand is in tail position; the earlier `#f`s short-circuit through.
    let src = format!("(define (loop n) (or #f (if (= n 0) 0 (loop (- n 1))))) (loop {TCO_DEPTH})");
    assert_tco_int("or", &src, 0);
}

#[test]
fn tco_through_cond() {
    // Each `cond` clause's last expr is tail (via the if-expansion, §4).
    let src =
        format!("(define (loop n) (cond ((= n 0) 0) (else (loop (- n 1))))) (loop {TCO_DEPTH})");
    assert_tco_int("cond", &src, 0);
}

#[test]
fn tco_through_case() {
    // A `case` else-clause's last expr is tail; the key is the recursion variable.
    let src =
        format!("(define (loop n) (case n ((0) 'done) (else (loop (- n 1))))) (loop {TCO_DEPTH})");
    assert_tco_sym("case", &src, "done");
}

#[test]
fn tco_through_do() {
    // `do`'s recursive self-call (the step) and its result expr are tail (§4: do→letrec
    // loop). Count up to TCO_DEPTH and return the terminal index.
    let src = format!("(do ((i 0 (+ i 1))) ((= i {TCO_DEPTH}) i))");
    assert_tco_int("do", &src, TCO_DEPTH);
}

#[test]
fn tco_through_call_with_values() {
    // ★ The P0 fix: a self loop whose tail step is a `call-with-values` consumer call.
    // Without tail-transparency this faults `recursion-limit` at ~10k (the consumer ran
    // via a non-tail host apply). The producer hands the loop variables to the consumer
    // (the same `loop`), which is applied in the caller's tail slot.
    let src = format!(
        "(define (loop n acc)
           (if (= n 0)
               acc
               (call-with-values
                 (lambda () (values (- n 1) (+ acc 1)))
                 loop)))
         (loop {TCO_DEPTH} 0)"
    );
    assert_tco_int("call-with-values", &src, TCO_DEPTH);
}

#[test]
fn tco_through_apply() {
    // A self loop whose tail step is `(apply loop …)`: `apply` returns an `Eval::TailApply`
    // the trampoline resolves in the caller's tail slot, so the loop runs at constant host
    // depth. A non-tail apply would fault `recursion-limit` past CALL_DEPTH_LIMIT.
    let src = format!(
        "(define (loop n acc)
           (if (= n 0)
               acc
               (apply loop (list (- n 1) (+ acc 1)))))
         (loop {TCO_DEPTH} 0)"
    );
    assert_tco_int("apply", &src, TCO_DEPTH);
}

/// Build the symbol `Value` `name` (for §9 control-family expectations).
fn sym(name: &str) -> Value {
    read_one(name, "<sym>").expect("readable symbol").to_value()
}

// ─────────────────────────────────────────────────────────────────────────────
// ★ §9 — escape-only call/cc + dynamic-wind control family (doc-INDEPENDENT).
//
// Exercises the R6 control mechanisms through the harness's own driver (so the
// `Actual` Err/Vals arms are covered): a call/cc escape that returns to its owner,
// dynamic-wind's before→thunk→after ordering (incl. cleanup on escape), and the E340
// stale-continuation negative. `escape_outcome_maps_to_e340` separately pins the
// defensive `Eval::Escape → E340` mapping in `actual_of_eval`.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ctrl_call_cc_escape_returns_to_owner() {
    // `(k 'out)` unwinds to the owning `call/cc`, which returns `(values 'out)` → the
    // single value `out`; the post-escape `'fell-through` is never reached (§9).
    let mut it = Interp::new();
    let src = "(call/cc (lambda (k) (k 'out) 'fell-through))";
    let actual = eval_src(&mut it, src, "<ctrl>");
    match actual {
        Actual::Vals(vs) => assert_eq!(write_join(&vs), "out", "escape must return `out`"),
        other => panic!("expected the escaped value `out`, got {other:?}"),
    }
}

#[test]
fn ctrl_call_cc_escape_out_of_map_returns_value() {
    // The escape jumps out of the middle of a `map` traversal (a HOST apply path) and
    // returns its value to the owner — proof the escape threads through HOFs (§9).
    let mut it = Interp::new();
    let src = "(call/cc (lambda (k)
                 (map (lambda (x) (if (= x 3) (k 'found) x)) '(1 2 3 4 5))
                 'fell-through))";
    assert_eq!(
        eval_src(&mut it, src, "<ctrl>"),
        Actual::Vals(vec![sym("found")])
    );
}

#[test]
fn ctrl_dynamic_wind_after_thunk_ordering() {
    // before → thunk → after; the `after` runs LAST and exactly once on the normal path.
    let mut it = Interp::new();
    let src = "(dynamic-wind
                 (lambda () (display \"B\"))
                 (lambda () (display \"T\") 'r)
                 (lambda () (display \"A\")))";
    let actual = eval_src(&mut it, src, "<ctrl>");
    assert_eq!(
        actual,
        Actual::Vals(vec![sym("r")]),
        "result is the thunk value"
    );
    assert_eq!(
        it.take_output(),
        "BTA",
        "ordering must be before→thunk→after"
    );
}

#[test]
fn ctrl_dynamic_wind_after_runs_on_escape() {
    // An escape crossing the wind still runs `after` (cleanup), THEN the escape returns
    // to the owner; the post-escape thunk code ("X") never runs (§9 after-on-escape).
    let mut it = Interp::new();
    let src = "(call/cc (lambda (k)
                 (dynamic-wind
                   (lambda () (display \"B\"))
                   (lambda () (display \"T\") (k 'escaped) (display \"X\"))
                   (lambda () (display \"A\")))))";
    let actual = eval_src(&mut it, src, "<ctrl>");
    assert_eq!(actual, Actual::Vals(vec![sym("escaped")]));
    assert_eq!(
        it.take_output(),
        "BTA",
        "after runs on escape, X is skipped"
    );
}

#[test]
fn ctrl_stale_continuation_is_e340() {
    // A `k` captured, its `call/cc` returns, THEN `k` invoked → used outside its extent
    // → E340 (deterministic; multi-shot re-entry is v2). Each datum is a separate
    // top-level form (so `saved` survives but the tag does not).
    let mut it = Interp::new();
    assert_eq!(
        eval_src(&mut it, "(define saved #f)", "<ctrl>"),
        Actual::Vals(vec![]) // define → zero values
    );
    let _ = eval_src(&mut it, "(call/cc (lambda (k) (set! saved k)))", "<ctrl>");
    assert_eq!(
        eval_src(&mut it, "(saved 42)", "<ctrl>"),
        Actual::Err("E340".to_string()),
        "a stale continuation must fault E340"
    );
}

#[test]
fn escape_outcome_maps_to_e340() {
    // Directly pin the defensive `Eval::Escape → E340` arm of `actual_of_eval` (§9): a
    // live escape that somehow surfaced at top level is reported as out-of-extent (E340).
    // This is the only way to exercise that arm, since the interpreter always catches a
    // live escape at its owning `call/cc` frame and faults a STALE `(k …)` as
    // `Eval::Error(E340)` at the call site (covered by `ctrl_stale_continuation_is_e340`).
    let escaped = Eval::Escape {
        tag: 0,
        vals: Outcome::One(Value::Bool(true)),
    };
    assert_eq!(actual_of_eval(escaped), Actual::Err("E340".to_string()));
}
