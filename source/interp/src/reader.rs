//! Reader / lexer (LISPEX-RUNTIME.md §12 + LISPEX.md §1-§2).
//!
//! Parses UTF-8 source text into a sequence of top-level **spanned** datums:
//! the reader's output is a [`Syntax`] tree (see [`crate::syntax`]) in which
//! every node — atoms AND compound list/vector nodes, recursively — carries its
//! source [`Span`]. Round 1 stops at *surface syntax*: the reader does NOT
//! enforce reserved words (E110) or derived-form shape (E130) — those are the
//! normalizer's job (R2). It reports lexical/structural diagnostics (E100, E140,
//! E150, E314) plus the reader-level banned extensions (E120; see below).
//!
//! ## Design decisions where the SSOTs were ambiguous (see crate README/report):
//! - **Number vs symbol.** A token is parsed as a number iff it *begins*
//!   number-like — first char is a digit, OR first char is `-` followed by a
//!   digit (the pinned grammar in §2 allows a leading `-` only, NOT `+`). Such a
//!   token MUST fully match one of {integer, rational, real} or it is E100
//!   ("ambiguous/leading-zero tokens are E100", §2). So `007`, `1.`, `1/0`,
//!   `-5x`, `12abc` are all E100; `+5`, `-`, `->`, `...`, `.foo` are symbols
//!   (they don't begin number-like, and the symbol class in §2.1 admits them).
//! - **Char literals need a delimiter.** A single-char `#\X` is valid only when
//!   the next input is EOF or a delimiter, so `#\1` followed by `2` does NOT read
//!   as `#\1` then `2` — the token is `#\12`, which is not a valid char name, so
//!   it is E150. A non-alphanumeric start (`#\(`, `#\;`, `#\+`) is always a
//!   single char (it cannot begin a name or hex escape), so no continuation is
//!   consumed. An alphanumeric start may continue into a name (`#\space`) or hex
//!   escape (`#\x41`); if the continuation is neither, it is E150.
//! - **Char-literal errors → E150.** §12/the task pin surrogate/out-of-range hex
//!   to E150; we extend E150 to *all* malformed char literals (unknown name,
//!   bad/incomplete hex, undelimited continuation) since E150 is the char/string
//!   literal error code.
//! - **Unterminated string / unterminated list / unterminated block comment →
//!   E100** ("illegal token / paren error", §13). **Bad string escape → E150.**
//! - **Bytevector elements are LEXICAL integers** (§12 `<byte>`): each element is
//!   read as a raw integer-literal token and must be `0..=255`, so `#u8(4/2)` is
//!   rejected (a rational is not byte syntax even though it would normalize to an
//!   int). Element errors → E100 (§12 says only "static error"; none is pinned).
//! - **Banned reader extensions → E120.** The reader-level extensions `#;`
//!   (datum comment) and `#lang` are an immediate error E120 (LISPEX.md §4).
//!   Other unrecognized `#…` (incl. `#x10`/`#e1` radix & exactness prefixes,
//!   which §2 already pins) stays E100. Symbol-level banned forms (e.g.
//!   `define-syntax`) remain the R2 normalizer's job.
//! - **Source spans are PRESERVED.** Per-datum source spans (LISPEX.md §16) are
//!   carried in the `Syntax` output for later phases; the reader still aborts on
//!   the first error (deterministic, simple — error recovery is not needed yet).

use std::rc::Rc;

use crate::syntax::{Syntax, SyntaxKind};
use crate::value::{Interner, Value};

/// Diagnostic codes the reader AND the R2 normalizer can emit (LISPEX.md §13).
///
/// The reader (R1) emits E100/E120/E140/E150/E314; the normalizer (R2) adds
/// E110 (binding a reserved word), E120 (forbidden macro/reader-extension form),
/// and E130 (malformed derived form). The whole pipeline shares one `ErrCode` /
/// [`Diagnostic`] type so spans + the `CODE file:line:col message` rendering are
/// uniform across phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrCode {
    /// Paren/dotted-list/illegal-token errors.
    E100,
    /// (R2) Binding a §4 reserved word (`(let ((if 1)) …)`, bad formals, …).
    E110,
    /// Banned reader extension `#;` / `#lang` (reader); or (R2) a forbidden
    /// user-macro / library / multi-binding form (`define-syntax`, `let-values`,
    /// …) per LISPEX.md §4/§11.
    E120,
    /// (R2) Malformed derived form: empty `cond`, bad `case`/`cond` clause, bad
    /// `let` bindings, bad `lambda` formals, bare `unquote` outside quasiquote, …
    E130,
    /// Malformed dotted list (bad form after the dot).
    E140,
    /// Bad / out-of-range string or character escape / literal.
    E150,
    /// Inexact (real) literal is not finite, e.g. `1e9999` (§2 finite-`Real`).
    E314,
}

impl std::fmt::Display for ErrCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ErrCode::E100 => "E100",
            ErrCode::E110 => "E110",
            ErrCode::E120 => "E120",
            ErrCode::E130 => "E130",
            ErrCode::E140 => "E140",
            ErrCode::E150 => "E150",
            ErrCode::E314 => "E314",
        };
        f.write_str(s)
    }
}

/// A 1-based source position (LISPEX.md §13 `line:col`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub line: usize,
    pub col: usize,
}

/// A structured reader diagnostic. Renders as `CODE file:line:col message`
/// (LISPEX.md §13 message format).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: ErrCode,
    pub file: String,
    pub span: Span,
    pub message: String,
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}:{}:{} {}",
            self.code, self.file, self.span.line, self.span.col, self.message
        )
    }
}

/// Header pragmas recognized from `;! …` line comments (LISPEX.md §0.1).
/// Recorded only — Round 1 does not *act* on `compat: r5rs`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// e.g. `Some("1.2")` from `;! lispex 1.2`.
    pub version: Option<String>,
    /// `true` if `;! compat: r5rs` was seen.
    pub compat_r5rs: bool,
}

/// The reader's output: the top-level spanned datums plus header pragmas.
#[derive(Clone, Debug)]
pub struct Program {
    pub datums: Vec<Syntax>,
    pub header: Header,
}

/// Parse a whole source string into top-level datums. Aborts on the first error.
pub fn read_program(src: &str, file: &str) -> Result<Program, Diagnostic> {
    read_program_with_scored_mutations(src, file, true)
}

/// Parse canonical Core for structural verification without applying a source
/// mutation a second time. Mutation builds alter the original source read; the
/// receipt's normalized Core is already the result of that read.
#[cfg(feature = "scored-native-contract")]
pub(crate) fn read_program_without_scored_mutations(
    src: &str,
    file: &str,
) -> Result<Program, Diagnostic> {
    read_program_with_scored_mutations(src, file, false)
}

fn read_program_with_scored_mutations(
    src: &str,
    file: &str,
    apply_scored_mutations: bool,
) -> Result<Program, Diagnostic> {
    let mut r = Reader::new(src, file, apply_scored_mutations);
    let datums = r.read_all()?;
    Ok(Program {
        datums,
        header: r.header,
    })
}

/// Convenience: read exactly one datum from `src` (errors if zero or >1).
pub fn read_one(src: &str, file: &str) -> Result<Syntax, Diagnostic> {
    let prog = read_program(src, file)?;
    let mut it = prog.datums.into_iter();
    match (it.next(), it.next()) {
        (Some(v), None) => Ok(v),
        (None, _) => Err(Diagnostic {
            code: ErrCode::E100,
            file: file.to_string(),
            span: Span { line: 1, col: 1 },
            message: "expected exactly one datum, found none".to_string(),
        }),
        (Some(_), Some(_)) => Err(Diagnostic {
            code: ErrCode::E100,
            file: file.to_string(),
            span: Span { line: 1, col: 1 },
            message: "expected exactly one datum, found more".to_string(),
        }),
    }
}

struct Reader {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    col: usize,
    file: String,
    interner: Interner,
    header: Header,
    apply_scored_mutations: bool,
}

/// A character is a token delimiter if it ends the current atom. `#` is NOT a
/// delimiter (it may appear mid-symbol per §2.1) — it only starts special
/// syntax at the *start* of a token.
fn is_delimiter(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '(' | ')' | '[' | ']' | '{' | '}' | '"' | ';' | '\'' | '`' | ','
        )
}

/// A char-literal continuation stops at a normal delimiter or at `|` (the pipe
/// is also a delimiter for the purpose of terminating a `#\…` token, §12 list).
fn ends_char_literal(c: char) -> bool {
    is_delimiter(c) || c == '|'
}

fn is_hex_digit(c: char) -> bool {
    c.is_ascii_hexdigit()
}

impl Reader {
    fn new(src: &str, file: &str, apply_scored_mutations: bool) -> Self {
        Reader {
            chars: src.chars().collect(),
            pos: 0,
            line: 1,
            col: 1,
            file: file.to_string(),
            interner: Interner::new(),
            header: Header::default(),
            apply_scored_mutations,
        }
    }

    // ── low-level cursor ──────────────────────────────────────────────────────
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn peek2(&self) -> Option<char> {
        self.chars.get(self.pos + 1).copied()
    }
    fn at_end(&self) -> bool {
        self.pos >= self.chars.len()
    }
    fn span(&self) -> Span {
        Span {
            line: self.line,
            col: self.col,
        }
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied()?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }

    fn err(&self, code: ErrCode, span: Span, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            code,
            file: self.file.clone(),
            span,
            message: message.into(),
        }
    }

    // ── top level ─────────────────────────────────────────────────────────────
    fn read_all(&mut self) -> Result<Vec<Syntax>, Diagnostic> {
        let mut out = Vec::new();
        loop {
            self.skip_atmosphere()?;
            if self.at_end() {
                break;
            }
            out.push(self.read_datum()?);
        }
        Ok(out)
    }

    /// Skip whitespace, line comments (recording `;!` pragmas), and nestable
    /// `#| |#` block comments.
    fn skip_atmosphere(&mut self) -> Result<(), Diagnostic> {
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => {
                    self.bump();
                }
                Some(';') => self.read_line_comment(),
                Some('#') if self.peek2() == Some('|') => self.read_block_comment()?,
                _ => break,
            }
        }
        Ok(())
    }

    fn read_line_comment(&mut self) {
        // consume ';'
        self.bump();
        // A `;!` pragma? (LISPEX.md §0.1)
        let is_pragma = self.peek() == Some('!');
        let mut content = String::new();
        while let Some(c) = self.peek() {
            if c == '\n' {
                break;
            }
            content.push(c);
            self.bump();
        }
        if is_pragma {
            // content begins with '!'
            self.parse_pragma(content[1..].trim());
        }
    }

    fn parse_pragma(&mut self, body: &str) {
        // `lispex 1.1`  |  `compat: r5rs` / `compat:r5rs` / `compat r5rs`
        let mut parts = body.split_whitespace();
        let Some(first) = parts.next() else {
            return; // bare `;!` — nothing to record
        };
        if first == "lispex" {
            if let Some(ver) = parts.next() {
                self.header.version = Some(ver.to_string());
            }
        } else if first.starts_with("compat") && body.to_lowercase().contains("r5rs") {
            self.header.compat_r5rs = true;
        }
        // any other pragma: ignored in Round 1
    }

    fn read_block_comment(&mut self) -> Result<(), Diagnostic> {
        let start = self.span();
        // consume '#|'
        self.bump();
        self.bump();
        let mut depth = 1usize;
        while depth > 0 {
            match (self.peek(), self.peek2()) {
                (Some('#'), Some('|')) => {
                    self.bump();
                    self.bump();
                    depth += 1;
                }
                (Some('|'), Some('#')) => {
                    self.bump();
                    self.bump();
                    depth -= 1;
                }
                (Some(_), _) => {
                    self.bump();
                }
                (None, _) => {
                    return Err(self.err(
                        ErrCode::E100,
                        start,
                        "unterminated block comment (missing `|#`)",
                    ));
                }
            }
        }
        Ok(())
    }

    // ── datum dispatch ────────────────────────────────────────────────────────
    fn read_datum(&mut self) -> Result<Syntax, Diagnostic> {
        self.skip_atmosphere()?;
        let start = self.span();
        match self.peek() {
            None => Err(self.err(ErrCode::E100, start, "unexpected end of input")),
            Some('(') => self.read_list(),
            Some(')') => {
                self.bump();
                Err(self.err(ErrCode::E100, start, "unexpected `)`"))
            }
            Some('[') | Some(']') | Some('{') | Some('}') => {
                let c = self.peek().unwrap();
                self.bump();
                Err(self.err(
                    ErrCode::E100,
                    start,
                    format!("unsupported bracket `{c}` (Lispex uses `(` … `)` only)"),
                ))
            }
            Some('"') => self.read_string(),
            Some('#') => self.read_hash(),
            Some('\'') => self.read_quote("quote", start),
            Some('`') => self.read_quote("quasiquote", start),
            Some(',') => {
                if self.peek2() == Some('@') {
                    // consume ',@'
                    self.bump();
                    self.bump();
                    let inner = self.read_datum()?;
                    Ok(self.wrap("unquote-splicing", inner, start))
                } else {
                    self.bump(); // ','
                    let inner = self.read_datum()?;
                    Ok(self.wrap("unquote", inner, start))
                }
            }
            Some('.') if self.dot_is_token() => {
                self.bump();
                Err(self.err(ErrCode::E100, start, "unexpected `.` outside a dotted list"))
            }
            Some(_) => self.read_atom(),
        }
    }

    fn read_quote(&mut self, sym: &str, start: Span) -> Result<Syntax, Diagnostic> {
        self.bump(); // the quote char
        let inner = self.read_datum()?;
        Ok(self.wrap(sym, inner, start))
    }

    /// `(sym inner)` as a spanned 2-element list; both the injected symbol and the
    /// wrapping list take `span` (the position of the quote shorthand char).
    fn wrap(&mut self, sym: &str, inner: Syntax, span: Span) -> Syntax {
        let s = Syntax::new(SyntaxKind::Sym(self.interner.intern(sym)), span);
        Syntax::new(SyntaxKind::List(vec![s, inner]), span)
    }

    /// Is the `.` at the cursor a standalone dot token (the dotted-list marker),
    /// as opposed to the first char of a symbol like `...` or `.foo`?
    fn dot_is_token(&self) -> bool {
        debug_assert_eq!(self.peek(), Some('.'));
        match self.peek2() {
            None => true,
            Some(c) => is_delimiter(c),
        }
    }

    // ── lists & dotted lists ──────────────────────────────────────────────────
    fn read_list(&mut self) -> Result<Syntax, Diagnostic> {
        let open = self.span();
        self.bump(); // '('
        let mut items: Vec<Syntax> = Vec::new();
        loop {
            self.skip_atmosphere()?;
            match self.peek() {
                None => {
                    return Err(self.err(ErrCode::E100, open, "unterminated list (missing `)`)"));
                }
                Some(')') => {
                    self.bump();
                    return Ok(Syntax::new(SyntaxKind::List(items), open));
                }
                Some('.') if self.dot_is_token() => {
                    let dot = self.span();
                    self.bump(); // '.'
                    if items.is_empty() {
                        return Err(self.err(
                            ErrCode::E140,
                            dot,
                            "dotted list has no car before `.`",
                        ));
                    }
                    self.skip_atmosphere()?;
                    if matches!(self.peek(), None | Some(')')) {
                        return Err(self.err(
                            ErrCode::E140,
                            dot,
                            "dotted list has no cdr after `.`",
                        ));
                    }
                    let tail = self.read_datum()?;
                    self.skip_atmosphere()?;
                    match self.peek() {
                        Some(')') => {
                            self.bump();
                            return Ok(Syntax::new(
                                SyntaxKind::DottedList(items, Box::new(tail)),
                                open,
                            ));
                        }
                        _ => {
                            return Err(self.err(
                                ErrCode::E140,
                                dot,
                                "dotted list has more than one datum after `.`",
                            ));
                        }
                    }
                }
                _ => {
                    items.push(self.read_datum()?);
                }
            }
        }
    }

    // ── `#…` dispatch ─────────────────────────────────────────────────────────
    fn read_hash(&mut self) -> Result<Syntax, Diagnostic> {
        let start = self.span();
        // we know peek()=='#'
        match self.peek2() {
            Some('(') => {
                self.bump(); // '#'
                self.read_vector(start)
            }
            Some('\\') => {
                self.bump(); // '#'
                self.read_char(start)
            }
            Some('t') | Some('f') => self.read_boolean(start),
            Some('u') => self.read_bytevector(start),
            Some(';') => {
                // Banned reader extension: datum comment (LISPEX.md §4).
                self.bump(); // '#'
                self.bump(); // ';'
                Err(self.err(
                    ErrCode::E120,
                    start,
                    "datum comment `#;` is a banned reader extension (LISPEX §4)",
                ))
            }
            Some('l') => {
                // Possibly `#lang` — a banned reader extension (LISPEX.md §4).
                self.bump(); // '#'
                let tok = self.take_token();
                if tok == "lang" {
                    Err(self.err(
                        ErrCode::E120,
                        start,
                        "`#lang` is a banned reader extension (LISPEX §4)",
                    ))
                } else {
                    let shown: String = std::iter::once('#').chain(tok.chars()).collect();
                    Err(self.err(
                        ErrCode::E100,
                        start,
                        format!("unrecognized `#` syntax: `{shown}`"),
                    ))
                }
            }
            _ => {
                // Unrecognized `#…`. Consume the `#` plus any token chars so the
                // diagnostic span is sensible, then report E100. This covers
                // `#x10`/`#e1` (radix/exactness → E100 per §2).
                self.bump(); // '#'
                let tok = self.take_token();
                let shown: String = std::iter::once('#').chain(tok.chars()).collect();
                Err(self.err(
                    ErrCode::E100,
                    start,
                    format!("unrecognized `#` syntax: `{shown}`"),
                ))
            }
        }
    }

    fn read_boolean(&mut self, start: Span) -> Result<Syntax, Diagnostic> {
        self.bump(); // '#'
        let tok = self.take_token();
        match tok.as_str() {
            "t" | "true" => Ok(Syntax::new(SyntaxKind::Bool(true), start)),
            // SCORED-MUTATION-SITE M12: the shared reader decodes false as true.
            "f" | "false" if self.apply_scored_mutations && cfg!(scored_mutant = "M12") => {
                Ok(Syntax::new(SyntaxKind::Bool(true), start))
            }
            "f" | "false" => Ok(Syntax::new(SyntaxKind::Bool(false), start)),
            other => Err(self.err(
                ErrCode::E100,
                start,
                format!("invalid boolean literal `#{other}`"),
            )),
        }
    }

    fn read_vector(&mut self, start: Span) -> Result<Syntax, Diagnostic> {
        self.bump(); // '('
        let mut items: Vec<Syntax> = Vec::new();
        loop {
            self.skip_atmosphere()?;
            match self.peek() {
                None => {
                    return Err(self.err(
                        ErrCode::E100,
                        start,
                        "unterminated vector (missing `)`)",
                    ));
                }
                Some(')') => {
                    self.bump();
                    return Ok(Syntax::new(SyntaxKind::Vector(items), start));
                }
                Some('.') if self.dot_is_token() => {
                    let dot = self.span();
                    self.bump();
                    return Err(self.err(ErrCode::E100, dot, "`.` is not allowed in a vector"));
                }
                _ => items.push(self.read_datum()?),
            }
        }
    }

    fn read_bytevector(&mut self, start: Span) -> Result<Syntax, Diagnostic> {
        // Expect exactly `#u8(`.
        // peek()=='#', peek2()=='u'
        if !(self.chars.get(self.pos + 2) == Some(&'8')
            && self.chars.get(self.pos + 3) == Some(&'('))
        {
            // not a bytevector — report the offending `#u…` token
            self.bump(); // '#'
            let tok = self.take_token();
            let shown: String = std::iter::once('#').chain(tok.chars()).collect();
            return Err(self.err(
                ErrCode::E100,
                start,
                format!("expected `#u8(` bytevector, found `{shown}`"),
            ));
        }
        // consume `#u8(`
        self.bump();
        self.bump();
        self.bump();
        self.bump();
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            self.skip_atmosphere()?;
            let el = self.span();
            match self.peek() {
                None => {
                    return Err(self.err(
                        ErrCode::E100,
                        start,
                        "unterminated bytevector (missing `)`)",
                    ));
                }
                Some(')') => {
                    self.bump();
                    return Ok(Syntax::new(SyntaxKind::Bytevector(bytes), start));
                }
                _ => {
                    // §12: a bytevector element is a LEXICAL integer literal
                    // `<byte>`, NOT an arbitrary datum. Read the raw token and
                    // require it be an integer literal in 0..=255. This rejects
                    // `#u8(4/2)` — a rational that would *normalize* to int 2 is
                    // not byte syntax — and `1.5`, symbols, etc.
                    let tok = self.take_token();
                    if !is_integer_lit(&tok) {
                        return Err(self.err(
                            ErrCode::E100,
                            el,
                            format!(
                                "bytevector element must be an integer literal 0..=255, found `{tok}`"
                            ),
                        ));
                    }
                    let n: num_bigint::BigInt = tok.parse().expect("validated integer literal");
                    use num_traits::ToPrimitive;
                    match n.to_u8() {
                        Some(b) => bytes.push(b),
                        None => {
                            return Err(self.err(
                                ErrCode::E100,
                                el,
                                format!("bytevector element out of range 0..=255: `{tok}`"),
                            ));
                        }
                    }
                }
            }
        }
    }

    // ── characters ────────────────────────────────────────────────────────────
    fn read_char(&mut self, start: Span) -> Result<Syntax, Diagnostic> {
        // cursor at '\' (peek()=='\'); '#' already consumed
        self.bump(); // '\'
        let first = match self.bump() {
            Some(c) => c,
            None => {
                return Err(self.err(ErrCode::E150, start, "incomplete character literal `#\\`"));
            }
        };
        // A non-alphanumeric start (`#\(`, `#\;`, `#\+`, `#\ `, …) cannot begin a
        // character name or hex escape, so it is always a single literal char and
        // we never greedily consume what follows.
        if !first.is_alphanumeric() {
            return Ok(Syntax::new(SyntaxKind::Char(first), start));
        }
        // Alphanumeric start: collect the continuation (rest of the token).
        let mut tail = String::new();
        while let Some(c) = self.peek() {
            if ends_char_literal(c) {
                break;
            }
            tail.push(c);
            self.bump();
        }
        if tail.is_empty() {
            // Single alnum char followed by EOF or a delimiter: `#\a`, `#\1`, `#\x`.
            return Ok(Syntax::new(SyntaxKind::Char(first), start));
        }
        // There IS a continuation → it must be a named char or a hex escape.
        let name: String = std::iter::once(first).chain(tail.chars()).collect();
        // hex escape `#\xHH…`
        if first == 'x' || first == 'X' {
            let rest = &name[1..];
            if !rest.is_empty() && rest.chars().all(is_hex_digit) {
                let c = self.scalar_from_hex(rest, start)?;
                return Ok(Syntax::new(SyntaxKind::Char(c), start));
            }
        }
        // named characters (R7RS names + a couple of common aliases)
        let c = match name.as_str() {
            "space" => ' ',
            "newline" | "linefeed" => '\n',
            "tab" => '\t',
            "return" => '\r',
            "null" | "nul" => '\0',
            "delete" | "rubout" => '\u{7f}',
            "escape" | "esc" => '\u{1b}',
            "backspace" => '\u{8}',
            "alarm" => '\u{7}',
            "page" => '\u{c}',
            other => {
                return Err(self.err(
                    ErrCode::E150,
                    start,
                    format!("unknown character name `#\\{other}`"),
                ));
            }
        };
        Ok(Syntax::new(SyntaxKind::Char(c), start))
    }

    fn scalar_from_hex(&self, hex: &str, start: Span) -> Result<char, Diagnostic> {
        match u32::from_str_radix(hex, 16) {
            Ok(n) => match char::from_u32(n) {
                Some(c) => Ok(c),
                None => Err(self.err(
                    ErrCode::E150,
                    start,
                    format!("character scalar out of range or a surrogate: U+{n:04X}"),
                )),
            },
            Err(_) => Err(self.err(
                ErrCode::E150,
                start,
                format!("character scalar value too large: #\\x{hex}"),
            )),
        }
    }

    // ── strings ───────────────────────────────────────────────────────────────
    fn read_string(&mut self) -> Result<Syntax, Diagnostic> {
        let start = self.span();
        self.bump(); // opening '"'
        let mut s = String::new();
        loop {
            match self.bump() {
                None => {
                    return Err(self.err(
                        ErrCode::E100,
                        start,
                        "unterminated string (missing closing `\"`)",
                    ));
                }
                Some('"') => {
                    return Ok(Syntax::new(SyntaxKind::Str(Rc::from(s.as_str())), start));
                }
                Some('\\') => {
                    let esc = self.span();
                    match self.bump() {
                        None => {
                            return Err(self.err(
                                ErrCode::E100,
                                start,
                                "unterminated string after `\\`",
                            ));
                        }
                        Some('"') => s.push('"'),
                        Some('\\') => s.push('\\'),
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('r') => s.push('\r'),
                        Some('x') | Some('X') => {
                            // `\xHH…;` — variable-length hex Unicode scalar, ';'-terminated
                            let mut hex = String::new();
                            loop {
                                match self.peek() {
                                    Some(';') => {
                                        self.bump();
                                        break;
                                    }
                                    Some(c) if is_hex_digit(c) => {
                                        hex.push(c);
                                        self.bump();
                                    }
                                    _ => {
                                        return Err(self.err(
                                            ErrCode::E150,
                                            esc,
                                            "malformed `\\x…;` escape (expected hex digits then `;`)",
                                        ));
                                    }
                                }
                            }
                            if hex.is_empty() {
                                return Err(self.err(
                                    ErrCode::E150,
                                    esc,
                                    "empty `\\x;` escape (no hex digits)",
                                ));
                            }
                            let c = self.scalar_from_hex(&hex, esc)?;
                            s.push(c);
                        }
                        Some(other) => {
                            return Err(self.err(
                                ErrCode::E150,
                                esc,
                                format!("invalid string escape `\\{other}`"),
                            ));
                        }
                    }
                }
                Some(c) => s.push(c),
            }
        }
    }

    // ── atoms: numbers & symbols ──────────────────────────────────────────────
    /// Read a maximal run of non-delimiter chars (the current token text).
    fn take_token(&mut self) -> String {
        let mut t = String::new();
        while let Some(c) = self.peek() {
            if is_delimiter(c) {
                break;
            }
            t.push(c);
            self.bump();
        }
        t
    }

    fn read_atom(&mut self) -> Result<Syntax, Diagnostic> {
        let start = self.span();
        let tok = self.take_token();
        debug_assert!(!tok.is_empty());

        // A lone `.` reaching here is a stray dot (outside any list).
        if tok == "." {
            return Err(self.err(ErrCode::E100, start, "unexpected `.`"));
        }

        let value = if begins_number_like(&tok) {
            self.classify_number(&tok, start)?
        } else {
            // Otherwise: a symbol (case-sensitive, interned).
            self.interner.sym(&tok)
        };
        Ok(Syntax::new(leaf_kind(value), start))
    }

    fn classify_number(&mut self, tok: &str, start: Span) -> Result<Value, Diagnostic> {
        if is_integer_lit(tok) {
            let n: num_bigint::BigInt = tok.parse().expect("validated integer literal");
            return Ok(Value::Int(n));
        }
        if let Some((num, den)) = parse_rational_parts(tok) {
            return Ok(Value::ratio(num, den));
        }
        if is_real_lit(tok) {
            let f: f64 = tok.parse().expect("validated real literal");
            return match Value::real(f) {
                Some(v) => Ok(v),
                None => Err(self.err(
                    ErrCode::E314,
                    start,
                    format!("inexact (real) literal is not finite: `{tok}`"),
                )),
            };
        }
        // Began number-like but matched no numeric production → ambiguous/illegal.
        Err(self.err(
            ErrCode::E100,
            start,
            format!("malformed numeric literal: `{tok}`"),
        ))
    }
}

/// Map a reader-produced atom [`Value`] to its [`SyntaxKind`]. Only ever called
/// with the leaves [`read_atom`](Reader::read_atom) yields (Int/Rational/Real
/// from [`classify_number`](Reader::classify_number), or an interned Sym).
fn leaf_kind(v: Value) -> SyntaxKind {
    match v {
        Value::Int(i) => SyntaxKind::Int(i),
        Value::Rational(r) => SyntaxKind::Rational(r),
        Value::Real(f) => SyntaxKind::Real(f),
        Value::Sym(s) => SyntaxKind::Sym(s),
        other => unreachable!("read_atom yields only Int/Rational/Real/Sym, got {other:?}"),
    }
}

// ── numeric-token classification (hand-written; no regex dep) ─────────────────

/// Does the token *begin* as a number attempt? First char a digit, or `-` then a
/// digit. (The §2 grammar permits a leading `-` only — never `+`.)
fn begins_number_like(tok: &str) -> bool {
    let mut it = tok.chars();
    match it.next() {
        Some(c) if c.is_ascii_digit() => true,
        Some('-') => matches!(it.next(), Some(c) if c.is_ascii_digit()),
        _ => false,
    }
}

/// `-?(0|[1-9][0-9]*)` — full match.
fn is_integer_lit(tok: &str) -> bool {
    let body = tok.strip_prefix('-').unwrap_or(tok);
    is_unsigned_int(body)
}

/// `0 | [1-9][0-9]*` — no leading zeros (except the single `0`).
fn is_unsigned_int(s: &str) -> bool {
    let bytes = s.as_bytes();
    match bytes {
        [] => false,
        [b'0'] => true,
        [first, ..] if (b'1'..=b'9').contains(first) => s.bytes().all(|b| b.is_ascii_digit()),
        _ => false,
    }
}

/// Parse `<int>/[1-9][0-9]*` into (numerator, denominator) if it matches.
fn parse_rational_parts(tok: &str) -> Option<(num_bigint::BigInt, num_bigint::BigInt)> {
    let (n, d) = tok.split_once('/')?;
    if n.contains('/') || d.contains('/') {
        return None; // more than one '/'
    }
    if !is_integer_lit(n) {
        return None;
    }
    // denominator: [1-9][0-9]*  (>= 1, no sign, no leading zero, non-zero)
    let dbytes = d.as_bytes();
    let den_ok = matches!(dbytes, [first, ..] if (b'1'..=b'9').contains(first))
        && d.bytes().all(|b| b.is_ascii_digit());
    if !den_ok {
        return None;
    }
    let num: num_bigint::BigInt = n.parse().ok()?;
    let den: num_bigint::BigInt = d.parse().ok()?;
    Some((num, den))
}

/// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?` with **at least one** of
/// fraction or exponent present (else it's an integer, not a real).
fn is_real_lit(tok: &str) -> bool {
    let body = tok.strip_prefix('-').unwrap_or(tok);

    // Split off the exponent, if any.
    let (mantissa, has_exp) = match body.split_once(['e', 'E']) {
        Some((m, exp)) => {
            if !is_exponent(exp) {
                return false;
            }
            (m, true)
        }
        None => (body, false),
    };

    // Mantissa: integer part is `0 | [1-9][0-9]*`; optional `.` then 1+ digits.
    let has_frac = match mantissa.split_once('.') {
        Some((int_part, frac)) => {
            if !is_unsigned_int(int_part) {
                return false;
            }
            if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            true
        }
        None => {
            if !is_unsigned_int(mantissa) {
                return false;
            }
            false
        }
    };

    has_frac || has_exp
}

/// `[-+]?[0-9]+`
fn is_exponent(s: &str) -> bool {
    let digits = s.strip_prefix(['-', '+']).unwrap_or(s);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// The outcome of parsing a string as a §2 numeric token — the engine behind the
/// `string->number` primitive (LISPEX-RUNTIME.md §2/§10). Reuses the SAME hand-written
/// grammar the reader applies to source literals, so `string->number` and the reader
/// agree exactly (decimal only; integer / `p/q` rational / positional or exponent
/// real; no radix/exactness prefixes).
#[derive(Clone, Debug, PartialEq)]
pub enum NumberParse {
    /// A valid numeric token → this value.
    Number(Value),
    /// Matched the real production but the value is **non-finite** (e.g. `"1e9999"`).
    /// `string->number` must raise E314 here, NOT return `#f` (§2: every f64 producer
    /// is finite-checked).
    NotFinite,
    /// Did not match any numeric production → `string->number` yields `#f`.
    NotANumber,
}

/// Parse `tok` as a §2 numeric token for `string->number`. Pure (no `Reader`/`Span`
/// state) so the evaluator can call it directly.
pub fn parse_number_token(tok: &str) -> NumberParse {
    if !begins_number_like(tok) {
        return NumberParse::NotANumber;
    }
    if is_integer_lit(tok) {
        let n: num_bigint::BigInt = tok.parse().expect("validated integer literal");
        return NumberParse::Number(Value::Int(n));
    }
    if let Some((num, den)) = parse_rational_parts(tok) {
        return NumberParse::Number(Value::ratio(num, den));
    }
    if is_real_lit(tok) {
        let f: f64 = tok.parse().expect("validated real literal");
        return match Value::real(f) {
            Some(v) => NumberParse::Number(v),
            None => NumberParse::NotFinite,
        };
    }
    NumberParse::NotANumber
}
