//! Two-layer `csk.checked-profile/v1` source checking.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::canonical::{canonical_program_bytes, CANONICAL_FORMAT_TAG};
use crate::core::{Binding, CoreExpr, CoreKind, Formals, Ident};
use crate::reader::{read_one, read_program, read_program_without_scored_mutations, Span};
use crate::syntax::{Syntax, SyntaxKind};
use crate::value::Value;

pub const CHECKED_PROFILE_TAG: &str = "csk.checked-profile/v1";
pub const MAX_SOURCE_BYTES: usize = 1_048_576;

pub const COVERED_PRIMITIVES: &[&str] = &[
    "+",
    "-",
    "*",
    "/",
    "=",
    "<",
    "<=",
    ">",
    ">=",
    "cons",
    "car",
    "cdr",
    "null?",
    "pair?",
    "list",
    "exact-integer?",
    "decision-approve",
    "decision-deny",
    "decision-review",
    "decision-invalid-input",
];

const UNCOVERED_HEADS: &[&str] = &[
    "set!",
    "letrec",
    "let*",
    "quote",
    "quasiquote",
    "unquote",
    "unquote-splicing",
    "values",
    "call-with-values",
    "call/cc",
    "dynamic-wind",
    "guard",
    "case",
    "when",
    "unless",
    "do",
    "module",
    "export",
    "import",
    "define-syntax",
    "syntax-rules",
    "define-library",
    "vector",
    "make-vector",
    "vector-set!",
    "bytevector",
    "make-bytevector",
    "display",
    "write",
    "newline",
    "println",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileErrorCode {
    ResourceLimit,
    NativeLoweringFailed,
    ProfileEscape,
}

impl ProfileErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResourceLimit => "artifact-resource-limit",
            Self::NativeLoweringFailed => "native-lowering-failed",
            Self::ProfileEscape => "profile-escape",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileError {
    pub code: ProfileErrorCode,
    pub span: Span,
    pub message: String,
}

impl ProfileError {
    fn new(code: ProfileErrorCode, span: Span, message: impl Into<String>) -> Self {
        Self {
            code,
            span,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CheckedProgram {
    core: Vec<CoreExpr>,
    normalized_bytes: Vec<u8>,
}

pub(super) struct ParsedCheckedSource {
    datums: Vec<Syntax>,
}

impl CheckedProgram {
    pub fn core(&self) -> &[CoreExpr] {
        &self.core
    }

    pub fn normalized_bytes(&self) -> &[u8] {
        &self.normalized_bytes
    }
}

pub fn prepare_checked_program(source: &[u8]) -> Result<CheckedProgram, ProfileError> {
    prepare_parsed_checked_source(parse_checked_source(source)?)
}

pub(super) fn parse_checked_source(source: &[u8]) -> Result<ParsedCheckedSource, ProfileError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(ProfileError::new(
            ProfileErrorCode::ResourceLimit,
            Span { line: 1, col: 1 },
            "source byte limit exceeded",
        ));
    }
    let source = std::str::from_utf8(source).map_err(|_| {
        ProfileError::new(
            ProfileErrorCode::NativeLoweringFailed,
            Span { line: 1, col: 1 },
            "source is not UTF-8",
        )
    })?;
    let program = read_program(source, "<checked-profile>").map_err(|error| {
        ProfileError::new(
            ProfileErrorCode::NativeLoweringFailed,
            error.span,
            error.message,
        )
    })?;
    Ok(ParsedCheckedSource {
        datums: program.datums,
    })
}

pub(super) fn prepare_parsed_checked_source(
    parsed: ParsedCheckedSource,
) -> Result<CheckedProgram, ProfileError> {
    classify_surface(&parsed.datums)?;
    let mut lowerer = Lowerer::default();
    let core = parsed
        .datums
        .iter()
        .map(|form| lowerer.lower(form))
        .collect::<Result<Vec<_>, _>>()?;
    validate_core(&core)?;
    let normalized_bytes = canonical_program_bytes(&core).map_err(|error| {
        ProfileError::new(
            ProfileErrorCode::ProfileEscape,
            Span { line: 1, col: 1 },
            error.to_string(),
        )
    })?;
    Ok(CheckedProgram {
        core,
        normalized_bytes,
    })
}

/// Parse the exact Canonical Core bytes carried by a differential receipt.
///
/// Canonical Core deliberately prints hygienic identifiers as `#:tN`, a token
/// the public reader cannot produce. Structural verification therefore uses a
/// dedicated inverse for the checked-profile Core subset and requires an exact
/// serialize-after-parse round trip before accepting the result.
pub fn parse_checked_normalized_program(normalized: &[u8]) -> Result<CheckedProgram, ProfileError> {
    if normalized.len() > MAX_SOURCE_BYTES {
        return Err(ProfileError::new(
            ProfileErrorCode::ResourceLimit,
            Span { line: 1, col: 1 },
            "normalized program byte limit exceeded",
        ));
    }
    let text = std::str::from_utf8(normalized).map_err(|_| {
        ProfileError::new(
            ProfileErrorCode::ProfileEscape,
            Span { line: 1, col: 1 },
            "normalized program is not UTF-8",
        )
    })?;
    let prefix = format!("{CANONICAL_FORMAT_TAG}\n");
    let body = text.strip_prefix(&prefix).ok_or_else(|| {
        ProfileError::new(
            ProfileErrorCode::ProfileEscape,
            Span { line: 1, col: 1 },
            "normalized program tag mismatch",
        )
    })?;
    if body.is_empty() || !body.ends_with('\n') {
        return Err(ProfileError::new(
            ProfileErrorCode::ProfileEscape,
            Span { line: 1, col: 1 },
            "normalized program framing is invalid",
        ));
    }

    let (readable, temp_names) = make_normalized_core_readable(body)?;
    let program = read_program_without_scored_mutations(&readable, "<checked-normalized>")
        .map_err(|error| {
            ProfileError::new(ProfileErrorCode::ProfileEscape, error.span, error.message)
        })?;
    let parser = NormalizedCoreParser { temp_names };
    let core = program
        .datums
        .iter()
        .map(|form| parser.parse(form))
        .collect::<Result<Vec<_>, _>>()?;
    validate_core(&core)?;
    let reproduced = canonical_program_bytes(&core).map_err(|error| {
        ProfileError::new(
            ProfileErrorCode::ProfileEscape,
            Span { line: 1, col: 1 },
            error.to_string(),
        )
    })?;
    if reproduced != normalized {
        return Err(ProfileError::new(
            ProfileErrorCode::ProfileEscape,
            Span { line: 1, col: 1 },
            "normalized program is not canonical checked Core",
        ));
    }
    Ok(CheckedProgram {
        core,
        normalized_bytes: normalized.to_vec(),
    })
}

fn make_normalized_core_readable(
    body: &str,
) -> Result<(String, HashMap<String, u32>), ProfileError> {
    let mut salt = 0u32;
    let prefix = loop {
        let candidate = format!("cskverifytemp{salt}x");
        if !body.contains(&candidate) {
            break candidate;
        }
        salt = salt.checked_add(1).ok_or_else(|| {
            ProfileError::new(
                ProfileErrorCode::ResourceLimit,
                Span { line: 1, col: 1 },
                "temporary identifier namespace exhausted",
            )
        })?;
    };

    let bytes = body.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut names = HashMap::new();
    let mut index = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            output.push(byte);
            index += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        if byte == b'"' {
            in_string = true;
            output.push(byte);
            index += 1;
            continue;
        }
        let token_start = index == 0 || is_core_delimiter(bytes[index - 1]);
        if token_start && bytes[index..].starts_with(b"#:t") {
            let digit_start = index + 3;
            let mut end = digit_start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end == digit_start || (end < bytes.len() && !is_core_delimiter(bytes[end])) {
                return Err(ProfileError::new(
                    ProfileErrorCode::ProfileEscape,
                    Span { line: 1, col: 1 },
                    "malformed normalized temporary identifier",
                ));
            }
            let digits = std::str::from_utf8(&bytes[digit_start..end]).expect("ASCII digits");
            let number = digits.parse::<u32>().map_err(|_| {
                ProfileError::new(
                    ProfileErrorCode::ResourceLimit,
                    Span { line: 1, col: 1 },
                    "normalized temporary identifier is out of range",
                )
            })?;
            if number.to_string() != digits {
                return Err(ProfileError::new(
                    ProfileErrorCode::ProfileEscape,
                    Span { line: 1, col: 1 },
                    "normalized temporary identifier is not canonical",
                ));
            }
            let placeholder = format!("{prefix}{number}");
            names.insert(placeholder.clone(), number);
            output.extend_from_slice(placeholder.as_bytes());
            index = end;
            continue;
        }
        output.push(byte);
        index += 1;
    }
    let readable = String::from_utf8(output).expect("input was UTF-8 and replacements are ASCII");
    Ok((readable, names))
}

fn is_core_delimiter(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'(' | b')')
}

struct NormalizedCoreParser {
    temp_names: HashMap<String, u32>,
}

impl NormalizedCoreParser {
    fn parse(&self, syntax: &Syntax) -> Result<CoreExpr, ProfileError> {
        let SyntaxKind::List(items) = &syntax.node else {
            return match &syntax.node {
                SyntaxKind::Sym(_) => Ok(CoreExpr::new(
                    CoreKind::Var(self.ident(syntax)?),
                    syntax.span,
                )),
                _ => escape(syntax.span, "bare value is not canonical checked Core"),
            };
        };
        if items.is_empty() {
            return escape(
                syntax.span,
                "empty application is not canonical checked Core",
            );
        }
        let kind = match symbol_name(&items[0]) {
            Some("quote") if items.len() == 2 => CoreKind::Quote(items[1].to_value()),
            Some("if") if items.len() == 4 => CoreKind::If(
                Box::new(self.parse(&items[1])?),
                Box::new(self.parse(&items[2])?),
                Box::new(self.parse(&items[3])?),
            ),
            Some("lambda") if items.len() == 3 => CoreKind::Lambda {
                formals: Formals {
                    fixed: self.ident_list(&items[1])?,
                    rest: None,
                },
                body: Box::new(self.parse(&items[2])?),
            },
            Some("begin") if items.len() >= 2 => CoreKind::Begin(
                items[1..]
                    .iter()
                    .map(|item| self.parse(item))
                    .collect::<Result<_, _>>()?,
            ),
            Some("define") if items.len() == 3 => CoreKind::Define {
                name: self.ident(&items[1])?,
                value: Box::new(self.parse(&items[2])?),
            },
            Some("let") if items.len() == 3 => {
                let raw_bindings = match &items[1].node {
                    SyntaxKind::Nil => &[][..],
                    SyntaxKind::List(bindings) => bindings.as_slice(),
                    _ => return escape(items[1].span, "normalized let bindings are malformed"),
                };
                let mut bindings = Vec::with_capacity(raw_bindings.len());
                for binding in raw_bindings {
                    let SyntaxKind::List(pair) = &binding.node else {
                        return escape(binding.span, "normalized let binding is malformed");
                    };
                    if pair.len() != 2 {
                        return escape(binding.span, "normalized let binding is malformed");
                    }
                    bindings.push(Binding {
                        name: self.ident(&pair[0])?,
                        init: self.parse(&pair[1])?,
                    });
                }
                CoreKind::Let {
                    bindings,
                    body: Box::new(self.parse(&items[2])?),
                }
            }
            Some("quote" | "if" | "lambda" | "begin" | "define" | "let") => {
                return escape(syntax.span, "normalized Core form has the wrong shape")
            }
            _ => CoreKind::App {
                op: Box::new(self.parse(&items[0])?),
                args: items[1..]
                    .iter()
                    .map(|item| self.parse(item))
                    .collect::<Result<_, _>>()?,
            },
        };
        Ok(CoreExpr::new(kind, syntax.span))
    }

    fn ident(&self, syntax: &Syntax) -> Result<Ident, ProfileError> {
        let SyntaxKind::Sym(name) = &syntax.node else {
            return escape(syntax.span, "normalized Core identifier is not a symbol");
        };
        Ok(self
            .temp_names
            .get(name.as_ref())
            .copied()
            .map(Ident::Temp)
            .unwrap_or_else(|| Ident::User(name.clone())))
    }

    fn ident_list(&self, syntax: &Syntax) -> Result<Vec<Ident>, ProfileError> {
        match &syntax.node {
            SyntaxKind::Nil => Ok(Vec::new()),
            SyntaxKind::List(items) => items.iter().map(|item| self.ident(item)).collect(),
            _ => escape(syntax.span, "normalized lambda formals are not fixed arity"),
        }
    }
}

pub fn classify_surface(forms: &[Syntax]) -> Result<(), ProfileError> {
    for form in forms {
        classify_expr(form)?;
    }
    Ok(())
}

fn classify_expr(form: &Syntax) -> Result<(), ProfileError> {
    match &form.node {
        SyntaxKind::Bool(_)
        | SyntaxKind::Int(_)
        | SyntaxKind::Rational(_)
        | SyntaxKind::Real(_)
        | SyntaxKind::Str(_)
        | SyntaxKind::Nil
        | SyntaxKind::Sym(_) => Ok(()),
        SyntaxKind::Char(_)
        | SyntaxKind::DottedList(_, _)
        | SyntaxKind::Vector(_)
        | SyntaxKind::Bytevector(_) => Err(ProfileError::new(
            ProfileErrorCode::NativeLoweringFailed,
            form.span,
            "source datum has no checked-profile production",
        )),
        SyntaxKind::List(items) if items.is_empty() => Ok(()),
        SyntaxKind::List(items) => classify_list(items, form.span),
    }
}

fn classify_list(items: &[Syntax], span: Span) -> Result<(), ProfileError> {
    let head = symbol_name(&items[0]);
    if head.is_some_and(|name| UNCOVERED_HEADS.contains(&name)) {
        return Err(ProfileError::new(
            ProfileErrorCode::NativeLoweringFailed,
            span,
            "form has no checked-profile production",
        ));
    }
    match head {
        Some("if") if items.len() == 4 => classify_all(&items[1..]),
        Some("lambda") if items.len() >= 3 => {
            match &items[1].node {
                SyntaxKind::Nil | SyntaxKind::List(_) => {}
                _ => return lowering_shape(span, "checked lambda must have fixed arity"),
            }
            classify_all(&items[2..])
        }
        Some("begin") => classify_all(&items[1..]),
        Some("define") if items.len() == 3 && matches!(items[1].node, SyntaxKind::Sym(_)) => {
            classify_expr(&items[2])
        }
        Some("let") if items.len() >= 3 => {
            let bindings = match &items[1].node {
                SyntaxKind::Nil => &[][..],
                SyntaxKind::List(bindings) => bindings.as_slice(),
                _ => return lowering_shape(span, "checked let requires a binding list"),
            };
            for binding in bindings {
                let pair = match &binding.node {
                    SyntaxKind::List(pair)
                        if pair.len() == 2 && matches!(pair[0].node, SyntaxKind::Sym(_)) =>
                    {
                        pair
                    }
                    _ => return lowering_shape(binding.span, "malformed checked let binding"),
                };
                classify_expr(&pair[1])?;
            }
            classify_all(&items[2..])
        }
        Some("and") | Some("or") => classify_all(&items[1..]),
        Some("cond") => classify_cond(items, span),
        Some("if" | "lambda" | "define" | "let") => {
            lowering_shape(span, "malformed checked-profile form")
        }
        _ => classify_all(items),
    }
}

fn classify_cond(items: &[Syntax], span: Span) -> Result<(), ProfileError> {
    if items.len() < 3 {
        return lowering_shape(span, "checked cond requires a test and final else clause");
    }
    for (index, clause) in items[1..].iter().enumerate() {
        let pair = match &clause.node {
            SyntaxKind::List(pair) if pair.len() == 2 => pair,
            _ => return lowering_shape(clause.span, "unsupported checked cond clause"),
        };
        let is_last = index + 1 == items.len() - 1;
        let is_else = symbol_name(&pair[0]) == Some("else");
        if is_else != is_last {
            return lowering_shape(clause.span, "checked cond requires exactly one final else");
        }
        if !is_else {
            classify_expr(&pair[0])?;
        }
        classify_expr(&pair[1])?;
    }
    Ok(())
}

fn classify_all(forms: &[Syntax]) -> Result<(), ProfileError> {
    for form in forms {
        classify_expr(form)?;
    }
    Ok(())
}

fn lowering_shape<T>(span: Span, message: &str) -> Result<T, ProfileError> {
    Err(ProfileError::new(
        ProfileErrorCode::NativeLoweringFailed,
        span,
        message,
    ))
}

#[derive(Default)]
struct Lowerer {
    next_temp: u32,
}

impl Lowerer {
    fn lower(&mut self, syntax: &Syntax) -> Result<CoreExpr, ProfileError> {
        let kind = match &syntax.node {
            SyntaxKind::Bool(_)
            | SyntaxKind::Int(_)
            | SyntaxKind::Rational(_)
            | SyntaxKind::Real(_)
            | SyntaxKind::Str(_)
            | SyntaxKind::Nil => CoreKind::Quote(syntax.to_value()),
            SyntaxKind::Sym(name) if name.starts_with("$sym:") => {
                let literal = &name[5..];
                let valid_identifier = read_one(literal, "<checked-symbol-literal>")
                    .ok()
                    .is_some_and(|syntax| {
                        matches!(syntax.node, SyntaxKind::Sym(parsed) if parsed.as_ref() == literal)
                    });
                if !valid_identifier || literal == "input" || COVERED_PRIMITIVES.contains(&literal)
                {
                    return lowering_shape(syntax.span, "invalid restricted symbol literal");
                }
                CoreKind::Quote(Value::Sym(Rc::from(literal)))
            }
            SyntaxKind::Sym(name) => CoreKind::Var(Ident::User(name.clone())),
            SyntaxKind::List(items) if items.is_empty() => CoreKind::Quote(Value::Nil),
            SyntaxKind::List(items) => return self.lower_list(items, syntax.span),
            _ => return lowering_shape(syntax.span, "unclassified source datum"),
        };
        Ok(CoreExpr::new(kind, syntax.span))
    }

    fn lower_list(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, ProfileError> {
        match symbol_name(&items[0]) {
            Some("if") => Ok(CoreExpr::new(
                CoreKind::If(
                    Box::new(self.lower(&items[1])?),
                    Box::new(self.lower(&items[2])?),
                    Box::new(self.lower(&items[3])?),
                ),
                span,
            )),
            Some("lambda") => {
                let params = binders(&items[1])?;
                Ok(CoreExpr::new(
                    CoreKind::Lambda {
                        formals: Formals {
                            fixed: params,
                            rest: None,
                        },
                        body: Box::new(self.lower_body(&items[2..], span)?),
                    },
                    span,
                ))
            }
            Some("begin") => Ok(CoreExpr::new(
                CoreKind::Begin(
                    items[1..]
                        .iter()
                        .map(|item| self.lower(item))
                        .collect::<Result<_, _>>()?,
                ),
                span,
            )),
            Some("define") => Ok(CoreExpr::new(
                CoreKind::Define {
                    name: binder(&items[1])?,
                    value: Box::new(self.lower(&items[2])?),
                },
                span,
            )),
            Some("let") => {
                let binding_syntax = match &items[1].node {
                    SyntaxKind::Nil => &[][..],
                    SyntaxKind::List(bindings) => bindings.as_slice(),
                    _ => unreachable!("surface classifier fixed let binding shape"),
                };
                let mut bindings = Vec::with_capacity(binding_syntax.len());
                for syntax in binding_syntax {
                    let SyntaxKind::List(pair) = &syntax.node else {
                        unreachable!("surface classifier fixed binding shape")
                    };
                    bindings.push(Binding {
                        name: binder(&pair[0])?,
                        init: self.lower(&pair[1])?,
                    });
                }
                Ok(CoreExpr::new(
                    CoreKind::Let {
                        bindings,
                        body: Box::new(self.lower_body(&items[2..], span)?),
                    },
                    span,
                ))
            }
            Some("and") => self.lower_and(&items[1..], span),
            Some("or") => self.lower_or(&items[1..], span),
            Some("cond") => self.lower_cond(&items[1..], span),
            _ => {
                let mut args = items[1..]
                    .iter()
                    .map(|item| self.lower(item))
                    .collect::<Result<Vec<_>, _>>()?;
                // SCORED-MUTATION-SITE M11: reverse subtraction operands in the
                // shared checked-profile normalizer before either path runs.
                if cfg!(scored_mutant = "M11") && symbol_name(&items[0]) == Some("-") {
                    args.reverse();
                }
                Ok(CoreExpr::new(
                    CoreKind::App {
                        op: Box::new(self.lower(&items[0])?),
                        args,
                    },
                    span,
                ))
            }
        }
    }

    fn lower_body(&mut self, forms: &[Syntax], span: Span) -> Result<CoreExpr, ProfileError> {
        let mut lowered = forms
            .iter()
            .map(|form| self.lower(form))
            .collect::<Result<Vec<_>, _>>()?;
        if lowered.len() == 1 {
            Ok(lowered.remove(0))
        } else {
            Ok(CoreExpr::new(CoreKind::Begin(lowered), span))
        }
    }

    fn lower_and(&mut self, forms: &[Syntax], span: Span) -> Result<CoreExpr, ProfileError> {
        match forms {
            [] => Ok(CoreExpr::new(CoreKind::Quote(Value::Bool(true)), span)),
            [one] => self.lower(one),
            [first, rest @ ..] => Ok(CoreExpr::new(
                CoreKind::If(
                    Box::new(self.lower(first)?),
                    Box::new(self.lower_and(rest, span)?),
                    Box::new(CoreExpr::new(CoreKind::Quote(Value::Bool(false)), span)),
                ),
                span,
            )),
        }
    }

    fn lower_or(&mut self, forms: &[Syntax], span: Span) -> Result<CoreExpr, ProfileError> {
        match forms {
            [] => Ok(CoreExpr::new(CoreKind::Quote(Value::Bool(false)), span)),
            [one] => self.lower(one),
            [first, rest @ ..] => {
                let temp = Ident::Temp(self.next_temp);
                self.next_temp += 1;
                Ok(CoreExpr::new(
                    CoreKind::Let {
                        bindings: vec![Binding {
                            name: temp.clone(),
                            init: self.lower(first)?,
                        }],
                        body: Box::new(CoreExpr::new(
                            CoreKind::If(
                                Box::new(CoreExpr::new(CoreKind::Var(temp.clone()), span)),
                                Box::new(CoreExpr::new(CoreKind::Var(temp), span)),
                                Box::new(self.lower_or(rest, span)?),
                            ),
                            span,
                        )),
                    },
                    span,
                ))
            }
        }
    }

    fn lower_cond(&mut self, clauses: &[Syntax], span: Span) -> Result<CoreExpr, ProfileError> {
        let SyntaxKind::List(last) = &clauses.last().expect("classified cond").node else {
            unreachable!()
        };
        let mut result = self.lower(&last[1])?;
        for clause in clauses[..clauses.len() - 1].iter().rev() {
            let SyntaxKind::List(pair) = &clause.node else {
                unreachable!()
            };
            result = CoreExpr::new(
                CoreKind::If(
                    Box::new(self.lower(&pair[0])?),
                    Box::new(self.lower(&pair[1])?),
                    Box::new(result),
                ),
                clause.span,
            );
        }
        let _ = span;
        Ok(result)
    }
}

fn binder(syntax: &Syntax) -> Result<Ident, ProfileError> {
    match &syntax.node {
        SyntaxKind::Sym(name) => Ok(Ident::User(name.clone())),
        _ => lowering_shape(syntax.span, "binder must be a symbol"),
    }
}

fn binders(syntax: &Syntax) -> Result<Vec<Ident>, ProfileError> {
    match &syntax.node {
        SyntaxKind::Nil => Ok(Vec::new()),
        SyntaxKind::List(items) => items.iter().map(binder).collect(),
        _ => lowering_shape(syntax.span, "fixed parameter list required"),
    }
}

fn symbol_name(syntax: &Syntax) -> Option<&str> {
    match &syntax.node {
        SyntaxKind::Sym(name) => Some(name),
        _ => None,
    }
}

pub fn validate_core(core: &[CoreExpr]) -> Result<(), ProfileError> {
    if core.is_empty() {
        return Err(ProfileError::new(
            ProfileErrorCode::ProfileEscape,
            Span { line: 1, col: 1 },
            "checked program requires at least one top-level form",
        ));
    }
    let mut top_level: HashSet<Ident> = COVERED_PRIMITIVES
        .iter()
        .map(|name| Ident::User(Rc::from(*name)))
        .collect();
    top_level.insert(Ident::User(Rc::from("input")));
    let mut definitions = HashSet::new();

    for form in core {
        if let CoreKind::Define { name, value } = &form.kind {
            reject_binding(name, form.span)?;
            if is_primitive(name) || !definitions.insert(name.clone()) {
                return escape(form.span, "duplicate or primitive top-level definition");
            }
            if free_reference(value, name, &mut HashSet::new()) {
                return escape(form.span, "recursive covered top-level definition");
            }
            validate_expr(value, &top_level)?;
            top_level.insert(name.clone());
        } else {
            validate_expr(form, &top_level)?;
        }
    }
    Ok(())
}

fn validate_expr(expr: &CoreExpr, scope: &HashSet<Ident>) -> Result<(), ProfileError> {
    match &expr.kind {
        CoreKind::Var(name) if scope.contains(name) => Ok(()),
        CoreKind::Var(_) => escape(expr.span, "unbound checked-profile variable"),
        CoreKind::Quote(value) if covered_literal(value) => Ok(()),
        CoreKind::Quote(_) => escape(expr.span, "literal is outside the checked profile"),
        CoreKind::If(test, consequent, alternate) => {
            validate_expr(test, scope)?;
            validate_expr(consequent, scope)?;
            validate_expr(alternate, scope)
        }
        CoreKind::Lambda { formals, body } if formals.rest.is_none() => {
            reject_duplicates(&formals.fixed, expr.span)?;
            let mut child = scope.clone();
            for parameter in &formals.fixed {
                reject_binding(parameter, expr.span)?;
                child.insert(parameter.clone());
            }
            validate_expr(body, &child)
        }
        CoreKind::App { op, args } => {
            validate_expr(op, scope)?;
            for arg in args {
                validate_expr(arg, scope)?;
            }
            Ok(())
        }
        CoreKind::Begin(forms) if !forms.is_empty() => {
            for form in forms {
                validate_expr(form, scope)?;
            }
            Ok(())
        }
        CoreKind::Begin(_) => escape(expr.span, "empty begin"),
        CoreKind::Let { bindings, body } => {
            let names: Vec<_> = bindings
                .iter()
                .map(|binding| binding.name.clone())
                .collect();
            reject_duplicates(&names, expr.span)?;
            for binding in bindings {
                reject_binding(&binding.name, expr.span)?;
                validate_expr(&binding.init, scope)?;
            }
            let mut child = scope.clone();
            child.extend(names);
            validate_expr(body, &child)
        }
        CoreKind::Define { .. } => escape(expr.span, "define is allowed only as a root"),
        CoreKind::Lambda { .. }
        | CoreKind::Set { .. }
        | CoreKind::Letrec { .. }
        | CoreKind::Values(_)
        | CoreKind::Intrinsic(_)
        | CoreKind::Guard { .. } => escape(expr.span, "Core form is outside checked profile"),
    }
}

fn covered_literal(value: &Value) -> bool {
    matches!(
        value,
        Value::Bool(_)
            | Value::Int(_)
            | Value::Rational(_)
            | Value::Real(_)
            | Value::Str(_)
            | Value::Nil
            | Value::Sym(_)
    )
}

fn reject_binding(name: &Ident, span: Span) -> Result<(), ProfileError> {
    if ident_text(name) == Some("input") {
        escape(span, "reserved input binding may not be bound or shadowed")
    } else {
        Ok(())
    }
}

fn reject_duplicates(names: &[Ident], span: Span) -> Result<(), ProfileError> {
    let mut seen = HashSet::new();
    if names.iter().any(|name| !seen.insert(name.clone())) {
        escape(span, "duplicate binding names")
    } else {
        Ok(())
    }
}

fn is_primitive(name: &Ident) -> bool {
    ident_text(name).is_some_and(|name| COVERED_PRIMITIVES.contains(&name))
}

fn ident_text(name: &Ident) -> Option<&str> {
    match name {
        Ident::User(name) => Some(name),
        Ident::Temp(_) => None,
    }
}

fn free_reference(expr: &CoreExpr, target: &Ident, bound: &mut HashSet<Ident>) -> bool {
    match &expr.kind {
        CoreKind::Var(name) => name == target && !bound.contains(name),
        CoreKind::Quote(_) | CoreKind::Intrinsic(_) => false,
        CoreKind::If(a, b, c) => {
            free_reference(a, target, bound)
                || free_reference(b, target, bound)
                || free_reference(c, target, bound)
        }
        CoreKind::Lambda { formals, body } => {
            let old = bound.clone();
            bound.extend(formals.fixed.iter().cloned());
            if let Some(rest) = &formals.rest {
                bound.insert(rest.clone());
            }
            let result = free_reference(body, target, bound);
            *bound = old;
            result
        }
        CoreKind::App { op, args } => {
            free_reference(op, target, bound)
                || args.iter().any(|arg| free_reference(arg, target, bound))
        }
        CoreKind::Begin(forms) | CoreKind::Values(forms) => {
            forms.iter().any(|form| free_reference(form, target, bound))
        }
        CoreKind::Set { value, .. } | CoreKind::Define { value, .. } => {
            free_reference(value, target, bound)
        }
        CoreKind::Let { bindings, body } => {
            if bindings
                .iter()
                .any(|binding| free_reference(&binding.init, target, bound))
            {
                return true;
            }
            let old = bound.clone();
            bound.extend(bindings.iter().map(|binding| binding.name.clone()));
            let result = free_reference(body, target, bound);
            *bound = old;
            result
        }
        CoreKind::Letrec { bindings, body } => {
            let old = bound.clone();
            bound.extend(bindings.iter().map(|binding| binding.name.clone()));
            let result = bindings
                .iter()
                .any(|binding| free_reference(&binding.init, target, bound))
                || free_reference(body, target, bound);
            *bound = old;
            result
        }
        CoreKind::Guard {
            clauses,
            else_body,
            body,
            ..
        } => {
            free_reference(body, target, bound)
                || clauses.iter().any(|clause| {
                    free_reference(&clause.test, target, bound)
                        || free_reference(&clause.body, target, bound)
                })
                || else_body
                    .as_deref()
                    .is_some_and(|body| free_reference(body, target, bound))
        }
    }
}

fn escape<T>(span: Span, message: &str) -> Result<T, ProfileError> {
    Err(ProfileError::new(
        ProfileErrorCode::ProfileEscape,
        span,
        message,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(source: &str) -> ProfileErrorCode {
        prepare_checked_program(source.as_bytes()).unwrap_err().code
    }

    #[test]
    fn surface_uncovered_examples_fail_before_core() {
        for source in [
            "(set! x 1)",
            "(letrec ((x 1)) x)",
            "(lambda x x)",
            "(values 1)",
            "(call/cc (lambda (k) 1))",
            "(dynamic-wind f g h)",
            "(guard (x (else 1)) 1)",
            "#(1)",
            "#u8(1)",
            "(quote x)",
            "(quasiquote x)",
            "(cond (#t 1 2) (else 3))",
        ] {
            assert_eq!(
                error(source),
                ProfileErrorCode::NativeLoweringFailed,
                "{source}"
            );
        }
    }

    #[test]
    fn covered_shape_violations_are_post_normalization_profile_escapes() {
        for source in [
            "(lambda (input) input)",
            "(lambda (x x) x)",
            "(let ((x 1) (x 2)) x)",
            "(begin)",
            "(define f (lambda (x) (f x)))",
            "(define input 1)",
        ] {
            assert_eq!(error(source), ProfileErrorCode::ProfileEscape, "{source}");
        }
    }

    #[test]
    fn normalization_is_byte_reproducible() {
        let source =
            b"(define threshold 10)\n(if (< input threshold) (decision-approve) (decision-deny))";
        let a = prepare_checked_program(source).unwrap();
        let b = prepare_checked_program(source).unwrap();
        assert_eq!(a.normalized_bytes(), b.normalized_bytes());
        assert_eq!(a.core(), b.core());
    }

    #[test]
    fn normalized_core_round_trip_recovers_hygienic_temps() {
        let source = b"(or #f (decision-approve))";
        let prepared = prepare_checked_program(source).unwrap();
        assert!(std::str::from_utf8(prepared.normalized_bytes())
            .unwrap()
            .contains("#:t0"));
        let parsed = parse_checked_normalized_program(prepared.normalized_bytes()).unwrap();
        let CoreKind::Let { bindings, .. } = &parsed.core()[0].kind else {
            panic!("or lowering must reparse as let")
        };
        assert_eq!(bindings[0].name, Ident::Temp(0));
        assert_eq!(parsed.normalized_bytes(), prepared.normalized_bytes());
    }

    #[test]
    fn normalized_core_parser_rejects_noncanonical_and_surface_bytes() {
        let prepared = prepare_checked_program(b"(+ 1 2)").unwrap();
        let mut noncanonical = prepared.normalized_bytes().to_vec();
        noncanonical.extend_from_slice(b"\n");
        assert!(parse_checked_normalized_program(&noncanonical).is_err());
        assert!(parse_checked_normalized_program(b"(+ 1 2)\n").is_err());
    }

    #[test]
    fn restricted_symbol_literal_is_not_general_quote() {
        let program = prepare_checked_program(b"$sym:ok").unwrap();
        assert!(matches!(
            program.core()[0].kind,
            CoreKind::Quote(Value::Sym(_))
        ));
    }

    #[test]
    fn every_covered_form_and_primitive_has_a_positive_boundary() {
        for source in [
            "#t",
            "1",
            "1/2",
            "1.5",
            "\"x\"",
            "()",
            "$sym:ok",
            "input",
            "(lambda (x) x)",
            "((lambda (x) x) 1)",
            "(if #t 1 2)",
            "(begin 1 2)",
            "(let ((x 1)) x)",
            "(define x 1)",
            "(and #t 1)",
            "(or #f 1)",
            "(cond (#t 1) (else 2))",
            "(+ 1 2)",
            "(- 1 2)",
            "(* 1 2)",
            "(/ 1 2)",
            "(= 1 2)",
            "(< 1 2)",
            "(<= 1 2)",
            "(> 1 2)",
            "(>= 1 2)",
            "(cons 1 2)",
            "(car input)",
            "(cdr input)",
            "(null? input)",
            "(pair? input)",
            "(list 1 2)",
            "(exact-integer? 1)",
            "(decision-approve)",
            "(decision-deny)",
            "(decision-review)",
            "(decision-invalid-input)",
        ] {
            prepare_checked_program(source.as_bytes())
                .unwrap_or_else(|error| panic!("covered source failed: {source}: {error:?}"));
        }
    }

    #[test]
    fn lexical_scope_and_top_level_definition_boundaries_are_closed() {
        for source in [
            "missing",
            "(define + 1)",
            "(define x 1) (define x 2)",
            "x (define x 1)",
        ] {
            assert_eq!(error(source), ProfileErrorCode::ProfileEscape, "{source}");
        }
        assert!(prepare_checked_program(b"(define x 1) x").is_ok());
        assert!(prepare_checked_program(b"(lambda (+) (+ 1 2))").is_ok());
    }

    #[test]
    fn source_byte_limit_is_exact_and_checked_before_reading() {
        let mut exact = Vec::with_capacity(MAX_SOURCE_BYTES);
        exact.push(b';');
        exact.extend(std::iter::repeat_n(b'a', MAX_SOURCE_BYTES - 3));
        exact.extend_from_slice(b"\n1");
        assert_eq!(exact.len(), MAX_SOURCE_BYTES);
        assert!(prepare_checked_program(&exact).is_ok());
        exact.insert(1, b'a');
        assert_eq!(
            prepare_checked_program(&exact).unwrap_err().code,
            ProfileErrorCode::ResourceLimit
        );
    }
}
