//! Hygienic normalizer — surface [`Syntax`] → [`CoreExpr`] (Round 2).
//!
//! This is the deterministic, **pure** transform `Syntax -> Result<CoreExpr,
//! Diagnostic>` (and the program-level `&[Syntax] -> Result<Vec<CoreExpr>, _>`).
//! It desugars every derived form (LISPEX.md §6 + §10), enforces the normalize-time
//! static diagnostics (E110/E120/E130, §13), and is **hygienic**: expansions emit
//! hidden [`Intrinsic`]s + fresh [`Ident::Temp`]s, never user-shadowable surface
//! names or user-collidable temps (LISPEX-RUNTIME.md §7.1). It does NOT evaluate
//! anything — the evaluator is R3.
//!
//! ## Determinism
//! Same input ⇒ same output, including temp numbering: a single monotonically
//! increasing counter ([`Normalizer::gensym`]) mints every `Temp`, in a fixed
//! traversal order. No hash-map iteration or other nondeterminism influences shape.
//!
//! ## Static diagnostics (first error aborts)
//! - **E110** binding a §4 reserved word (formals, `let`/`letrec`/`let*`/named-`let`
//!   /`do` binders, `set!`/`define` targets), and using a syntactic keyword as a
//!   value.
//! - **E120** a forbidden user-macro / library / multi-binding form, anywhere it
//!   appears as a symbol (LISPEX.md §4/§11).
//! - **E130** a malformed derived form (empty `cond`, bad clause shapes, bad
//!   bindings, bad formals, bare `unquote`/`unquote-splicing` outside quasiquote,
//!   empty application, improper-list expression, …).

use std::rc::Rc;

use crate::core::{Binding, CoreExpr, CoreKind, Formals, GuardClause, Ident, Intrinsic};
use crate::reader::{Diagnostic, ErrCode, Span};
use crate::syntax::{Syntax, SyntaxKind};
use crate::value::Value;

/// §4 reserved words — none may be *bound* (→ E110).
const RESERVED: &[&str] = &[
    "quote",
    "quasiquote",
    "unquote",
    "unquote-splicing",
    "lambda",
    "if",
    "begin",
    "set!",
    "define",
    "let",
    "let*",
    "letrec",
    "cond",
    "case",
    "guard",
    "and",
    "or",
    "when",
    "unless",
    "do",
    "values",
    "call-with-values",
    "call/cc",
    "dynamic-wind",
    "module",
    "export",
    "import",
];

/// Reserved words that are *syntactic keywords* (not first-class values): using one
/// as a bare value is an error. The complement — `values`, `call-with-values`,
/// `call/cc`, `dynamic-wind` — ARE procedures R6 binds, so they may be referenced.
fn is_syntactic_keyword(name: &str) -> bool {
    is_reserved(name)
        && !matches!(
            name,
            "values" | "call-with-values" | "call/cc" | "dynamic-wind"
        )
}

fn is_reserved(name: &str) -> bool {
    RESERVED.contains(&name)
}

/// §11 forbidden forms (user macros, reader extensions, advanced library syntax,
/// multi-binding special forms) — any occurrence as a symbol is E120.
const FORBIDDEN: &[&str] = &[
    "define-syntax",
    "syntax-rules",
    "syntax-case",
    "let-syntax",
    "letrec-syntax",
    "define-library",
    "include",
    "include-ci",
    "include-library-declarations",
    "define-values",
    "let-values",
    "let*-values",
];

fn is_forbidden(name: &str) -> bool {
    FORBIDDEN.contains(&name)
}

/// Normalize a whole program. Top-level `(module …)` headers are **flattened**: the
/// reference interpreter has one global namespace, so a module's `export`/`import`
/// clauses are dropped and its body forms are spliced in as ordinary top-level forms
/// (LISPEX.md §3 note + §12 R5RS-compat: "module header dropped/flattened").
pub fn normalize_program(datums: &[Syntax], file: &str) -> Result<Vec<CoreExpr>, Diagnostic> {
    let mut n = Normalizer::new(file);
    let mut out = Vec::new();
    for d in datums {
        n.norm_toplevel(d, &mut out)?;
    }
    Ok(out)
}

/// Normalize a single expression (convenience; mostly for tests).
pub fn normalize_one(s: &Syntax, file: &str) -> Result<CoreExpr, Diagnostic> {
    Normalizer::new(file).norm(s)
}

struct Normalizer {
    file: String,
    /// Monotonic counter backing [`Ident::Temp`] — the deterministic gensym.
    counter: u32,
}

impl Normalizer {
    fn new(file: &str) -> Normalizer {
        Normalizer {
            file: file.to_string(),
            counter: 0,
        }
    }

    fn gensym(&mut self) -> Ident {
        let n = self.counter;
        self.counter += 1;
        Ident::Temp(n)
    }

    fn err(&self, code: ErrCode, span: Span, msg: impl Into<String>) -> Diagnostic {
        Diagnostic {
            code,
            file: self.file.clone(),
            span,
            message: msg.into(),
        }
    }

    // ── small builders (every synthesized node carries a source span) ───────────
    fn quote(&self, v: Value, span: Span) -> CoreExpr {
        CoreExpr::new(CoreKind::Quote(v), span)
    }
    fn quote_bool(&self, b: bool, span: Span) -> CoreExpr {
        self.quote(Value::Bool(b), span)
    }
    fn nil(&self, span: Span) -> CoreExpr {
        self.quote(Value::Nil, span)
    }
    fn var(&self, id: Ident, span: Span) -> CoreExpr {
        CoreExpr::new(CoreKind::Var(id), span)
    }
    fn zero_values(&self, span: Span) -> CoreExpr {
        CoreExpr::new(CoreKind::Values(vec![]), span)
    }
    fn if_(&self, t: CoreExpr, a: CoreExpr, b: CoreExpr, span: Span) -> CoreExpr {
        CoreExpr::new(CoreKind::If(Box::new(t), Box::new(a), Box::new(b)), span)
    }
    fn call_intrinsic(&self, i: Intrinsic, args: Vec<CoreExpr>, span: Span) -> CoreExpr {
        let op = CoreExpr::new(CoreKind::Intrinsic(i), span);
        CoreExpr::new(
            CoreKind::App {
                op: Box::new(op),
                args,
            },
            span,
        )
    }
    /// `(cons a b)` via the hidden intrinsic (used to build quasiquote spines).
    fn cons(&self, a: CoreExpr, b: CoreExpr, span: Span) -> CoreExpr {
        self.call_intrinsic(Intrinsic::Cons, vec![a, b], span)
    }

    /// Wrap a body sequence into one expression: one expr stays as-is, several
    /// become a `begin`, zero (defensive) becomes zero values.
    fn body(&self, exprs: Vec<CoreExpr>, span: Span) -> CoreExpr {
        match exprs.len() {
            0 => self.zero_values(span),
            1 => exprs.into_iter().next().unwrap(),
            _ => CoreExpr::new(CoreKind::Begin(exprs), span),
        }
    }

    // ── top level (handles module flattening) ───────────────────────────────────
    fn norm_toplevel(&mut self, s: &Syntax, out: &mut Vec<CoreExpr>) -> Result<(), Diagnostic> {
        if let SyntaxKind::List(items) = &s.node {
            if let Some("module") = head_name(items) {
                return self.flatten_module(items, s.span, out);
            }
        }
        out.push(self.norm(s)?);
        Ok(())
    }

    fn flatten_module(
        &mut self,
        items: &[Syntax],
        span: Span,
        out: &mut Vec<CoreExpr>,
    ) -> Result<(), Diagnostic> {
        // (module <name> (export <id>*) (import <modname>*) body…). The name is
        // required; well-formed leading (export …)/(import …) header clauses are
        // validated then dropped; the remaining forms are flattened (recursively, so
        // nested modules splice). A malformed clause, or an export/import that
        // appears after the body has begun, is E130 (§3/§14).
        if items.len() < 2 {
            return Err(self.err(
                ErrCode::E130,
                span,
                "malformed module header (missing name)",
            ));
        }
        // name: a symbol or a dotted path (id.id…). We don't bind it; just validate
        // it is a symbol or list/dotted-list of symbols.
        validate_module_name(&items[1]).map_err(|m| self.err(ErrCode::E130, items[1].span, m))?;
        let mut in_body = false;
        for form in &items[2..] {
            if let SyntaxKind::List(inner) = &form.node {
                if let Some(kw @ ("export" | "import")) = head_name(inner) {
                    if in_body {
                        return Err(self.err(
                            ErrCode::E130,
                            form.span,
                            format!("`{kw}` clause must precede the module body (§3)"),
                        ));
                    }
                    // Header clause: each item must be an identifier / dotted-path
                    // symbol (§14: `(export <id>*)`, `(import <modname>*)`).
                    for item in &inner[1..] {
                        if !matches!(item.node, SyntaxKind::Sym(_)) {
                            return Err(self.err(
                                ErrCode::E130,
                                item.span,
                                format!("`{kw}` items must be identifiers (§3)"),
                            ));
                        }
                    }
                    continue; // valid header clause → dropped
                }
            }
            in_body = true;
            self.norm_toplevel(form, out)?;
        }
        Ok(())
    }

    // ── the core dispatch ───────────────────────────────────────────────────────
    fn norm(&mut self, s: &Syntax) -> Result<CoreExpr, Diagnostic> {
        match &s.node {
            // self-evaluating literals → a `quote` node (the literal carrier).
            SyntaxKind::Bool(_)
            | SyntaxKind::Int(_)
            | SyntaxKind::Rational(_)
            | SyntaxKind::Real(_)
            | SyntaxKind::Char(_)
            | SyntaxKind::Str(_)
            | SyntaxKind::Vector(_)
            | SyntaxKind::Bytevector(_) => Ok(self.quote(s.to_value(), s.span)),

            SyntaxKind::Sym(name) => self.norm_sym(name, s.span),

            // `()` as an expression is an empty application; `Nil` never comes from
            // the reader but is handled for completeness.
            SyntaxKind::Nil => Err(self.err(ErrCode::E130, s.span, "empty application `()`")),
            SyntaxKind::List(items) if items.is_empty() => {
                Err(self.err(ErrCode::E130, s.span, "empty application `()`"))
            }

            // A dotted list is data, never a valid expression / application.
            SyntaxKind::DottedList(..) => Err(self.err(
                ErrCode::E130,
                s.span,
                "improper (dotted) list is not a valid expression",
            )),

            SyntaxKind::List(items) => self.norm_list(items, s.span),
        }
    }

    fn norm_sym(&self, name: &Rc<str>, span: Span) -> Result<CoreExpr, Diagnostic> {
        if is_forbidden(name) {
            return Err(self.err(
                ErrCode::E120,
                span,
                format!("`{name}` is a forbidden form (user macros / reader extensions are not supported, LISPEX §11)"),
            ));
        }
        if is_syntactic_keyword(name) {
            return Err(self.err(
                ErrCode::E110,
                span,
                format!("reserved word `{name}` cannot be used as a value"),
            ));
        }
        Ok(self.var(Ident::User(name.clone()), span))
    }

    fn norm_list(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        // Dispatch on the head symbol (if any). Reserved/forbidden heads are
        // resolved here before any application interpretation.
        if let Some(name) = head_name(items) {
            if is_forbidden(name) {
                return Err(self.err(
                    ErrCode::E120,
                    items[0].span,
                    format!("`{name}` is a forbidden form (LISPEX §11)"),
                ));
            }
            match name {
                "quote" => return self.norm_quote(items, span),
                "if" => return self.norm_if(items, span),
                "lambda" => return self.norm_lambda(items, span),
                "begin" => return self.norm_begin(items, span),
                "set!" => return self.norm_set(items, span),
                "define" => return self.norm_define(items, span),
                "let" => return self.norm_let(items, span),
                "let*" => return self.norm_let_star(items, span),
                "letrec" => return self.norm_letrec(items, span),
                "cond" => return self.norm_cond(items, span),
                "case" => return self.norm_case(items, span),
                "guard" => return self.norm_guard(items, span),
                "and" => return self.norm_and(&items[1..], span),
                "or" => return self.norm_or(&items[1..], span),
                "when" => return self.norm_when_unless(items, span, true),
                "unless" => return self.norm_when_unless(items, span, false),
                "do" => return self.norm_do(items, span),
                "values" => return self.norm_values(items, span),
                "quasiquote" => return self.norm_quasiquote(items, span),
                "unquote" | "unquote-splicing" => {
                    return Err(self.err(
                        ErrCode::E130,
                        items[0].span,
                        format!("`{name}` outside a quasiquote"),
                    ));
                }
                "module" => {
                    return Err(self.err(
                        ErrCode::E130,
                        items[0].span,
                        "`module` is only valid at top level",
                    ));
                }
                "export" | "import" => {
                    return Err(self.err(
                        ErrCode::E130,
                        items[0].span,
                        format!("`{name}` is only valid inside a module header"),
                    ));
                }
                // call/cc, call-with-values, dynamic-wind, and every ordinary name
                // fall through to the application path below.
                _ => {}
            }
        }
        // Ordinary application: operator first, then operands (norm each).
        self.norm_application(items, span)
    }

    fn norm_application(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        let op = self.norm(&items[0])?;
        let mut args = Vec::with_capacity(items.len() - 1);
        for a in &items[1..] {
            args.push(self.norm(a)?);
        }
        Ok(CoreExpr::new(
            CoreKind::App {
                op: Box::new(op),
                args,
            },
            span,
        ))
    }

    // ── core forms ──────────────────────────────────────────────────────────────
    fn norm_quote(&self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        if items.len() != 2 {
            return Err(self.err(ErrCode::E130, span, "`quote` takes exactly one datum"));
        }
        Ok(self.quote(items[1].to_value(), span))
    }

    fn norm_if(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        if items.len() != 4 {
            return Err(self.err(
                ErrCode::E130,
                span,
                "`if` must be `(if test then else)` (3-arm, else mandatory)",
            ));
        }
        let t = self.norm(&items[1])?;
        let a = self.norm(&items[2])?;
        let b = self.norm(&items[3])?;
        Ok(self.if_(t, a, b, span))
    }

    fn norm_lambda(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        if items.len() < 3 {
            return Err(self.err(
                ErrCode::E130,
                span,
                "`lambda` must be `(lambda (formals) body+)`",
            ));
        }
        let formals = self.parse_formals(&items[1])?;
        let body = self.norm_body(&items[2..], span)?;
        Ok(CoreExpr::new(
            CoreKind::Lambda {
                formals,
                body: Box::new(body),
            },
            span,
        ))
    }

    fn norm_begin(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        if items.len() < 2 {
            return Err(self.err(ErrCode::E130, span, "`begin` needs at least one expression"));
        }
        let mut es = Vec::with_capacity(items.len() - 1);
        for e in &items[1..] {
            es.push(self.norm(e)?);
        }
        Ok(self.body(es, span))
    }

    fn norm_set(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        if items.len() != 3 {
            return Err(self.err(ErrCode::E130, span, "`set!` must be `(set! id expr)`"));
        }
        let target = self.binder(&items[1])?;
        let value = self.norm(&items[2])?;
        Ok(CoreExpr::new(
            CoreKind::Set {
                target,
                value: Box::new(value),
            },
            span,
        ))
    }

    fn norm_define(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        if items.len() < 2 {
            return Err(self.err(ErrCode::E130, span, "malformed `define`"));
        }
        match &items[1].node {
            // (define id expr)
            SyntaxKind::Sym(_) => {
                if items.len() != 3 {
                    return Err(self.err(
                        ErrCode::E130,
                        span,
                        "`define` must be `(define id expr)`",
                    ));
                }
                let name = self.binder(&items[1])?;
                let value = self.norm(&items[2])?;
                Ok(CoreExpr::new(
                    CoreKind::Define {
                        name,
                        value: Box::new(value),
                    },
                    span,
                ))
            }
            // (define (f params…) body+)  ⇒  (define f (lambda (params…) body…))
            // and the dotted variant (define (f . rest) body+).
            SyntaxKind::List(_) | SyntaxKind::DottedList(..) => {
                let (name_syn, formals) = self.parse_define_head(&items[1])?;
                if items.len() < 3 {
                    return Err(self.err(ErrCode::E130, span, "function `define` needs a body"));
                }
                let name = self.binder(name_syn)?;
                let body = self.norm_body(&items[2..], span)?;
                let lambda = CoreExpr::new(
                    CoreKind::Lambda {
                        formals,
                        body: Box::new(body),
                    },
                    span,
                );
                Ok(CoreExpr::new(
                    CoreKind::Define {
                        name,
                        value: Box::new(lambda),
                    },
                    span,
                ))
            }
            _ => Err(self.err(ErrCode::E130, items[1].span, "malformed `define` target")),
        }
    }

    fn norm_values(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        let mut es = Vec::with_capacity(items.len() - 1);
        for e in &items[1..] {
            es.push(self.norm(e)?);
        }
        Ok(CoreExpr::new(CoreKind::Values(es), span))
    }

    // ── let family ──────────────────────────────────────────────────────────────
    fn norm_let(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        // Named let?  (let name ((v init)…) body+)
        if items.len() >= 2 {
            if let SyntaxKind::Sym(_) = &items[1].node {
                return self.norm_named_let(items, span);
            }
        }
        // Plain let:  (let ((id init)…) body+)
        if items.len() < 3 {
            return Err(self.err(
                ErrCode::E130,
                span,
                "`let` must be `(let ((id init)…) body+)`",
            ));
        }
        let bindings = self.parse_bindings(&items[1])?;
        let body = self.norm_body(&items[2..], span)?;
        Ok(CoreExpr::new(
            CoreKind::Let {
                bindings,
                body: Box::new(body),
            },
            span,
        ))
    }

    fn norm_named_let(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        // (let name ((v init)…) body+)
        //   ⇒ (letrec ((name (lambda (v…) body…))) (name init…))
        // `name` stays a User ident (visible by design); `v…` are the loop params.
        if items.len() < 4 {
            return Err(self.err(
                ErrCode::E130,
                span,
                "named `let` must be `(let name ((v init)…) body+)`",
            ));
        }
        let name = self.binder(&items[1])?;
        let raw = self.parse_binding_specs(&items[2])?;
        let mut params = Vec::with_capacity(raw.len());
        let mut inits = Vec::with_capacity(raw.len());
        for (id, _bspan, init_syn) in raw {
            params.push(id);
            inits.push(self.norm(init_syn)?);
        }
        let lam_body = self.norm_body(&items[3..], span)?;
        let lambda = CoreExpr::new(
            CoreKind::Lambda {
                formals: Formals {
                    fixed: params,
                    rest: None,
                },
                body: Box::new(lam_body),
            },
            span,
        );
        let call = CoreExpr::new(
            CoreKind::App {
                op: Box::new(self.var(name.clone(), span)),
                args: inits,
            },
            span,
        );
        Ok(CoreExpr::new(
            CoreKind::Letrec {
                bindings: vec![Binding { name, init: lambda }],
                body: Box::new(call),
            },
            span,
        ))
    }

    fn norm_letrec(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        if items.len() < 3 {
            return Err(self.err(
                ErrCode::E130,
                span,
                "`letrec` must be `(letrec ((id init)…) body+)`",
            ));
        }
        let bindings = self.parse_bindings(&items[1])?;
        let body = self.norm_body(&items[2..], span)?;
        Ok(CoreExpr::new(
            CoreKind::Letrec {
                bindings,
                body: Box::new(body),
            },
            span,
        ))
    }

    fn norm_let_star(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        // (let* ((x e1)(y e2)…) body) ⇒ nested single-binding `let`s.
        // 0 bindings ⇒ (let () body).
        if items.len() < 3 {
            return Err(self.err(
                ErrCode::E130,
                span,
                "`let*` must be `(let* ((id init)…) body+)`",
            ));
        }
        let specs = self.parse_binding_specs(&items[1])?;
        // Normalize the inits up front (deterministic order, before building nests).
        let mut bindings = Vec::with_capacity(specs.len());
        for (id, bspan, init_syn) in specs {
            let init = self.norm(init_syn)?;
            bindings.push((id, bspan, init));
        }
        let mut acc = self.norm_body(&items[2..], span)?;
        // No bindings ⇒ always a plain `(let () body)`. We decide this from the
        // binding count itself, NOT by inspecting the normalized body's kind (a body
        // that is itself a `let` must keep this outer empty wrapper).
        if bindings.is_empty() {
            return Ok(CoreExpr::new(
                CoreKind::Let {
                    bindings: vec![],
                    body: Box::new(acc),
                },
                span,
            ));
        }
        // Fold from the innermost binding outward into nested single-binding `let`s.
        for (id, bspan, init) in bindings.into_iter().rev() {
            acc = CoreExpr::new(
                CoreKind::Let {
                    bindings: vec![Binding { name: id, init }],
                    body: Box::new(acc),
                },
                bspan,
            );
        }
        Ok(acc)
    }

    // ── cond / case ─────────────────────────────────────────────────────────────
    fn norm_cond(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        let clauses = &items[1..];
        if clauses.is_empty() {
            return Err(self.err(ErrCode::E130, span, "empty `cond`"));
        }
        // Build the fall-through, then fold non-else clauses from the right.
        let last = clauses.len() - 1;
        let mut acc;
        let upto; // exclusive end of the non-else clauses to fold
        match self.clause_kind(&clauses[last])? {
            ClauseHead::Else(body_syn, cspan) => {
                acc = self.norm_body_clause(body_syn, cspan)?;
                upto = last;
            }
            ClauseHead::Test => {
                // No else: unmatched cond yields zero values (§0.3 "unspecified =
                // zero values").
                acc = self.zero_values(span);
                upto = clauses.len();
            }
        }
        // Any `else` not in last position is malformed.
        for c in &clauses[..upto] {
            if let ClauseHead::Else(_, cspan) = self.clause_kind(c)? {
                return Err(self.err(
                    ErrCode::E130,
                    cspan,
                    "`else` must be the last `cond` clause",
                ));
            }
        }
        for c in clauses[..upto].iter().rev() {
            let (test_syn, body_syn, cspan) = self.cond_test_clause(c)?;
            let test = self.norm(test_syn)?;
            let then = self.norm_body_clause(body_syn, cspan)?;
            acc = self.if_(test, then, acc, cspan);
        }
        Ok(acc)
    }

    fn norm_guard(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        // (guard (var clause+) body+) — a fixed surface form (not a user macro): on a
        // CATCHABLE fault bind `var` to the condition and run the cond-style clauses,
        // reraising when none match and there is no `else` (§8). The clauses reuse the
        // exact `cond` clause machinery, so guard clauses behave identically to `cond`.
        if items.len() < 3 {
            return Err(self.err(
                ErrCode::E130,
                span,
                "`guard` must be `(guard (var clause+) body+)`",
            ));
        }
        let spec = match &items[1].node {
            SyntaxKind::List(xs) if !xs.is_empty() => xs,
            _ => {
                return Err(self.err(
                    ErrCode::E130,
                    items[1].span,
                    "`guard` needs a `(var clause+)` head",
                ))
            }
        };
        let var = self.binder(&spec[0])?;
        let clauses_syn = &spec[1..];
        if clauses_syn.is_empty() {
            return Err(self.err(
                ErrCode::E130,
                items[1].span,
                "`guard` needs at least one clause",
            ));
        }
        // A trailing `else` becomes `else_body`; the rest are cond-style test clauses.
        let last = clauses_syn.len() - 1;
        let mut else_body: Option<Box<CoreExpr>> = None;
        let upto;
        match self.clause_kind(&clauses_syn[last])? {
            ClauseHead::Else(body_syn, cspan) => {
                else_body = Some(Box::new(self.norm_body_clause(body_syn, cspan)?));
                upto = last;
            }
            ClauseHead::Test => {
                upto = clauses_syn.len();
            }
        }
        for c in &clauses_syn[..upto] {
            if let ClauseHead::Else(_, cspan) = self.clause_kind(c)? {
                return Err(self.err(
                    ErrCode::E130,
                    cspan,
                    "`else` must be the last `guard` clause",
                ));
            }
        }
        let mut clauses = Vec::with_capacity(upto);
        for c in &clauses_syn[..upto] {
            let (test_syn, body_syn, cspan) = self.cond_test_clause(c)?;
            let test = self.norm(test_syn)?;
            let body = self.norm_body_clause(body_syn, cspan)?;
            clauses.push(GuardClause { test, body });
        }
        let body = self.norm_body(&items[2..], span)?;
        Ok(CoreExpr::new(
            CoreKind::Guard {
                var,
                clauses,
                else_body,
                body: Box::new(body),
            },
            span,
        ))
    }

    fn norm_case(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        // (case key clause+) ⇒ (let ((t key)) <if-chain on (eqv? t datum)…>)
        if items.len() < 3 {
            return Err(self.err(ErrCode::E130, span, "`case` needs a key and ≥1 clause"));
        }
        let clauses = &items[2..];
        let key = self.norm(&items[1])?;
        let t = self.gensym();

        let last = clauses.len() - 1;
        let mut acc;
        let upto;
        match self.clause_kind(&clauses[last])? {
            ClauseHead::Else(body_syn, cspan) => {
                acc = self.norm_body_clause(body_syn, cspan)?;
                upto = last;
            }
            ClauseHead::Test => {
                acc = self.zero_values(span);
                upto = clauses.len();
            }
        }
        for c in &clauses[..upto] {
            if let ClauseHead::Else(_, cspan) = self.clause_kind(c)? {
                return Err(self.err(
                    ErrCode::E130,
                    cspan,
                    "`else` must be the last `case` clause",
                ));
            }
        }
        for c in clauses[..upto].iter().rev() {
            let (datums_syn, body_syn, cspan) = self.case_clause(c)?;
            let pred = self.case_predicate(&t, datums_syn, cspan);
            let then = self.norm_body_clause(body_syn, cspan)?;
            acc = self.if_(pred, then, acc, cspan);
        }
        Ok(CoreExpr::new(
            CoreKind::Let {
                bindings: vec![Binding { name: t, init: key }],
                body: Box::new(acc),
            },
            span,
        ))
    }

    /// Build `(eqv? t d1) ∨ (eqv? t d2) ∨ …` without duplicating any clause body and
    /// without `or`/temps: a right fold of `(if (eqv? t di) #t <rest>)`, base `#f`.
    /// Uses the hidden `eqv?` intrinsic (§0.1) — unaffected by a user-bound `eqv?`.
    fn case_predicate(&self, t: &Ident, datums: &[Syntax], span: Span) -> CoreExpr {
        let mut acc = self.quote_bool(false, span);
        for d in datums.iter().rev() {
            let test = self.call_intrinsic(
                Intrinsic::Eqv,
                vec![self.var(t.clone(), span), self.quote(d.to_value(), span)],
                span,
            );
            acc = self.if_(test, self.quote_bool(true, span), acc, span);
        }
        acc
    }

    // ── and / or (§6.5 / §6.6 — last operand lands in tail position) ────────────
    fn norm_and(&mut self, es: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        match es {
            [] => Ok(self.quote_bool(true, span)),
            [one] => self.norm(one),
            [first, rest @ ..] => {
                let head = self.norm(first)?;
                let tail = self.norm_and(rest, span)?;
                let f = self.quote_bool(false, span);
                Ok(self.if_(head, tail, f, first.span))
            }
        }
    }

    fn norm_or(&mut self, es: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        match es {
            [] => Ok(self.quote_bool(false, span)),
            [one] => self.norm(one),
            [first, rest @ ..] => {
                // (or e1 e2…) ⇒ (let ((t e1)) (if t t (or e2…))) with a fresh temp.
                let t = self.gensym();
                let head = self.norm(first)?;
                let tail = self.norm_or(rest, span)?;
                let cond = self.if_(
                    self.var(t.clone(), first.span),
                    self.var(t.clone(), first.span),
                    tail,
                    first.span,
                );
                Ok(CoreExpr::new(
                    CoreKind::Let {
                        bindings: vec![Binding {
                            name: t,
                            init: head,
                        }],
                        body: Box::new(cond),
                    },
                    first.span,
                ))
            }
        }
    }

    // ── when / unless (§6.7; NO user-shadowable `not`) ──────────────────────────
    fn norm_when_unless(
        &mut self,
        items: &[Syntax],
        span: Span,
        is_when: bool,
    ) -> Result<CoreExpr, Diagnostic> {
        let kw = if is_when { "when" } else { "unless" };
        if items.len() < 3 {
            return Err(self.err(
                ErrCode::E130,
                span,
                format!("`{kw}` must be `({kw} test body+)`"),
            ));
        }
        let test = self.norm(&items[1])?;
        let body = self.norm_body(&items[2..], span)?;
        let zero = self.zero_values(span);
        // when:   (if test body  (values))
        // unless: (if test (values) body)     ← never goes through `not`
        Ok(if is_when {
            self.if_(test, body, zero, span)
        } else {
            self.if_(test, zero, body, span)
        })
    }

    // ── do (§6.8 — loop lowered to a fresh-named letrec) ────────────────────────
    fn norm_do(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        // (do ((var init step?)…) (test done…) body…)
        //   ⇒ (letrec ((loop (lambda (var…)
        //         (if test (begin done…) (begin body… (loop step…))))))
        //        (loop init…))
        if items.len() < 3 {
            return Err(self.err(
                ErrCode::E130,
                span,
                "`do` must be `(do (specs) (test done…) body…)`",
            ));
        }
        // Parse the do-var specs.
        let specs = match &items[1].node {
            SyntaxKind::List(v) => v,
            _ => {
                return Err(self.err(ErrCode::E130, items[1].span, "`do` bindings must be a list"))
            }
        };
        let mut vars: Vec<Ident> = Vec::with_capacity(specs.len());
        let mut inits: Vec<CoreExpr> = Vec::with_capacity(specs.len());
        let mut steps: Vec<CoreExpr> = Vec::with_capacity(specs.len());
        for spec in specs {
            let parts = match &spec.node {
                SyntaxKind::List(p) if p.len() == 2 || p.len() == 3 => p,
                _ => {
                    return Err(self.err(
                        ErrCode::E130,
                        spec.span,
                        "`do` spec must be `(var init [step])`",
                    ))
                }
            };
            let var = self.binder(&parts[0])?;
            inits.push(self.norm(&parts[1])?);
            // Step is optional; if omitted the variable keeps its value.
            let step = if parts.len() == 3 {
                self.norm(&parts[2])?
            } else {
                self.var(var.clone(), parts[0].span)
            };
            vars.push(var);
            steps.push(step);
        }

        // Test clause: (test done…).
        let test_clause = match &items[2].node {
            SyntaxKind::List(t) if !t.is_empty() => t,
            _ => {
                return Err(self.err(
                    ErrCode::E130,
                    items[2].span,
                    "`do` test clause must be `(test done…)`",
                ))
            }
        };
        let test = self.norm(&test_clause[0])?;
        let done = {
            let mut d = Vec::with_capacity(test_clause.len() - 1);
            for e in &test_clause[1..] {
                d.push(self.norm(e)?);
            }
            // Empty result ⇒ zero values (§0.3).
            if d.is_empty() {
                self.zero_values(items[2].span)
            } else {
                self.body(d, items[2].span)
            }
        };

        let loop_id = self.gensym();
        let recur = CoreExpr::new(
            CoreKind::App {
                op: Box::new(self.var(loop_id.clone(), span)),
                args: steps,
            },
            span,
        );
        // body… then the tail self-call (recur is the tail position → proper TCO).
        let mut recur_body = Vec::with_capacity(items.len() - 3 + 1);
        for e in &items[3..] {
            recur_body.push(self.norm(e)?);
        }
        recur_body.push(recur);
        let recur_branch = self.body(recur_body, span);

        let if_expr = self.if_(test, done, recur_branch, span);
        let lambda = CoreExpr::new(
            CoreKind::Lambda {
                formals: Formals {
                    fixed: vars,
                    rest: None,
                },
                body: Box::new(if_expr),
            },
            span,
        );
        let entry = CoreExpr::new(
            CoreKind::App {
                op: Box::new(self.var(loop_id.clone(), span)),
                args: inits,
            },
            span,
        );
        Ok(CoreExpr::new(
            CoreKind::Letrec {
                bindings: vec![Binding {
                    name: loop_id,
                    init: lambda,
                }],
                body: Box::new(entry),
            },
            span,
        ))
    }

    // ── quasiquote (§10 — fully expanded to quote + intrinsic constructors) ──────
    fn norm_quasiquote(&mut self, items: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        if items.len() != 2 {
            return Err(self.err(
                ErrCode::E130,
                span,
                "`quasiquote` takes exactly one template",
            ));
        }
        self.qq(&items[1], 1)
    }

    /// Expand a quasiquote template at nesting `depth` (1 = the outermost backtick).
    fn qq(&mut self, t: &Syntax, depth: u32) -> Result<CoreExpr, Diagnostic> {
        match &t.node {
            SyntaxKind::List(items) => {
                if let Some(name) = head_name(items) {
                    match name {
                        "unquote" => {
                            if items.len() != 2 {
                                return Err(self.err(
                                    ErrCode::E130,
                                    t.span,
                                    "malformed `unquote` (expected `(unquote expr)`)",
                                ));
                            }
                            return if depth == 1 {
                                self.norm(&items[1])
                            } else {
                                // Reconstruct `(unquote …)` as data at deeper levels.
                                let inner = self.qq(&items[1], depth - 1)?;
                                Ok(self.reconstruct("unquote", inner, t.span))
                            };
                        }
                        "unquote-splicing" => {
                            // A standalone `,@x` (not as a list element) cannot splice.
                            if depth == 1 {
                                return Err(self.err(
                                    ErrCode::E130,
                                    t.span,
                                    "`unquote-splicing` not in a list context",
                                ));
                            }
                            if items.len() != 2 {
                                return Err(self.err(
                                    ErrCode::E130,
                                    t.span,
                                    "malformed `unquote-splicing`",
                                ));
                            }
                            let inner = self.qq(&items[1], depth - 1)?;
                            return Ok(self.reconstruct("unquote-splicing", inner, t.span));
                        }
                        "quasiquote" => {
                            if items.len() != 2 {
                                return Err(self.err(
                                    ErrCode::E130,
                                    t.span,
                                    "malformed nested `quasiquote`",
                                ));
                            }
                            let inner = self.qq(&items[1], depth + 1)?;
                            return Ok(self.reconstruct("quasiquote", inner, t.span));
                        }
                        _ => {}
                    }
                }
                // A general list template: fold elements, base = '().
                let base = self.nil(t.span);
                self.qq_seq(items, base, depth)
            }
            SyntaxKind::DottedList(items, tail) => {
                let base = self.qq(tail, depth)?;
                self.qq_seq(items, base, depth)
            }
            SyntaxKind::Vector(items) => {
                let base = self.nil(t.span);
                let list = self.qq_seq(items, base, depth)?;
                Ok(self.call_intrinsic(Intrinsic::ListToVector, vec![list], t.span))
            }
            // Any atom (incl. symbols and `#u8(…)`) is literal data.
            _ => Ok(self.quote(t.to_value(), t.span)),
        }
    }

    /// Fold list-template elements into a spine ending in `tail`, honoring
    /// `,@` splices (→ `append`) and `,`/plain elements (→ `cons`).
    fn qq_seq(
        &mut self,
        elems: &[Syntax],
        tail: CoreExpr,
        depth: u32,
    ) -> Result<CoreExpr, Diagnostic> {
        let mut acc = tail;
        for el in elems.iter().rev() {
            if let Some(spliced) = unquote_splicing_operand(el) {
                if depth == 1 {
                    let head = self.norm(spliced)?;
                    acc = self.call_intrinsic(Intrinsic::Append, vec![head, acc], el.span);
                } else {
                    let inner = self.qq(spliced, depth - 1)?;
                    let reb = self.reconstruct("unquote-splicing", inner, el.span);
                    acc = self.cons(reb, acc, el.span);
                }
            } else {
                let head = self.qq(el, depth)?;
                acc = self.cons(head, acc, el.span);
            }
        }
        Ok(acc)
    }

    /// Build the *data* `(sym inner)` for a deeper-level reconstruction, i.e.
    /// `(cons 'sym (cons inner '()))`, using only the hidden `cons` intrinsic.
    fn reconstruct(&self, sym: &str, inner: CoreExpr, span: Span) -> CoreExpr {
        let q = self.quote(Value::Sym(Rc::from(sym)), span);
        let tail = self.cons(inner, self.nil(span), span);
        self.cons(q, tail, span)
    }

    // ── binders / formals / bindings ────────────────────────────────────────────
    /// A binding-position identifier: must be a plain symbol that is neither a §11
    /// forbidden form (→ E120) nor a §4 reserved word (→ E110). Covers every binder
    /// target: `define`/`set!`, `lambda`/function-`define` formals, `let`/`let*`/
    /// `letrec`/named-`let`/`do` binders.
    fn binder(&self, s: &Syntax) -> Result<Ident, Diagnostic> {
        match &s.node {
            SyntaxKind::Sym(name) => {
                if is_forbidden(name) {
                    Err(self.err(
                        ErrCode::E120,
                        s.span,
                        format!("`{name}` is a forbidden form and cannot be bound (LISPEX §11)"),
                    ))
                } else if is_reserved(name) {
                    Err(self.err(
                        ErrCode::E110,
                        s.span,
                        format!("cannot bind reserved word `{name}`"),
                    ))
                } else {
                    Ok(Ident::User(name.clone()))
                }
            }
            _ => Err(self.err(ErrCode::E130, s.span, "expected an identifier")),
        }
    }

    fn parse_formals(&self, s: &Syntax) -> Result<Formals, Diagnostic> {
        let (fixed_syn, rest_syn): (&[Syntax], Option<&Syntax>) = match &s.node {
            SyntaxKind::List(items) => (items, None),
            SyntaxKind::DottedList(items, tail) => (items, Some(tail)),
            SyntaxKind::Nil => (&[], None),
            _ => {
                return Err(self.err(
                    ErrCode::E130,
                    s.span,
                    "bad `lambda` formals (expected `(x …)` or `(x … . rest)`)",
                ))
            }
        };
        let mut fixed = Vec::with_capacity(fixed_syn.len());
        for p in fixed_syn {
            fixed.push(self.binder(p)?);
        }
        let rest = match rest_syn {
            Some(r) => Some(self.binder(r)?),
            None => None,
        };
        // Reject duplicate parameter names (a malformed formals list).
        self.check_unique(&fixed, rest.as_ref(), s.span)?;
        Ok(Formals { fixed, rest })
    }

    fn check_unique(
        &self,
        fixed: &[Ident],
        rest: Option<&Ident>,
        span: Span,
    ) -> Result<(), Diagnostic> {
        let mut seen: Vec<&str> = Vec::new();
        for id in fixed.iter().chain(rest) {
            if let Ident::User(n) = id {
                if seen.contains(&n.as_ref()) {
                    return Err(self.err(
                        ErrCode::E130,
                        span,
                        format!("duplicate parameter `{n}`"),
                    ));
                }
                seen.push(n);
            }
        }
        Ok(())
    }

    /// `(define (f a b) …)` / `(define (f . rest) …)` head → (name-syntax, formals).
    fn parse_define_head<'a>(&self, head: &'a Syntax) -> Result<(&'a Syntax, Formals), Diagnostic> {
        match &head.node {
            SyntaxKind::List(items) => {
                if items.is_empty() {
                    return Err(self.err(
                        ErrCode::E130,
                        head.span,
                        "function `define` needs a name",
                    ));
                }
                let formals = self.parse_formals_from(&items[1..], None, head.span)?;
                Ok((&items[0], formals))
            }
            SyntaxKind::DottedList(items, tail) => {
                if items.is_empty() {
                    return Err(self.err(
                        ErrCode::E130,
                        head.span,
                        "function `define` needs a name",
                    ));
                }
                let formals = self.parse_formals_from(&items[1..], Some(tail), head.span)?;
                Ok((&items[0], formals))
            }
            _ => Err(self.err(ErrCode::E130, head.span, "malformed function `define` head")),
        }
    }

    fn parse_formals_from(
        &self,
        fixed_syn: &[Syntax],
        rest_syn: Option<&Syntax>,
        span: Span,
    ) -> Result<Formals, Diagnostic> {
        let mut fixed = Vec::with_capacity(fixed_syn.len());
        for p in fixed_syn {
            fixed.push(self.binder(p)?);
        }
        let rest = match rest_syn {
            Some(r) => Some(self.binder(r)?),
            None => None,
        };
        self.check_unique(&fixed, rest.as_ref(), span)?;
        Ok(Formals { fixed, rest })
    }

    /// Parse a `let`/`letrec` binding list into normalized [`Binding`]s.
    fn parse_bindings(&mut self, s: &Syntax) -> Result<Vec<Binding>, Diagnostic> {
        let specs = self.parse_binding_specs(s)?;
        let mut out = Vec::with_capacity(specs.len());
        for (id, _span, init_syn) in specs {
            out.push(Binding {
                name: id,
                init: self.norm(init_syn)?,
            });
        }
        Ok(out)
    }

    /// Parse a binding list `((id init)…)` into `(Ident, span, &init-syntax)`
    /// triples WITHOUT normalizing the inits (so callers — `let*`, named `let` —
    /// can control ordering / wrapping). The list must be proper; each binding a
    /// 2-element list with a non-reserved identifier.
    fn parse_binding_specs<'a>(
        &self,
        s: &'a Syntax,
    ) -> Result<Vec<(Ident, Span, &'a Syntax)>, Diagnostic> {
        let specs = match &s.node {
            SyntaxKind::List(items) => items,
            SyntaxKind::Nil => return Ok(vec![]),
            _ => {
                return Err(self.err(ErrCode::E130, s.span, "binding list must be `((id init)…)`"))
            }
        };
        let mut out = Vec::with_capacity(specs.len());
        for b in specs {
            let parts = match &b.node {
                SyntaxKind::List(p) if p.len() == 2 => p,
                _ => {
                    return Err(self.err(ErrCode::E130, b.span, "each binding must be `(id init)`"))
                }
            };
            let id = self.binder(&parts[0])?;
            out.push((id, parts[0].span, &parts[1]));
        }
        Ok(out)
    }

    // ── bodies & clauses ────────────────────────────────────────────────────────
    fn norm_body(&mut self, exprs: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        if exprs.is_empty() {
            return Err(self.err(ErrCode::E130, span, "empty body"));
        }
        let mut es = Vec::with_capacity(exprs.len());
        for e in exprs {
            es.push(self.norm(e)?);
        }
        Ok(self.body(es, span))
    }

    /// Normalize a clause body sequence (≥1 expr) into one expression.
    fn norm_body_clause(&mut self, exprs: &[Syntax], span: Span) -> Result<CoreExpr, Diagnostic> {
        if exprs.is_empty() {
            return Err(self.err(ErrCode::E130, span, "clause body must have ≥1 expression"));
        }
        self.norm_body(exprs, span)
    }

    /// Classify a clause as `(else body…)` or a test clause, validating it is a
    /// non-empty list.
    fn clause_kind<'a>(&self, c: &'a Syntax) -> Result<ClauseHead<'a>, Diagnostic> {
        let items = match &c.node {
            SyntaxKind::List(items) if !items.is_empty() => items,
            _ => return Err(self.err(ErrCode::E130, c.span, "clause must be a non-empty list")),
        };
        if let SyntaxKind::Sym(name) = &items[0].node {
            if &**name == "else" {
                return Ok(ClauseHead::Else(&items[1..], c.span));
            }
        }
        Ok(ClauseHead::Test)
    }

    /// `(test body+)` → (test, body, span). The `=>` clause variant is unsupported.
    fn cond_test_clause<'a>(
        &self,
        c: &'a Syntax,
    ) -> Result<(&'a Syntax, &'a [Syntax], Span), Diagnostic> {
        let items = match &c.node {
            SyntaxKind::List(items) if !items.is_empty() => items,
            _ => return Err(self.err(ErrCode::E130, c.span, "malformed `cond` clause")),
        };
        if items.len() < 2 {
            return Err(self.err(
                ErrCode::E130,
                c.span,
                "`cond` clause must be `(test body+)`",
            ));
        }
        if let SyntaxKind::Sym(s) = &items[1].node {
            if &**s == "=>" {
                return Err(self.err(
                    ErrCode::E130,
                    items[1].span,
                    "`cond` `=>` clause is unsupported in Lispex v1",
                ));
            }
        }
        Ok((&items[0], &items[1..], c.span))
    }

    /// `((d1 d2…) body+)` → (datums, body, span). Datums must be a proper list.
    fn case_clause<'a>(
        &self,
        c: &'a Syntax,
    ) -> Result<(&'a [Syntax], &'a [Syntax], Span), Diagnostic> {
        let items = match &c.node {
            SyntaxKind::List(items) if !items.is_empty() => items,
            _ => return Err(self.err(ErrCode::E130, c.span, "malformed `case` clause")),
        };
        let datums = match &items[0].node {
            SyntaxKind::List(d) => d.as_slice(),
            SyntaxKind::Nil => &[],
            _ => {
                return Err(self.err(
                    ErrCode::E130,
                    items[0].span,
                    "`case` clause datums must be a list `(d …)`",
                ))
            }
        };
        if items.len() < 2 {
            return Err(self.err(
                ErrCode::E130,
                c.span,
                "`case` clause must be `((datum…) body+)`",
            ));
        }
        Ok((datums, &items[1..], c.span))
    }
}

/// A clause's head: `else` (with its body) or an ordinary test clause.
enum ClauseHead<'a> {
    Else(&'a [Syntax], Span),
    Test,
}

/// If `items` is non-empty and its head is a symbol, return that name.
fn head_name(items: &[Syntax]) -> Option<&str> {
    match items.first().map(|s| &s.node) {
        Some(SyntaxKind::Sym(name)) => Some(name),
        _ => None,
    }
}

/// If `el` is exactly `(unquote-splicing operand)`, return the operand.
fn unquote_splicing_operand(el: &Syntax) -> Option<&Syntax> {
    if let SyntaxKind::List(items) = &el.node {
        if items.len() == 2 && head_name(items) == Some("unquote-splicing") {
            return Some(&items[1]);
        }
    }
    None
}

/// A module name is a symbol or a dotted path `id.id…` (we accept a symbol — the
/// reader already lexes `util.string` as one symbol — and otherwise a (dotted) list
/// of symbols, mirroring the lenient §3 header).
fn validate_module_name(s: &Syntax) -> Result<(), String> {
    match &s.node {
        SyntaxKind::Sym(_) => Ok(()),
        SyntaxKind::List(items) if items.iter().all(|i| matches!(i.node, SyntaxKind::Sym(_))) => {
            Ok(())
        }
        _ => Err("module name must be a symbol or dotted path".to_string()),
    }
}
