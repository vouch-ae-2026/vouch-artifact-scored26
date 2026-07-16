//! Canonical Core v0 bytes and hash domains (CSK-CANONICAL-CORE.md).
//!
//! This module owns the public byte contract. `CoreExpr::sexpr` delegates here so
//! debug output cannot drift away from the canonical grammar by accident.

use std::collections::HashSet;
use std::fmt;
use std::rc::Rc;

use sha2::{Digest, Sha256};

use crate::core::{Binding, CoreExpr, CoreKind, Formals, GuardClause, Ident, Intrinsic};
use crate::reader::read_one;
use crate::value::Value;

pub const CANONICAL_FORMAT_TAG: &str = "lispex.core.canonical/v0";
pub const CORE_HASH_DOMAIN: &str = "lispex/core-hash/v0";
pub const SOURCE_HASH_DOMAIN: &str = "lispex/source-hash/v0";
pub const RUNTIME_HASH_DOMAIN: &str = "lispex/runtime-hash/v0";
pub const ENGINE_VERSION_DOMAIN: &str = "lispex/engine-version/v0";
pub const PROFILE_INPUT_HASH_DOMAIN: &str = "csk/profile-input-hash/v0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonFault {
    message: String,
}

impl CanonFault {
    fn new(message: impl Into<String>) -> CanonFault {
        CanonFault {
            message: message.into(),
        }
    }
}

impl fmt::Display for CanonFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CanonFault {}

pub fn canonical_program_bytes(core: &[CoreExpr]) -> Result<Vec<u8>, CanonFault> {
    let mut out = String::new();
    out.push_str(CANONICAL_FORMAT_TAG);
    out.push('\n');
    for expr in core {
        write_core_expr(expr, &mut out)?;
        out.push('\n');
    }
    Ok(out.into_bytes())
}

pub fn canonical_expr_string(expr: &CoreExpr) -> Result<String, CanonFault> {
    let mut out = String::new();
    write_core_expr(expr, &mut out)?;
    Ok(out)
}

pub fn canonical_datum_string(value: &Value) -> Result<String, CanonFault> {
    validate_literal(value, &mut HashSet::new())?;
    Ok(value.write_repr())
}

pub fn canonical_datum_parse(text: &str) -> Result<Value, CanonFault> {
    let syntax = read_one(text, "<canonical-datum>")
        .map_err(|e| CanonFault::new(format!("datum text is not readable: {}", e.message)))?;
    let value = syntax.to_value();
    let rendered = canonical_datum_string(&value)?;
    if rendered != text {
        return Err(CanonFault::new(
            "datum text is readable but not canonical Canonical Core v0 bytes",
        ));
    }
    Ok(value)
}

pub fn hash_with_domain_hex(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

pub fn source_hash_hex(source_bytes: &[u8]) -> String {
    hash_with_domain_hex(SOURCE_HASH_DOMAIN, source_bytes)
}

pub fn core_hash_hex(canonical_bytes: &[u8]) -> String {
    hash_with_domain_hex(CORE_HASH_DOMAIN, canonical_bytes)
}

pub fn runtime_hash_hex(runtime_transcript: &[u8]) -> String {
    hash_with_domain_hex(RUNTIME_HASH_DOMAIN, runtime_transcript)
}

pub fn profile_input_hash_hex(input_datum_bytes: &[u8]) -> String {
    hash_with_domain_hex(PROFILE_INPUT_HASH_DOMAIN, input_datum_bytes)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn write_core_expr(expr: &CoreExpr, out: &mut String) -> Result<(), CanonFault> {
    match &expr.kind {
        CoreKind::Var(id) => write_ident(id, out),
        CoreKind::Quote(v) => {
            validate_literal(v, &mut HashSet::new())?;
            out.push_str("(quote ");
            out.push_str(&v.write_repr());
            out.push(')');
        }
        CoreKind::If(t, a, b) => {
            out.push_str("(if ");
            write_core_expr(t, out)?;
            out.push(' ');
            write_core_expr(a, out)?;
            out.push(' ');
            write_core_expr(b, out)?;
            out.push(')');
        }
        CoreKind::Lambda { formals, body } => {
            out.push_str("(lambda ");
            write_formals(formals, out);
            out.push(' ');
            write_core_expr(body, out)?;
            out.push(')');
        }
        CoreKind::App { op, args } => {
            out.push('(');
            write_core_expr(op, out)?;
            for a in args {
                out.push(' ');
                write_core_expr(a, out)?;
            }
            out.push(')');
        }
        CoreKind::Begin(es) => {
            out.push_str("(begin");
            for e in es {
                out.push(' ');
                write_core_expr(e, out)?;
            }
            out.push(')');
        }
        CoreKind::Set { target, value } => {
            out.push_str("(set! ");
            write_ident(target, out);
            out.push(' ');
            write_core_expr(value, out)?;
            out.push(')');
        }
        CoreKind::Define { name, value } => {
            out.push_str("(define ");
            write_ident(name, out);
            out.push(' ');
            write_core_expr(value, out)?;
            out.push(')');
        }
        CoreKind::Let { bindings, body } => write_let("let", bindings, body, out)?,
        CoreKind::Letrec { bindings, body } => write_let("letrec", bindings, body, out)?,
        CoreKind::Values(es) => {
            out.push_str("(values");
            for e in es {
                out.push(' ');
                write_core_expr(e, out)?;
            }
            out.push(')');
        }
        CoreKind::Intrinsic(i) => write_intrinsic(*i, out),
        CoreKind::Guard {
            var,
            clauses,
            else_body,
            body,
        } => write_guard(var, clauses, else_body.as_deref(), body, out)?,
    }
    Ok(())
}

fn write_ident(id: &Ident, out: &mut String) {
    match id {
        Ident::User(n) => out.push_str(n),
        Ident::Temp(k) => {
            out.push_str("#:t");
            out.push_str(&k.to_string());
        }
    }
}

fn write_intrinsic(i: Intrinsic, out: &mut String) {
    out.push_str("#<intrinsic:");
    out.push_str(i.name());
    out.push('>');
}

fn write_formals(formals: &Formals, out: &mut String) {
    out.push('(');
    for (i, p) in formals.fixed.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        write_ident(p, out);
    }
    if let Some(rest) = &formals.rest {
        if !formals.fixed.is_empty() {
            out.push(' ');
        }
        out.push_str(". ");
        write_ident(rest, out);
    }
    out.push(')');
}

fn write_let(
    kw: &str,
    bindings: &[Binding],
    body: &CoreExpr,
    out: &mut String,
) -> Result<(), CanonFault> {
    out.push('(');
    out.push_str(kw);
    out.push_str(" (");
    for (i, b) in bindings.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push('(');
        write_ident(&b.name, out);
        out.push(' ');
        write_core_expr(&b.init, out)?;
        out.push(')');
    }
    out.push_str(") ");
    write_core_expr(body, out)?;
    out.push(')');
    Ok(())
}

fn write_guard(
    var: &Ident,
    clauses: &[GuardClause],
    else_body: Option<&CoreExpr>,
    body: &CoreExpr,
    out: &mut String,
) -> Result<(), CanonFault> {
    out.push_str("(guard (");
    write_ident(var, out);
    for c in clauses {
        out.push_str(" (");
        write_core_expr(&c.test, out)?;
        out.push(' ');
        write_core_expr(&c.body, out)?;
        out.push(')');
    }
    if let Some(eb) = else_body {
        out.push_str(" (else ");
        write_core_expr(eb, out)?;
        out.push(')');
    }
    out.push_str(") ");
    write_core_expr(body, out)?;
    out.push(')');
    Ok(())
}

fn validate_literal(v: &Value, active_vectors: &mut HashSet<usize>) -> Result<(), CanonFault> {
    match v {
        Value::Closure(_) | Value::Primitive(_) | Value::Cont(_) | Value::ErrorObject(_) => {
            return Err(CanonFault::new(
                "execution-only value cannot appear in Canonical Core literal",
            ));
        }
        #[cfg(feature = "scored-native-contract")]
        Value::Decision(_) => {
            return Err(CanonFault::new(
                "contract decision cannot appear in Canonical Core literal",
            ));
        }
        Value::Pair(p) => {
            validate_literal(&p.car, active_vectors)?;
            validate_literal(&p.cdr, active_vectors)?;
        }
        Value::Vector(data) => {
            let ptr = Rc::as_ptr(data) as usize;
            if !active_vectors.insert(ptr) {
                return Err(CanonFault::new(
                    "cyclic vector cannot appear in Canonical Core literal",
                ));
            }
            for item in data.items.borrow().iter() {
                validate_literal(item, active_vectors)?;
            }
            active_vectors.remove(&ptr);
        }
        Value::Bool(_)
        | Value::Int(_)
        | Value::Rational(_)
        | Value::Real(_)
        | Value::Char(_)
        | Value::Sym(_)
        | Value::Str(_)
        | Value::Nil
        | Value::Bytevector(_) => {}
    }
    Ok(())
}
