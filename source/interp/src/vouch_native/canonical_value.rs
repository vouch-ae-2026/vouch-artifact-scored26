//! Canonical contract value encoding (A-4).

use sha2::{Digest, Sha256};
use vouch::artifact_json::{write_canonical, JsonValue, JsonWriteError};

use crate::value::{format_real, Decision, Value};

pub const INPUT_VALUE_HASH_DOMAIN: &str = "csk.v0.input-canonical-value";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalValue {
    Integer(String),
    Rational {
        numerator: String,
        denominator: String,
    },
    Real(String),
    Boolean(bool),
    Nil,
    List {
        items: Vec<CanonicalValue>,
        improper_tail: Option<Box<CanonicalValue>>,
    },
    Symbol(String),
    String(String),
    Void,
    Decision(Decision),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileEscape;

impl CanonicalValue {
    pub fn from_value(value: &Value) -> Result<Self, ProfileEscape> {
        match value {
            Value::Bool(value) => Ok(Self::Boolean(*value)),
            Value::Int(value) => Ok(Self::Integer(value.to_string())),
            Value::Rational(value) => Ok(Self::Rational {
                numerator: value.numer().to_string(),
                denominator: value.denom().to_string(),
            }),
            Value::Real(value) => Ok(Self::Real(format_real(value.get()))),
            Value::Sym(value) => Ok(Self::Symbol(value.to_string())),
            Value::Str(value) => Ok(Self::String(value.to_string())),
            Value::Nil => Ok(Self::Nil),
            Value::Pair(_) => Self::from_pair(value),
            Value::Decision(value) => Ok(Self::Decision(*value)),
            Value::Char(_)
            | Value::Vector(_)
            | Value::Bytevector(_)
            | Value::Closure(_)
            | Value::Primitive(_)
            | Value::Cont(_)
            | Value::ErrorObject(_) => Err(ProfileEscape),
        }
    }

    fn from_pair(value: &Value) -> Result<Self, ProfileEscape> {
        let mut items = Vec::new();
        let mut cursor = value;
        loop {
            match cursor {
                Value::Pair(pair) => {
                    items.push(Self::from_value(&pair.car)?);
                    cursor = &pair.cdr;
                }
                Value::Nil => {
                    return Ok(Self::List {
                        items,
                        improper_tail: None,
                    });
                }
                tail => {
                    return Ok(Self::List {
                        items,
                        improper_tail: Some(Box::new(Self::from_value(tail)?)),
                    });
                }
            }
        }
    }

    pub fn contains_decision(&self) -> bool {
        match self {
            Self::Decision(_) => true,
            Self::List {
                items,
                improper_tail,
            } => {
                items.iter().any(Self::contains_decision)
                    || improper_tail
                        .as_deref()
                        .is_some_and(Self::contains_decision)
            }
            _ => false,
        }
    }

    pub fn to_json(&self) -> JsonValue {
        let string = |value: &str| JsonValue::String(value.to_string());
        match self {
            Self::Integer(value) => JsonValue::object([("t", string("int")), ("v", string(value))]),
            Self::Rational {
                numerator,
                denominator,
            } => JsonValue::object([
                ("t", string("rat")),
                ("n", string(numerator)),
                ("d", string(denominator)),
            ]),
            Self::Real(value) => JsonValue::object([("t", string("real")), ("v", string(value))]),
            Self::Boolean(value) => {
                JsonValue::object([("t", string("bool")), ("v", JsonValue::Bool(*value))])
            }
            Self::Nil => JsonValue::object([("t", string("nil"))]),
            Self::List {
                items,
                improper_tail,
            } => JsonValue::object([
                ("t", string("list")),
                (
                    "items",
                    JsonValue::Array(items.iter().map(Self::to_json).collect()),
                ),
                (
                    "improper_tail",
                    improper_tail
                        .as_deref()
                        .map(Self::to_json)
                        .unwrap_or(JsonValue::Null),
                ),
            ]),
            Self::Symbol(value) => JsonValue::object([("t", string("sym")), ("v", string(value))]),
            Self::String(value) => JsonValue::object([("t", string("str")), ("v", string(value))]),
            Self::Void => JsonValue::object([("t", string("void"))]),
            Self::Decision(value) => JsonValue::object([
                ("t", string("decision")),
                (
                    "v",
                    string(match value {
                        Decision::Approve => "approve",
                        Decision::Deny => "deny",
                        Decision::Review => "review",
                        Decision::InvalidInput => "invalid-input",
                    }),
                ),
            ]),
        }
        .expect("canonical value fields are unique")
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, JsonWriteError> {
        write_canonical(&self.to_json())
    }

    pub fn input_value_digest(&self) -> Result<String, JsonWriteError> {
        Ok(domain_hash(
            INPUT_VALUE_HASH_DOMAIN,
            &self.canonical_bytes()?,
        ))
    }
}

pub fn domain_hash(label: &str, content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update([0x1f]);
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_is_opaque_canonical_root_value() {
        let value = CanonicalValue::from_value(&Value::Decision(Decision::Approve)).unwrap();
        assert_eq!(value, CanonicalValue::Decision(Decision::Approve));
        assert!(value.contains_decision());
    }
}
