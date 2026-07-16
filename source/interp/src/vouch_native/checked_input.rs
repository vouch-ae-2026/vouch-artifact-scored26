//! Canonical `csk.checked-input/v1` parser and host-to-Lispex mapping.

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::One;
use sha2::{Digest, Sha256};
use vouch::artifact_json::{
    resource_preflight, write_canonical, JsonGateError, JsonValue, RawArtifactKind,
};
use vouch::io_boundary::FrozenBytes;

use crate::reader::read_one;
use crate::syntax::SyntaxKind;
use crate::value::{format_real, Value};

use super::canonical_value::{domain_hash, CanonicalValue, INPUT_VALUE_HASH_DOMAIN};

pub const CHECKED_INPUT_TAG: &str = "csk.checked-input/v1";
pub const MAX_INPUT_BYTES: usize = 1_048_576;
pub const MAX_RATIONAL_DIGITS: usize = 4_096;

const COVERED_PRIMITIVES: &[&str] = &[
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckedInputError {
    ResourceLimit,
    ParseFailed,
    ProfileInvalid,
}

impl CheckedInputError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ResourceLimit => "artifact-resource-limit",
            Self::ParseFailed => "native-input-parse-failed",
            Self::ProfileInvalid => "native-input-profile-invalid",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CheckedInput {
    raw: FrozenBytes,
    mapped_value: Value,
    canonical_value: CanonicalValue,
    raw_digest: String,
    canonical_value_digest: String,
}

impl CheckedInput {
    pub fn parse(bytes: &[u8]) -> Result<Self, CheckedInputError> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(CheckedInputError::ResourceLimit);
        }
        let raw = FrozenBytes::from_slice(bytes);
        let bytes = raw.bytes();
        if bytes.starts_with(&[0xef, 0xbb, 0xbf])
            || !bytes.ends_with(b"\n")
            || bytes.ends_with(b"\n\n")
            || std::str::from_utf8(bytes).is_err()
            || serde_json::from_slice::<serde_json::Value>(bytes).is_err()
        {
            return Err(CheckedInputError::ParseFailed);
        }

        let parsed = resource_preflight(bytes, RawArtifactKind::Artifact).map_err(|error| {
            if matches!(error, JsonGateError::ResourceLimit(_)) {
                CheckedInputError::ResourceLimit
            } else {
                CheckedInputError::ProfileInvalid
            }
        })?;
        if write_canonical(parsed.value()).map_err(|_| CheckedInputError::ProfileInvalid)? != bytes
        {
            return Err(CheckedInputError::ProfileInvalid);
        }
        let object = parsed
            .value()
            .as_object()
            .ok_or(CheckedInputError::ProfileInvalid)?;
        if object.len() != 2
            || object.get("input").and_then(JsonValue::as_str) != Some(CHECKED_INPUT_TAG)
        {
            return Err(CheckedInputError::ProfileInvalid);
        }
        let host = object
            .get("value")
            .ok_or(CheckedInputError::ProfileInvalid)?;
        let mapped_value = map_host_value(host)?;
        let canonical_value = CanonicalValue::from_value(&mapped_value)
            .map_err(|_| CheckedInputError::ProfileInvalid)?;
        let canonical_bytes = canonical_value
            .canonical_bytes()
            .map_err(|_| CheckedInputError::ProfileInvalid)?;
        let raw_digest = domain_hash("csk.v0.input", bytes);
        let canonical_value_digest = domain_hash(INPUT_VALUE_HASH_DOMAIN, &canonical_bytes);
        Ok(Self {
            raw,
            mapped_value,
            canonical_value,
            raw_digest,
            canonical_value_digest,
        })
    }

    pub fn raw_bytes(&self) -> &[u8] {
        self.raw.bytes()
    }

    pub fn raw_byte_length(&self) -> usize {
        self.raw.len()
    }

    pub fn mapped_value(&self) -> &Value {
        &self.mapped_value
    }

    pub fn canonical_value(&self) -> &CanonicalValue {
        &self.canonical_value
    }

    pub fn raw_digest(&self) -> &str {
        &self.raw_digest
    }

    pub fn canonical_value_digest(&self) -> &str {
        &self.canonical_value_digest
    }
}

fn map_host_value(value: &JsonValue) -> Result<Value, CheckedInputError> {
    match value {
        JsonValue::Bool(value) => Ok(Value::Bool(*value)),
        JsonValue::Integer(value) => Ok(Value::int(*value)),
        JsonValue::String(value) => Ok(Value::Str(value.as_str().into())),
        JsonValue::Array(values) => Ok(Value::list(
            values
                .iter()
                .map(map_host_value)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter(),
        )),
        JsonValue::Object(object) if object.len() == 1 => {
            if let Some(value) = object.get("$rat") {
                return map_rational(value);
            }
            if let Some(value) = object.get("$real") {
                return map_real(value);
            }
            if let Some(value) = object.get("$sym") {
                return map_symbol(value);
            }
            Err(CheckedInputError::ProfileInvalid)
        }
        JsonValue::Null | JsonValue::Object(_) => Err(CheckedInputError::ProfileInvalid),
    }
}

fn map_rational(value: &JsonValue) -> Result<Value, CheckedInputError> {
    let object = value.as_object().ok_or(CheckedInputError::ProfileInvalid)?;
    if object.len() != 2 {
        return Err(CheckedInputError::ProfileInvalid);
    }
    let numerator = object
        .get("n")
        .and_then(JsonValue::as_str)
        .ok_or(CheckedInputError::ProfileInvalid)?;
    let denominator = object
        .get("d")
        .and_then(JsonValue::as_str)
        .ok_or(CheckedInputError::ProfileInvalid)?;
    validate_integer_string(numerator, true)?;
    validate_integer_string(denominator, false)?;
    let numerator_digits = numerator.strip_prefix('-').unwrap_or(numerator).len();
    if numerator_digits > MAX_RATIONAL_DIGITS || denominator.len() > MAX_RATIONAL_DIGITS {
        return Err(CheckedInputError::ResourceLimit);
    }
    let numerator = numerator
        .parse::<BigInt>()
        .map_err(|_| CheckedInputError::ProfileInvalid)?;
    let denominator = denominator
        .parse::<BigInt>()
        .map_err(|_| CheckedInputError::ProfileInvalid)?;
    // v8.6 makes the tagged host grammar disjoint: denominator-one values
    // must use the JSON-integer production so application code can test the
    // required host type after P-3 mapping without losing tag provenance.
    if denominator <= BigInt::one() || numerator.gcd(&denominator) != BigInt::one() {
        return Err(CheckedInputError::ProfileInvalid);
    }
    Ok(Value::ratio(numerator, denominator))
}

fn map_real(value: &JsonValue) -> Result<Value, CheckedInputError> {
    let text = value.as_str().ok_or(CheckedInputError::ProfileInvalid)?;
    let parsed = text
        .parse::<f64>()
        .map_err(|_| CheckedInputError::ProfileInvalid)?;
    if !parsed.is_finite() || format_real(parsed) != text {
        return Err(CheckedInputError::ProfileInvalid);
    }
    Value::real(parsed).ok_or(CheckedInputError::ProfileInvalid)
}

fn map_symbol(value: &JsonValue) -> Result<Value, CheckedInputError> {
    let name = value.as_str().ok_or(CheckedInputError::ProfileInvalid)?;
    if name == "input" || COVERED_PRIMITIVES.contains(&name) {
        return Err(CheckedInputError::ProfileInvalid);
    }
    let syntax =
        read_one(name, "<checked-input-symbol>").map_err(|_| CheckedInputError::ProfileInvalid)?;
    match syntax.node {
        SyntaxKind::Sym(parsed) if parsed.as_ref() == name => Ok(Value::Sym(parsed)),
        _ => Err(CheckedInputError::ProfileInvalid),
    }
}

fn validate_integer_string(value: &str, allow_negative: bool) -> Result<(), CheckedInputError> {
    let digits = if let Some(rest) = value.strip_prefix('-') {
        if !allow_negative || rest == "0" {
            return Err(CheckedInputError::ProfileInvalid);
        }
        rest
    } else {
        value
    };
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return Err(CheckedInputError::ProfileInvalid);
    }
    Ok(())
}

pub fn ordinary_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &str) -> Result<CheckedInput, CheckedInputError> {
        CheckedInput::parse(value.as_bytes())
    }

    #[test]
    fn maps_every_checked_host_variant_and_is_deterministic() {
        let bytes = b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": [\n    true,\n    -7,\n    \"x\",\n    {\n      \"$rat\": {\n        \"d\": \"2\",\n        \"n\": \"1\"\n      }\n    },\n    {\n      \"$real\": \"1.5\"\n    },\n    {\n      \"$sym\": \"ok\"\n    }\n  ]\n}\n";
        let a = CheckedInput::parse(bytes).unwrap();
        let b = CheckedInput::parse(bytes).unwrap();
        assert_eq!(a.raw_digest(), b.raw_digest());
        assert_eq!(a.canonical_value_digest(), b.canonical_value_digest());
        assert_eq!(a.canonical_value(), b.canonical_value());
    }

    #[test]
    fn fixes_checked_input_boundaries() {
        assert_eq!(
            parse("null\n").unwrap_err(),
            CheckedInputError::ProfileInvalid
        );
        assert_eq!(
            parse("{\"input\":\"csk.checked-input/v1\",\"value\":null}\n").unwrap_err(),
            CheckedInputError::ProfileInvalid
        );
        assert_eq!(
            parse("{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": {\n    \"$sym\": \"input\"\n  }\n}\n").unwrap_err(),
            CheckedInputError::ProfileInvalid
        );
        assert_eq!(
            parse("{}\ntrailing").unwrap_err(),
            CheckedInputError::ParseFailed
        );
        assert_eq!(
            parse("{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": {\n    \"$rat\": {\n      \"d\": \"1\",\n      \"n\": \"7\"\n    }\n  }\n}\n").unwrap_err(),
            CheckedInputError::ProfileInvalid
        );
    }

    #[test]
    fn input_byte_and_rational_digit_limits_are_exact() {
        let empty = JsonValue::object([
            ("input", JsonValue::String(CHECKED_INPUT_TAG.to_string())),
            ("value", JsonValue::String(String::new())),
        ])
        .unwrap();
        let overhead = write_canonical(&empty).unwrap().len();
        let exact = JsonValue::object([
            ("input", JsonValue::String(CHECKED_INPUT_TAG.to_string())),
            (
                "value",
                JsonValue::String("a".repeat(MAX_INPUT_BYTES - overhead)),
            ),
        ])
        .unwrap();
        let exact = write_canonical(&exact).unwrap();
        assert_eq!(exact.len(), MAX_INPUT_BYTES);
        assert!(CheckedInput::parse(&exact).is_ok());
        let mut plus_one = exact.clone();
        plus_one.insert(plus_one.len() - 3, b'a');
        assert_eq!(
            CheckedInput::parse(&plus_one).unwrap_err(),
            CheckedInputError::ResourceLimit
        );

        let rational = |digits: usize| {
            let denominator = format!("1{}", "0".repeat(digits - 1));
            let value = JsonValue::object([(
                "$rat",
                JsonValue::object([
                    ("d", JsonValue::String(denominator)),
                    ("n", JsonValue::String("1".to_string())),
                ])
                .unwrap(),
            )])
            .unwrap();
            write_canonical(
                &JsonValue::object([
                    ("input", JsonValue::String(CHECKED_INPUT_TAG.to_string())),
                    ("value", value),
                ])
                .unwrap(),
            )
            .unwrap()
        };
        assert!(CheckedInput::parse(&rational(MAX_RATIONAL_DIGITS)).is_ok());
        assert_eq!(
            CheckedInput::parse(&rational(MAX_RATIONAL_DIGITS + 1)).unwrap_err(),
            CheckedInputError::ResourceLimit
        );
    }
}
