//! Canonical `csk.artifact-json/v0` bytes and bounded resource preflight.

use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;

pub const MAX_ARTIFACT_BYTES: usize = 16_777_216;
pub const MAX_JSON_DEPTH: usize = 128;
pub const MAX_OBJECT_MEMBERS: usize = 10_000;
pub const MAX_ARRAY_MEMBERS: usize = 10_000;
pub const MAX_STRING_BYTES: usize = 1_048_576;
pub const MAX_JSON_NODES: usize = 100_000;
pub const MIN_SAFE_INTEGER: i64 = -9_007_199_254_740_991;
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    pub fn object<I, K>(members: I) -> Result<Self, ProgrammaticJsonError>
    where
        I: IntoIterator<Item = (K, JsonValue)>,
        K: Into<String>,
    {
        let mut object = BTreeMap::new();
        for (name, value) in members {
            let name = name.into();
            if object.insert(name.clone(), value).is_some() {
                return Err(ProgrammaticJsonError::DuplicateMember(name));
            }
        }
        Ok(Self::Object(object))
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgrammaticJsonError {
    DuplicateMember(String),
}

impl fmt::Display for ProgrammaticJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateMember(name) => write!(f, "duplicate JSON member: {name}"),
        }
    }
}

impl Error for ProgrammaticJsonError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawArtifactKind {
    Artifact,
    Envelope,
    Payload,
    BridgeReport,
}

impl RawArtifactKind {
    pub const fn limit_subject(self) -> &'static str {
        match self {
            Self::Artifact => "artifact-bytes",
            Self::Envelope => "envelope-bytes",
            Self::Payload => "payload-bytes",
            Self::BridgeReport => "bridge-report-bytes",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonGateError {
    NonCanonicalArtifactJson,
    ResourceLimit(&'static str),
}

impl JsonGateError {
    pub const fn class(&self) -> &'static str {
        match self {
            Self::NonCanonicalArtifactJson => "non-canonical-artifact-json",
            Self::ResourceLimit(_) => "artifact-resource-limit",
        }
    }

    pub const fn subject(&self) -> Option<&'static str> {
        match self {
            Self::NonCanonicalArtifactJson => None,
            Self::ResourceLimit(subject) => Some(subject),
        }
    }
}

impl fmt::Display for JsonGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalArtifactJson => f.write_str("non-canonical-artifact-json"),
            Self::ResourceLimit(subject) => write!(f, "artifact-resource-limit: {subject}"),
        }
    }
}

impl Error for JsonGateError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonWriteError {
    IntegerOutOfRange(i64),
}

impl fmt::Display for JsonWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntegerOutOfRange(value) => {
                write!(f, "integer outside csk.artifact-json/v0 range: {value}")
            }
        }
    }
}

impl Error for JsonWriteError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceCounts {
    pub raw_byte_count: usize,
    pub maximum_container_depth: usize,
    pub total_json_node_count: usize,
}

/// A bounded parse result. The object model exists only after token-level
/// resource and duplicate-member checks have succeeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreflightedJson {
    value: JsonValue,
    counts: ResourceCounts,
}

impl PreflightedJson {
    pub const fn counts(&self) -> ResourceCounts {
        self.counts
    }

    pub fn value(&self) -> &JsonValue {
        &self.value
    }
}

/// A canonical byte-gated value. Future schema and cryptographic stages accept
/// this type rather than raw bytes, structurally pinning preflight first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalJson {
    bytes: Vec<u8>,
    value: JsonValue,
    counts: ResourceCounts,
}

impl CanonicalJson {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn value(&self) -> &JsonValue {
        &self.value
    }

    pub const fn counts(&self) -> ResourceCounts {
        self.counts
    }
}

pub fn resource_preflight(
    bytes: &[u8],
    kind: RawArtifactKind,
) -> Result<PreflightedJson, JsonGateError> {
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(JsonGateError::ResourceLimit(kind.limit_subject()));
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(JsonGateError::NonCanonicalArtifactJson);
    }
    let source = std::str::from_utf8(bytes).map_err(|_| JsonGateError::NonCanonicalArtifactJson)?;
    let mut parser = Parser {
        source,
        offset: 0,
        current_container_depth: 0,
        maximum_container_depth: 0,
        total_json_node_count: 0,
    };
    parser.skip_whitespace();
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.offset != source.len() {
        return Err(JsonGateError::NonCanonicalArtifactJson);
    }
    Ok(PreflightedJson {
        value,
        counts: ResourceCounts {
            raw_byte_count: bytes.len(),
            maximum_container_depth: parser.maximum_container_depth,
            total_json_node_count: parser.total_json_node_count,
        },
    })
}

pub fn canonical_gate(bytes: &[u8], kind: RawArtifactKind) -> Result<CanonicalJson, JsonGateError> {
    let preflighted = resource_preflight(bytes, kind)?;
    let written = write_canonical(preflighted.value())
        .map_err(|_| JsonGateError::NonCanonicalArtifactJson)?;
    if written != bytes {
        return Err(JsonGateError::NonCanonicalArtifactJson);
    }
    Ok(CanonicalJson {
        bytes: bytes.to_vec(),
        value: preflighted.value,
        counts: preflighted.counts,
    })
}

pub fn write_canonical(value: &JsonValue) -> Result<Vec<u8>, JsonWriteError> {
    let mut output = Vec::new();
    write_value(value, 0, &mut output)?;
    output.push(b'\n');
    Ok(output)
}

fn write_value(
    value: &JsonValue,
    depth: usize,
    output: &mut Vec<u8>,
) -> Result<(), JsonWriteError> {
    match value {
        JsonValue::Null => output.extend_from_slice(b"null"),
        JsonValue::Bool(false) => output.extend_from_slice(b"false"),
        JsonValue::Bool(true) => output.extend_from_slice(b"true"),
        JsonValue::Integer(value) => {
            if !(MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(value) {
                return Err(JsonWriteError::IntegerOutOfRange(*value));
            }
            output.extend_from_slice(value.to_string().as_bytes());
        }
        JsonValue::String(value) => write_string(value, output),
        JsonValue::Array(values) if values.is_empty() => output.extend_from_slice(b"[]"),
        JsonValue::Array(values) => {
            output.extend_from_slice(b"[\n");
            for (index, item) in values.iter().enumerate() {
                indent(depth + 1, output);
                write_value(item, depth + 1, output)?;
                if index + 1 != values.len() {
                    output.push(b',');
                }
                output.push(b'\n');
            }
            indent(depth, output);
            output.push(b']');
        }
        JsonValue::Object(values) if values.is_empty() => output.extend_from_slice(b"{}"),
        JsonValue::Object(values) => {
            output.extend_from_slice(b"{\n");
            for (index, (name, item)) in values.iter().enumerate() {
                indent(depth + 1, output);
                write_string(name, output);
                output.extend_from_slice(b": ");
                write_value(item, depth + 1, output)?;
                if index + 1 != values.len() {
                    output.push(b',');
                }
                output.push(b'\n');
            }
            indent(depth, output);
            output.push(b'}');
        }
    }
    Ok(())
}

fn indent(depth: usize, output: &mut Vec<u8>) {
    output.resize(output.len() + depth.saturating_mul(2), b' ');
}

fn write_string(value: &str, output: &mut Vec<u8>) {
    output.push(b'"');
    for ch in value.chars() {
        match ch {
            '"' => output.extend_from_slice(br#"\""#),
            '\\' => output.extend_from_slice(br#"\\"#),
            '\u{0008}' => output.extend_from_slice(br#"\b"#),
            '\t' => output.extend_from_slice(br#"\t"#),
            '\n' => output.extend_from_slice(br#"\n"#),
            '\u{000c}' => output.extend_from_slice(br#"\f"#),
            '\r' => output.extend_from_slice(br#"\r"#),
            '\u{0000}'..='\u{001f}' => {
                let code = ch as u32;
                output.extend_from_slice(br#"\u00"#);
                output.push(lower_hex(((code >> 4) & 0x0f) as u8));
                output.push(lower_hex((code & 0x0f) as u8));
            }
            _ => {
                let mut encoded = [0_u8; 4];
                output.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    output.push(b'"');
}

const fn lower_hex(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        10..=15 => b'a' + value - 10,
        _ => unreachable!(),
    }
}

struct Parser<'a> {
    source: &'a str,
    offset: usize,
    current_container_depth: usize,
    maximum_container_depth: usize,
    total_json_node_count: usize,
}

impl Parser<'_> {
    fn count_json_node(&mut self) -> Result<(), JsonGateError> {
        self.total_json_node_count = self
            .total_json_node_count
            .checked_add(1)
            .ok_or(JsonGateError::ResourceLimit("json-nodes"))?;
        if self.total_json_node_count > MAX_JSON_NODES {
            return Err(JsonGateError::ResourceLimit("json-nodes"));
        }
        Ok(())
    }

    fn parse_value(&mut self) -> Result<JsonValue, JsonGateError> {
        self.count_json_node()?;
        match self.peek() {
            Some(b'n') => {
                self.expect_literal(b"null")?;
                Ok(JsonValue::Null)
            }
            Some(b'f') => {
                self.expect_literal(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            Some(b't') => {
                self.expect_literal(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'-' | b'0'..=b'9') => self.parse_integer(),
            _ => Err(JsonGateError::NonCanonicalArtifactJson),
        }
    }

    fn enter_container(&mut self) -> Result<(), JsonGateError> {
        self.current_container_depth = self
            .current_container_depth
            .checked_add(1)
            .ok_or(JsonGateError::ResourceLimit("json-depth"))?;
        if self.current_container_depth > MAX_JSON_DEPTH {
            return Err(JsonGateError::ResourceLimit("json-depth"));
        }
        self.maximum_container_depth = self
            .maximum_container_depth
            .max(self.current_container_depth);
        Ok(())
    }

    fn leave_container(&mut self) {
        self.current_container_depth -= 1;
    }

    fn parse_array(&mut self) -> Result<JsonValue, JsonGateError> {
        self.enter_container()?;
        self.offset += 1;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.consume(b']') {
            self.leave_container();
            return Ok(JsonValue::Array(values));
        }
        let mut member_count = 0_usize;
        loop {
            member_count = member_count
                .checked_add(1)
                .ok_or(JsonGateError::ResourceLimit("array-members"))?;
            if member_count > MAX_ARRAY_MEMBERS {
                return Err(JsonGateError::ResourceLimit("array-members"));
            }
            values.push(self.parse_value()?);
            self.skip_whitespace();
            if self.consume(b']') {
                self.leave_container();
                return Ok(JsonValue::Array(values));
            }
            if !self.consume(b',') {
                return Err(JsonGateError::NonCanonicalArtifactJson);
            }
            self.skip_whitespace();
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, JsonGateError> {
        self.enter_container()?;
        self.offset += 1;
        self.skip_whitespace();
        if self.consume(b'}') {
            self.leave_container();
            return Ok(JsonValue::Object(BTreeMap::new()));
        }
        let mut occurrences = Vec::new();
        let mut names = HashSet::new();
        let mut member_count = 0_usize;
        loop {
            if self.peek() != Some(b'"') {
                return Err(JsonGateError::NonCanonicalArtifactJson);
            }
            // A member name is a JSON string occurrence and therefore counts
            // as its own C-LIM-11 node, independently of the member value.
            self.count_json_node()?;
            let name = self.parse_string()?;
            self.skip_whitespace();
            if !self.consume(b':') {
                return Err(JsonGateError::NonCanonicalArtifactJson);
            }
            member_count = member_count
                .checked_add(1)
                .ok_or(JsonGateError::ResourceLimit("object-members"))?;
            if member_count > MAX_OBJECT_MEMBERS {
                return Err(JsonGateError::ResourceLimit("object-members"));
            }
            if !names.insert(name.clone()) {
                return Err(JsonGateError::NonCanonicalArtifactJson);
            }
            self.skip_whitespace();
            let value = self.parse_value()?;
            occurrences.push((name, value));
            self.skip_whitespace();
            if self.consume(b'}') {
                self.leave_container();
                return Ok(JsonValue::Object(occurrences.into_iter().collect()));
            }
            if !self.consume(b',') {
                return Err(JsonGateError::NonCanonicalArtifactJson);
            }
            self.skip_whitespace();
        }
    }

    fn parse_integer(&mut self) -> Result<JsonValue, JsonGateError> {
        let start = self.offset;
        let negative = self.consume(b'-');
        match self.peek() {
            Some(b'0') => {
                self.offset += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(JsonGateError::NonCanonicalArtifactJson);
                }
            }
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.offset += 1;
                }
            }
            _ => return Err(JsonGateError::NonCanonicalArtifactJson),
        }
        if negative && &self.source[start..self.offset] == "-0" {
            return Err(JsonGateError::NonCanonicalArtifactJson);
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E' | b'+')) {
            return Err(JsonGateError::NonCanonicalArtifactJson);
        }
        let value = self.source[start..self.offset]
            .parse::<i64>()
            .map_err(|_| JsonGateError::NonCanonicalArtifactJson)?;
        if !(MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
            return Err(JsonGateError::NonCanonicalArtifactJson);
        }
        Ok(JsonValue::Integer(value))
    }

    fn parse_string(&mut self) -> Result<String, JsonGateError> {
        if !self.consume(b'"') {
            return Err(JsonGateError::NonCanonicalArtifactJson);
        }
        let mut output = String::new();
        let mut decoded_bytes = 0_usize;
        loop {
            let byte = self.peek().ok_or(JsonGateError::NonCanonicalArtifactJson)?;
            let ch = match byte {
                b'"' => {
                    self.offset += 1;
                    return Ok(output);
                }
                b'\\' => {
                    self.offset += 1;
                    self.parse_escape()?
                }
                0x00..=0x1f => return Err(JsonGateError::NonCanonicalArtifactJson),
                _ => {
                    let ch = self.source[self.offset..]
                        .chars()
                        .next()
                        .ok_or(JsonGateError::NonCanonicalArtifactJson)?;
                    self.offset += ch.len_utf8();
                    ch
                }
            };
            decoded_bytes = decoded_bytes
                .checked_add(ch.len_utf8())
                .ok_or(JsonGateError::ResourceLimit("string-bytes"))?;
            if decoded_bytes > MAX_STRING_BYTES {
                return Err(JsonGateError::ResourceLimit("string-bytes"));
            }
            output.push(ch);
        }
    }

    fn parse_escape(&mut self) -> Result<char, JsonGateError> {
        let escaped = self.peek().ok_or(JsonGateError::NonCanonicalArtifactJson)?;
        self.offset += 1;
        match escaped {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => {
                let first = self.parse_hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if !self.consume(b'\\') || !self.consume(b'u') {
                        return Err(JsonGateError::NonCanonicalArtifactJson);
                    }
                    let second = self.parse_hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(JsonGateError::NonCanonicalArtifactJson);
                    }
                    0x10000 + (((first as u32) - 0xd800) << 10) + ((second as u32) - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(JsonGateError::NonCanonicalArtifactJson);
                } else {
                    first as u32
                };
                char::from_u32(scalar).ok_or(JsonGateError::NonCanonicalArtifactJson)
            }
            _ => Err(JsonGateError::NonCanonicalArtifactJson),
        }
    }

    fn parse_hex_quad(&mut self) -> Result<u16, JsonGateError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let byte = self.peek().ok_or(JsonGateError::NonCanonicalArtifactJson)?;
            self.offset += 1;
            let digit = match byte {
                b'0'..=b'9' => (byte - b'0') as u16,
                b'a'..=b'f' => (byte - b'a' + 10) as u16,
                b'A'..=b'F' => (byte - b'A' + 10) as u16,
                _ => return Err(JsonGateError::NonCanonicalArtifactJson),
            };
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn expect_literal(&mut self, expected: &[u8]) -> Result<(), JsonGateError> {
        if self
            .source
            .as_bytes()
            .get(self.offset..self.offset + expected.len())
            != Some(expected)
        {
            return Err(JsonGateError::NonCanonicalArtifactJson);
        }
        self.offset += expected.len();
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.offset += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }
}
