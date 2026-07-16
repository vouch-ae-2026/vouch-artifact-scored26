//! Closed Rust data model for `csk.differential-receipt/v0`.

use vouch::artifact_json::{write_canonical, JsonValue, JsonWriteError};
use vouch::dsse::encode_base64;

use super::graph::{graph_to_json, ContractGraph};
use super::transcript::{Terminal, Transcript};

pub const DIFFERENTIAL_RECEIPT_TAG: &str = "csk.differential-receipt/v0";
pub const MEANING_ENV_REPORT_TAG: &str = "csk.meaning-env-report/v0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildVariant {
    Release,
    Mutant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComparisonStatus {
    Agree,
    Disagree,
    NotComparable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineIdentity {
    pub executable_sha256: String,
    pub target_triple: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionIdentity {
    pub context_digest: String,
    pub lispex_version: String,
    pub build_commit: String,
    pub build_variant: BuildVariant,
    pub mutant_id: Option<String>,
    pub target_triple: String,
    pub executable_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteIdentity {
    pub sha256: String,
    pub byte_length: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputIdentity {
    pub sha256: String,
    pub byte_length: usize,
    pub canonical_value_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalProgramIdentity {
    pub normalized_sha256: String,
    pub normalized_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphReceiptValue {
    pub graph_sha256: String,
    pub graph: ContractGraph,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceReport {
    pub transcript_sha256: String,
    pub transcript: Transcript,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeaningEnvReport {
    pub graph_sha256: String,
    pub transcript_sha256: String,
    pub node_count: usize,
    pub transcript: Transcript,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Comparison {
    pub status: ComparisonStatus,
    pub first_divergence_index: Option<usize>,
    pub comparison_unavailable_at: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptDiagnostic {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DifferentialReceipt {
    pub engine: EngineIdentity,
    pub execution: ExecutionIdentity,
    pub source: ByteIdentity,
    pub input: InputIdentity,
    pub canonical: CanonicalProgramIdentity,
    pub graph: GraphReceiptValue,
    pub reference: TraceReport,
    pub meaning_env: MeaningEnvReport,
    pub comparison: Comparison,
    pub diagnostics: Vec<ReceiptDiagnostic>,
    pub boundary_statement_sha256: String,
}

impl DifferentialReceipt {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::object([
            (
                "differential_receipt",
                JsonValue::String(DIFFERENTIAL_RECEIPT_TAG.to_string()),
            ),
            ("engine", self.engine.to_json()),
            ("execution", self.execution.to_json()),
            ("source", self.source.to_json()),
            ("input", self.input.to_json()),
            ("canonical", self.canonical.to_json()),
            ("graph", self.graph.to_json()),
            ("reference", self.reference.to_json()),
            ("meaning_env", self.meaning_env.to_json()),
            ("comparison", self.comparison.to_json()),
            (
                "diagnostics",
                JsonValue::Array(
                    self.diagnostics
                        .iter()
                        .map(ReceiptDiagnostic::to_json)
                        .collect(),
                ),
            ),
            (
                "boundary",
                object([("statement_sha256", string(&self.boundary_statement_sha256))]),
            ),
        ])
        .expect("receipt fields are unique")
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, JsonWriteError> {
        write_canonical(&self.to_json())
    }
}

impl EngineIdentity {
    fn to_json(&self) -> JsonValue {
        object([
            ("executable_sha256", string(&self.executable_sha256)),
            ("target_triple", string(&self.target_triple)),
        ])
    }
}

impl ExecutionIdentity {
    fn to_json(&self) -> JsonValue {
        object([
            ("invocation", string("native-checked")),
            ("context_digest", string(&self.context_digest)),
            ("profile", string("csk.checked-profile/v1")),
            ("lispex_version", string(&self.lispex_version)),
            ("build_commit", string(&self.build_commit)),
            (
                "build_variant",
                string(match self.build_variant {
                    BuildVariant::Release => "release",
                    BuildVariant::Mutant => "mutant",
                }),
            ),
            (
                "mutant_id",
                self.mutant_id
                    .as_deref()
                    .map(string)
                    .unwrap_or(JsonValue::Null),
            ),
            ("target_triple", string(&self.target_triple)),
            ("executable_sha256", string(&self.executable_sha256)),
        ])
    }
}

impl ByteIdentity {
    fn to_json(&self) -> JsonValue {
        object([
            ("sha256", string(&self.sha256)),
            ("byte_length", integer(self.byte_length)),
        ])
    }
}

impl InputIdentity {
    fn to_json(&self) -> JsonValue {
        object([
            ("sha256", string(&self.sha256)),
            ("byte_length", integer(self.byte_length)),
            (
                "canonical_value_sha256",
                string(&self.canonical_value_sha256),
            ),
        ])
    }
}

impl CanonicalProgramIdentity {
    fn to_json(&self) -> JsonValue {
        object([
            ("normalized_sha256", string(&self.normalized_sha256)),
            (
                "normalized_bytes_b64",
                string(&encode_base64(&self.normalized_bytes)),
            ),
        ])
    }
}

impl GraphReceiptValue {
    fn to_json(&self) -> JsonValue {
        object([
            ("graph_sha256", string(&self.graph_sha256)),
            ("node_count", integer(self.graph.nodes.len())),
            ("value", graph_to_json(&self.graph)),
        ])
    }
}

impl TraceReport {
    fn to_json(&self) -> JsonValue {
        object([
            ("transcript_sha256", string(&self.transcript_sha256)),
            ("terminal", self.transcript.terminal.to_json()),
            ("transcript", self.transcript.to_json()),
        ])
    }
}

impl MeaningEnvReport {
    fn to_json(&self) -> JsonValue {
        object([
            ("meaning_env", string(MEANING_ENV_REPORT_TAG)),
            ("graph_sha256", string(&self.graph_sha256)),
            ("transcript_sha256", string(&self.transcript_sha256)),
            ("node_count", integer(self.node_count)),
            ("terminal", self.transcript.terminal.to_json()),
            ("transcript", self.transcript.to_json()),
        ])
    }
}

impl Comparison {
    fn to_json(&self) -> JsonValue {
        object([
            (
                "status",
                string(match self.status {
                    ComparisonStatus::Agree => "agree",
                    ComparisonStatus::Disagree => "disagree",
                    ComparisonStatus::NotComparable => "not-comparable",
                }),
            ),
            (
                "first_divergence_index",
                optional_integer(self.first_divergence_index),
            ),
            (
                "comparison_unavailable_at",
                optional_integer(self.comparison_unavailable_at),
            ),
        ])
    }
}

impl ReceiptDiagnostic {
    fn to_json(&self) -> JsonValue {
        object([
            ("code", string(&self.code)),
            ("message", string(&self.message)),
        ])
    }
}

fn object<const N: usize>(members: [(&str, JsonValue); N]) -> JsonValue {
    JsonValue::object(members).expect("schema fields are unique")
}

fn string(value: &str) -> JsonValue {
    JsonValue::String(value.to_string())
}

fn integer(value: usize) -> JsonValue {
    JsonValue::Integer(value as i64)
}

fn optional_integer(value: Option<usize>) -> JsonValue {
    value.map(integer).unwrap_or(JsonValue::Null)
}

#[allow(dead_code)]
fn terminal(report: &TraceReport) -> &Terminal {
    &report.transcript.terminal
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vouch_native::canonical_value::CanonicalValue;
    use crate::vouch_native::graph::ContractNode;
    use crate::vouch_native::transcript::TranscriptEvent;

    #[test]
    fn receipt_type_emits_exact_twelve_member_shape() {
        let transcript = Transcript {
            events: vec![TranscriptEvent::Value {
                form_index: 0,
                value: CanonicalValue::Boolean(true),
            }],
            terminal: Terminal::Completed,
        };
        let graph = ContractGraph {
            roots: vec![0],
            nodes: vec![ContractNode::Lit {
                value: CanonicalValue::Boolean(true),
            }],
        };
        let receipt = DifferentialReceipt {
            engine: EngineIdentity {
                executable_sha256: format!("sha256:{}", "0".repeat(64)),
                target_triple: "test".to_string(),
            },
            execution: ExecutionIdentity {
                context_digest: "0".repeat(64),
                lispex_version: "test".to_string(),
                build_commit: "0".repeat(40),
                build_variant: BuildVariant::Release,
                mutant_id: None,
                target_triple: "test".to_string(),
                executable_sha256: format!("sha256:{}", "0".repeat(64)),
            },
            source: ByteIdentity {
                sha256: "0".repeat(64),
                byte_length: 1,
            },
            input: InputIdentity {
                sha256: "0".repeat(64),
                byte_length: 1,
                canonical_value_sha256: "0".repeat(64),
            },
            canonical: CanonicalProgramIdentity {
                normalized_sha256: "0".repeat(64),
                normalized_bytes: b"x\n".to_vec(),
            },
            graph: GraphReceiptValue {
                graph_sha256: "0".repeat(64),
                graph: graph.clone(),
            },
            reference: TraceReport {
                transcript_sha256: "0".repeat(64),
                transcript: transcript.clone(),
            },
            meaning_env: MeaningEnvReport {
                graph_sha256: "0".repeat(64),
                transcript_sha256: "0".repeat(64),
                node_count: 1,
                transcript,
            },
            comparison: Comparison {
                status: ComparisonStatus::Agree,
                first_divergence_index: None,
                comparison_unavailable_at: None,
            },
            diagnostics: vec![],
            boundary_statement_sha256: "0".repeat(64),
        };
        assert_eq!(receipt.to_json().as_object().unwrap().len(), 12);
        assert!(receipt.canonical_bytes().unwrap().ends_with(b"\n"));
    }
}
