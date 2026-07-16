//! Closed `csk.transcript/v0` Rust model.

use vouch::artifact_json::{write_canonical, JsonValue, JsonWriteError};

use super::canonical_value::CanonicalValue;

pub const TRANSCRIPT_TAG: &str = "csk.transcript/v0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranscriptEvent {
    Output {
        form_index: usize,
        bytes_b64: String,
    },
    Value {
        form_index: usize,
        value: CanonicalValue,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationPhase {
    Reference,
    Meaning,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LanguageFaultCode {
    ArityMismatch,
    TypeError,
    DivisionByZero,
    NumericDomainError,
    ReferenceBudgetExhausted,
    MeaningEnvBudgetExhausted,
}

impl LanguageFaultCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArityMismatch => "arity-mismatch",
            Self::TypeError => "type-error",
            Self::DivisionByZero => "division-by-zero",
            Self::NumericDomainError => "numeric-domain-error",
            Self::ReferenceBudgetExhausted => "reference-budget-exhausted",
            Self::MeaningEnvBudgetExhausted => "meaning-env-budget-exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InfrastructureFailureCode {
    ReferenceExecutionFailed,
    MeaningExecutionFailed,
}

impl InfrastructureFailureCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReferenceExecutionFailed => "native-reference-execution-failed",
            Self::MeaningExecutionFailed => "native-meaning-execution-failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Terminal {
    Completed,
    LanguageFault {
        code: LanguageFaultCode,
        form_index: usize,
    },
    InfrastructureFailure {
        code: InfrastructureFailureCode,
        phase: EvaluationPhase,
        next_form_index: usize,
    },
}

impl Terminal {
    pub fn to_json(&self) -> JsonValue {
        match self {
            Self::Completed => {
                JsonValue::object([("kind", JsonValue::String("completed".to_string()))])
                    .expect("terminal fields are unique")
            }
            Self::LanguageFault { code, form_index } => JsonValue::object([
                ("kind", JsonValue::String("language-fault".to_string())),
                ("code", JsonValue::String(code.as_str().to_string())),
                ("form_index", JsonValue::Integer(*form_index as i64)),
            ])
            .expect("terminal fields are unique"),
            Self::InfrastructureFailure {
                code,
                phase,
                next_form_index,
            } => JsonValue::object([
                (
                    "kind",
                    JsonValue::String("infrastructure-failure".to_string()),
                ),
                ("code", JsonValue::String(code.as_str().to_string())),
                (
                    "phase",
                    JsonValue::String(
                        match phase {
                            EvaluationPhase::Reference => "reference-evaluation",
                            EvaluationPhase::Meaning => "meaning-evaluation",
                        }
                        .to_string(),
                    ),
                ),
                (
                    "next_form_index",
                    JsonValue::Integer(*next_form_index as i64),
                ),
            ])
            .expect("terminal fields are unique"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transcript {
    pub events: Vec<TranscriptEvent>,
    pub terminal: Terminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptError(pub String);

impl TranscriptEvent {
    pub fn to_json(&self) -> JsonValue {
        match self {
            Self::Output {
                form_index,
                bytes_b64,
            } => JsonValue::object([
                ("kind", JsonValue::String("output".to_string())),
                ("form_index", JsonValue::Integer(*form_index as i64)),
                ("bytes_b64", JsonValue::String(bytes_b64.clone())),
            ]),
            Self::Value { form_index, value } => JsonValue::object([
                ("kind", JsonValue::String("value".to_string())),
                ("form_index", JsonValue::Integer(*form_index as i64)),
                ("value", value.to_json()),
            ]),
        }
        .expect("event fields are unique")
    }
}

impl Transcript {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::object([
            ("transcript", JsonValue::String(TRANSCRIPT_TAG.to_string())),
            (
                "events",
                JsonValue::Array(self.events.iter().map(TranscriptEvent::to_json).collect()),
            ),
            ("terminal", self.terminal.to_json()),
        ])
        .expect("transcript fields are unique")
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, JsonWriteError> {
        write_canonical(&self.to_json())
    }

    pub fn validate(&self, root_count: usize) -> Result<(), TranscriptError> {
        if root_count == 0 {
            return Err(TranscriptError("zero-root transcript".to_string()));
        }
        if self
            .events
            .iter()
            .any(|event| matches!(event, TranscriptEvent::Output { .. }))
        {
            return Err(TranscriptError(
                "output event forbidden in checked-profile/v1".to_string(),
            ));
        }
        let expected_count = match self.terminal {
            Terminal::Completed => root_count,
            Terminal::LanguageFault { form_index, .. } => {
                if form_index >= root_count {
                    return Err(TranscriptError("fault form index out of range".to_string()));
                }
                form_index
            }
            Terminal::InfrastructureFailure {
                next_form_index, ..
            } => {
                if next_form_index > root_count {
                    return Err(TranscriptError(
                        "failure next form index out of range".to_string(),
                    ));
                }
                next_form_index
            }
        };
        if self.events.len() != expected_count {
            return Err(TranscriptError("incomplete transcript".to_string()));
        }
        for (expected, event) in self.events.iter().enumerate() {
            let TranscriptEvent::Value { form_index, value } = event else {
                unreachable!()
            };
            if *form_index != expected {
                return Err(TranscriptError("noncanonical event order".to_string()));
            }
            if value.contains_decision()
                && (!matches!(value, CanonicalValue::Decision(_)) || expected + 1 != root_count)
            {
                return Err(TranscriptError(
                    "decision at forbidden position".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decision;

    #[test]
    fn decision_must_be_complete_final_root_value() {
        let transcript = Transcript {
            events: vec![
                TranscriptEvent::Value {
                    form_index: 0,
                    value: CanonicalValue::Decision(Decision::Deny),
                },
                TranscriptEvent::Value {
                    form_index: 1,
                    value: CanonicalValue::Decision(Decision::Approve),
                },
            ],
            terminal: Terminal::Completed,
        };
        assert!(transcript.validate(2).is_err());
    }
}
