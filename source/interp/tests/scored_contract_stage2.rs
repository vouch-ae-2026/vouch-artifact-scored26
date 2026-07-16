#![cfg(feature = "scored-native-contract")]

use lispex::vouch_native::checked_input::CheckedInput;
use lispex::vouch_native::checked_profile::prepare_checked_program;
use lispex::vouch_native::graph::{
    contract_graph_bytes, contract_graph_digest, lower_contract_graph,
};

const SOURCE: &[u8] =
    b"(define threshold 10)\n(if (< (car input) threshold) (decision-approve) (decision-review))\n";
const INPUT: &[u8] = b"{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": [\n    7\n  ]\n}\n";

#[test]
fn identical_source_and_input_reproduce_every_stage2_preimage_and_digest() {
    let first_program = prepare_checked_program(SOURCE).unwrap();
    let second_program = prepare_checked_program(SOURCE).unwrap();
    let first_input = CheckedInput::parse(INPUT).unwrap();
    let second_input = CheckedInput::parse(INPUT).unwrap();
    let first_graph = lower_contract_graph(first_program.core()).unwrap();
    let second_graph = lower_contract_graph(second_program.core()).unwrap();

    assert_eq!(
        first_program.normalized_bytes(),
        second_program.normalized_bytes()
    );
    assert_eq!(
        contract_graph_bytes(&first_graph).unwrap(),
        contract_graph_bytes(&second_graph).unwrap()
    );
    assert_eq!(
        contract_graph_digest(&first_graph).unwrap(),
        contract_graph_digest(&second_graph).unwrap()
    );
    assert_eq!(first_input.raw_digest(), second_input.raw_digest());
    assert_eq!(
        first_input.canonical_value_digest(),
        second_input.canonical_value_digest()
    );
    assert_eq!(
        first_input.canonical_value(),
        second_input.canonical_value()
    );
}
