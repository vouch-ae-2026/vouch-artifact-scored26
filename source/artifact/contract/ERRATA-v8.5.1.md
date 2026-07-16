# Errata for NATIVE-IMPLEMENTATION-CONDITIONS v8.5.1

This erratum is an additive historical record. It does not modify or reinterpret the byte-frozen v8.5.1 contract or its SHA-256 digest.

The M7 release implemented and validated 211 of the contract's 213 condition rows. `P-4` and `P-11` remained `not-started` because A-1 omitted a total type predicate while P-2 admitted nonnumeric host values and P-4/P-11 required every wrong positional element type to evaluate to `decision-invalid-input`. The seven C-WL-06 invalid transformations did not cover that universal requirement.

The terminal `S=pass` recorded a valid D/Q/R/P/paper chain and passing generated reports for the implemented scope. It was not a valid verdict of complete v8.5.1 conformance: the release gate did not consume the condition ledger, and it failed to reject built-scope rows whose `implementation_status` was not `built` or whose fixture list was empty.

Version 8.6.0 corrects both defects without changing v8.5.1. It versions the checked input and profile, adds a total `exact-integer?` primitive to both evaluators, makes host grammar alternatives disjoint, adds exhaustive application-schema fixtures, and makes 213/213 built, unique, fixture-backed condition coverage a release gate.
