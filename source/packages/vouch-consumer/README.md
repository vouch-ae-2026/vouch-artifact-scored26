# Lispex Vouch consumer

This package keeps authenticated Native evidence, promoted Native decisions, and
checked external Bridge evidence as separate live in-process capabilities. A
serialized verification report is never a capability and cannot be promoted.

The boundary is intentionally limited: an application can ignore this package,
discard its result, or draw a false interface. These capabilities constrain
honest code that elects to use the API; they do not constrain a deliberately
dishonest application or authenticate Bridge evidence.

The Stage 7 Bridge entry point applies the bounded canonical byte gate, the
closed nine-field `vouch.bridge-report/v0` schema, and fixed-order comparison
against a private copy of the caller-supplied expected context before minting a
distinct `CheckedBridgeEvidence` capability. Bridge evidence remains external
consistency evidence; it is not authenticated, fresh, or independently
witnessed.
