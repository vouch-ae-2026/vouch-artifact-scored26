# Consumer capability boundary

The repaired consumer API separates authenticated Native evidence, promoted
Native decisions, and checked external Bridge evidence as live in-process
capabilities. Serialized reports are public projections, not capabilities.

This is an honest-consumer boundary. An application can ignore the package,
discard its decisions, or draw a false interface. The capability design does
not constrain a deliberately dishonest application, and checked Bridge
evidence is not authenticated, fresh, trusted, or independently witnessed.

Stage 7 adds the complete closed nine-field `vouch.bridge-report/v0` schema and
fixed-order comparison against an entry-copied expected profile, engine digest,
source bytes, input bytes, and canonical input-value digest. A successful check
mints only `CheckedBridgeEvidence` with runtime status `checked-external`; it
does not promote a decision or enter either Native renderer or Native promotion
path.

The Rust `verify-bridge` command mirrors that boundary and publishes a canonical
checked/rejected report atomically without replacing an existing path. Those
serialized reports remain projections and cannot be deserialized into a live
capability.
