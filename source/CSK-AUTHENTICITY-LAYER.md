# Authenticity Layer Design

Status: v1.3.7 candidate design. This is not an active Lispex Vouch claim.

Lispex Vouch receipts, verify reports, and replay reports are artifact-consistency
records. They bind deterministic bytes to hashes and comparison reports. They do
not identify who created a receipt, prove when it was created, prove who applied
a decision, or prove that a deployed system used the same rule.

Those questions belong to a separate authenticity layer.

## 1. Layer Boundary

The current Vouch layer attests:

- deterministic receipt and report bytes
- hash preimages and schema conformance
- source hash checks when a source file is supplied
- replay comparisons over committed receipt corpora

The current Vouch layer excludes:

- receipt-authenticity
- generation-honesty
- issuer-binding
- timestamping
- input-provenance
- non-repudiation
- deployment-attestation
- external-independent-verification

An authenticity layer MAY bind a Vouch artifact to signer identity, a timestamp
service, release provenance, or deployment logs. It MUST NOT rewrite the meaning
of the underlying receipt. The receipt remains the byte-level record. The
authenticity layer is an envelope around that record.

## 2. Candidate Envelope

A future envelope can be a sibling artifact:

```json
{
  "vouch_authenticity": "csk.vouch-authenticity/v0",
  "subject": {
    "path": "receipts/refund-window.json",
    "hash": {
      "algo": "sha-256",
      "domain": "csk/differential-receipt-hash/v0",
      "hex": "<64-hex>"
    }
  },
  "signatures": [],
  "timestamps": [],
  "provenance": [],
  "boundary": {
    "attests": [],
    "excludes": [
      "legal-sufficiency",
      "regulatory-approval",
      "semantic-equivalence",
      "external-independent-verification"
    ]
  }
}
```

The envelope references a subject hash. It does not embed itself into the subject
and does not add a self hash field to the subject. This keeps the v1.2.16 Layer
A and Layer B split intact.

## 3. Signing

Signing MAY attest that a key holder signed the subject hash. It does not by
itself prove that the signer ran the generator honestly or applied the decision
to a customer. Key custody, signer policy, rotation, revocation, and audit trail
are outside the current reference implementation.

## 4. Timestamping

Timestamping MAY attest that a subject hash existed before or at a recorded time
according to the timestamp service. It does not prove when the decision was
actually applied, who applied it, or that the timestamp service is legally
sufficient for a given jurisdiction.

## 5. Deployment And Execution

Deployment and execution claims require host-system evidence. Examples include
deployment provenance, runtime logs, request identifiers, operator identity, and
policy for linking those records to a Vouch receipt. None of those are present in
the v1.3.7 reference surface.

## 6. Promotion Criteria

This design can move from candidate to active only after all of the following
exist:

- a deterministic `csk.vouch-authenticity/v0` schema
- at least one signing or timestamp fixture
- path-neutral JSON and no self-hash checks
- negative fixtures for tampered subject hashes, missing signatures, malformed
  timestamps, and mismatched envelope subjects
- public copy that says the layer attests only the implemented trust facts

Until then, Lispex Vouch public copy must keep saying that receipts are records,
not proof of generation honesty, receipt authenticity, decision application, or
deployment.
