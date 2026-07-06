# Anonymous Vouch Artifact Bundle

This double-blind bundle contains the public artifact-checking surface used by the paper evaluation. It reproduces offline verification, Bridge checking, rule-change replay, adversarial fixture checks, and hash comparison over committed artifacts.

It does not contain the private Rust reference-interpreter implementation, private adapters, commercial infrastructure, git history, or receipt-generation path. Native receipt generation uses the Rust reference interpreter and is outside this public checking surface. This bundle checks committed artifacts, report boundaries, and expected hashes.

Anonymization policy:

- Author, organization, email, commercial-product, and private-engine strings were scrubbed from bundle text.
- The bundle is delivered as a no-history tarball.
- Lispex, Vouch, CSK, and Core Semantic Kernel remain because they are paper-facing terminology.
- The machine boundary enum `topaz-reporting` remains inside native receipts and contracts because changing it would fork the checked artifact contract and break offline verification.

Run `npm run check` from this directory to reproduce the bundle checks.

## vNext Evidence Addendum

The `vnext-evidence/` directory adds post-baseline evidence records without
replacing the original contracts, receipts, or expected hashes.

It contains:

- transcription-fidelity records for five mapped rules across JSON Logic, Cedar,
  and OpenFisca Core
- profile-growth records showing zero proposed CSK Profile admissions
- deterministic generated disjointness, artifact grammar, and mutation records
- a seeded-divergence fixture that records a deterministic `disagree` result

Run the addendum check from this directory:

```sh
node vnext-evidence/scripts/check-vnext-evidence.mjs
```

This addendum does not claim policy correctness, semantic equivalence,
independent verification, receipt authenticity, issuer binding, or generation
honesty.
