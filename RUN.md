# Reproduction Commands

```sh
npm run check
```

Additional vNext evidence check:

```sh
node vnext-evidence/scripts/check-vnext-evidence.mjs
```

The check command runs:

- Vouch Bridge positive verification with source, target, linked-artifact bytes, and expected-context manifest.
- Context-mismatch fixtures for profile, subject, route, checked-profile, and capability declarations.
- Welfare replay over a 12-input committed corpus against the changed receipts.
- Native receipt verification over welfare expected and changed-expected receipts.
- A.1-A.12 laundering-adversarial fixtures with promoted-to-native = 0.
- Expected hash recomputation for committed artifacts.
- M7 D to Q to R to P to S hash-chain and Ed25519 signature verification.
- M7 owner-report digest, fixture, workload, mutation, and ledger checks.
- Whole-tree identity and generic secret scanning with negative controls.

The M7 addendum can also be checked by itself:

    npm run check:m7

The whole-tree anonymity check can also be run by itself:

    npm run check:anonymity
