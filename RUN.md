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
