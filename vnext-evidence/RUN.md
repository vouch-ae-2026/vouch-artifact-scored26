# Running The vNext Addendum Check

From the artifact bundle root:

```sh
node vnext-evidence/scripts/check-vnext-evidence.mjs
```

The check reads only files inside this anonymous artifact bundle. It verifies the
additive vNext evidence records and confirms that the original welfare receipt
still carries the expected v1 boundary exclusions.

The root bundle check remains unchanged:

```sh
npm run check
```

The two checks are intentionally separate. The original check covers the
submitted artifact surface. The vNext check covers the additive evidence
directory.
