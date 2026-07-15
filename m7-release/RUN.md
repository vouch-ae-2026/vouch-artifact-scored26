# Running the M7 Addendum Check

From the artifact bundle root:

    npm run check:m7

The checker performs these operations without network access:

1. hashes every distributed M7 evidence file against the manifest;
2. verifies the Ed25519 signatures on descriptor D and observation R using the
   bundled consumer trust policy;
3. verifies the D to Q to R to P to S digest links;
4. verifies Q's owner-report digests and the recorded result counts;
5. verifies that the condition ledger contains 211 built rows and only P-4 and
   P-11 as not-started;
6. exercises tampered-signature and tampered-report negative controls.

Run all baseline, vNext, M7, and anonymity checks with:

    npm run check
