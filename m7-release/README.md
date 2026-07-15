# M7 Authenticated-Native Release Addendum

This additive directory publishes the completed built-scope M7 release evidence.
It does not replace the baseline bundle or the vNext evidence directory.

Included evidence:

- consumer trust policy and the authenticated release descriptor D;
- pinned-Linux clean-run report Q;
- authenticated reproduction observation R;
- publication record P and terminal publication report S;
- exact-reproduction, fixture, workload, twelve-mutant, and performance owner
  reports;
- the 213-condition ledger;
- the machine-rendered M7 release record.

Observed results at this release:

- terminal S status: pass;
- built fixtures: 163 of 163 matched, zero mismatched and zero skipped;
- workload: 1,536 candidates, 240 selected, 83 flips, 19 held-out flips;
- mutation campaign: 12 seeded and built, 5 activated, 4 detected, 33.3 percent;
- condition ledger: 211 built and 2 not-started.

The two not-started conditions are P-4 and P-11. They remain unresolved because
of the recorded DEV-002 contract contradiction and are not reported conformant.

The 449,651,509-byte source archive is not distributed in this double-blind
addendum because its embedded private Git history is outside the anonymous
surface. Descriptor D still authenticates its exact digest:

sha256:c65d79d8a1deb2230e841793142410472f0aa7b23ef3809ce893b65edf513aa6

This omission means the addendum supports offline verification of the published
signature chain and owner reports, but not a fresh extraction and execution of
the undistributed source archive. The run was performed and audited by the same
implementation agent and is not an independent reproduction. It is evidence of
observed agreement over the checked surface, not proof of semantic equivalence
or policy correctness.

Run the local checker from the bundle root:

    npm run check:m7
