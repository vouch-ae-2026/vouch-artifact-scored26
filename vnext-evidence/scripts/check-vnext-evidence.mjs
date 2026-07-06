#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const evidenceRoot = resolve(scriptDir, '..');
const bundleRoot = resolve(evidenceRoot, '..');

const failures = [];

function readJson(root, rel) {
  return JSON.parse(readFileSync(resolve(root, rel), 'utf8'));
}

function readText(root, rel) {
  return readFileSync(resolve(root, rel), 'utf8');
}

function expect(name, actual, expected) {
  if (actual !== expected) {
    failures.push(`${name}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function expectTrue(name, value) {
  if (value !== true) failures.push(`${name}: expected true, got ${JSON.stringify(value)}`);
}

function expectIncludes(name, list, value) {
  if (!Array.isArray(list) || !list.includes(value)) {
    failures.push(`${name}: missing ${JSON.stringify(value)}`);
  }
}

function nonEmptyNonCommentLoc(text) {
  return text
    .split(/\r?\n/)
    .filter((line) => {
      const trimmed = line.trim();
      return trimmed && !trimmed.startsWith(';');
    }).length;
}

function countPattern(text, pattern) {
  const match = text.match(pattern);
  return match ? match.length : 0;
}

const addendum = readJson(evidenceRoot, 'manifests/v2-addendum.v0.json');
expect('addendum.base_bundle_commit', addendum.base_bundle_commit, '8408e45d');
expectTrue('addendum.preserves_original_surface', addendum.preserves_original_surface);

const ledger = readJson(evidenceRoot, 'manifests/transcription-fidelity-ledger.v0.json');
expect('ledger.tag', ledger.transcription_fidelity_ledger, 'vouch.transcription-fidelity-ledger/v0');
expect('ledger.version', ledger.version, '1.3.11');
expect('ledger.summary.source_manifest_count', ledger.summary.source_manifest_count, 3);
expect('ledger.summary.rule_count', ledger.summary.rule_count, 5);
expect('ledger.summary.case_count', ledger.summary.case_count, 676);
expect('ledger.summary.by_outcome.agree', ledger.summary.by_outcome.agree, 676);
expect('ledger.summary.by_outcome.disagree', ledger.summary.by_outcome.disagree, 0);
expect('ledger.summary.by_outcome.not-run', ledger.summary.by_outcome['not-run'], 0);
expect('ledger.summary.agree_rate', ledger.summary.agree_rate, '676/676');
expect('ledger.summary.invalid_input_case_count', ledger.summary.invalid_input_case_count, 160);
expect('ledger.JSON Logic cases', ledger.summary.source_system_case_counts['JSON Logic'], 68);
expect('ledger.Cedar cases', ledger.summary.source_system_case_counts.Cedar, 64);
expect('ledger.OpenFisca Core cases', ledger.summary.source_system_case_counts['OpenFisca Core'], 544);
expect('ledger.executable-engine rules', ledger.summary.oracle_strength_distribution['executable-engine'], 1);

const complexity = readJson(evidenceRoot, 'manifests/transcription-complexity-metrics.v0.json');
expect('complexity.summary.rule_count', complexity.summary.rule_count, 5);
expect('complexity.summary.case_count', complexity.summary.case_count, 676);
expect('complexity.summary.lispex_non_empty_loc', complexity.summary.lispex_non_empty_loc, 43);
expect('complexity.summary.upstream_non_empty_loc', complexity.summary.upstream_non_empty_loc, 186);
expect('complexity.summary.invalid_input_class_count', complexity.summary.invalid_input_class_count, 2);

const profileGrowth = readJson(evidenceRoot, 'manifests/profile-growth-batch-proposal.v0.json');
expect('profileGrowth.evidence_summary.m2_case_count', profileGrowth.evidence_summary.m2_case_count, 676);
expect('profileGrowth.evidence_summary.observed_out_of_profile_case_count', profileGrowth.evidence_summary.observed_out_of_profile_case_count, 0);
expect('profileGrowth.evidence_summary.profile_expansions_recommended', profileGrowth.evidence_summary.profile_expansions_recommended, 0);
expect('profileGrowth.evidence_summary.l2_promotion_supported_count', profileGrowth.evidence_summary.l2_promotion_supported_count, 0);
expect('profileGrowth.evidence_summary.l3_promotion_supported_count', profileGrowth.evidence_summary.l3_promotion_supported_count, 0);
expect('profileGrowth.proposal.profile_version_change', profileGrowth.proposal.profile_version_change, false);
expect('profileGrowth.proposed_l2_changes length', profileGrowth.proposal.proposed_l2_changes.length, 0);
expect('profileGrowth.proposed_l3_changes length', profileGrowth.proposal.proposed_l3_changes.length, 0);
expect('profileGrowth.proposed_profile_expansions length', profileGrowth.proposal.proposed_profile_expansions.length, 0);

const generated = readJson(evidenceRoot, 'manifests/generated-disjointness.v0.json');
expectTrue('generated.P1_no_dual_accept', generated.properties.P1_no_dual_accept);
expectTrue('generated.P2_valid_bridge_native_rejects', generated.properties.P2_valid_bridge_native_rejects);
expectTrue('generated.P3_valid_native_bridge_rejects', generated.properties.P3_valid_native_bridge_rejects);
expect('generated.summary.generated_case_count', generated.summary.generated_case_count, 32);
expect('generated.summary.dual_accept_count', generated.summary.dual_accept_count, 0);

const grammar = readJson(evidenceRoot, 'manifests/artifact-grammar-fuzzer.v0.json');
expect('grammar.summary.case_count', grammar.summary.case_count, 26);
expect('grammar.summary.entrypoint_check_count', grammar.summary.entrypoint_check_count, 27);
expect('grammar.summary.positive_accept_count', grammar.summary.positive_accept_count, 5);
expect('grammar.summary.negative_reject_count', grammar.summary.negative_reject_count, 22);
expect('grammar.summary.unexpected_accept_count', grammar.summary.unexpected_accept_count, 0);
expect('grammar.summary.unexpected_reject_count', grammar.summary.unexpected_reject_count, 0);
expect('grammar.summary.missing_expected_failure_count', grammar.summary.missing_expected_failure_count, 0);

const mutation = readJson(evidenceRoot, 'manifests/mutation-generator.v0.json');
expect('mutation.summary.case_count', mutation.summary.case_count, 15);
expect('mutation.summary.active_case_count', mutation.summary.active_case_count, 15);
expect('mutation.summary.active_caught_count', mutation.summary.active_caught_count, 15);
expect('mutation.summary.wrong_failure_class_count', mutation.summary.wrong_failure_class_count, 0);
expect('mutation.summary.active_not_caught_count', mutation.summary.active_not_caught_count, 0);
expectTrue('mutation.P4_bridge_canonical_idempotence', mutation.properties.P4_bridge_canonical_idempotence);
expectTrue('mutation.P4_native_canonical_idempotence', mutation.properties.P4_native_canonical_idempotence);
expectTrue('mutation.P5_binding_soundness', mutation.properties.P5_binding_soundness);
expectTrue('mutation.P6_boundary_exactness', mutation.properties.P6_boundary_exactness);
expectTrue('mutation.P7_diagnostic_precision', mutation.properties.P7_diagnostic_precision);

const seeded = readJson(evidenceRoot, 'manifests/seeded-divergence.v0.json');
expect('seeded.expected.comparison_status', seeded.expected.comparison_status, 'disagree');
expect('seeded.expected.reason', seeded.expected.reason, 'transcript-bytes-differ');
expect('seeded.expected.first_divergence.index', seeded.expected.first_divergence.index, 0);
expect('seeded.expected.first_divergence.reference', seeded.expected.first_divergence.reference, '1');
expect('seeded.expected.first_divergence.meaning_env', seeded.expected.first_divergence.meaning_env, '2');
expect('seeded.expected.verify_exit', seeded.expected.verify_exit, 0);

const seededReceipt = readJson(evidenceRoot, 'detection/seeded-divergence/expected/seeded-branch.disagree.json');
expect('seededReceipt.comparison.status', seededReceipt.comparison.status, 'disagree');
expect('seededReceipt.comparison.reason', seededReceipt.comparison.reason, 'transcript-bytes-differ');
expect('seededReceipt.comparison.first_divergence.index', seededReceipt.comparison.first_divergence.index, 0);

const welfareRule = readText(evidenceRoot, 'profile-gallery/welfare-replay/cases/welfare-low-single.lspx');
expect('welfare-low-single non-empty non-comment LOC', nonEmptyNonCommentLoc(welfareRule), 103);
expect('welfare-low-single bracket rows', countPattern(welfareRule, /\(b[0-9] /g), 3);
expect('welfare-low-single dependent categories', countPattern(welfareRule, /\((adult|child|senior) /g), 3);

const frozenReceipt = readJson(bundleRoot, 'examples/welfare/expected/welfare-low-single.json');
expect('frozen receipt engine.version', frozenReceipt.engine.version, '1.3.11');
expect('frozen receipt excludes length', frozenReceipt.boundary.excludes.length, 14);
for (const item of [
  'topaz-reporting',
  'receipt-authenticity',
  'generation-honesty',
  'issuer-binding',
  'timestamping',
  'non-repudiation',
]) {
  expectIncludes(`frozen receipt boundary.excludes`, frozenReceipt.boundary.excludes, item);
}

if (failures.length) {
  console.error('vNext evidence addendum check failed');
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log('vNext evidence addendum check passed');
console.log('M2 transcription fidelity: 676/676 agree');
console.log('Profile growth: 0 profile extensions recommended');
console.log('Generated disjointness: 32 cases, dual_accept = 0');
console.log('Artifact grammar: 26 cases, 27 entrypoint checks, 5 accepts, 22 rejects');
console.log('Mutation generator: 15 active mutations caught, wrong_failure_class = 0');
console.log('Seeded divergence: comparison.status = disagree with first_divergence');
