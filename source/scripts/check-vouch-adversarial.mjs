import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(fileURLToPath(new URL('..', import.meta.url)));
const cli = join(repoRoot, 'cli', 'bin', 'lispex.js');
const write = process.argv.includes('--write');

const bridgeReportPath =
  'examples/vouch-bridge/reports/checkout-discount.bridge.json';
const bridgeSourcePath = 'examples/vouch-bridge/source/checkout-discount.ts';
const bridgeTargetPath = 'examples/vouch-bridge/target/checkout_discount.py';
const nativeReceiptPath = 'examples/vouch-loop/expected/refund-window.json';
const nativeSourcePath = 'examples/vouch-loop/cases/refund-window.lspx';
const resultPath = 'adversarial/vouch-evidence-laundering/results.json';

const authenticityExcludes = [
  'receipt-authenticity',
  'generation-honesty',
  'issuer-binding',
  'timestamping',
  'non-repudiation',
];

function fail(message) {
  throw new Error(message);
}

function exactJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function readJson(path) {
  return JSON.parse(readFileSync(join(repoRoot, path), 'utf8'));
}

function writeJson(path, value) {
  writeFileSync(path, exactJson(value));
}

function runCli(args) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 120000,
  });
}

function parseStdout(result, label) {
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    fail(`${label} stdout is not JSON: ${error.message}\n${result.stdout}`);
  }
}

function diagnostics(report) {
  return (report.diagnostics ?? []).map((entry) => entry.code);
}

function expectDiagnostic(report, code, label) {
  if (!diagnostics(report).includes(code)) {
    fail(
      `${label} missing diagnostic ${code}: ${diagnostics(report).join(', ')}`
    );
  }
}

function expectExit(result, expected, label) {
  if (result.status !== expected) {
    fail(
      `${label} exited ${result.status}, expected ${expected}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`
    );
  }
}

function verifyBridge(path) {
  const result = runCli([
    'verify-bridge',
    '--source',
    bridgeSourcePath,
    '--target',
    bridgeTargetPath,
    path,
  ]);
  const report = parseStdout(result, `verify-bridge ${path}`);
  return { result, report };
}

function verifyNative(path, sourcePath = null) {
  const args = ['verify'];
  if (sourcePath) args.push('--source', sourcePath);
  args.push(path);
  const result = runCli(args);
  const report = parseStdout(result, `verify ${path}`);
  return { result, report };
}

function writeMutation(tmp, name, value) {
  const path = join(tmp, `${name}.json`);
  writeFileSync(path, exactJson(value));
  return path;
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (value === null || typeof value !== 'object') return value;
  const next = {};
  for (const key of Object.keys(value).sort()) {
    next[key] = sortedObject(value[key]);
  }
  return next;
}

function writeNativeMutation(tmp, name, value) {
  return writeMutation(tmp, name, sortedObject(value));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function assertNotPromotedToNative(path, label) {
  const native = verifyNative(path);
  if (native.result.status === 0 || native.report.summary?.status === 'pass') {
    fail(`${label} was promoted to native evidence`);
  }
  return diagnostics(native.report);
}

function assertDisjoint(path, label) {
  const nativeResult = verifyNative(path);
  const bridgeResult = verifyBridge(path);
  if (nativeResult.result.status === 0 && bridgeResult.result.status === 0) {
    fail(`${label} was accepted by both native and bridge verifiers`);
  }
  return {
    id: label,
    native_accepts: nativeResult.result.status === 0,
    bridge_accepts: bridgeResult.result.status === 0,
    native_failure_head: diagnostics(nativeResult.report).slice(0, 3),
    bridge_failure_head: diagnostics(bridgeResult.report).slice(0, 3),
  };
}

function groupARow({
  id,
  attack,
  gate,
  fixture,
  run,
  expectedStatus,
  expectedFailure,
  assertNative = true,
}) {
  const { result, report } = run(fixture);
  expectExit(result, expectedStatus, id);
  if (expectedFailure) expectDiagnostic(report, expectedFailure, id);
  const nativeDiagnostics = assertNative
    ? assertNotPromotedToNative(fixture, id)
    : [];
  return {
    id,
    attack,
    gate,
    failure_class: expectedFailure ?? 'none',
    status: expectedStatus === 0 ? 'accepted-as-external' : 'rejected',
    promoted_to_native: 'no',
    native_gate_diagnostics: nativeDiagnostics.slice(0, 8),
  };
}

function runPublicClaimsNegative() {
  const path = join(
    repoRoot,
    'artifact',
    'consumer-demo',
    'vulnerable',
    '__adversarial-authenticity-overclaim.ts'
  );
  writeFileSync(
    path,
    [
      'export const badClaims = [',
      "  'authentic Vouch-generated receipt',",
      "  'authentically generated',",
      "  'non-repudiable',",
      "  'Vouch offers non-repudiation today',",
      "  'tamper-proof receipt',",
      "  'provably authentic',",
      "  '진본 검증된',",
      "  '위변조 불가',",
      "  '부인 방지',",
      '];',
      '',
    ].join('\n')
  );
  try {
    const result = spawnSync(
      process.execPath,
      ['scripts/check-vouch-public-claims.mjs'],
      {
        cwd: repoRoot,
        encoding: 'utf8',
        timeout: 120000,
      }
    );
    if (result.status === 0) {
      fail('public-claims negative fixture unexpectedly passed');
    }
    const combined = `${result.stdout}\n${result.stderr}`;
    for (const id of [
      'authentic-vouch-generated-receipt-overclaim',
      'authentically-generated-overclaim',
      'non-repudiable-overclaim',
      'non-repudiation-overclaim',
      'tamper-proof-receipt-overclaim',
      'provably-authentic-overclaim',
      'authenticity-verified-ko',
      'tamper-proof-ko',
      'non-repudiation-ko',
    ]) {
      if (!combined.includes(id)) {
        fail(`public-claims negative fixture missing ${id}`);
      }
    }
    return {
      status: 'rejected-promotional-overclaims',
      checked_patterns: 9,
    };
  } finally {
    rmSync(path, { force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(`vouch adversarial check failed: ${error.message}`);
  process.exitCode = 1;
}

function main() {
const bridge = readJson(bridgeReportPath);
const native = readJson(nativeReceiptPath);

const tmp = mkdtempSync(join(tmpdir(), 'lispex-vouch-adversarial-'));
try {
  const fixtures = {
    tagOnlyRelabel: (() => {
      const { bridge_report: _bridgeReport, ...rest } = clone(bridge);
      const next = {
        boundary: rest.boundary,
        diagnostics: rest.diagnostics,
        differential_receipt: 'csk.differential-receipt/v0',
        engine: rest.engine,
        profile: rest.profile,
        subject: rest.subject,
        checks: rest.checks,
        linked_artifacts: rest.linked_artifacts,
        summary: rest.summary,
      };
      return writeNativeMutation(tmp, 'a01-tag-only-relabel', next);
    })(),
    fieldGrafting: (() => {
      const next = clone(bridge);
      next.comparison = {
        status: 'agree',
        reason: 'transcript-bytes-equal',
      };
      return writeMutation(tmp, 'a02-field-grafting', next);
    })(),
    missingNativeRequired: writeMutation(
      tmp,
      'a03-missing-native-required',
      clone(bridge)
    ),
    nativeWithBridgeField: (() => {
      const next = clone(native);
      next.bridge_report = 'vouch.bridge-report/v0';
      next.subject = clone(bridge.subject);
      return writeNativeMutation(tmp, 'a04-native-with-bridge-field', next);
    })(),
    missingBoundary: (() => {
      const next = clone(bridge);
      delete next.boundary;
      return writeMutation(tmp, 'a05-missing-boundary', next);
    })(),
    boundaryOmission: (() => {
      const next = clone(bridge);
      next.boundary.excludes = next.boundary.excludes.filter(
        (entry) => entry !== 'target-code-correctness'
      );
      return writeMutation(tmp, 'a06-boundary-omission', next);
    })(),
    hashDomainSubstitution: (() => {
      const next = clone(bridge);
      next.subject.source.hash.domain = 'lispex/source-hash/v0';
      return writeMutation(tmp, 'a07-hash-domain-substitution', next);
    })(),
    unknownTrustField: (() => {
      const next = clone(bridge);
      next.semantic_proof = true;
      next.verified_by = 'external-witness';
      next.native_agree = true;
      return writeMutation(tmp, 'a08-unknown-trust-field', next);
    })(),
    pathTimestampPollution: (() => {
      const next = clone(bridge);
      next.subject.source.path = '/tmp/checkout-discount.ts';
      next.generated_at = '2026-07-04T00:00:00Z';
      return writeMutation(tmp, 'a09-path-timestamp-pollution', next);
    })(),
    optionalNullSmuggling: (() => {
      const next = clone(bridge);
      next.linked_artifacts = null;
      return writeMutation(tmp, 'a10-optional-null-smuggling', next);
    })(),
    contradictoryBoundary: (() => {
      const next = clone(bridge);
      next.boundary.attests = [
        ...next.boundary.attests,
        'semantic-equivalence',
      ];
      return writeMutation(tmp, 'a11-contradictory-boundary', next);
    })(),
    validBridge: writeMutation(tmp, 'a12-valid-bridge-positive', clone(bridge)),
  };

  const groupA = [
    groupARow({
      id: 'A.1',
      attack: 'tag-only relabel from bridge to native',
      gate: 'native-verify',
      fixture: fixtures.tagOnlyRelabel,
      run: verifyNative,
      expectedStatus: 1,
      expectedFailure: 'unknown-top-level-field:profile',
    }),
    groupARow({
      id: 'A.2',
      attack: 'field grafting native comparison into bridge',
      gate: 'bridge-verify',
      fixture: fixtures.fieldGrafting,
      run: verifyBridge,
      expectedStatus: 1,
      expectedFailure: 'unknown-top-level-field:comparison',
    }),
    groupARow({
      id: 'A.3',
      attack: 'bridge report supplied to native verifier',
      gate: 'native-verify',
      fixture: fixtures.missingNativeRequired,
      run: verifyNative,
      expectedStatus: 1,
      expectedFailure: 'missing-source',
    }),
    groupARow({
      id: 'A.4',
      attack: 'native receipt with bridge-only fields',
      gate: 'native-verify',
      fixture: fixtures.nativeWithBridgeField,
      run: verifyNative,
      expectedStatus: 1,
      expectedFailure: 'unknown-top-level-field:bridge_report',
    }),
    groupARow({
      id: 'A.5',
      attack: 'missing bridge boundary',
      gate: 'bridge-verify',
      fixture: fixtures.missingBoundary,
      run: verifyBridge,
      expectedStatus: 1,
      expectedFailure: 'missing-boundary',
    }),
    groupARow({
      id: 'A.6',
      attack: 'boundary omission removes required exclude',
      gate: 'bridge-verify',
      fixture: fixtures.boundaryOmission,
      run: verifyBridge,
      expectedStatus: 1,
      expectedFailure: 'boundary-excludes-mismatch',
    }),
    groupARow({
      id: 'A.7',
      attack: 'hash domain substitution',
      gate: 'bridge-verify',
      fixture: fixtures.hashDomainSubstitution,
      run: verifyBridge,
      expectedStatus: 1,
      expectedFailure: 'source-hash-domain',
    }),
    groupARow({
      id: 'A.8',
      attack: 'unknown trust-field smuggling',
      gate: 'bridge-verify',
      fixture: fixtures.unknownTrustField,
      run: verifyBridge,
      expectedStatus: 1,
      expectedFailure: 'unknown-top-level-field:semantic_proof',
    }),
    groupARow({
      id: 'A.9',
      attack: 'path and timestamp pollution',
      gate: 'bridge-verify',
      fixture: fixtures.pathTimestampPollution,
      run: verifyBridge,
      expectedStatus: 1,
      expectedFailure: 'unknown-top-level-field:generated_at',
    }),
    groupARow({
      id: 'A.10',
      attack: 'optional null smuggling',
      gate: 'bridge-verify',
      fixture: fixtures.optionalNullSmuggling,
      run: verifyBridge,
      expectedStatus: 1,
      expectedFailure: 'linked-artifacts-not-array',
    }),
    groupARow({
      id: 'A.11',
      attack: 'contradictory boundary attests semantic equivalence',
      gate: 'bridge-verify',
      fixture: fixtures.contradictoryBoundary,
      run: verifyBridge,
      expectedStatus: 1,
      expectedFailure: 'boundary-attests-mismatch',
    }),
    groupARow({
      id: 'A.12',
      attack: 'positive valid bridge report accepted only as external evidence',
      gate: 'bridge-verify',
      fixture: fixtures.validBridge,
      run: verifyBridge,
      expectedStatus: 0,
      expectedFailure: null,
    }),
  ];

  const forgedNative = clone(native);
  forgedNative.engine.commit.hex = '2'.repeat(40);
  const forgedPath = writeMutation(
    tmp,
    'b01-forged-native-shaped',
    forgedNative
  );
  const forgedCheck = verifyNative(forgedPath, nativeSourcePath);
  expectExit(forgedCheck.result, 0, 'B.1 forged native-shaped artifact');
  for (const excluded of authenticityExcludes) {
    if (!forgedNative.boundary?.excludes?.includes(excluded)) {
      fail(`B.2 forged native-shaped artifact missing ${excluded}`);
    }
  }
  const claimsNegative = runPublicClaimsNegative();
  const groupB = {
    id: 'B',
    status: 'documented-non-goal',
    forged_native_shape: {
      verifier_status: forgedCheck.report.summary?.status,
      checked_with_source: nativeSourcePath,
      changed_field: 'engine.commit.hex',
      claim: 'self-consistency can pass without receipt authenticity',
    },
    required_excludes_present: authenticityExcludes,
    public_claims_negative: claimsNegative,
    boundary: {
      attests: [
        'artifact-self-consistency-boundary',
        'authenticity-non-goals-present',
        'promotional-authenticity-overclaims-rejected',
      ],
      excludes: [
        'receipt-authenticity',
        'generation-honesty',
        'issuer-binding',
        'timestamping',
        'non-repudiation',
      ],
    },
  };

  const disjointnessFixtures = [
    ['D.1-valid-bridge', fixtures.validBridge],
    ['D.2-valid-native', forgedPath],
    ['D.3-tag-only-relabel', fixtures.tagOnlyRelabel],
    ['D.4-field-grafting', fixtures.fieldGrafting],
    ['D.5-native-with-bridge-field', fixtures.nativeWithBridgeField],
    ['D.6-unknown-trust-field', fixtures.unknownTrustField],
    ['D.7-optional-null-smuggling', fixtures.optionalNullSmuggling],
  ].map(([id, path]) => assertDisjoint(path, id));

  const report = {
    vouch_adversarial_evaluation: 'vouch.adversarial-evidence/v0',
    version: JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'))
      .version,
    groups: {
      artifact_class_spoofing: groupA,
      authenticity_boundary: groupB,
      disjointness: disjointnessFixtures,
    },
    summary: {
      group_a_total: groupA.length,
      group_a_promoted_to_native: groupA.filter(
        (row) => row.promoted_to_native !== 'no'
      ).length,
      group_b_status: groupB.status,
      disjointness_both_accepted: disjointnessFixtures.filter(
        (row) => row.native_accepts && row.bridge_accepts
      ).length,
    },
  };

  if (write) {
    mkdirSync(dirname(join(repoRoot, resultPath)), { recursive: true });
    writeJson(join(repoRoot, resultPath), report);
  }
  if (!existsSync(join(repoRoot, resultPath))) {
    fail(`${resultPath} missing; run npm run gen:vouch-adversarial`);
  }
  const expected = readJson(resultPath);
  if (exactJson(expected) !== exactJson(report)) {
    fail(`${resultPath} is stale; run npm run gen:vouch-adversarial`);
  }
  console.log(
    `vouch adversarial check passed (${groupA.length} spoofing cases, promoted-to-native 0, ${groupB.status})`
  );
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
}
