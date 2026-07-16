import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
export const artifactDir = path.resolve(scriptDir, '..');
export const manifestPath = path.join(
  artifactDir,
  'fixtures',
  'fixture-manifest.json'
);
export const registryPath = path.join(
  artifactDir,
  'fixtures',
  'fixture-registry.json'
);
export const contractPath = path.join(
  artifactDir,
  'contract',
  'NATIVE-IMPLEMENTATION-CONDITIONS-v8.6.0.md'
);

export const ROW_FIELDS = [
  'fixture_id',
  'scope',
  'input_paths',
  'command_or_api_operation',
  'expected_exit_code',
  'expected_primary_error',
  'expected_secondary_reason',
  'expected_failed_check',
  'expected_input_artifact',
  'expected_underlying_error',
  'expected_status',
  'expected_display',
  'paper_claim_identifiers',
];

// Stage 10C closes the final release-layer targets. The frozen contract says
// L01-L21 are built rows; a final full-fixture release has no design targets.
const DESIGN_TARGETS = new Set();

const CLEANROOM_FIXTURES = new Set([
  'C-REP-06',
  'C-REP-09',
  'L04',
  'L14',
  'L15',
  'L18',
  'L19',
  'S10-CLEANROOM-01',
]);

const FINALIZER_FIXTURES = new Set([
  'L06',
  'L07',
  'L08',
  'L10',
  'L11A',
  'L11B',
  'L13',
  'L16',
  'L20',
  'L21',
]);

const PUBLICATION_FIXTURES = new Set([
  'L01',
  'L02',
  'L03',
  'L09',
  'L12',
  'L17',
]);

const LIFECYCLE_EXPECTATIONS = new Map([
  ['L01', expected(1, 'chain-verification-failed', { status: 'fail' })],
  ['L02', expected(1, 'chain-verification-failed', { status: 'fail' })],
  ['L03', expected(1, 'chain-verification-failed', { status: 'fail' })],
  ['L04', expected(1, null)],
  ['L05', expected(1, null)],
  [
    'L06',
    expected(1, 'release-binding-mismatch', {
      failedCheck: 'rb-q-descriptor',
      status: 'refused',
    }),
  ],
  [
    'L07',
    expected(1, 'clean-run-derivation-mismatch', {
      failedCheck: 'qd-comparison-matched',
      status: 'refused',
    }),
  ],
  ['L08', expected(0, null, { status: 'finalized' })],
  ['L09', expected(0, null, { status: 'pass' })],
  ['L10', expected(2, 'usage-error')],
  [
    'L11A',
    expected(1, 'finalizer-input-invalid', {
      inputArtifact: 'workload-report',
      underlyingError: 'non-canonical-artifact-json',
      status: 'refused',
    }),
  ],
  [
    'L11B',
    expected(1, 'finalizer-input-invalid', {
      inputArtifact: 'workload-report',
      underlyingError: 'artifact-resource-limit',
      status: 'refused',
    }),
  ],
  [
    'L12',
    expected(3, 'input-output-failure', {
      inputArtifact: 'clean-run-report',
      status: 'fail',
    }),
  ],
  [
    'L13',
    expected(1, 'clean-run-derivation-mismatch', {
      failedCheck: 'qd-workload-bytes',
      status: 'refused',
    }),
  ],
  ['L14', expected(0, null, { status: 'pass' })],
  ['L15', expected(0, null, { status: 'pass' })],
  [
    'L16',
    expected(1, 'descriptor-authentication-failed', { status: 'refused' }),
  ],
  [
    'L17',
    expected(1, 'chain-verification-failed', {
      failedCheck: 'p3-rd-runtime',
      status: 'fail',
    }),
  ],
  ['L18', expected(1, null)],
  ['L19', expected(0, null, { status: 'pass', claims: ['P9', 'P15'] })],
  [
    'L20',
    expected(4, 'key-loading-or-signing-failure', {
      status: 'refused',
      claims: ['P9', 'P15', 'P17'],
    }),
  ],
  [
    'L21',
    expected(3, 'input-output-failure', {
      claims: ['P9', 'P15', 'P17'],
    }),
  ],
]);

const CONSUMER_FIXTURES = new Set([
  'U01',
  'U02',
  'U03',
  'U04',
  'U05',
  'U06',
  'U07',
  'U08',
  'U09',
  'U10',
  'U11',
  'U12',
  'U13',
  'T01',
  'T02',
  'C-CAP-11',
  'C-CAP-12',
  'S5-CAPABILITY-01',
  'S5-BRIDGE-BYTE-01',
  'S5-VULNERABLE-01',
  'S7-BRIDGE-API-01',
]);

const PRIMARY_ERRORS = new Set([
  'artifact-resource-limit',
  'non-canonical-artifact-json',
  'missing-native-attestation',
  'native-envelope-schema',
  'native-payload-type',
  'native-base64-invalid',
  'untrusted-native-key',
  'native-profile-disallowed',
  'native-payload-type-disallowed',
  'native-signature-invalid',
  'unsupported-native-version',
  'native-schema-version-below-policy',
  'native-receipt-schema',
  'native-receipt-inconsistent',
  'native-profile-mismatch',
  'native-engine-disallowed',
  'native-source-mismatch',
  'native-input-mismatch',
  'native-input-parse-failed',
  'native-input-profile-invalid',
  'unsupported-bridge-version',
  'bridge-report-schema',
  'bridge-profile-mismatch',
  'bridge-engine-mismatch',
  'bridge-source-mismatch',
  'bridge-input-mismatch',
  'bridge-input-canonical-value-mismatch',
  'native-result-not-signable',
  'native-self-verification-failed',
  'usage-error',
  'input-output-failure',
  'key-loading-or-signing-failure',
  'clean-run-derivation-mismatch',
  'descriptor-authentication-failed',
  'chain-verification-failed',
]);

const B_EXPECTATIONS = new Map([
  ['B01', [0, null, 'checked-external']],
  ['B02', [1, 'missing-native-attestation', 'rejected']],
  ['B03', [1, 'bridge-report-schema', 'rejected']],
  ['B04', [1, 'artifact-resource-limit', 'rejected']],
  ['B05', [1, 'non-canonical-artifact-json', 'rejected']],
  ['B06', [1, 'unsupported-bridge-version', 'rejected']],
  ['B07', [1, 'bridge-report-schema', 'rejected']],
  ['B08', [1, 'bridge-profile-mismatch', 'rejected']],
  ['B09', [1, 'bridge-engine-mismatch', 'rejected']],
  ['B10', [1, 'bridge-source-mismatch', 'rejected']],
  ['B11', [1, 'bridge-input-mismatch', 'rejected']],
  ['B12', [1, 'bridge-input-canonical-value-mismatch', 'rejected']],
]);

export async function loadInputs() {
  const [registryText, contractText] = await Promise.all([
    readFile(registryPath, 'utf8'),
    readFile(contractPath, 'utf8'),
  ]);
  return { registry: JSON.parse(registryText), contractText };
}

export function buildManifest(registry, contractText) {
  const descriptions = tableDescriptions(contractText);
  const fixtures = registry.fixtures.map(({ fixture_id: fixtureId }) => {
    const description = descriptions.get(fixtureId)?.description ?? '';
    const backs = descriptions.get(fixtureId)?.backs ?? '';
    const inferred = inferExpected(description);
    const bridge = B_EXPECTATIONS.get(fixtureId);
    const expectedExitCode = bridge?.[0] ?? inferred.exitCode;
    const expectedPrimaryError = bridge?.[1] ?? inferred.primaryError;
    const expectedStatus = bridge?.[2] ?? inferred.status;
    const lifecycle = LIFECYCLE_EXPECTATIONS.get(fixtureId);
    return {
      fixture_id: fixtureId,
      scope: DESIGN_TARGETS.has(fixtureId) ? 'design-target' : 'built',
      input_paths: fixtureId.startsWith('B')
        ? ['<fixture-report>', '<fixture-source>', '<fixture-input>']
        : [],
      command_or_api_operation: operationFor(fixtureId),
      expected_exit_code: lifecycle?.exitCode ?? expectedExitCode,
      expected_primary_error: lifecycle?.primaryError ?? expectedPrimaryError,
      expected_secondary_reason: inferred.secondaryReason,
      expected_failed_check: lifecycle?.failedCheck ?? null,
      expected_input_artifact: lifecycle?.inputArtifact ?? null,
      expected_underlying_error: lifecycle?.underlyingError ?? null,
      expected_status: lifecycle?.status ?? expectedStatus,
      expected_display:
        fixtureId === 'U03'
          ? 'Verified'
          : fixtureId === 'U04'
            ? 'External evidence checked'
            : null,
      paper_claim_identifiers:
        lifecycle?.claims ??
        [...backs.matchAll(/\bP(?:1[0-7]|[1-9])\b/g)].map((match) => match[0]),
    };
  });
  return {
    fixture_manifest: 'vouch.scored26-fixture-manifest/v0',
    contract_sha256: registry.contract_sha256,
    fixtures,
  };
}

export function validateManifest(manifest, registry) {
  const errors = [];
  if (manifest?.fixture_manifest !== 'vouch.scored26-fixture-manifest/v0') {
    errors.push('fixture-manifest-tag');
  }
  if (manifest?.contract_sha256 !== registry?.contract_sha256) {
    errors.push('fixture-manifest-contract');
  }
  if (!Array.isArray(manifest?.fixtures)) {
    return [...errors, 'fixture-manifest-rows'];
  }
  const registryIds = registry.fixtures.map((row) => row.fixture_id);
  const registrySet = new Set(registryIds);
  const seen = new Set();
  for (const [index, row] of manifest.fixtures.entries()) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      errors.push(`fixture-row-${index}-shape`);
      continue;
    }
    const names = Object.keys(row).sort();
    if (names.join('\0') !== [...ROW_FIELDS].sort().join('\0')) {
      errors.push(`fixture-row-${index}-fields`);
    }
    const id = row.fixture_id;
    if (typeof id !== 'string' || id.length === 0) {
      errors.push(`fixture-row-${index}-id`);
    } else if (seen.has(id)) {
      errors.push(`fixture-duplicate-${id}`);
    } else {
      seen.add(id);
      if (!registrySet.has(id)) errors.push(`fixture-unknown-${id}`);
    }
    if (!['built', 'design-target'].includes(row.scope)) {
      errors.push(`fixture-${id}-scope`);
    }
    if (!Array.isArray(row.input_paths) || !row.input_paths.every(isString)) {
      errors.push(`fixture-${id}-input-paths`);
    }
    if (!isString(row.command_or_api_operation)) {
      errors.push(`fixture-${id}-operation`);
    }
    if (
      row.expected_exit_code !== null &&
      (!Number.isSafeInteger(row.expected_exit_code) ||
        row.expected_exit_code < 0)
    ) {
      errors.push(`fixture-${id}-exit`);
    }
    for (const field of ROW_FIELDS.filter((name) =>
      name.startsWith('expected_')
    ).filter((name) => name !== 'expected_exit_code')) {
      if (row[field] !== null && !isString(row[field])) {
        errors.push(`fixture-${id}-${field}`);
      }
    }
    if (
      !Array.isArray(row.paper_claim_identifiers) ||
      !row.paper_claim_identifiers.every((claim) =>
        /^P(?:1[0-7]|[1-9])$/.test(claim)
      )
    ) {
      errors.push(`fixture-${id}-claims`);
    }
  }
  for (const id of registryIds) {
    if (!seen.has(id)) errors.push(`fixture-missing-${id}`);
  }
  if (manifest.fixtures.length !== registryIds.length) {
    errors.push('fixture-count');
  }
  return errors;
}

export function operationFor(fixtureId) {
  if (DESIGN_TARGETS.has(fixtureId)) return 'not-implemented';
  if (CLEANROOM_FIXTURES.has(fixtureId)) return 'scored26-clean-room';
  if (FINALIZER_FIXTURES.has(fixtureId)) return 'scored26-release-finalizer';
  if (PUBLICATION_FIXTURES.has(fixtureId)) {
    return 'scored26-release-publication';
  }
  if (fixtureId === 'L05') return 'scored26-workload-freeze';
  if (fixtureId === 'U01' || fixtureId === 'U02') {
    return 'strict-union-baseline';
  }
  if (/^R0[1-5]$/.test(fixtureId) || fixtureId === 'S8-REPLAY-01') {
    return 'replay-manifest-public-api';
  }
  if (fixtureId === 'S8-WORKLOAD-FREEZE-01') {
    return 'scored26-workload-freeze';
  }
  if (fixtureId === 'S8-WORKLOAD-RESULT-01') {
    return 'scored26-workload-results';
  }
  if (fixtureId === 'S10-CONDITION-LEDGER-01') {
    return 'scored26-condition-ledger';
  }
  if (fixtureId === 'S9-MUTATION-MECHANISM-01') {
    return 'scored26-mutation-mechanism';
  }
  if (fixtureId === 'S9-MUTATION-RESULT-01') {
    return 'scored26-mutation-results';
  }
  if (fixtureId === 'S10-RELEASE-SCHEMA-01') {
    return 'scored26-release-schema';
  }
  if (fixtureId === 'S10-FINALIZER-01') {
    return 'scored26-release-finalizer';
  }
  if (fixtureId === 'S10-PUBLICATION-01') {
    return 'scored26-release-publication';
  }
  if (fixtureId === 'S10-SUPPLY-01') {
    return 'scored26-release-supply';
  }
  if (fixtureId === 'S7-FIXTURE-GATE-01') return 'fixture-manifest-negative';
  if (fixtureId === 'S1-CROSS-WRITER-01') return 'cross-writer-goldens';
  if (CONSUMER_FIXTURES.has(fixtureId)) return 'vouch-consumer-public-api';
  return 'rust-public-contract-lane';
}

function expected(
  exitCode,
  primaryError,
  {
    failedCheck = null,
    inputArtifact = null,
    underlyingError = null,
    status = null,
    claims = [],
  } = {}
) {
  return Object.freeze({
    exitCode,
    primaryError,
    failedCheck,
    inputArtifact,
    underlyingError,
    status,
    claims,
  });
}

function tableDescriptions(contractText) {
  const descriptions = new Map();
  for (const line of contractText.split('\n')) {
    const match = /^\| ([A-Z][A-Z0-9-]+) \| (.*?) \| (.*?) \|$/.exec(line);
    if (!match || match[1] === 'ID') continue;
    descriptions.set(match[1], { description: match[2], backs: match[3] });
  }
  return descriptions;
}

function inferExpected(description) {
  const exitMatch = /\b(?:Exit|exits?|exit)\s+([0-9]+)\b/i.exec(description);
  const quoted = [...description.matchAll(/`([a-z][a-z0-9-]+)`/g)].map(
    (match) => match[1]
  );
  const primaryError =
    quoted.find((value) => PRIMARY_ERRORS.has(value)) ?? null;
  const secondaryReason =
    quoted.find((value) =>
      [
        'comparison-not-agree',
        'terminal-not-completed',
        'final-value-not-decision',
        'diagnostics-present',
        'mutant-build',
      ].includes(value)
    ) ?? null;
  const statusMatch = /\bstatus(?:\s*=| equal to)?\s+`?([a-z][a-z-]+)`?/i.exec(
    description
  );
  return {
    exitCode: exitMatch ? Number(exitMatch[1]) : null,
    primaryError,
    secondaryReason,
    status: statusMatch?.[1] ?? null,
  };
}

function isString(value) {
  return typeof value === 'string';
}
