import { spawnSync } from 'node:child_process';
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(fileURLToPath(new URL('..', import.meta.url)));
const cli = join(repoRoot, 'cli', 'bin', 'lispex.js');
const reportPath =
  'examples/vouch-bridge/reports/checkout-discount.bridge.json';
const sourcePath = 'examples/vouch-bridge/source/checkout-discount.ts';
const targetPath = 'examples/vouch-bridge/target/checkout_discount.py';
const linkedPath = 'examples/vouch-bridge/linked/conversion-gate-proof.json';
const contextPath =
  'examples/vouch-bridge/context/checkout-discount.context.json';

function fail(message) {
  console.error(`vouch bridge check failed: ${message}`);
  process.exit(1);
}

function run(args) {
  const result = spawnSync(process.execPath, [cli, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  return result;
}

function expectExit(args, status, diagnostic) {
  const result = run(args);
  if (result.status !== status) {
    fail(
      `${args.join(' ')} exited ${result.status}, expected ${status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`
    );
  }
  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch (error) {
    fail(`${args.join(' ')} stdout is not JSON: ${error.message}`);
  }
  if (report.bridge_verify_report !== 'vouch.bridge-verify-report/v0') {
    fail(`${args.join(' ')} did not emit vouch.bridge-verify-report/v0`);
  }
  if (report.summary?.exit_code !== status) {
    fail(`${args.join(' ')} exit_code mismatch`);
  }
  if (
    diagnostic &&
    !report.diagnostics?.some((entry) => entry.code === diagnostic)
  ) {
    fail(`${args.join(' ')} missing diagnostic ${diagnostic}`);
  }
  return report;
}

const generator = spawnSync(
  process.execPath,
  ['scripts/gen-vouch-bridge-example.mjs'],
  {
    cwd: repoRoot,
    encoding: 'utf8',
  }
);
if (generator.status !== 0) {
  fail(
    `example generator check failed\nstdout:\n${generator.stdout}\nstderr:\n${generator.stderr}`
  );
}

expectExit(
  [
    'verify-bridge',
    '--source',
    sourcePath,
    '--target',
    targetPath,
    '--linked',
    `conversion-gate-proof=${linkedPath}`,
    '--expect-context',
    contextPath,
    reportPath,
  ],
  0
);

const tmp = mkdtempSync(join(tmpdir(), 'lispex-vouch-bridge-'));
try {
  const tampered = join(tmp, 'tampered.bridge.json');
  cpSync(join(repoRoot, reportPath), tampered);
  const report = JSON.parse(readFileSync(tampered, 'utf8'));
  report.subject.source.hash.hex =
    report.subject.source.hash.hex[0] === '0'
      ? `1${report.subject.source.hash.hex.slice(1)}`
      : `0${report.subject.source.hash.hex.slice(1)}`;
  writeFileSync(tampered, `${JSON.stringify(report, null, 2)}\n`);
  expectExit(
    ['verify-bridge', '--source', sourcePath, '--target', targetPath, tampered],
    1,
    'source-hash-mismatch'
  );

  const wrongSource = join(tmp, 'wrong-source.ts');
  writeFileSync(wrongSource, 'export const wrong = true;\n');
  expectExit(
    [
      'verify-bridge',
      '--source',
      wrongSource,
      '--target',
      targetPath,
      reportPath,
    ],
    1,
    'source-hash-mismatch'
  );

  const wrongTarget = join(tmp, 'wrong-target.py');
  writeFileSync(wrongTarget, 'wrong = True\n');
  expectExit(
    [
      'verify-bridge',
      '--source',
      sourcePath,
      '--target',
      wrongTarget,
      reportPath,
    ],
    1,
    'target-hash-mismatch'
  );

  const wrongLinked = join(tmp, 'wrong-linked.json');
  writeFileSync(wrongLinked, '{"wrong":true}\n');
  expectExit(
    ['verify-bridge', '--linked', `conversion-gate-proof=${wrongLinked}`, reportPath],
    1,
    'linked-artifact-hash-mismatch'
  );

  const wrongContext = join(tmp, 'wrong-context.json');
  const context = JSON.parse(readFileSync(join(repoRoot, contextPath), 'utf8'));
  context.subject.route.id = 'wrong-route';
  writeFileSync(wrongContext, `${JSON.stringify(context, null, 2)}\n`);
  expectExit(
    ['verify-bridge', '--expect-context', wrongContext, reportPath],
    1,
    'context-route-id-mismatch'
  );

  const boundary = join(tmp, 'boundary.bridge.json');
  const boundaryReport = JSON.parse(
    readFileSync(join(repoRoot, reportPath), 'utf8')
  );
  boundaryReport.boundary.excludes = boundaryReport.boundary.excludes.filter(
    (entry) => entry !== 'target-code-correctness'
  );
  writeFileSync(boundary, `${JSON.stringify(boundaryReport, null, 2)}\n`);
  expectExit(['verify-bridge', boundary], 1, 'boundary-excludes-mismatch');

  const compact = join(tmp, 'compact.bridge.json');
  writeFileSync(
    compact,
    JSON.stringify(JSON.parse(readFileSync(join(repoRoot, reportPath))))
  );
  expectExit(['verify-bridge', compact], 1, 'non-canonical-artifact-json');

  const crlf = join(tmp, 'crlf.bridge.json');
  writeFileSync(
    crlf,
    readFileSync(join(repoRoot, reportPath), 'utf8').replace(/\n/g, '\r\n')
  );
  expectExit(['verify-bridge', crlf], 1, 'non-canonical-artifact-json');

  const duplicateKey = join(tmp, 'duplicate-key.bridge.json');
  const canonical = readFileSync(join(repoRoot, reportPath), 'utf8');
  writeFileSync(
    duplicateKey,
    canonical.replace(
      '  "bridge_report": "vouch.bridge-report/v0",\n',
      '  "bridge_report": "vouch.bridge-report/v0",\n  "bridge_report": "vouch.bridge-report/v0",\n'
    )
  );
  expectExit(['verify-bridge', duplicateKey], 1, 'non-canonical-artifact-json');

  const noncanonicalUnknown = join(tmp, 'noncanonical-unknown.bridge.json');
  writeFileSync(
    noncanonicalUnknown,
    '{"bridge_report":"vouch.bridge-report/v0","engine":{"extra":"trust-me"}}\n'
  );
  const noncanonicalUnknownReport = expectExit(
    ['verify-bridge', noncanonicalUnknown],
    1,
    'non-canonical-artifact-json'
  );
  if (
    noncanonicalUnknownReport.diagnostics?.some((entry) =>
      String(entry.code).startsWith('unknown-field:')
    )
  ) {
    fail('non-canonical artifact reported trusted field-path diagnostics');
  }

  const nestedUnknown = join(tmp, 'nested-unknown.bridge.json');
  const nestedUnknownReport = JSON.parse(
    readFileSync(join(repoRoot, reportPath), 'utf8')
  );
  nestedUnknownReport.engine.extra = 'trust-me';
  writeFileSync(
    nestedUnknown,
    `${JSON.stringify(nestedUnknownReport, null, 2)}\n`
  );
  expectExit(['verify-bridge', nestedUnknown], 1, 'unknown-field:engine.extra');

  for (const field of [
    'semantic_proof',
    'verified_by',
    'generated_at',
    'hostname',
  ]) {
    const nestedTrust = join(tmp, `nested-${field}.bridge.json`);
    const next = JSON.parse(readFileSync(join(repoRoot, reportPath), 'utf8'));
    next.subject.route[field] = 'trust-me';
    writeFileSync(nestedTrust, `${JSON.stringify(next, null, 2)}\n`);
    expectExit(
      ['verify-bridge', nestedTrust],
      1,
      `unknown-field:subject.route.${field}`
    );
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

console.log('vouch bridge check passed');
