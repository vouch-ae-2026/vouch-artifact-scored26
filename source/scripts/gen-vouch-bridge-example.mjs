import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(fileURLToPath(new URL('..', import.meta.url)));
const version = JSON.parse(
  readFileSync(join(repoRoot, 'package.json'), 'utf8')
).version;

const sourcePath = 'examples/vouch-bridge/source/checkout-discount.ts';
const targetPath = 'examples/vouch-bridge/target/checkout_discount.py';
const linkedPath = 'examples/vouch-bridge/linked/conversion-gate-proof.json';
const reportPath =
  'examples/vouch-bridge/reports/checkout-discount.bridge.json';
const contextPath =
  'examples/vouch-bridge/context/checkout-discount.context.json';

const domains = {
  source: 'vouch/external-source-hash/v0',
  target: 'vouch/external-target-hash/v0',
  linked: 'vouch/linked-artifact-hash/v0',
};

function hashWithDomain(domain, bytes) {
  return createHash('sha256')
    .update(domain, 'utf8')
    .update(Buffer.from([0]))
    .update(bytes)
    .digest('hex');
}

function hashObject(domain, bytes) {
  return {
    algo: 'sha-256',
    domain,
    hex: hashWithDomain(domain, bytes),
  };
}

function fileObject(path, language, domain) {
  const bytes = readFileSync(join(repoRoot, path));
  return {
    language,
    path,
    byte_len: bytes.length,
    hash: hashObject(domain, bytes),
  };
}

function linkedArtifact() {
  const bytes = readFileSync(join(repoRoot, linkedPath));
  return {
    id: 'conversion-gate-proof',
    kind: 'internal-gate-proof',
    path: linkedPath,
    disclosure: 'public-bytes',
    hash: hashObject(domains.linked, bytes),
  };
}

function report() {
  const linked = linkedArtifact();
  const checks = [
    {
      id: 'source-boundary',
      stage: 'source',
      status: 'pass',
      artifact_hash: linked.hash,
    },
    {
      id: 'conversion-route',
      stage: 'engine',
      status: 'pass',
      artifact_hash: linked.hash,
    },
    {
      id: 'target-adapter',
      stage: 'target',
      status: 'pass',
      artifact_hash: linked.hash,
    },
  ];
  return {
    bridge_report: 'vouch.bridge-report/v0',
    profile: {
      kind: 'conversion-evidence',
      version: 'v0',
    },
    engine: {
      name: 'example-conversion-engine',
      version,
      commit: {
        vcs: 'git',
        hex: '1111111111111111111111111111111111111111',
        dirty: false,
      },
    },
    subject: {
      kind: 'source-to-target-conversion',
      case_id: 'checkout-discount-ts-to-python',
      source: fileObject(sourcePath, 'TypeScript', domains.source),
      target: fileObject(targetPath, 'Python', domains.target),
      route: {
        id: 'checked-expression-route',
        checked_profile: 'vouch.conversion-evidence-profile/v0',
        capability_ids: [
          'function',
          'conditional',
          'comparison',
          'integer-arithmetic',
        ],
      },
    },
    checks,
    linked_artifacts: [linked],
    summary: {
      status: 'pass',
      check_count: checks.length,
      failed_checks: 0,
      not_run_checks: 0,
    },
    boundary: {
      attests: [
        'external-engine-evidence-shape',
        'source-target-byte-binding',
        'declared-gate-results',
        'linked-artifact-hash-binding',
        'boundary-disclosure',
      ],
      excludes: [
        'target-code-correctness',
        'semantic-equivalence',
        'external-engine-execution',
        'private-engine-disclosure',
        'production-enforcement',
        'receipt-authenticity',
        'generation-honesty',
        'issuer-binding',
        'timestamping',
        'non-repudiation',
        'external-independent-verification',
        'full-cskernel-coverage',
      ],
    },
    diagnostics: [],
  };
}

function contextManifest() {
  return {
    bridge_context_manifest: 'vouch.bridge-context-manifest/v0',
    profile: {
      kind: 'conversion-evidence',
      version: 'v0',
    },
    subject: {
      kind: 'source-to-target-conversion',
      case_id: 'checkout-discount-ts-to-python',
      route: {
        id: 'checked-expression-route',
        checked_profile: 'vouch.conversion-evidence-profile/v0',
        capability_ids: [
          'function',
          'conditional',
          'comparison',
          'integer-arithmetic',
        ],
      },
    },
  };
}

function exactJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

const next = exactJson(report());
const nextContext = exactJson(contextManifest());
const current = readFileSync(join(repoRoot, reportPath), 'utf8');
const currentContext = existsSync(join(repoRoot, contextPath))
  ? readFileSync(join(repoRoot, contextPath), 'utf8')
  : null;
if (process.argv.includes('--write')) {
  mkdirSync(dirname(join(repoRoot, reportPath)), { recursive: true });
  writeFileSync(join(repoRoot, reportPath), next);
  mkdirSync(dirname(join(repoRoot, contextPath)), { recursive: true });
  writeFileSync(join(repoRoot, contextPath), nextContext);
  console.log(`wrote ${reportPath}`);
  console.log(`wrote ${contextPath}`);
} else if (current !== next || currentContext !== nextContext) {
  console.error(
    `${reportPath} or ${contextPath} is stale. Run npm run gen:vouch-bridge-example.`
  );
  process.exit(1);
} else {
  console.log('vouch bridge example is current');
}
