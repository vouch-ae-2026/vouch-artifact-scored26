// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import {
  chmod,
  lstat,
  readFile,
  readdir,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const defaultRoot = path.resolve(scriptDir, '..');
const root = path.resolve(process.env.VOUCH_ARTIFACT_ROOT ?? defaultRoot);
const manifestName = 'ARTIFACT-MANIFEST.json';

const requiredPaths = Object.freeze([
  'LICENSE-SCOPE.md',
  'README.md',
  'RUN.md',
  'machine-record/vouch-scored26-release-record.pdf',
  'package.json',
  'release/audit/anonymity-report.json',
  'release/audit/bundle-reconciliation.json',
  'release/audit/lifecycle-audit.json',
  'release/audit/lifecycle-command-record.md',
  'release/audit/secret-scan-report.json',
  'release/audit/source-projection-report.json',
  'release/archive-chunks/archive-chunks.json',
  'release/chain/clean-run-report.json',
  'release/chain/native-release-public-key.json',
  'release/chain/release-descriptor.dsse.json',
  'release/chain/release-descriptor.json',
  'release/chain/release-publication.json',
  'release/chain/reproduction-observation.dsse.json',
  'release/chain/reproduction-observation.json',
  'release/chain/publication-report.json',
  'release/chain/trust-policy.json',
  'release/results/condition-map.json',
  'release/results/exact-reproduction-comparisons.json',
  'release/results/fixture-results.json',
  'release/results/mutation-results.json',
  'release/results/performance-results.json',
  'release/results/release-manifest.json',
  'release/results/workload-results.json',
  'scripts/build-artifact-manifest.mjs',
  'scripts/archive-chunks/README.md',
  'scripts/archive-chunks/archive-chunk-lib.mjs',
  'scripts/archive-chunks/archive-chunks.mjs',
  'scripts/archive-chunks/self-test.mjs',
  'scripts/archive-chunks/verify-archive-chunks.mjs',
  'scripts/check-artifact-negative.mjs',
  'scripts/check-artifact.mjs',
  'source/RIGHTS.md',
  'source/SOURCE-MANIFEST.json',
  'source/review-toolchain/chunks/typescript-5.8.2-typescript.js/manifest.json',
  'source/synthetic-history/vouch-scored26.bundle',
  'source/artifact/contract/NATIVE-IMPLEMENTATION-CONDITIONS-v8.5.1.md',
  'source/artifact/contract/NATIVE-IMPLEMENTATION-CONDITIONS-v8.6.0.md',
  'source/artifact/contract/condition-map.json',
  'source/artifact/fixtures/fixture-registry.json',
  'source/artifact/mutation/activation-results.json',
  'source/package.json',
]);

try {
  await refreshSourceProjectionReport(root);
  const inventory = await inventoryTree(root);
  const present = new Set(inventory.files.map((entry) => entry.path));
  const missing = requiredPaths.filter((entry) => !present.has(entry));
  if (missing.length !== 0) {
    throw new Error(`required artifact paths are missing: ${missing.join(', ')}`);
  }

  const manifest = {
    artifact_manifest: 'vouch.scored26-artifact-manifest/v1',
    directories: inventory.directories,
    files: inventory.files,
  };
  const bytes = writeCanonicalJson(manifest);
  await writeFile(path.join(root, manifestName), bytes, { mode: 0o644 });
  await chmod(path.join(root, manifestName), 0o644);
  console.log(
    `wrote ${manifestName} (${inventory.files.length} files, ${inventory.directories.length} directories)`
  );
} catch (error) {
  console.error(`artifact manifest build failed: ${error.message}`);
  process.exitCode = 1;
}

async function refreshSourceProjectionReport(base) {
  const sourceManifestBytes = await readFile(
    path.join(base, 'source', 'SOURCE-MANIFEST.json')
  );
  const sourceManifest = JSON.parse(sourceManifestBytes.toString('utf8'));
  if (
    sourceManifest.source_projection !==
      'vouch.scored26-source-projection/v2' ||
    !Array.isArray(sourceManifest.files)
  ) {
    throw new Error('source manifest cannot produce the projection report');
  }
  const rightsBytes = await readFile(path.join(base, 'source', 'RIGHTS.md'));
  const report = {
    boundary_status: 'pass',
    derived_from_commit: sourceManifest.source_snapshot.commit,
    release_archive_equivalent: false,
    release_chain_authenticated: false,
    rights_sha256: sha256Id(rightsBytes),
    source_file_count: sourceManifest.files.length,
    source_manifest_sha256: sha256Id(sourceManifestBytes),
    source_projection_report: 'vouch.scored26-source-projection-report/v1',
    status: 'pass',
  };
  const reportPath = path.join(
    base,
    'release',
    'audit',
    'source-projection-report.json'
  );
  await writeFile(reportPath, writeCanonicalJson(report), { mode: 0o644 });
  await chmod(reportPath, 0o644);
  console.log('wrote release/audit/source-projection-report.json');
}

async function inventoryTree(base) {
  const directories = [];
  const files = [];
  await walk('');
  directories.sort((left, right) => utf8Compare(left.path, right.path));
  files.sort((left, right) => utf8Compare(left.path, right.path));
  return { directories, files };

  async function walk(relativeDirectory) {
    const absoluteDirectory = path.join(base, relativeDirectory);
    const names = await readdir(absoluteDirectory);
    names.sort(utf8Compare);
    for (const name of names) {
      const relative = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      if (relative === '.git') {
        const metadataStat = await lstat(path.join(base, relative));
        if (
          metadataStat.isSymbolicLink() ||
          (!metadataStat.isDirectory() && !metadataStat.isFile())
        ) {
          throw new Error('root repository metadata is not a regular file or directory');
        }
        continue;
      }
      if (relative === manifestName) continue;
      validateRelativePath(relative);
      rejectResiduePath(relative);
      const absolute = path.join(base, ...relative.split('/'));
      const stat = await lstat(absolute);
      if (stat.isSymbolicLink()) {
        throw new Error(`symlink is forbidden: ${relative}`);
      }
      if (stat.isDirectory()) {
        const mode = portableMode(stat.mode, 'directory', relative);
        directories.push({ mode, path: relative });
        await walk(relative);
        continue;
      }
      if (!stat.isFile()) {
        throw new Error(`non-regular filesystem entry is forbidden: ${relative}`);
      }
      const mode = portableMode(stat.mode, 'file', relative);
      const bytes = await readFile(absolute);
      if (bytes.length >= 8_000_000) {
        throw new Error(
          `${relative}: distributed file is ${bytes.length} bytes; every file must remain below 4open's 8 MB limit`
        );
      }
      files.push({
        mode,
        path: relative,
        sha256: sha256Id(bytes),
        size: bytes.length,
      });
    }
  }
}

function portableMode(rawMode, kind, relative) {
  const mode = rawMode & 0o777;
  const allowed = kind === 'directory' ? new Set([0o755]) : new Set([0o644, 0o755]);
  if (!allowed.has(mode)) {
    throw new Error(
      `nonportable ${kind} mode ${mode.toString(8)}: ${relative}`
    );
  }
  return `0${mode.toString(8).padStart(3, '0')}`;
}

function rejectResiduePath(relative) {
  const parts = relative.split('/');
  const vendoredSource = relative.startsWith('source/vendor/');
  const declaredBridgeTarget =
    relative === 'source/examples/vouch-bridge/target' ||
    relative.startsWith('source/examples/vouch-bridge/target/');
  const forbiddenSegments = new Set([
    '.cache',
    '.git',
    '.next',
    '.npm',
    '.pytest_cache',
    '.turbo',
    '__pycache__',
    'coverage',
    'node_modules',
    'target',
  ]);
  const last = parts.at(-1);
  if (
    parts.some(
      (part) =>
        forbiddenSegments.has(part) &&
        !(declaredBridgeTarget && part === 'target') &&
        !(vendoredSource && ['coverage', 'node_modules', 'target'].includes(part))
    ) ||
    last === '.DS_Store'
  ) {
    throw new Error(`cache or repository residue is forbidden: ${relative}`);
  }
  if (
    last === '.gitmodules' ||
    last === '.mailmap' ||
    last === 'packed-refs' ||
    (last.endsWith('.bundle') &&
      relative !== 'source/synthetic-history/vouch-scored26.bundle')
  ) {
    throw new Error(`repository history material is forbidden: ${relative}`);
  }
}

function validateRelativePath(value) {
  if (
    value.length === 0 ||
    value.includes('\\') ||
    value.includes('\0') ||
    value.includes('\n') ||
    value.startsWith('/') ||
    value.normalize('NFC') !== value ||
    value.split('/').some((part) => part === '' || part === '.' || part === '..')
  ) {
    throw new Error(`noncanonical artifact path: ${JSON.stringify(value)}`);
  }
}

function sha256Id(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function writeCanonicalJson(value) {
  const chunks = [];
  writeValue(value, 0, chunks);
  chunks.push('\n');
  return Buffer.from(chunks.join(''), 'utf8');
}

function writeValue(value, depth, chunks) {
  if (value === null) {
    chunks.push('null');
  } else if (typeof value === 'boolean') {
    chunks.push(value ? 'true' : 'false');
  } else if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new Error('manifest JSON accepts only safe integers');
    }
    chunks.push(String(value));
  } else if (typeof value === 'string') {
    chunks.push(JSON.stringify(value));
  } else if (Array.isArray(value)) {
    if (value.length === 0) {
      chunks.push('[]');
      return;
    }
    chunks.push('[\n');
    value.forEach((item, index) => {
      chunks.push('  '.repeat(depth + 1));
      writeValue(item, depth + 1, chunks);
      chunks.push(index + 1 === value.length ? '\n' : ',\n');
    });
    chunks.push('  '.repeat(depth), ']');
  } else if (
    typeof value === 'object' &&
    Object.getPrototypeOf(value) === Object.prototype
  ) {
    const names = Object.keys(value).sort(utf8Compare);
    if (names.length === 0) {
      chunks.push('{}');
      return;
    }
    chunks.push('{\n');
    names.forEach((name, index) => {
      chunks.push('  '.repeat(depth + 1), JSON.stringify(name), ': ');
      writeValue(value[name], depth + 1, chunks);
      chunks.push(index + 1 === names.length ? '\n' : ',\n');
    });
    chunks.push('  '.repeat(depth), '}');
  } else {
    throw new Error('value is outside canonical artifact JSON');
  }
}

function utf8Compare(left, right) {
  const leftValue = typeof left === 'string' ? left : left.path;
  const rightValue = typeof right === 'string' ? right : right.path;
  return Buffer.compare(Buffer.from(leftValue, 'utf8'), Buffer.from(rightValue, 'utf8'));
}
