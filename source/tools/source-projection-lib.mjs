import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';

export const FREEZE_COMMIT = 'c90f97ddd6b1d662791a76fe4663b90e79c443ec';
export const BASE_COMMIT = 'ef7ef9bb4b56382ef5d413408a5f93a6898498c2';
export const SOURCE_COMMIT = '3e910c9ff87cc01d3bc241d63297218b44e75ede';
export const SOURCE_TREE = 'c686334b180b3a9581b91c70f08da15528f93d9a';
export const SOURCE_TRACKED_FILE_COUNT = 2_367;
export const SYNTHETIC_BUNDLE_PATH =
  'synthetic-history/vouch-scored26.bundle';
export const DISTRIBUTED_FILE_LIMIT_BYTES = 8_000_000;
export const TYPESCRIPT_REASSEMBLED_PATH =
  'review-toolchain/typescript/lib/typescript.js';
export const TYPESCRIPT_CHUNK_DIRECTORY =
  'review-toolchain/chunks/typescript-5.8.2-typescript.js';
export const TYPESCRIPT_CHUNK_MANIFEST_PATH =
  `${TYPESCRIPT_CHUNK_DIRECTORY}/manifest.json`;
export const TYPESCRIPT_CHUNK_SPEC = Object.freeze({
  chunk_manifest: 'vouch.review-toolchain-chunks/v1',
  distributed_file_limit_bytes: DISTRIBUTED_FILE_LIMIT_BYTES,
  original: {
    bytes: 9_065_569,
    mode: '0644',
    path: TYPESCRIPT_REASSEMBLED_PATH,
    sha256: '795e49e46d497cc16e4b02916b50cbca257b4256d62cddc4cc504103f7961027',
  },
  part_size_limit_bytes: 7_340_032,
  parts: [
    {
      bytes: 7_340_032,
      path: `${TYPESCRIPT_CHUNK_DIRECTORY}/part-0000`,
      sha256: 'd1372a4193d979f0b75250f75fce87cefd3a3f2545db648cb6cd9e97527d11df',
    },
    {
      bytes: 1_725_537,
      path: `${TYPESCRIPT_CHUNK_DIRECTORY}/part-0001`,
      sha256: 'fea0556aa41ad26b2ba08e1bd1337abb5924d11f57618525c6412f78e008bec9',
    },
  ],
  reassembly: 'ordered byte concatenation',
});
export const CONTRACT_SHA256 =
  'ecc294798be49f5843bd84e0ebad5d94a930f2b09f51db4852e42d2789addddc';
export const TYPESCRIPT_VERSION = '5.8.2';
export const TYPESCRIPT_NPM_INTEGRITY =
  'sha512-aJn6wq13/afZp/jT9QZmwEjDqqvSGp1VT5GVg+f/t6/oVyrgXM6BY1h9BRh/O5p3PlUPAe+WuiEZOmb/49RqoQ==';
export const TYPESCRIPT_PACKAGE_PATH = 'review-toolchain/typescript';
export const TYPESCRIPT_PACKAGE_FILE_COUNT = 130;
export const TYPESCRIPT_PACKAGE_BYTES = 22_866_019;
export const TYPESCRIPT_PACKAGE_TREE_SHA256 =
  '261edf26930381acf18ff5fd333e20f28ffd5ebbe410afff203dc995ad31edf7';
export const TYPESCRIPT_LICENSE_SHA256 =
  'a7d00bfd54525bc694b6e32f64c7ebcf5e6b7ae3657be5cc12767bce74654a47';
export const NODE_TYPES_VERSION = '20.19.43';
export const NODE_TYPES_NPM_INTEGRITY =
  'sha512-6oYBAi5ikg4Pl+kGsoYtawUMBT2zZMCvPNF7pVLnHZfd1zf38DRiWn/gT01RYCdUqkv7Fhr+C9ot4/tb+2sVvA==';
export const NODE_TYPES_PACKAGE_PATH = 'review-toolchain/types-node';
export const UNDICI_TYPES_VERSION = '6.21.0';
export const UNDICI_TYPES_NPM_INTEGRITY =
  'sha512-iwDZqg0QAGrg9Rav5H4n0M64c3mkR59cJ6wQp+7C4nI0gsmExaedaYLNO44eT4AtBBwjbTiGPMlt2Md0T9H9JQ==';
export const UNDICI_TYPES_PACKAGE_PATH = 'review-toolchain/undici-types';
export const AJV_PACKAGE_PATH = 'review-toolchain/ajv';

const reviewToolchainPackages = [
  {
    name: 'typescript',
    version: TYPESCRIPT_VERSION,
    path: TYPESCRIPT_PACKAGE_PATH,
    integrity: TYPESCRIPT_NPM_INTEGRITY,
    fileCount: TYPESCRIPT_PACKAGE_FILE_COUNT,
    bytes: TYPESCRIPT_PACKAGE_BYTES,
    treeSha256: TYPESCRIPT_PACKAGE_TREE_SHA256,
    license: 'Apache-2.0',
    licensePath: 'LICENSE.txt',
    licenseSha256: TYPESCRIPT_LICENSE_SHA256,
    metadataCheck: (metadata) => metadata.bin?.tsc === './bin/tsc',
  },
  {
    name: '@types/node',
    version: NODE_TYPES_VERSION,
    path: NODE_TYPES_PACKAGE_PATH,
    integrity: NODE_TYPES_NPM_INTEGRITY,
    fileCount: 69,
    bytes: 2_288_801,
    treeSha256: '4875fd8a4ba9bd648da35ec6f069793469a484855e6510be9fc7782c5c2814f7',
    license: 'MIT',
    licensePath: 'LICENSE',
    licenseSha256: 'c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383',
    metadataCheck: (metadata) => metadata.dependencies?.['undici-types'] === '~6.21.0',
  },
  {
    name: 'undici-types',
    version: UNDICI_TYPES_VERSION,
    path: UNDICI_TYPES_PACKAGE_PATH,
    integrity: UNDICI_TYPES_NPM_INTEGRITY,
    fileCount: 41,
    bytes: 83_680,
    treeSha256: 'f4b4e5b5e3aa89fde9544ecac9f3792ca436ca6e1699deeaf564d5c757a155e0',
    license: 'MIT',
    licensePath: 'LICENSE',
    licenseSha256: 'a6db8096b2707bc0102d256917d4d33f298ba36d8c3f25de067a2b5bb379db27',
    metadataCheck: () => true,
  },
  {
    name: 'ajv',
    version: '8.17.1',
    path: AJV_PACKAGE_PATH,
    integrity:
      'sha512-B/gBuNg5SiMTrPkC+A2+cW0RszwxYmn6VYxB/inlBStS5nx6xHIt/ehKRhIMhqusl7a8LjQoZnjCs5vhwxOQ1g==',
    fileCount: 466,
    bytes: 1_030_888,
    treeSha256: '9cfef146f3453a96c9fd2ebc4b7ca8605fdbbafff57c6eb503ab61e6cac20704',
    license: 'MIT',
    licensePath: 'LICENSE',
    licenseSha256: 'a05350a88e318e4f5f2c2a1ff1e2e88daa4dd38e6e78b71cccae422bdc762cc3',
    metadataCheck: (metadata) =>
      JSON.stringify(metadata.dependencies) ===
      JSON.stringify({
        'fast-deep-equal': '^3.1.3',
        'fast-uri': '^3.0.1',
        'json-schema-traverse': '^1.0.0',
        'require-from-string': '^2.0.2',
      }),
  },
  {
    name: 'fast-deep-equal',
    version: '3.1.3',
    path: 'review-toolchain/fast-deep-equal',
    integrity:
      'sha512-f3qQ9oQy9j2AhBe/H9VC91wLmKBCCU/gDOnKNAYG5hswO7BLKj09Hc5HYNz9cGI++xlpDCIgDaitVs03ATR84Q==',
    fileCount: 11,
    bytes: 12_966,
    treeSha256: '9304d4597f884478732c4c2a31fed626b64116083555b4055757ad96e6b44926',
    license: 'MIT',
    licensePath: 'LICENSE',
    licenseSha256: '7bf9b2de73a6b356761c948d0e9eeb4be6c1270bd04c79cd489c1e400ffdfc1a',
    metadataCheck: () => true,
  },
  {
    name: 'fast-uri',
    version: '3.1.3',
    path: 'review-toolchain/fast-uri',
    integrity:
      'sha512-i70LwGWUduXqzicKXWshooq+sWL1K3WUU5rKZNG/0i3a1OSoX3HqhH5WbWwTmqWfor4urUakGPiRQcleRZTwOg==',
    fileCount: 34,
    bytes: 157_708,
    treeSha256: '0d0104d40dd6c356fc38bf6458ddbf07b5a6d3ffe3f65da8b74a7624ed4c783e',
    license: 'BSD-3-Clause',
    licensePath: 'LICENSE',
    licenseSha256: 'b010b0dfdfdb23d7396e03b82cd4621fc9bb8f95d6b0aea70b9c24e12074c786',
    metadataCheck: () => true,
  },
  {
    name: 'json-schema-traverse',
    version: '1.0.0',
    path: 'review-toolchain/json-schema-traverse',
    integrity:
      'sha512-NM8/P9n3XjXhIZn1lLhkFaACTOURQXjWhV4BA/RnOv8xvgqtqpAX9IO4mRQxSx1Rlo4tqzeqb0sOlruaOy3dug==',
    fileCount: 12,
    bytes: 22_220,
    treeSha256: 'd3038e49ea48f3d6954548c8c49298ab575e40e0a5914ad6573ae3f2b08e4991',
    license: 'MIT',
    licensePath: 'LICENSE',
    licenseSha256: '7bf9b2de73a6b356761c948d0e9eeb4be6c1270bd04c79cd489c1e400ffdfc1a',
    metadataCheck: () => true,
  },
  {
    name: 'require-from-string',
    version: '2.0.2',
    path: 'review-toolchain/require-from-string',
    integrity:
      'sha512-Xf0nWe6RseziFMu+Ap9biiUbmplq6S9/p+7w7YXP/JBHhrUDDUhwa+vANyubuqfZWTveU//DYVGsDG7RKL/vEw==',
    fileCount: 4,
    bytes: 3_422,
    treeSha256: '910330a0f913b9a99df75e8da057e1db30fe6e3f2bdf93ddc06e4dce61983ccc',
    license: 'MIT',
    licensePath: 'license',
    licenseSha256: '6ee0feb1f6ef996ff5a68600f8cf98909cf412d39ef3cdceaefd87d636fa1b7f',
    metadataCheck: () => true,
  },
];

const authored = new Set([
  'README.md',
  'RIGHTS.md',
  'RUN.md',
  'tools/build-source-manifest.mjs',
  'tools/check-fixture-results-negative.mjs',
  'tools/check-fixture-results.mjs',
  'tools/check-replay-manifest-portable.mjs',
  'tools/check-source-negative.mjs',
  'tools/check-source-projection.mjs',
  'tools/check-synthetic-checkout.mjs',
  'tools/fixture-results-lib.mjs',
  'tools/prepare-review-toolchain.mjs',
  'tools/review-toolchain-lib.mjs',
  'tools/run-fixture-conformance.mjs',
  'tools/run-rust-core.mjs',
  'tools/run-vouch-loop-example.mjs',
  'tools/source-projection-lib.mjs',
  'tools/synthetic-checkout-lib.mjs',
]);

const transientDirectories = new Set(['packages/vouch-consumer/dist']);
const classicConformanceDocs = new Set([
  'getting-started.mdx',
  'introduction.mdx',
  'reference/core-functions.mdx',
  'reference/functional-library.mdx',
  'reference/list-operations.mdx',
  'reference/operators.mdx',
  'concepts/variables-scope.mdx',
  'concepts/control-flow.mdx',
  'concepts/data-types.mdx',
  'concepts/error-handling.mdx',
  'concepts/functions-closures.mdx',
  'concepts/syntax.mdx',
  'guides/using-map.mdx',
  'guides/first-project.mdx',
  'guides/recursion.mdx',
  'guides/capabilities.mdx',
  'guides/targets.mdx',
  'guides/understanding-closures.mdx',
]);
const publicVouchDocs = new Set([
  'classic/guides/vouch-bridge.mdx',
  'classic/vouch.mdx',
  'guides/vouch-bridge.mdx',
  'guides/vouch-replay.mdx',
  'guides/vouch.mdx',
  'reference/vouch-receipts.mdx',
  'vouch.mdx',
]);

export function projectionRoot(importMetaUrl) {
  return realpathSync(new URL('..', importMetaUrl));
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function canonicalJson(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function inventoryFiles(
  root,
  {
    allowReassembledTypeScript = false,
    includeManifest = false,
  } = {}
) {
  const out = [];
  visit(root, '');
  return out.sort((left, right) => compareUtf8(left.path, right.path));

  function visit(absolute, rel) {
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) {
      out.push({ path: rel, absolute, kind: 'symlink' });
      return;
    }
    if (stat.isDirectory()) {
      for (const name of readdirSync(absolute).sort(compareUtf8)) {
        const child = rel ? `${rel}/${name}` : name;
        if (rel === '' && name === 'node_modules') continue;
        if (rel === '' && name === 'target') continue;
        if (transientDirectories.has(child)) continue;
        visit(join(absolute, name), child);
      }
      return;
    }
    if (!stat.isFile()) return;
    if (!includeManifest && rel === 'SOURCE-MANIFEST.json') return;
    if (rel === TYPESCRIPT_REASSEMBLED_PATH) return;
    if (allowReassembledTypeScript && rel === 'lib/typescript.js') {
      out.push({ path: rel, absolute, kind: 'file', bytes: stat.size });
      return;
    }
    if (stat.size >= DISTRIBUTED_FILE_LIMIT_BYTES) {
      throw new Error(
        `${rel}: distributed file is ${stat.size} bytes; 4open requires every file below ${DISTRIBUTED_FILE_LIMIT_BYTES}`
      );
    }
    out.push({ path: rel, absolute, kind: 'file', bytes: stat.size });
  }
}

export function buildManifest(root) {
  const toolchainIssues = vendoredReviewToolchainIssues(root);
  if (toolchainIssues.length > 0) throw new Error(toolchainIssues.join('\n'));
  const transientIssues = transientReviewToolchainIssues(root);
  if (transientIssues.length > 0) throw new Error(transientIssues.join('\n'));
  const files = inventoryFiles(root).map((entry) => {
    if (entry.kind !== 'file') {
      throw new Error(`non-regular manifest entry: ${entry.path}`);
    }
    const bytes = readFileSync(entry.absolute);
    return {
      path: entry.path,
      bytes: bytes.length,
      sha256: sha256(bytes),
      class: classify(entry.path),
      origin: originFor(entry.path),
      rights: rightsFor(entry.path),
    };
  });
  const byClass = {};
  const byOrigin = {};
  const byRights = {};
  let bytes = 0;
  for (const file of files) {
    bytes += file.bytes;
    byClass[file.class] = (byClass[file.class] ?? 0) + 1;
    byOrigin[file.origin] = (byOrigin[file.origin] ?? 0) + 1;
    byRights[file.rights] = (byRights[file.rights] ?? 0) + 1;
  }
  return {
    source_projection: 'vouch.scored26-source-projection/v2',
    source_snapshot: {
      commit: SOURCE_COMMIT,
      repository_locator: null,
      working_tree_git_metadata_included: false,
    },
    synthetic_history: {
      bundle_path: SYNTHETIC_BUNDLE_PATH,
      bundle_authenticated_by_current_release: true,
      commit_count: 3,
      freeze_commit: FREEZE_COMMIT,
      base_commit: BASE_COMMIT,
      source_commit: SOURCE_COMMIT,
      source_tree: SOURCE_TREE,
      tracked_file_count: SOURCE_TRACKED_FILE_COUNT,
      ref: 'HEAD',
      hash_algorithm: 'sha1',
      identity: 'Artifact Maintainer <artifact@example.invalid>',
      lifecycle_status:
        'byte-identical to release/vouch-scored26.bundle in the D-bound release archive',
    },
    normative_contract: {
      path: 'artifact/contract/NATIVE-IMPLEMENTATION-CONDITIONS-v8.6.0.md',
      sha256: CONTRACT_SHA256,
      condition_count: 213,
      built_condition_count: 213,
    },
    review_toolchain: {
      package: 'typescript',
      version: TYPESCRIPT_VERSION,
      path: TYPESCRIPT_PACKAGE_PATH,
      npm_integrity: TYPESCRIPT_NPM_INTEGRITY,
      package_file_count: TYPESCRIPT_PACKAGE_FILE_COUNT,
      package_bytes: TYPESCRIPT_PACKAGE_BYTES,
      package_tree_sha256: TYPESCRIPT_PACKAGE_TREE_SHA256,
      license: 'Apache-2.0',
      license_path: `${TYPESCRIPT_PACKAGE_PATH}/LICENSE.txt`,
      license_sha256: TYPESCRIPT_LICENSE_SHA256,
      type_dependencies: reviewToolchainPackages.slice(1, 3).map((item) => ({
        package: item.name,
        version: item.version,
        path: item.path,
        npm_integrity: item.integrity,
        package_file_count: item.fileCount,
        package_bytes: item.bytes,
        package_tree_sha256: item.treeSha256,
        license: item.license,
        license_path: `${item.path}/${item.licensePath}`,
        license_sha256: item.licenseSha256,
      })),
      runtime_dependencies: reviewToolchainPackages.slice(3).map((item) => ({
        package: item.name,
        version: item.version,
        path: item.path,
        npm_integrity: item.integrity,
        package_file_count: item.fileCount,
        package_bytes: item.bytes,
        package_tree_sha256: item.treeSha256,
        license: item.license,
        license_path: `${item.path}/${item.licensePath}`,
        license_sha256: item.licenseSha256,
      })),
      installation:
        'distributed offline; prepare:review-toolchain verifies and atomically reassembles the split TypeScript payload and creates nine temporary local links only in an OS temporary copy',
      split_transport: {
        manifest_path: TYPESCRIPT_CHUNK_MANIFEST_PATH,
        original_path: TYPESCRIPT_REASSEMBLED_PATH,
        original_bytes: TYPESCRIPT_CHUNK_SPEC.original.bytes,
        original_sha256: TYPESCRIPT_CHUNK_SPEC.original.sha256,
        ordered_part_paths: TYPESCRIPT_CHUNK_SPEC.parts.map(
          (part) => part.path
        ),
        part_size_limit_bytes: TYPESCRIPT_CHUNK_SPEC.part_size_limit_bytes,
        distributed_file_limit_bytes: DISTRIBUTED_FILE_LIMIT_BYTES,
        reassembly:
          'verify manifest and ordered parts, then atomically reconstruct only in an OS temporary copy',
      },
    },
    rights: {
      first_party_license: 'UNLICENSED',
      limited_evaluation_permission: true,
      purpose: 'peer review and artifact evaluation only',
      permitted_acts: [
        'download',
        'local reproduction',
        'compile',
        'execute',
        'evaluation-only modification',
      ],
      redistribution_permitted: false,
      commercial_use_permitted: false,
      general_license_granted: false,
      notice: 'RIGHTS.md',
      vendor_terms: 'retained per dependency',
    },
    manifest_scope: {
      self_excluded: 'SOURCE-MANIFEST.json',
      transient_untracked_segments: [
        'node_modules (root only; exact temporary nine-link toolchain)',
        'packages/vouch-consumer/dist',
        'target (root Cargo output only)',
      ],
      vendor_exception: 'all tracked vendor and review-toolchain paths are inventoried without blanket segment filtering',
    },
    excluded_categories: [
      'original Lispex Git metadata, remotes, and non-synthetic history',
      'unrelated product site and implementation surfaces outside the synthetic Vouch dependency closure',
      'non-product planning, evaluation, and review records',
      'unrelated research tracks and full backend receipt archives',
      'internal product blueprint and broader Vouch research or ledger schemas',
      'release private keys, credentials, and local paths',
    ],
    transformations: [
      {
        paths: [
          'README.md',
          'RIGHTS.md',
          'RUN.md',
          'tools/build-source-manifest.mjs',
          'tools/check-fixture-results-negative.mjs',
          'tools/check-fixture-results.mjs',
          'tools/check-replay-manifest-portable.mjs',
          'tools/check-source-negative.mjs',
          'tools/check-source-projection.mjs',
          'tools/check-synthetic-checkout.mjs',
          'tools/fixture-results-lib.mjs',
          'tools/prepare-review-toolchain.mjs',
          'tools/review-toolchain-lib.mjs',
          'tools/run-fixture-conformance.mjs',
          'tools/run-rust-core.mjs',
          'tools/run-vouch-loop-example.mjs',
          'tools/source-projection-lib.mjs',
          'tools/synthetic-checkout-lib.mjs'
        ],
        reason: 'projection-only documentation and fail-closed standalone review tooling layered on top of the byte-exact synthetic C0 tracked tree',
      },
      {
        paths: [SYNTHETIC_BUNDLE_PATH],
        reason: 'portable synthetic F-to-B-to-C0 history for exact detached review checkout; byte-identical to the bundle carried by the D-bound release archive',
      },
      {
        paths: [
          TYPESCRIPT_CHUNK_MANIFEST_PATH,
          ...TYPESCRIPT_CHUNK_SPEC.parts.map((part) => part.path),
        ],
        reason: 'split the projection-only TypeScript compiler payload into deterministic parts no larger than 7 MiB for the 4open 8 MB per-file limit; the original bytes are verified and atomically reassembled only in a temporary review copy',
      },
    ],
    summary: {
      file_count: files.length,
      bytes,
      files_by_class: sortObject(byClass),
      files_by_origin: sortObject(byOrigin),
      files_by_rights: sortObject(byRights),
    },
    files,
  };
}

export function vendoredReviewToolchainIssues(root) {
  return [
    ...reviewToolchainChunkIssues(root),
    ...reviewToolchainPackages.flatMap((pin) => reviewPackageIssues(root, pin)),
  ];
}

function reviewPackageIssues(root, pin) {
  const issues = [];
  const packageRoot = join(root, ...pin.path.split('/'));
  if (!existsSync(packageRoot)) {
    return [`${pin.path}: pinned review toolchain package is missing`];
  }
  let entries;
  try {
    entries = inventoryFiles(packageRoot, {
      allowReassembledTypeScript: pin.name === 'typescript',
      includeManifest: true,
    });
  } catch (error) {
    return [`${pin.path}: cannot inventory package: ${error.message}`];
  }
  let reconstructed = null;
  if (pin.name === 'typescript') {
    reconstructed =
      entries.find((entry) => entry.path === 'lib/typescript.js') ?? null;
    entries = entries.filter((entry) => entry.path !== 'lib/typescript.js');
  }
  const rows = [];
  let bytes = 0;
  const exactEntryPaths = new Set(entries.map((entry) => entry.path));
  if (!exactEntryPaths.has(pin.licensePath)) {
    issues.push(
      `${pin.path}/${pin.licensePath}: exact-case license path is missing`
    );
  }
  for (const entry of entries) {
    if (entry.kind !== 'file') {
      issues.push(`${pin.path}/${entry.path}: regular file required`);
      continue;
    }
    const content = readFileSync(entry.absolute);
    const mode = lstatSync(entry.absolute).mode & 0o777;
    bytes += content.length;
    rows.push(
      `${entry.path}\0${mode.toString(8)}\0${content.length}\0${sha256(content)}\n`
    );
  }
  if (pin.name === 'typescript') {
    const expected = TYPESCRIPT_CHUNK_SPEC.original;
    exactEntryPaths.add('lib/typescript.js');
    bytes += expected.bytes;
    rows.push(
      `lib/typescript.js\0${Number.parseInt(expected.mode, 8)
        .toString(8)}\0${expected.bytes}\0${expected.sha256}\n`
    );
    if (reconstructed !== null) {
      const content = readFileSync(reconstructed.absolute);
      const mode = lstatSync(reconstructed.absolute).mode & 0o777;
      if (
        content.length !== expected.bytes ||
        sha256(content) !== expected.sha256 ||
        mode !== Number.parseInt(expected.mode, 8)
      ) {
        issues.push(
          `${TYPESCRIPT_REASSEMBLED_PATH}: reconstructed compiler bytes or mode mismatch`
        );
      }
    }
  }
  rows.sort(compareUtf8);
  const treeSha256 = sha256(Buffer.from(rows.join(''), 'utf8'));
  const logicalFileCount =
    entries.length + (pin.name === 'typescript' ? 1 : 0);
  if (logicalFileCount !== pin.fileCount) {
    issues.push(
      `${pin.path}: logical file count ${logicalFileCount} != ${pin.fileCount}`
    );
  }
  if (bytes !== pin.bytes) {
    issues.push(
      `${pin.path}: bytes ${bytes} != ${pin.bytes}`
    );
  }
  if (treeSha256 !== pin.treeSha256) {
    issues.push(
      `${pin.path}: tree SHA-256 ${treeSha256} != ${pin.treeSha256}`
    );
  }
  try {
    const metadata = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'));
    if (
      metadata.name !== pin.name ||
      metadata.version !== pin.version ||
      metadata.license !== pin.license ||
      !pin.metadataCheck(metadata)
    ) {
      issues.push(`${pin.path}/package.json: pinned metadata mismatch`);
    }
  } catch (error) {
    issues.push(`${pin.path}/package.json: ${error.message}`);
  }
  try {
    const license = readFileSync(join(packageRoot, pin.licensePath));
    if (sha256(license) !== pin.licenseSha256) {
      issues.push(`${pin.path}/${pin.licensePath}: pinned license mismatch`);
    }
  } catch (error) {
    issues.push(`${pin.path}/${pin.licensePath}: ${error.message}`);
  }
  return issues;
}

export function reviewToolchainChunkIssues(root) {
  const issues = [];
  const manifestPath = join(
    root,
    ...TYPESCRIPT_CHUNK_MANIFEST_PATH.split('/')
  );
  let manifestBytes;
  try {
    manifestBytes = readFileSync(manifestPath);
    const expectedBytes = canonicalJson(TYPESCRIPT_CHUNK_SPEC);
    if (!manifestBytes.equals(expectedBytes)) {
      issues.push(
        `${TYPESCRIPT_CHUNK_MANIFEST_PATH}: canonical chunk manifest mismatch`
      );
    }
  } catch (error) {
    return [
      `${TYPESCRIPT_CHUNK_MANIFEST_PATH}: missing chunk manifest: ${error.message}`,
    ];
  }

  const expectedNames = new Set([
    'manifest.json',
    ...TYPESCRIPT_CHUNK_SPEC.parts.map((part) => part.path.split('/').at(-1)),
  ]);
  try {
    const actualNames = new Set(
      readdirSync(join(root, ...TYPESCRIPT_CHUNK_DIRECTORY.split('/')))
    );
    for (const name of expectedNames) {
      if (!actualNames.has(name)) {
        issues.push(`${TYPESCRIPT_CHUNK_DIRECTORY}/${name}: missing chunk entry`);
      }
    }
    for (const name of actualNames) {
      if (!expectedNames.has(name)) {
        issues.push(
          `${TYPESCRIPT_CHUNK_DIRECTORY}/${name}: unexpected chunk entry`
        );
      }
    }
  } catch (error) {
    issues.push(
      `${TYPESCRIPT_CHUNK_DIRECTORY}: cannot inventory chunk directory: ${error.message}`
    );
  }

  const aggregate = createHash('sha256');
  let total = 0;
  for (const [index, part] of TYPESCRIPT_CHUNK_SPEC.parts.entries()) {
    try {
      const absolute = join(root, ...part.path.split('/'));
      const stat = lstatSync(absolute);
      const content = readFileSync(absolute);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        issues.push(`${part.path}: regular chunk file required`);
        continue;
      }
      if ((stat.mode & 0o777) !== 0o644) {
        issues.push(`${part.path}: chunk mode must be 0644`);
      }
      if (
        content.length !== part.bytes ||
        sha256(content) !== part.sha256
      ) {
        issues.push(`${part.path}: chunk bytes or SHA-256 mismatch`);
      }
      if (
        content.length > TYPESCRIPT_CHUNK_SPEC.part_size_limit_bytes ||
        content.length >= DISTRIBUTED_FILE_LIMIT_BYTES
      ) {
        issues.push(`${part.path}: chunk exceeds the distribution limit`);
      }
      if (
        part.path.split('/').at(-1) !==
        `part-${String(index).padStart(4, '0')}`
      ) {
        issues.push(`${part.path}: chunk order/name mismatch`);
      }
      aggregate.update(content);
      total += content.length;
    } catch (error) {
      issues.push(`${part.path}: cannot read chunk: ${error.message}`);
    }
  }
  if (
    total !== TYPESCRIPT_CHUNK_SPEC.original.bytes ||
    aggregate.digest('hex') !== TYPESCRIPT_CHUNK_SPEC.original.sha256
  ) {
    issues.push(
      `${TYPESCRIPT_REASSEMBLED_PATH}: ordered chunk reassembly identity mismatch`
    );
  }
  return issues;
}

export function isTemporaryProjectionRoot(root) {
  const absolute = realpathSync(root);
  const candidates = new Set([tmpdir(), '/tmp', '/var/tmp']);
  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue;
    const temporary = realpathSync(candidate);
    const rel = relative(temporary, absolute);
    if (rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`)) return true;
  }
  return false;
}

export function transientReviewToolchainIssues(root) {
  const nodeModules = join(root, 'node_modules');
  if (!existsSync(nodeModules)) return [];
  const issues = [];
  if (!isTemporaryProjectionRoot(root)) {
    issues.push('node_modules: temporary review toolchain is allowed only in an OS temporary copy');
  }
  const expected = new Map([
    ['', 'directory'],
    ['.bin', 'directory'],
    ['.bin/tsc', 'symlink'],
    ['@types', 'directory'],
    ['@types/node', 'symlink'],
    ['ajv', 'symlink'],
    ['fast-deep-equal', 'symlink'],
    ['fast-uri', 'symlink'],
    ['json-schema-traverse', 'symlink'],
    ['require-from-string', 'symlink'],
    ['typescript', 'symlink'],
    ['undici-types', 'symlink'],
  ]);
  const found = new Map();
  visit(nodeModules, '');
  for (const [path, kind] of expected) {
    if (found.get(path) !== kind) {
      issues.push(`node_modules/${path || '.'}: expected ${kind}`);
    }
  }
  for (const path of found.keys()) {
    if (!expected.has(path)) {
      issues.push(`node_modules/${path}: unexpected temporary toolchain entry`);
    }
  }
  for (const [path, wanted, target] of [
    [
      '.bin/tsc',
      '../../review-toolchain/typescript/bin/tsc',
      join(root, TYPESCRIPT_PACKAGE_PATH, 'bin', 'tsc'),
    ],
    [
      '@types/node',
      '../../review-toolchain/types-node',
      join(root, NODE_TYPES_PACKAGE_PATH),
    ],
    [
      'undici-types',
      '../review-toolchain/undici-types',
      join(root, UNDICI_TYPES_PACKAGE_PATH),
    ],
    [
      'typescript',
      '../review-toolchain/typescript',
      join(root, TYPESCRIPT_PACKAGE_PATH),
    ],
    ['ajv', '../review-toolchain/ajv', join(root, AJV_PACKAGE_PATH)],
    [
      'fast-deep-equal',
      '../review-toolchain/fast-deep-equal',
      join(root, 'review-toolchain/fast-deep-equal'),
    ],
    [
      'fast-uri',
      '../review-toolchain/fast-uri',
      join(root, 'review-toolchain/fast-uri'),
    ],
    [
      'json-schema-traverse',
      '../review-toolchain/json-schema-traverse',
      join(root, 'review-toolchain/json-schema-traverse'),
    ],
    [
      'require-from-string',
      '../review-toolchain/require-from-string',
      join(root, 'review-toolchain/require-from-string'),
    ],
  ]) {
    if (found.get(path) !== 'symlink') continue;
    const link = join(nodeModules, ...path.split('/'));
    const actual = readlinkSync(link);
    if (actual !== wanted) {
      issues.push(`node_modules/${path}: link ${actual} != ${wanted}`);
    } else {
      try {
        if (realpathSync(link) !== realpathSync(target)) {
          issues.push(`node_modules/${path}: link escapes the pinned package`);
        }
      } catch (error) {
        issues.push(`node_modules/${path}: cannot resolve pinned link: ${error.message}`);
      }
    }
  }
  return issues;

  function visit(absolute, rel) {
    const stat = lstatSync(absolute);
    const kind = stat.isSymbolicLink()
      ? 'symlink'
      : stat.isDirectory()
        ? 'directory'
        : stat.isFile()
          ? 'file'
          : 'other';
    found.set(rel, kind);
    if (kind !== 'directory') return;
    for (const name of readdirSync(absolute).sort(compareUtf8)) {
      visit(join(absolute, name), rel ? `${rel}/${name}` : name);
    }
  }
}

export function scanProjection(root) {
  const issues = [];
  for (const entry of inventoryFiles(root, { includeManifest: true })) {
    const path = entry.path.split(sep).join('/');
    scanPath(path, entry, issues);
    if (entry.kind !== 'file' || thirdPartyPath(path)) continue;
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(
        readFileSync(entry.absolute)
      );
    } catch {
      continue;
    }
    scanText(path, text, issues);
  }
  return issues;
}

function scanPath(path, entry, issues) {
  const segments = path.split('/');
  const basename = segments.at(-1) ?? '';
  const conformanceDoc = isClassicConformanceFixture(path);
  const publicVouchDoc = isPublicVouchDocumentation(path);
  const reservedRecordNames = new Set([
    `${'AG'}${'ENTS'}.MD`,
    `${'GO'}${'AL'}.MD`,
    `${'HAND'}${'OFF'}.MD`,
  ]);
  const correlationRecordPattern = new RegExp(
    [
      `${'NORTH'}-${'STAR'}`,
      '(?:anonymization|identity)[-_ ].*(?:report|delta)',
      '(?:hash|identity)[-_ ].*delta',
      `${'REPORT'}[.]${'s'}${'ol'}`,
      `${'re'}${'view'}[-_ ]${'packet'}`,
    ].join('|'),
    'i'
  );
  if (entry.kind === 'symlink') issues.push(`${path}: symlink is forbidden`);
  if (path.startsWith('vendor/')) return;
  if (segments.includes('.git')) issues.push(`${path}: Git metadata is forbidden`);
  if (
    !conformanceDoc &&
    !publicVouchDoc &&
    segments.some((segment) =>
      ['submission', 'docs', 'content', 'm3c'].includes(segment.toLowerCase())
    )
  ) {
    issues.push(`${path}: excluded non-product subtree`);
  }
  if (
    reservedRecordNames.has(basename.toUpperCase()) ||
    correlationRecordPattern.test(path)
  ) {
    issues.push(`${path}: excluded non-product record`);
  }
  if (!path.startsWith('vendor/') && /\.(?:pk8|p12|pfx|key)$/i.test(path)) {
    issues.push(`${path}: key-material filename outside vendor`);
  }
}

function scanText(path, text, issues) {
  const releaseSupplyScanner =
    path === 'artifact/scripts/check-release-supply.mjs';
  const allowedEmail = /@(?:example\.(?:com|org|invalid)|users\.noreply\.github\.com)$/i;
  for (const match of text.matchAll(
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu
  )) {
    if (!allowedEmail.test(match[0])) {
      issues.push(`${path}: non-placeholder email address`);
    }
  }

  const unixHome = new RegExp(
    `${['', 'Users', '[A-Za-z0-9._-]+'].join('/')}(?:/|$)`,
    'g'
  );
  const linuxHome = new RegExp(
    `${['', 'home', '[A-Za-z0-9._-]+'].join('/')}(?:/|$)`,
    'g'
  );
  const windowsHome = new RegExp(
    `${['[A-Za-z]:', 'Users', '[^\\\\/]+'].join('\\\\')}(?:\\\\|$)`,
    'g'
  );
  if (
    !releaseSupplyScanner &&
    (unixHome.test(text) || linuxHome.test(text) || windowsHome.test(text))
  ) {
    issues.push(`${path}: user-home absolute path`);
  }
  if (/https?:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+/i.test(text)) {
    issues.push(`${path}: repository account URL`);
  }
  if (
    !/scan-(?:private-key-markers|release-secrets)\.mjs$/.test(path) &&
    text.includes(['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' '))
  ) {
    issues.push(`${path}: private-key PEM marker`);
  }
  if (/AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{30,}/.test(text)) {
    issues.push(`${path}: credential-shaped token`);
  }
  if (/"(?:author|creator|organization|company)"\s*:\s*"[^"\n]+"/i.test(text)) {
    issues.push(`${path}: identity-bearing metadata field`);
  }
  const processActor = [
    `${'mo'}${'del'}`,
    `${'ag'}${'ent'}`,
    `${'l'}${'lm'}`,
  ].join('|');
  const processAction = ['review', 'approval', 'workflow', 'checkpoint'].join(
    '|'
  );
  if (new RegExp(`(?:${processActor})[-_ ]+(?:${processAction})`, 'i').test(text)) {
    issues.push(`${path}: excluded non-product process prose`);
  }
}

function thirdPartyPath(path) {
  return (
    path.startsWith('vendor/') ||
    path.startsWith('review-toolchain/') ||
    ['Cargo.lock', 'package-lock.json'].includes(path)
  );
}

function classify(path) {
  if (path === SYNTHETIC_BUNDLE_PATH) return 'synthetic-release-history';
  if (isClassicConformanceFixture(path)) return 'classic-conformance-fixture';
  if (isPublicVouchDocumentation(path)) return 'vouch-public-documentation';
  if (
    [
      'wasm/Cargo.toml',
      'cli/package.json',
      'src/config/release.ts',
      'public/version.json',
    ].includes(path)
  ) {
    return 'version-surface-fixture';
  }
  if (path.startsWith('vendor/')) return 'vendored-rust-dependency';
  if (path.startsWith('review-toolchain/')) {
    return 'vendored-review-toolchain';
  }
  if (path.startsWith('interp/')) return 'rust-reference-and-native';
  if (path.startsWith('vouch/')) return 'rust-vouch-core';
  if (path.startsWith('scored26-release/')) return 'rust-release-anchor';
  if (path.startsWith('lock-anchors/')) return 'dependency-lock-anchor';
  if (path.startsWith('packages/vouch-consumer/')) return 'typescript-consumer';
  if (path.startsWith('schemas/vouch.bridge-')) return 'bridge-schema';
  if (path.startsWith('examples/vouch-bridge/')) return 'bridge-example';
  if (path === 'cli/bin/lispex.js') return 'bridge-verifier-cli';
  if (
    [
      'scripts/check-vouch-adversarial.mjs',
      'scripts/check-vouch-bridge.mjs',
      'scripts/check-vouch-loop-example.mjs',
      'scripts/gen-vouch-bridge-example.mjs',
    ].includes(path)
  ) {
    return path === 'scripts/check-vouch-loop-example.mjs'
      ? 'native-vouch-loop-tooling'
      : 'bridge-tooling';
  }
  if (path.startsWith('artifact/contract/')) return 'normative-contract';
  if (path.startsWith('artifact/')) return 'artifact-fixture-evidence-and-tooling';
  if (path.startsWith('generated/')) return 'generated-evaluation-presentation';
  if (path.startsWith('differential/')) return 'differential-fixture';
  if (path.startsWith('meaning-graph/') || path.startsWith('meaning-env/')) {
    return 'meaning-evaluator-fixture';
  }
  if (path.startsWith('examples/') || path.startsWith('adversarial/')) {
    return 'negative-control-and-example';
  }
  if (path.startsWith('tools/')) return 'projection-tooling';
  if (path.endsWith('.md')) return 'semantic-documentation';
  return 'build-and-lock-metadata';
}

function originFor(path) {
  if (path.startsWith('review-toolchain/chunks/')) {
    return 'projection-authored';
  }
  const toolchain = reviewToolchainPackages.find((item) =>
    path.startsWith(`${item.path}/`)
  );
  if (toolchain) {
    return `npm-package-${toolchain.name}-${toolchain.version}-byte-exact`;
  }
  if (path === SYNTHETIC_BUNDLE_PATH) return 'synthetic-history-bundle';
  if (authored.has(path)) return 'projection-authored';
  return 'source-snapshot-byte-exact';
}

function rightsFor(path) {
  if (path.startsWith('review-toolchain/chunks/')) {
    return 'Apache-2.0 (review-toolchain/typescript/LICENSE.txt)';
  }
  const toolchain = reviewToolchainPackages.find((item) =>
    path.startsWith(`${item.path}/`)
  );
  if (toolchain) {
    return `${toolchain.license} (${toolchain.path}/${toolchain.licensePath})`;
  }
  if (path.startsWith('vendor/')) {
    return 'upstream dependency terms retained in vendor package';
  }
  return 'limited first-party evaluation permission (RIGHTS.md)';
}

function isClassicConformanceFixture(path) {
  const match = /^content\/(?:en|ko|ru)\/docs\/classic\/(.+)$/.exec(path);
  return match !== null && classicConformanceDocs.has(match[1]);
}

function isPublicVouchDocumentation(path) {
  const match = /^content\/(?:en|ko|ru)\/docs\/(.+)$/.exec(path);
  return match !== null && publicVouchDocs.has(match[1]);
}

function sortObject(value) {
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => compareUtf8(left, right))
  );
}

function compareUtf8(left, right) {
  return Buffer.from(left).compare(Buffer.from(right));
}
