// SPDX-License-Identifier: Apache-2.0

import { cp, chmod, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  createSourceChildEnvironment,
  verifyArtifact,
} from './check-artifact.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const defaultRoot = path.resolve(path.dirname(scriptPath), '..');
const root = path.resolve(process.env.VOUCH_ARTIFACT_ROOT ?? defaultRoot);

try {
  await verifyArtifact(root, { runSourceChecks: false, quiet: true });
  verifySourceEnvironmentScrubControl();

  const cases = [
    {
      name: 'undeclared file',
      rebuild: false,
      mutate: async (copyRoot) => {
        await writeFile(path.join(copyRoot, 'unexpected.txt'), 'unexpected\n');
      },
    },
    {
      name: 'symlink',
      rebuild: false,
      mutate: async (copyRoot) => {
        await symlink('README.md', path.join(copyRoot, 'readme-link'));
      },
    },
    {
      name: 'manifested content change',
      rebuild: false,
      mutate: async (copyRoot) => {
        const target = path.join(copyRoot, 'README.md');
        const bytes = await readFile(target);
        await writeFile(target, Buffer.concat([bytes, Buffer.from('\nchanged\n')]));
      },
    },
    {
      name: 'nonportable mode',
      rebuild: false,
      mutate: async (copyRoot) => {
        await chmod(path.join(copyRoot, 'README.md'), 0o600);
      },
    },
    {
      name: 'changed signed descriptor payload',
      rebuild: true,
      mutate: async (copyRoot) => {
        await mutateJson(
          copyRoot,
          'release/chain/release-descriptor.json',
          (value) => {
            value.build_parameters.locale = `${value.build_parameters.locale}-changed`;
          }
        );
      },
    },
    {
      name: 'changed observation signature',
      rebuild: true,
      mutate: async (copyRoot) => {
        await mutateJson(
          copyRoot,
          'release/chain/reproduction-observation.dsse.json',
          (value) => {
            const bytes = Buffer.from(value.signatures[0].sig, 'base64');
            bytes[0] ^= 0x01;
            value.signatures[0].sig = bytes.toString('base64');
          }
        );
      },
    },
    {
      name: 'widened trust policy',
      rebuild: true,
      mutate: async (copyRoot) => {
        await mutateJson(copyRoot, 'release/chain/trust-policy.json', (value) => {
          value.keys[0].allowed_profiles.push('csk.unreviewed-profile/v0');
        });
      },
    },
    {
      name: 'false terminal chain field',
      rebuild: true,
      mutate: async (copyRoot) => {
        await mutateJson(
          copyRoot,
          'release/chain/publication-report.json',
          (value) => {
            value.chain_verified = 'fail';
          }
        );
      },
    },
    {
      name: 'changed workload count',
      rebuild: true,
      mutate: async (copyRoot) => {
        await mutateJson(
          copyRoot,
          'release/results/workload-results.json',
          (value) => {
            value.workload_summary.held_out_flips -= 1;
          }
        );
      },
    },
    {
      name: 'substituted machine record',
      rebuild: true,
      mutate: async (copyRoot) => {
        const target = path.join(
          copyRoot,
          'machine-record/vouch-scored26-release-record.pdf'
        );
        const bytes = await readFile(target);
        bytes[bytes.length - 1] ^= 0x01;
        await writeFile(target, bytes);
      },
    },
    {
      name: 'weakened source boundary',
      rebuild: true,
      mutate: async (copyRoot) => {
        await mutateJson(copyRoot, 'source/SOURCE-MANIFEST.json', (value) => {
          value.source_snapshot.working_tree_git_metadata_included = true;
        });
      },
    },
    {
      name: 'tampered synthetic history bundle',
      rebuild: true,
      mutate: async (copyRoot) => {
        const target = path.join(
          copyRoot,
          'source/synthetic-history/vouch-scored26.bundle'
        );
        const bytes = await readFile(target);
        bytes[bytes.length - 1] ^= 0x01;
        await writeFile(target, bytes);
      },
    },
    {
      name: 'false exact-bundle authentication claim',
      rebuild: true,
      mutate: async (copyRoot) => {
        await mutateJson(
          copyRoot,
          'release/audit/bundle-reconciliation.json',
          (value) => {
            value.source_projection_report_fact.release_chain_authenticated =
              false;
          }
        );
      },
    },
    {
      name: 'widened whole-projection authentication claim',
      rebuild: true,
      mutate: async (copyRoot) => {
        await mutateJson(
          copyRoot,
          'release/audit/bundle-reconciliation.json',
          (value) => {
            value.source_projection_report_fact.whole_projection_release_chain_authenticated =
              true;
          }
        );
      },
    },
    {
      name: 'altered D-bound release-manifest bundle row',
      rebuild: true,
      mutate: async (copyRoot) => {
        await mutateJson(
          copyRoot,
          'release/results/release-manifest.json',
          (value) => {
            const row = value.files.find(
              (entry) => entry.path === 'release/vouch-scored26.bundle'
            );
            if (row === undefined) {
              throw new Error('release-manifest bundle row is absent');
            }
            row.byte_length += 1;
          }
        );
      },
    },
    {
      name: 'corrupt release archive chunk',
      rebuild: true,
      mutate: async (copyRoot) => {
        const manifest = JSON.parse(
          await readFile(
            path.join(
              copyRoot,
              'release/archive-chunks/archive-chunks.json'
            ),
            'utf8'
          )
        );
        const target = path.join(
          copyRoot,
          'release/archive-chunks',
          manifest.chunks[0].path
        );
        const bytes = await readFile(target);
        bytes[0] ^= 0x01;
        await writeFile(target, bytes);
      },
    },
    {
      name: 'unlisted archive chunk identity payload',
      rebuild: true,
      mutate: async (copyRoot) => {
        await writeFile(
          path.join(
            copyRoot,
            'release/archive-chunks/vouch-scored26-artifact.tar.zst.part-999999'
          ),
          'reviewer@university.edu\n'
        );
      },
    },
    {
      name: 'projected dependency identity mismatch',
      rebuild: true,
      mutate: async (copyRoot) => {
        const target = path.join(copyRoot, 'source/package-lock.json');
        const bytes = await readFile(target);
        await writeFile(target, Buffer.concat([bytes, Buffer.from('\n')]));
      },
    },
    {
      name: 'private-key material',
      rebuild: true,
      mutate: async (copyRoot) => {
        const header = ['-----', 'BEGIN', ' PRIVATE', ' KEY-----'].join('');
        const footer = ['-----', 'END', ' PRIVATE', ' KEY-----'].join('');
        await writeFile(
          path.join(copyRoot, 'release/audit/debug-material.txt'),
          `${header}\nAAAA\n${footer}\n`
        );
      },
    },
    {
      name: 'binary private-key extension',
      rebuild: true,
      mutate: async (copyRoot) => {
        await writeFile(
          path.join(copyRoot, 'release/audit/unexpected-private.der'),
          Buffer.from('3003020100', 'hex')
        );
      },
    },
    {
      name: 'private JWK material',
      rebuild: true,
      mutate: async (copyRoot) => {
        await writeFile(
          path.join(copyRoot, 'release/audit/unexpected-keyset.json'),
          '{"keys":[{"crv":"Ed25519","d":"AAAA","kty":"OKP","x":"AAAA"}]}\n'
        );
      },
    },
    {
      name: 'local absolute path',
      rebuild: true,
      mutate: async (copyRoot) => {
        const localPath = ['', 'Users', 'sample', 'work', 'input.json'].join('/');
        await writeFile(
          path.join(copyRoot, 'release/audit/local-path.txt'),
          `${localPath}\n`
        );
      },
    },
    {
      name: 'hash-delta metadata outside source manifest',
      rebuild: true,
      mutate: async (copyRoot) => {
        await writeFile(
          path.join(copyRoot, 'release/audit/original-delta.json'),
          '{"original_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n'
        );
      },
    },
    {
      name: 'identity-bearing filename',
      rebuild: true,
      mutate: async (copyRoot) => {
        await writeFile(
          path.join(copyRoot, 'release/audit/named.reviewer@university.edu.txt'),
          'filename identity negative\n'
        );
      },
    },
    {
      name: 'false lifecycle audit fact',
      rebuild: true,
      mutate: async (copyRoot) => {
        await mutateJson(copyRoot, 'release/audit/lifecycle-audit.json', (value) => {
          value.log_evidence.raw_stdout_retained_locally = false;
        });
      },
    },
  ];

  for (const testCase of cases) {
    await expectRejected(root, testCase);
  }
  console.log('Vouch artifact tamper negatives passed');
} catch (error) {
  console.error(`artifact negative verification failed: ${error.message}`);
  process.exitCode = 1;
}

async function expectRejected(sourceRoot, testCase) {
  const temporary = await mkdtemp(path.join(tmpdir(), 'vouch-artifact-negative-'));
  try {
    await cp(sourceRoot, temporary, {
      recursive: true,
      filter: (source) => {
        const relative = path.relative(sourceRoot, source);
        return relative !== '.git' && !relative.startsWith(`.git${path.sep}`);
      },
    });
    await testCase.mutate(temporary);
    if (testCase.rebuild) rebuildManifest(temporary);
    let rejected = false;
    try {
      await verifyArtifact(temporary, { runSourceChecks: false, quiet: true });
    } catch {
      rejected = true;
    }
    if (!rejected) {
      throw new Error(`negative control was accepted: ${testCase.name}`);
    }
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
}

function rebuildManifest(copyRoot) {
  const script = path.join(copyRoot, 'scripts/build-artifact-manifest.mjs');
  const result = spawnSync(process.execPath, [script], {
    cwd: copyRoot,
    env: { ...process.env, VOUCH_ARTIFACT_ROOT: copyRoot },
    encoding: 'utf8',
  });
  if (result.error !== undefined) {
    throw new Error(`negative manifest rebuild failed: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(
      `negative manifest rebuild failed (${result.status}): ${result.stderr.trim()}`
    );
  }
}

function verifySourceEnvironmentScrubControl() {
  const key = 'AWS_SECRET_ACCESS_KEY';
  const sentinel = 'must-not-reach-projected-source';
  const previous = process.env[key];
  process.env[key] = sentinel;
  try {
    const isolatedRoot = path.join(tmpdir(), 'vouch-environment-scrub-control');
    const environment = createSourceChildEnvironment({
      cargoHome: path.join(isolatedRoot, 'cargo-home'),
      home: path.join(isolatedRoot, 'home'),
      npmCache: path.join(isolatedRoot, 'npm-cache'),
      npmUserConfig: path.join(isolatedRoot, 'npmrc'),
      rustBin: null,
      temporary: path.join(isolatedRoot, 'tmp'),
    });
    if (
      Object.hasOwn(environment, key) ||
      Object.values(environment).includes(sentinel)
    ) {
      throw new Error('source environment scrub control leaked a parent secret');
    }
  } finally {
    if (previous === undefined) delete process.env[key];
    else process.env[key] = previous;
  }
}

async function mutateJson(copyRoot, relative, mutate) {
  const target = path.join(copyRoot, ...relative.split('/'));
  const value = JSON.parse(await readFile(target, 'utf8'));
  mutate(value);
  await writeFile(target, writeCanonicalJson(value));
}

function writeCanonicalJson(value) {
  const chunks = [];
  writeValue(value, 0, chunks);
  chunks.push('\n');
  return chunks.join('');
}

function writeValue(value, depth, chunks) {
  if (value === null) {
    chunks.push('null');
  } else if (typeof value === 'boolean') {
    chunks.push(value ? 'true' : 'false');
  } else if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new Error('negative JSON writer accepts only safe integers');
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
    const names = Object.keys(value).sort((left, right) =>
      Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'))
    );
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
    throw new Error('negative JSON writer received an unsupported value');
  }
}
