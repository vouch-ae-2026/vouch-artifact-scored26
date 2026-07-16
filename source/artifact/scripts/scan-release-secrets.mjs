import { spawnSync } from 'node:child_process';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  keyHandlePath,
  keyHandleSyntaxValid,
} from './release-finalizer-lib.mjs';
import { regularFiles } from './release-layer-lib.mjs';

const options = parseArgs(process.argv.slice(2));
const root = realpathSync(options.get('--root'));
const bundle = realpathSync(options.get('--bundle'));
const keyHandle = options.get('--private-key-handle');
if (!keyHandleSyntaxValid(keyHandle)) throw new Error('invalid key handle');
const keyPath = realpathSync(keyHandlePath(keyHandle));
if (keyPath === root || keyPath.startsWith(`${root}/`)) {
  throw new Error('release private key is inside the scanned archive root');
}

const privateBytes = readFileSync(keyPath);
const privateKey = createPrivateKey({
  key: privateBytes,
  format: 'der',
  type: 'pkcs8',
});
const spki = createPublicKey(privateKey).export({
  format: 'der',
  type: 'spki',
});
const rawPublic = spki.subarray(-32);
const patterns = releaseKeyPatterns(privateBytes, rawPublic);

for (const path of regularFiles(root)) {
  scan(
    readFileSync(join(root, ...path.split('/'))),
    `archive:${path}`,
    patterns
  );
}
scan(readFileSync(bundle), 'git-bundle-bytes', patterns);

const scratch = mkdtempSync(join(tmpdir(), 'scored26-secret-scan-'));
try {
  const bare = join(scratch, 'repo.git');
  command('git', ['clone', '--quiet', '--bare', bundle, bare]);
  const objects = command(
    'git',
    ['cat-file', '--batch-all-objects', '--batch'],
    { cwd: bare, encoding: 'buffer', maxBuffer: 1024 * 1024 * 1024 }
  ).stdout;
  scan(objects, 'reachable-git-objects', patterns);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log('SCORED26 release secret scan passed (archive/store/Git objects)');

function releaseKeyPatterns(pkcs8, publicKey) {
  const values = new Map();
  const add = (bytes, label) => {
    if (bytes.length < 16 || bytes.equals(publicKey)) return;
    values.set(bytes.toString('hex'), { bytes: Buffer.from(bytes), label });
    values.set(Buffer.from(bytes.toString('hex')), {
      bytes: Buffer.from(bytes.toString('hex')),
      label: `${label}-hex`,
    });
    values.set(Buffer.from(bytes.toString('base64')), {
      bytes: Buffer.from(bytes.toString('base64')),
      label: `${label}-base64`,
    });
  };
  add(pkcs8, 'pkcs8');
  for (let index = 0; index + 32 <= pkcs8.length; index += 1) {
    add(pkcs8.subarray(index, index + 32), `private-window-${index}`);
  }
  return [...values.values()];
}

function scan(bytes, label, patterns) {
  for (const pattern of patterns) {
    if (bytes.indexOf(pattern.bytes) !== -1) {
      throw new Error(
        `${label}: release key material detected (${pattern.label})`
      );
    }
  }
}

function parseArgs(raw) {
  const allowed = new Set(['--root', '--bundle', '--private-key-handle']);
  if (raw.length % 2 !== 0) throw new Error('every option requires a value');
  const values = new Map();
  for (let index = 0; index < raw.length; index += 2) {
    if (!allowed.has(raw[index]) || values.has(raw[index]) || !raw[index + 1]) {
      throw new Error(`invalid option ${raw[index]}`);
    }
    values.set(raw[index], raw[index + 1]);
  }
  for (const name of allowed) {
    if (!values.has(name)) throw new Error(`${name} is required`);
  }
  return values;
}

function command(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: options.cwd,
    encoding: options.encoding ?? 'utf8',
    maxBuffer: options.maxBuffer ?? 128 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${program} failed during release secret scan`);
  }
  return result;
}
