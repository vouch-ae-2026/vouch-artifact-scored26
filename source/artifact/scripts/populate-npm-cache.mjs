import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawn } from 'node:child_process';

const args = parseArgs(process.argv.slice(2));
const lockPath = resolve(args.get('--package-lock'));
const cachePath = resolve(args.get('--cache'));
const npm = args.get('--npm');
const jobs = Number.parseInt(args.get('--jobs') ?? '8', 10);
if (!Number.isSafeInteger(jobs) || jobs < 1 || jobs > 32) {
  throw new Error('--jobs must be an integer from 1 through 32');
}

const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
if (lock.lockfileVersion !== 3 || typeof lock.packages !== 'object') {
  throw new Error('package-lock.json must use lockfileVersion 3');
}
const resolved = [
  ...new Set(
    Object.values(lock.packages)
      .map((entry) => entry?.resolved)
      .filter((value) => typeof value === 'string')
  ),
].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
if (
  resolved.length === 0 ||
  resolved.some((value) => !value.startsWith('https://registry.npmjs.org/'))
) {
  throw new Error('every locked package must use the npm registry over HTTPS');
}

rmSync(cachePath, { recursive: true, force: true });
mkdirSync(cachePath, { recursive: true, mode: 0o700 });
let cursor = 0;
let completed = 0;
let failure;

await Promise.all(
  Array.from({ length: Math.min(jobs, resolved.length) }, async () => {
    while (failure === undefined) {
      const index = cursor;
      cursor += 1;
      if (index >= resolved.length) return;
      try {
        await cacheAdd(npm, resolved[index], cachePath);
        completed += 1;
        if (completed % 50 === 0 || completed === resolved.length) {
          console.log(`npm offline cache: ${completed}/${resolved.length}`);
        }
      } catch (error) {
        failure = error;
      }
    }
  })
);
if (failure !== undefined) throw failure;
console.log(
  `SCORED26 npm offline cache populated (${resolved.length} locked tarballs)`
);

function parseArgs(raw) {
  const allowed = new Set(['--package-lock', '--cache', '--npm', '--jobs']);
  if (raw.length % 2 !== 0) throw new Error('every option requires a value');
  const values = new Map();
  for (let index = 0; index < raw.length; index += 2) {
    const name = raw[index];
    const value = raw[index + 1];
    if (!allowed.has(name) || !value || value.startsWith('--')) {
      throw new Error(`invalid option ${name}`);
    }
    if (values.has(name)) throw new Error(`${name} may appear only once`);
    values.set(name, value);
  }
  for (const required of ['--package-lock', '--cache', '--npm']) {
    if (!values.has(required)) throw new Error(`${required} is required`);
  }
  return values;
}

function cacheAdd(program, spec, cache) {
  return new Promise((accept, reject) => {
    const child = spawn(
      program,
      [
        'cache',
        'add',
        spec,
        '--cache',
        cache,
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
      ],
      {
        env: {
          ...process.env,
          npm_config_update_notifier: 'false',
        },
        stdio: ['ignore', 'ignore', 'pipe'],
      }
    );
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
      if (stderr.length > 1_048_576) stderr = stderr.slice(-1_048_576);
    });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) accept();
      else reject(new Error(`npm cache add failed for ${spec}: ${stderr}`));
    });
  });
}
