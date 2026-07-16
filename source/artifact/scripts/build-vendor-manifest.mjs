import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { writeArtifactJson } from './artifact-json.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const vendorRoot = join(repoRoot, 'vendor');
const outputPath = join(repoRoot, 'artifact/vendor-manifest.json');
const write = process.argv.slice(2).includes('--write');
const unknown = process.argv.slice(2).filter((value) => value !== '--write');
if (unknown.length !== 0) fail(`unknown argument ${unknown[0]}`);

function fail(message) {
  console.error(`SCORED26 vendor-manifest generation failed: ${message}`);
  process.exit(1);
}

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function parseLock(bytes) {
  const output = [];
  for (const block of bytes.toString('utf8').split('[[package]]').slice(1)) {
    const name = /^name = "([^"]+)"$/m.exec(block)?.[1];
    const version = /^version = "([^"]+)"$/m.exec(block)?.[1];
    const source = /^source = "([^"]+)"$/m.exec(block)?.[1];
    const checksum = /^checksum = "([0-9a-f]{64})"$/m.exec(block)?.[1];
    if (source?.startsWith('registry+') && name && version && checksum) {
      output.push({ checksum, name, version });
    }
  }
  return output.sort((left, right) =>
    Buffer.from(`${left.name}\0${left.version}`).compare(
      Buffer.from(`${right.name}\0${right.version}`)
    )
  );
}

function vendorPackages() {
  const output = new Map();
  for (const entry of readdirSync(vendorRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name === 'npm-cache') continue;
    const path = join(vendorRoot, entry.name);
    const manifest = readFileSync(join(path, 'Cargo.toml'), 'utf8');
    const packageBlock = manifest.split('[package]', 2)[1] ?? '';
    const name = /^name = "([^"]+)"$/m.exec(packageBlock)?.[1];
    const version = /^version = "([^"]+)"$/m.exec(packageBlock)?.[1];
    const checksum = JSON.parse(
      readFileSync(join(path, '.cargo-checksum.json'), 'utf8')
    ).package;
    if (!name || !version || !/^[0-9a-f]{64}$/.test(checksum)) {
      throw new Error(`${entry.name}: invalid vendored package metadata`);
    }
    const key = `${name}\0${version}`;
    if (output.has(key))
      throw new Error(`${name} ${version}: duplicate vendor`);
    output.set(key, { checksum, path: `vendor/${entry.name}` });
  }
  return output;
}

function allFiles(root) {
  const paths = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) paths.push(path);
      else throw new Error(`${path}: vendor tree contains a non-regular entry`);
    }
  };
  visit(root);
  return paths.sort((left, right) =>
    Buffer.from(relative(root, left).split(sep).join('/')).compare(
      Buffer.from(relative(root, right).split(sep).join('/'))
    )
  );
}

try {
  const cargoLock = readFileSync(join(repoRoot, 'Cargo.lock'));
  const locked = parseLock(cargoLock);
  const supplied = vendorPackages();
  const crates = locked.map(({ checksum, name, version }) => {
    const key = `${name}\0${version}`;
    const vendor = supplied.get(key);
    if (!vendor || vendor.checksum !== checksum) {
      throw new Error(`${name} ${version}: lock/vendor checksum mismatch`);
    }
    supplied.delete(key);
    return { checksum, name, path: vendor.path, version };
  });
  if (supplied.size !== 0) {
    throw new Error(
      `unlocked vendor entries: ${[...supplied.keys()].join(',')}`
    );
  }

  const files = allFiles(vendorRoot).filter(
    (path) => !relative(vendorRoot, path).split(sep).includes('npm-cache')
  );
  const tree = createHash('sha256');
  let byteLength = 0;
  for (const path of files) {
    const name = relative(repoRoot, path).split(sep).join('/');
    const bytes = readFileSync(path);
    byteLength += bytes.length;
    tree.update(
      Buffer.from(`${Buffer.byteLength(name)}\0${name}\0${bytes.length}\0`)
    );
    tree.update(bytes);
  }
  const value = {
    byte_length: byteLength,
    cargo_lock_sha256: sha256(cargoLock),
    crates,
    file_count: files.length,
    tree_sha256: `sha256:${tree.digest('hex')}`,
    vendor_manifest: 'vouch.scored26-vendor-manifest/v0',
  };
  const expected = writeArtifactJson(value);
  if (write) {
    writeFileSync(outputPath, expected);
  } else if (!readFileSync(outputPath).equals(expected)) {
    throw new Error('artifact/vendor-manifest.json differs from vendor/');
  }
  console.log(
    `SCORED26 Cargo vendor verified (${crates.length} crates/${files.length} files)`
  );
} catch (error) {
  fail(error.message);
}
