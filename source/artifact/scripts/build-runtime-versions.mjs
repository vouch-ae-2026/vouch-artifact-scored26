import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { writeArtifactJson } from './artifact-json.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const outputPath = join(repoRoot, 'artifact/runtime-versions.json');
const write = process.argv.slice(2).includes('--write');
const unknown = process.argv.slice(2).filter((value) => value !== '--write');
if (unknown.length !== 0) fail(`unknown argument ${unknown[0]}`);

const expectedCargo = Object.freeze({
  base64: '0.22.1',
  'ed25519-dalek': '2.1.1',
  serde: '1.0.219',
  serde_json: '1.0.140',
  sha2: '0.10.8',
});
const expectedNpm = Object.freeze({ ajv: '8.17.1', typescript: '5.8.2' });

function fail(message) {
  console.error(`SCORED26 runtime-version generation failed: ${message}`);
  process.exit(1);
}

function cargoPackages(bytes) {
  const packages = new Map();
  for (const block of bytes.toString('utf8').split('[[package]]').slice(1)) {
    const name = /^name = "([^"]+)"$/m.exec(block)?.[1];
    const version = /^version = "([^"]+)"$/m.exec(block)?.[1];
    if (name && version) {
      const versions = packages.get(name) ?? [];
      versions.push(version);
      packages.set(name, versions);
    }
  }
  return packages;
}

function requireOne(packages, name, version, ecosystem) {
  const found = packages.get(name) ?? [];
  if (found.length !== 1 || found[0] !== version) {
    throw new Error(
      `${ecosystem} ${name}: expected exactly ${version}, found ${found.join(',') || 'none'}`
    );
  }
}

try {
  const cargoLock = readFileSync(join(repoRoot, 'Cargo.lock'));
  const cargo = cargoPackages(cargoLock);
  for (const [name, version] of Object.entries(expectedCargo)) {
    requireOne(cargo, name, version, 'Cargo.lock');
  }

  const packageJson = JSON.parse(
    readFileSync(join(repoRoot, 'package.json'), 'utf8')
  );
  const packageLock = JSON.parse(
    readFileSync(join(repoRoot, 'package-lock.json'), 'utf8')
  );
  const npm = new Map();
  for (const [name, version] of Object.entries(expectedNpm)) {
    const declared =
      packageJson.dependencies?.[name] ?? packageJson.devDependencies?.[name];
    const locked = packageLock.packages?.[`node_modules/${name}`]?.version;
    if (declared !== version || locked !== version) {
      throw new Error(
        `npm ${name}: expected declaration and lock ${version}, found ${declared}/${locked}`
      );
    }
    npm.set(name, version);
  }

  const value = {
    dependencies: [
      ...Object.entries(expectedCargo).map(([name, version]) => ({
        ecosystem: 'cargo',
        name,
        version,
      })),
      ...[...npm].map(([name, version]) => ({
        ecosystem: 'npm',
        name,
        version,
      })),
    ].sort((left, right) =>
      Buffer.from(`${left.ecosystem}\0${left.name}`).compare(
        Buffer.from(`${right.ecosystem}\0${right.name}`)
      )
    ),
    runtime_versions: 'vouch.scored26-runtime-versions/v0',
    target_triple: 'x86_64-unknown-linux-gnu',
    toolchains: {
      cargo: 'cargo 1.85.1 (d73d2caf9 2024-12-31)',
      glibc: 'glibc 2.39',
      node: 'v22.14.0',
      npm: '10.9.2',
      rustc: 'rustc 1.85.1 (4eb161250 2025-03-15)',
      typescript: '5.8.2',
    },
  };
  const expected = writeArtifactJson(value);
  if (write) {
    writeFileSync(outputPath, expected);
  } else if (!readFileSync(outputPath).equals(expected)) {
    throw new Error('artifact/runtime-versions.json differs from its pins');
  }
  console.log('SCORED26 runtime versions verified (Rust/Node/dependency pins)');
} catch (error) {
  fail(error.message);
}
