import { fileURLToPath } from 'node:url';

import { generateFreezeArtifacts } from './workload-lib.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const maximum = Number(process.argv[2] ?? '128');
const minimum = Number(process.argv[3] ?? '0');
if (
  !Number.isSafeInteger(maximum) ||
  !Number.isSafeInteger(minimum) ||
  minimum < 0 ||
  maximum < minimum ||
  maximum > 10_000
) {
  console.error(
    'usage: search-workload-threshold-shift.mjs [maximum-shift<=10000] [minimum-shift]'
  );
  process.exit(2);
}

const concurrency = 1;
// The committed parameter table contains the selected t4 - 3 result. Restore
// the pre-search seed so this diagnostic reproduces the recorded search.
const seedRestoration = [0, 0, 0, 3, 0, 0];
for (let start = minimum; start <= maximum; start += concurrency) {
  const shifts = Array.from(
    { length: Math.min(concurrency, maximum - start + 1) },
    (_, index) => start + index
  );
  const results = await Promise.all(
    shifts.map(async (thresholdShift) => ({
      thresholdShift,
      generated: await generateFreezeArtifacts(repoRoot, {
        thresholdShift,
        thresholdAdjustments: seedRestoration,
        enforcePartition: false,
      }),
    }))
  );
  for (const { thresholdShift, generated } of results) {
    const counts = generated.values.split.counts;
    console.error(
      `shift ${thresholdShift}: development ` +
        `${counts.development.boundary}/${counts.development.interior}/${counts.development.invalid}`
    );
    if (generated.values.partitionMatched) {
      console.log(thresholdShift);
      process.exit(0);
    }
  }
}

console.error(`no conforming shift found through ${maximum}`);
process.exit(1);
