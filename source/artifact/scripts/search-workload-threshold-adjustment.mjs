import { fileURLToPath } from 'node:url';

import { generateFreezeArtifacts } from './workload-lib.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const maximum = Number(process.argv[2] ?? '64');
if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 10_000) {
  console.error(
    'usage: search-workload-threshold-adjustment.mjs [maximum-absolute-adjustment]'
  );
  process.exit(2);
}

// The committed parameter table contains the selected t4 - 3 result. Restore
// the pre-search seed so this diagnostic reproduces the recorded search.
const seedRestoration = [0, 0, 0, 3, 0, 0];
for (let magnitude = 1; magnitude <= maximum; magnitude += 1) {
  for (const sign of [1, -1]) {
    for (let thresholdIndex = 0; thresholdIndex < 6; thresholdIndex += 1) {
      const thresholdAdjustments = [...seedRestoration];
      thresholdAdjustments[thresholdIndex] += magnitude * sign;
      let generated;
      try {
        generated = await generateFreezeArtifacts(repoRoot, {
          thresholdAdjustments,
          enforcePartition: false,
        });
      } catch (error) {
        if (String(error.message).includes('threshold spacing')) continue;
        throw error;
      }
      const counts = generated.values.split.counts.development;
      console.error(
        `adjust t${thresholdIndex + 1} ${magnitude * sign}: ` +
          `${counts.boundary}/${counts.interior}/${counts.invalid}`
      );
      if (generated.values.partitionMatched) {
        console.log(`${thresholdIndex + 1} ${magnitude * sign}`);
        process.exit(0);
      }
    }
  }
}

console.error(
  `no conforming single-threshold adjustment found through +/-${maximum}`
);
process.exit(1);
