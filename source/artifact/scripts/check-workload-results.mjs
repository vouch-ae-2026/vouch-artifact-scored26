import { fileURLToPath } from 'node:url';

import {
  validateCommittedWorkloadResults,
  validateWorkloadResultNegativeControls,
} from './workload-results-lib.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const errors = validateCommittedWorkloadResults(repoRoot);
errors.push(...validateWorkloadResultNegativeControls(repoRoot));
if (errors.length !== 0) {
  console.error('SCORED26 workload result check failed:');
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(
  'SCORED26 workload result check passed ' +
    '(owner schema/arithmetic, held-out, coverage, smoke, CSV, TeX, negatives)'
);
