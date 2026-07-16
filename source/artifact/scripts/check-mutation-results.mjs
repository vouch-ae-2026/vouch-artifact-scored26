import { fileURLToPath } from 'node:url';

import {
  validateCommittedMutationArtifacts,
  validateMutationNegativeControls,
} from './mutation-results-lib.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const errors = [
  ...validateCommittedMutationArtifacts(repoRoot),
  ...validateMutationNegativeControls(repoRoot),
];
if (errors.length !== 0) {
  console.error('SCORED26 mutation result check failed:');
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}
console.log(
  'SCORED26 mutation result check passed (12 mutants, owner-report arithmetic, negative controls)'
);
