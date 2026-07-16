import { projectionRoot } from './source-projection-lib.mjs';
import { prepareReviewToolchain } from './review-toolchain-lib.mjs';

const root = projectionRoot(import.meta.url);
const prepared = prepareReviewToolchain(root);
console.log(
  `review toolchain ${prepared.created ? 'prepared' : 'already prepared'} (TypeScript payload ${prepared.reconstructed ? 'verified and atomically reassembled' : 'already reassembled'}, lock-pinned declarations and schema validator, nine temporary links)`
);
