import { projectionRoot } from './source-projection-lib.mjs';
import {
  assertSyntheticCheckoutClean,
  createSyntheticCheckout,
  removeSyntheticCheckout,
  runInCheckout,
} from './synthetic-checkout-lib.mjs';

const root = projectionRoot(import.meta.url);
const synthetic = createSyntheticCheckout(root);
console.log(
  `running the public Vouch generate/verify/replay loop from detached synthetic commit ${synthetic.commit}`
);
try {
  runInCheckout(synthetic.checkout, process.execPath, [
    'scripts/check-vouch-loop-example.mjs',
  ]);
  assertSyntheticCheckoutClean(synthetic.checkout);
} finally {
  removeSyntheticCheckout(synthetic);
}
