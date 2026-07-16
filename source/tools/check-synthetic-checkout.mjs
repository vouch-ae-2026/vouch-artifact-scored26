import { mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';

import { projectionRoot } from './source-projection-lib.mjs';
import {
  assertSyntheticCheckoutClean,
  createSyntheticCheckout,
  ignoreSyntheticTopLevelPath,
  removeSyntheticCheckout,
} from './synthetic-checkout-lib.mjs';

const root = projectionRoot(import.meta.url);
const first = createSyntheticCheckout(root);
let second;
try {
  second = createSyntheticCheckout(root);
  if (first.commit !== second.commit) {
    throw new Error(
      `synthetic checkout is not deterministic: ${first.commit} != ${second.commit}`
    );
  }
  const dependencyTarget = join(first.container, 'dependency-target');
  mkdirSync(dependencyTarget);
  symlinkSync(dependencyTarget, join(first.checkout, 'node_modules'), 'dir');
  ignoreSyntheticTopLevelPath(first.checkout, 'node_modules');
  assertSyntheticCheckoutClean(first.checkout);
  console.log(
    `exact bundle checkout passed (F/B/C0 verified, detached C0 ${first.commit}, no remote, ignored dependency link stays clean)`
  );
} finally {
  if (second) removeSyntheticCheckout(second);
  removeSyntheticCheckout(first);
}
