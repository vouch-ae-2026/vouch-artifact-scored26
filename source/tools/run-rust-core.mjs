import { projectionRoot } from './source-projection-lib.mjs';
import {
  createSyntheticCheckout,
  removeSyntheticCheckout,
  runInCheckout,
} from './synthetic-checkout-lib.mjs';

const root = projectionRoot(import.meta.url);
const synthetic = createSyntheticCheckout(root);
console.log(
  `running Rust review lane from detached synthetic commit ${synthetic.commit}`
);
try {
  for (const [command, args] of [
    ['cargo', ['fmt', '--all', '--', '--check']],
    [
      'cargo',
      [
        'clippy',
        '--workspace',
        '--all-targets',
        '--all-features',
        '--frozen',
        '--offline',
        '--',
        '-D',
        'warnings',
      ],
    ],
    ['cargo', ['test', '--frozen', '--offline', '-p', 'vouch']],
    [
      'cargo',
      ['test', '--frozen', '--offline', '-p', 'scored26-release-anchor'],
    ],
    [
      'cargo',
      [
        'test',
        '--manifest-path',
        'interp/Cargo.toml',
        '--features',
        'scored-native-contract',
        '--locked',
      ],
    ],
  ]) {
    runInCheckout(synthetic.checkout, command, args);
  }
} finally {
  removeSyntheticCheckout(synthetic);
}
