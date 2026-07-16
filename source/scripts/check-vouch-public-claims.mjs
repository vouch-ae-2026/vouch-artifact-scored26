import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(fileURLToPath(new URL('..', import.meta.url)));
const scanRoots = [
  'README.md',
  'RUN.md',
  'LISPEX-RUNTIME.md',
  'content',
  'cli',
  'packages/vouch-consumer/README.md',
  'examples',
  'artifact/paper',
  'artifact/consumer-demo',
  'generated',
  'src/config',
  'public/version.json',
  'package.json',
];
const allowedExtensions = new Set([
  '.js',
  '.json',
  '.md',
  '.mdx',
  '.tex',
  '.ts',
  '.tsx',
]);
const ignoredDirectories = new Set([
  '.git',
  '.next',
  'dist',
  'node_modules',
  'target',
]);
const rules = [
  {
    id: 'authentic-vouch-generated-receipt-overclaim',
    pattern: /\bauthentic\s+Vouch[\s-]generated\s+receipt\b/i,
    phrase: 'authentic Vouch-generated receipt',
    message: 'Do not claim that a receipt is authentic merely because it has Vouch form.',
  },
  {
    id: 'authentically-generated-overclaim',
    pattern: /\bauthentically\s+generated\b/i,
    phrase: 'authentically generated',
    message: 'Do not claim generation authenticity outside the authenticated issuance boundary.',
  },
  {
    id: 'non-repudiable-overclaim',
    pattern: /\bnon[\s-]?repudiable\b/i,
    phrase: 'non-repudiable',
    message: 'Do not claim non-repudiability.',
  },
  {
    id: 'non-repudiation-overclaim',
    pattern: /\bnon[\s-]?repudiation\b/i,
    phrase: 'non-repudiation',
    message: 'Do not claim non-repudiation.',
  },
  {
    id: 'tamper-proof-receipt-overclaim',
    pattern: /\btamper[\s-]?proof\s+receipt\b/i,
    phrase: 'tamper-proof receipt',
    message: 'Use evidence-bound or tamper-evident wording, not tamper-proof receipt.',
  },
  {
    id: 'provably-authentic-overclaim',
    pattern: /\bprovably\s+authentic\b/i,
    phrase: 'provably authentic',
    message: 'Do not turn authenticated evidence into a proof claim.',
  },
  {
    id: 'authenticity-verified-ko',
    pattern: /진본\s*검증된/,
    phrase: '진본 검증된',
    message: '진본 자체를 검증했다는 표현을 사용하지 마십시오.',
  },
  {
    id: 'tamper-proof-ko',
    pattern: /위변조\s*불가/,
    phrase: '위변조 불가',
    message: '위변조 불가라는 절대적 표현을 사용하지 마십시오.',
  },
  {
    id: 'non-repudiation-ko',
    pattern: /부인\s*방지/,
    phrase: '부인 방지',
    message: '부인 방지를 제공한다고 주장하지 마십시오.',
  },
];

const findings = [];
for (const rule of rules) {
  rule.pattern.lastIndex = 0;
  if (!rule.pattern.test(rule.phrase)) {
    findings.push({
      file: 'scripts/check-vouch-public-claims.mjs',
      line: 1,
      column: 1,
      id: 'denylist-self-test-no-match',
      message: `${rule.id} does not match its required fixture`,
      text: rule.phrase,
    });
  }
}

for (const root of scanRoots) {
  if (!existsSync(join(repoRoot, root))) continue;
  for (const file of walk(root)) {
    const lines = readFileSync(file, 'utf8').split(/\r?\n/);
    lines.forEach((line, lineIndex) => {
      for (const rule of rules) {
        if (isQuotedBoundaryTermLine(line)) continue;
        rule.pattern.lastIndex = 0;
        const match = rule.pattern.exec(line);
        if (!match) continue;
        findings.push({
          file: relative(repoRoot, file),
          line: lineIndex + 1,
          column: match.index + 1,
          id: rule.id,
          message: rule.message,
          text: line.trim(),
        });
      }
    });
  }
}

if (findings.length > 0) {
  console.error('Vouch public-claim boundary check failed:\n');
  for (const finding of findings) {
    console.error(
      `${finding.file}:${finding.line}:${finding.column} ${finding.id} - ${finding.message}`
    );
    console.error(`  ${finding.text}`);
  }
  process.exitCode = 1;
} else {
  console.log(
    `Vouch public-claim boundary check passed (${rules.length} rules, ${scanRoots.length} scoped roots)`
  );
}

function* walk(path) {
  const absolute = join(repoRoot, path);
  const stat = statSync(absolute);
  if (stat.isDirectory()) {
    for (const entry of readdirSync(absolute).sort()) {
      if (ignoredDirectories.has(entry)) continue;
      yield* walk(join(path, entry));
    }
    return;
  }
  if (allowedExtensions.has(extname(absolute))) yield absolute;
}

function isQuotedBoundaryTermLine(line) {
  return /^['"`](receipt-authenticity|generation-honesty|issuer-binding|timestamping|non-repudiation)['"`],?$/.test(
    line.trim()
  );
}
