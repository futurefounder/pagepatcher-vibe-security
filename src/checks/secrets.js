import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

const DANGEROUS_KEY_PATTERNS = [
  { pattern: /sk_live_[a-zA-Z0-9]{10,}/, title: 'Stripe live secret key hardcoded in source' },
  { pattern: /sk_test_[a-zA-Z0-9]{10,}/, title: 'Stripe test secret key hardcoded in source' },
  { pattern: /AKIA[A-Z0-9]{16}/, title: 'AWS access key hardcoded in source' },
  { pattern: /ghp_[a-zA-Z0-9]{36,}/, title: 'GitHub personal access token hardcoded' },
  { pattern: /glpat-[a-zA-Z0-9_-]{20,}/, title: 'GitLab personal access token hardcoded' },
  { pattern: /xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+/, title: 'Slack bot token hardcoded' },
  { pattern: /xoxs-[a-zA-Z0-9-]+/, title: 'Slack user token hardcoded' },
  { pattern: /AIza[0-9A-Za-z-_]{35}/, title: 'Google API key hardcoded' },
];

// Dangerous patterns: secret/service keys exposed via public env prefixes
const DANGEROUS_PUBLIC_ENV =
  /(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_)[A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE_KEY|SERVICE_KEY|SIGNING)[A-Z0-9_]*/i;

export function check(files, rootDir) {
  const findings = [];
  const JS_EXT = /\.(js|ts|jsx|tsx|mjs|cjs)$/;

  for (const { path, lines } of files) {
    // Skip env files and markdown (they're expected to have values shown)
    if (path.endsWith('.md')) continue;

    lines.forEach((line, i) => {
      const trimmed = line.trim();
      // Skip comment lines
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return;
      // Skip lines where it's just a comment inline but only value
      if (/^\s*\/\//.test(line)) return;

      // Don't flag env files for the key patterns (they're allowed to have them)
      if (!path.includes('.env')) {
        for (const { pattern, title } of DANGEROUS_KEY_PATTERNS) {
          if (pattern.test(line)) {
            findings.push({
              severity: 'critical',
              title,
              file: path,
              line: i + 1,
              code: trimmed.substring(0, 90),
              risk: 'This key is in source code and likely in git history. Consider it compromised — rotate immediately.',
              fix: 'Move to .env file and access via process.env. Never commit real credentials.',
            });
          }
        }
      }

      // Check for public env vars containing secrets — in any JS/TS or env file
      if (JS_EXT.test(path) || path.includes('.env')) {
        if (DANGEROUS_PUBLIC_ENV.test(line)) {
          findings.push({
            severity: 'critical',
            title: 'Secret key exposed via public env var prefix',
            file: path,
            line: i + 1,
            code: trimmed.substring(0, 90),
            risk: 'NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_ values are baked into the client bundle at build time — visible to anyone in DevTools.',
            fix: 'Remove the public prefix. Access this key only in server-side code.',
          });
        }
      }

      // Hardcoded passwords (not in env files, not referencing env vars)
      if (JS_EXT.test(path) && !path.includes('.env')) {
        if (
          /(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{3,}['"]/i.test(line) &&
          !/process\.env|import\.meta\.env/.test(line)
        ) {
          findings.push({
            severity: 'high',
            title: 'Hardcoded password in source code',
            file: path,
            line: i + 1,
            code: trimmed.substring(0, 90),
            risk: 'Hardcoded passwords are exposed in source and git history.',
            fix: 'Use an environment variable: process.env.DB_PASSWORD',
          });
        }
      }
    });
  }

  // .gitignore check
  const gitignorePath = join(rootDir, '.gitignore');
  if (!existsSync(gitignorePath)) {
    findings.push({
      severity: 'high',
      title: '.gitignore file is missing',
      file: join(rootDir, '.gitignore'),
      line: 0,
      code: '',
      risk: 'Without a .gitignore, .env files with secrets may be accidentally committed.',
      fix: 'Create .gitignore with at minimum: .env, .env.local, .env.*.local',
    });
  } else {
    const content = readFileSync(gitignorePath, 'utf-8');
    if (!content.includes('.env')) {
      findings.push({
        severity: 'high',
        title: '.env files not listed in .gitignore',
        file: gitignorePath,
        line: 0,
        code: '',
        risk: 'Any committed .env file permanently exposes all secrets in git history.',
        fix: 'Add .env and .env*.local to .gitignore immediately.',
      });
    }
  }

  return findings;
}
