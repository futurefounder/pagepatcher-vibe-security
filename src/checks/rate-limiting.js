const JS_EXT = /\.(js|ts|jsx|tsx|mjs|cjs)$/;
const RATE_LIMIT_SIGNAL =
  /ratelimit|rate.limit|rate_limit|upstash|express-rate-limit|next-rate-limit|limiter/i;

const SENSITIVE_ROUTES = [
  { pattern: /\/(?:api\/)?(?:auth|login|logout|register|signup|sign-in|sign-up|forgot|reset|otp|verify)/i, label: 'auth' },
  { pattern: /\/(?:api\/)?(?:chat|ai|openai|anthropic|generate|complete|llm|gpt)/i, label: 'AI' },
  { pattern: /\/(?:api\/)?(?:email|send|newsletter|contact|sms|message)/i, label: 'email/messaging' },
];

export function check(files) {
  const findings = [];

  for (const { path, lines } of files) {
    if (!JS_EXT.test(path)) continue;

    // Only look at API route files
    const isRoute =
      path.includes('/api/') ||
      path.includes('route.ts') ||
      path.includes('route.js') ||
      path.includes('pages/api');

    if (!isRoute) continue;

    const content = lines.join('\n');
    if (RATE_LIMIT_SIGNAL.test(content)) continue; // already rate-limited

    for (const { pattern, label } of SENSITIVE_ROUTES) {
      if (pattern.test(path)) {
        findings.push({
          severity: 'medium',
          title: `No rate limiting on ${label} endpoint`,
          file: path,
          line: 1,
          code: '',
          risk:
            label === 'auth'
              ? 'Without rate limiting, attackers can brute-force passwords or enumerate accounts.'
              : label === 'AI'
              ? 'A single user can exhaust your entire AI API budget in minutes.'
              : 'Your email/SMS infrastructure can be abused as a spam relay.',
          fix: 'Add @upstash/ratelimit or express-rate-limit. Check the README for an example.',
        });
        break;
      }
    }
  }

  return findings;
}
