const JS_EXT = /\.(js|ts|jsx|tsx|mjs|cjs)$/;

export function check(files, rootDir, stacks) {
  if (!stacks.has('stripe')) return [];

  const findings = [];

  for (const { path, lines } of files) {
    if (!JS_EXT.test(path)) continue;

    const content = lines.join('\n');

    // Only look at files that import stripe
    if (!/stripe/i.test(content)) continue;

    // ── Client-submitted price ────────────────────────────────
    lines.forEach((line, i) => {
      if (
        /unit_amount\s*:\s*(?:req|request|body|params|data)(?:\.\w+)*\.(?:price|amount|cost|total)/i.test(
          line
        )
      ) {
        findings.push({
          severity: 'critical',
          title: 'Stripe price taken from client request body',
          file: path,
          line: i + 1,
          code: line.trim().substring(0, 90),
          risk: 'An attacker can set the price to $0.01 by modifying the request before it reaches the server.',
          fix: 'Look up the price server-side from your DB, or use a Stripe Price ID created in the Stripe dashboard.',
        });
      }
    });

    // ── Webhook: missing signature verification ───────────────
    const isWebhookFile =
      /webhook|stripe-signature|constructEvent/.test(content);

    if (isWebhookFile) {
      if (!content.includes('constructEvent')) {
        findings.push({
          severity: 'critical',
          title: 'Stripe webhook missing signature verification',
          file: path,
          line: 1,
          code: '',
          risk: 'Anyone can send fake Stripe events to trigger payments, refunds, or grant subscription upgrades.',
          fix: 'Call stripe.webhooks.constructEvent(body, sig, webhookSecret) at the top of your webhook handler.',
        });
      }

      // Webhook using .json() which destroys the raw body
      if (/await\s+(?:req|request)\.json\(\)/.test(content) && content.includes('constructEvent')) {
        const lineIdx = lines.findIndex((l) => /request\.json\(\)|req\.json\(\)/.test(l));
        findings.push({
          severity: 'high',
          title: "Stripe webhook uses request.json() — breaks signature verification",
          file: path,
          line: lineIdx + 1,
          code: lines[lineIdx]?.trim().substring(0, 90),
          risk: "Parsing the body as JSON destroys the raw bytes Stripe needs to verify the HMAC signature.",
          fix: 'Use await request.text() (Next.js App Router) or express.raw() middleware (Express).',
        });
      }
    }
  }

  return findings;
}
