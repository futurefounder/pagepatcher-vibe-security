const JS_EXT = /\.(js|ts|jsx|tsx|mjs|cjs)$/;

export function check(files) {
  const findings = [];

  for (const { path, lines } of files) {
    if (!JS_EXT.test(path)) continue;

    lines.forEach((line, i) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

      // ── Server-side open redirect ─────────────────────────
      if (
        /(?:res|response)\.redirect\s*\(/.test(line) &&
        /(?:req|request)\.(?:query|body|params)/.test(line)
      ) {
        findings.push({
          severity: 'high',
          title: 'Open redirect — redirect URL controlled by user input',
          file: path,
          line: i + 1,
          code: trimmed.substring(0, 90),
          risk: 'Attackers can send users to phishing sites after login by setting the redirect parameter to an external URL.',
          fix: "Validate the URL is relative before redirecting: if (!url.startsWith('/') || url.startsWith('//')) return error;",
        });
      }

      // ── Next.js router.push / redirect with searchParams ──
      if (
        /(?:router\.push|redirect)\s*\(\s*(?:searchParams|params|query)\.get\(/.test(line) ||
        /(?:router\.push|redirect)\s*\(\s*(?:req|request)\.(?:query|params)/.test(line)
      ) {
        findings.push({
          severity: 'medium',
          title: 'Potential open redirect via URL search parameters',
          file: path,
          line: i + 1,
          code: trimmed.substring(0, 90),
          risk: 'Redirecting to a URL from query parameters can be exploited for phishing after login flows.',
          fix: "Only allow relative paths: const url = searchParams.get('redirect'); if (!url?.startsWith('/')) return;",
        });
      }
    });
  }

  return findings;
}
