const JS_EXT = /\.(js|ts|jsx|tsx|mjs|cjs)$/;

export function check(files) {
  const findings = [];

  for (const { path, lines } of files) {
    const content = lines.join('\n');

    // ── CORS wildcard ─────────────────────────────────────────
    if (JS_EXT.test(path) || path.endsWith('.json')) {
      if (/Access-Control-Allow-Origin['":\s]+\*/.test(content)) {
        const lineIdx = lines.findIndex((l) => /Access-Control-Allow-Origin['":\s]+\*/.test(l));
        findings.push({
          severity: 'high',
          title: 'CORS wildcard — Access-Control-Allow-Origin: *',
          file: path,
          line: lineIdx + 1,
          code: lines[lineIdx]?.trim().substring(0, 90),
          risk: 'Any website can make cross-origin requests to your API, defeating same-origin protection.',
          fix: "Whitelist specific origins: 'Access-Control-Allow-Origin': 'https://yourdomain.com'",
        });
      }
    }

    // ── Source maps in production ─────────────────────────────
    if (/next\.config|vite\.config|webpack\.config/.test(path)) {
      if (/productionBrowserSourceMaps\s*:\s*true|(?:^|[,{\s])sourcemap\s*:\s*true/im.test(content)) {
        const lineIdx = lines.findIndex((l) =>
          /productionBrowserSourceMaps\s*:\s*true|sourcemap\s*:\s*true/.test(l)
        );
        findings.push({
          severity: 'medium',
          title: 'Source maps enabled in production config',
          file: path,
          line: lineIdx + 1,
          code: lines[lineIdx]?.trim().substring(0, 90),
          risk: 'Source maps expose your full original source code in the browser DevTools to anyone.',
          fix: 'Remove or set productionBrowserSourceMaps: false in your build config.',
        });
      }

      // Missing security headers (Next.js only)
      if (path.includes('next.config')) {
        const hasHeaders =
          /headers\s*\(/.test(content) || /['"]headers['"]/.test(content);
        if (!hasHeaders) {
          findings.push({
            severity: 'medium',
            title: 'No security headers configured in next.config',
            file: path,
            line: 1,
            code: '',
            risk: 'Missing headers like X-Frame-Options and Content-Security-Policy leave the app exposed to clickjacking and XSS escalation.',
            fix: 'Add a headers() export to next.config.js with X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Strict-Transport-Security.',
          });
        }
      }
    }

    // ── Full error object returned to client ──────────────────
    if (JS_EXT.test(path)) {
      lines.forEach((line, i) => {
        if (/(?:res|response)\.(?:send|json)\s*\(\s*(?:err|error)\b/.test(line)) {
          findings.push({
            severity: 'medium',
            title: 'Full error object sent to client',
            file: path,
            line: i + 1,
            code: line.trim().substring(0, 90),
            risk: 'Stack traces and internal error messages leak implementation details that attackers can exploit.',
            fix: "Return a generic message: res.status(500).json({ error: 'Internal server error' })",
          });
        }
      });
    }
  }

  return findings;
}
