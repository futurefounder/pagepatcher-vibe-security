const JS_EXT = /\.(js|ts|jsx|tsx|mjs|cjs)$/;

export function check(files) {
  const findings = [];

  for (const { path, lines } of files) {
    if (!JS_EXT.test(path)) continue;

    const content = lines.join('\n');

    // ── jwt.decode without jwt.verify ────────────────────────
    if (/jwt\.decode\(/.test(content) && !/jwt\.verify\(/.test(content)) {
      const lineIdx = lines.findIndex((l) => /jwt\.decode\(/.test(l));
      findings.push({
        severity: 'high',
        title: 'jwt.decode() used without signature verification',
        file: path,
        line: lineIdx + 1,
        code: lines[lineIdx]?.trim().substring(0, 90),
        risk: 'jwt.decode() reads the payload without checking the signature — an attacker can forge any JWT payload.',
        fix: 'Use jwt.verify(token, secret, { algorithms: ["HS256"] }) instead.',
      });
    }

    // ── Token stored in localStorage ─────────────────────────
    lines.forEach((line, i) => {
      if (
        /localStorage\.setItem\(/.test(line) &&
        /['"](?:[^'"]*(?:token|jwt|auth|session|refresh|access_token)[^'"]*)['"]/i.test(line)
      ) {
        findings.push({
          severity: 'high',
          title: 'Auth token stored in localStorage',
          file: path,
          line: i + 1,
          code: line.trim().substring(0, 90),
          risk: 'localStorage is accessible to any JavaScript on the page. A single XSS vulnerability exposes this token.',
          fix: 'Store tokens in HttpOnly + Secure + SameSite=Lax cookies instead.',
        });
      }
    });

    // ── Server Actions without auth check ────────────────────
    if (content.includes("'use server'") || content.includes('"use server"')) {
      const hasAuth =
        /\b(?:auth|session|getUser|getUserIdentity|currentUser|verifyToken|requireAuth|getServerSession|getSession)\b/.test(
          content
        );

      if (!hasAuth) {
        const lineIdx = lines.findIndex((l) => /['"]use server['"]/.test(l));
        findings.push({
          severity: 'high',
          title: "Server Action file missing authentication check",
          file: path,
          line: lineIdx + 1,
          code: "'use server'",
          risk: 'Server Actions compile into public POST endpoints callable by anyone with curl. No auth = unauthenticated access to your logic and database.',
          fix: "Add at the top of each action: const session = await auth(); if (!session?.user) redirect('/login');",
        });
      }
    }

    // ── next-auth middleware-only auth ───────────────────────
    if (path.includes('middleware') && /export.*function|export.*default/.test(content)) {
      if (/withAuth|NextAuth|getToken/.test(content)) {
        // Has middleware auth — check if there are also route handlers without auth
        // (soft warning, medium severity)
        findings.push({
          severity: 'medium',
          title: 'Auth only in middleware — verify route handlers also authenticate',
          file: path,
          line: 1,
          code: '',
          risk: 'CVE-2025-29927: Next.js middleware can be bypassed via the x-middleware-subrequest header. Do not rely on middleware as your only auth layer.',
          fix: 'Re-verify auth inside every API route handler and Server Action, not just middleware.',
        });
      }
    }
  }

  return findings;
}
