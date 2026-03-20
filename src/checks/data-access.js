const JS_EXT = /\.(js|ts|jsx|tsx|mjs|cjs)$/;

export function check(files) {
  const findings = [];

  for (const { path, lines } of files) {
    if (!JS_EXT.test(path)) continue;

    lines.forEach((line, i) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

      // ── $queryRawUnsafe with user input ──────────────────────
      if (
        /\$queryRawUnsafe\(/.test(line) &&
        /\$\{|req\.|request\.|body\.|params\.|query\./.test(line)
      ) {
        findings.push({
          severity: 'high',
          title: 'Prisma $queryRawUnsafe with user input — SQL injection',
          file: path,
          line: i + 1,
          code: trimmed.substring(0, 90),
          risk: 'User input in a raw SQL string enables SQL injection. Attackers can read, modify, or delete any data.',
          fix: 'Use tagged template literals: prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`',
        });
      }

      // ── SQL string concatenation ──────────────────────────────
      if (
        /(?:db|pool|client)\.(?:query|execute)\s*\(\s*`[^`]*\$\{/.test(line) ||
        /(?:db|pool|client)\.(?:query|execute)\s*\(\s*['"][^'"]*'\s*\+/.test(line)
      ) {
        findings.push({
          severity: 'high',
          title: 'SQL string concatenation — injection risk',
          file: path,
          line: i + 1,
          code: trimmed.substring(0, 90),
          risk: 'Dynamic SQL built from user input enables SQL injection — attackers can extract or modify any data.',
          fix: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = $1", [userId])',
        });
      }

      // ── Mass assignment ───────────────────────────────────────
      if (/(?:data|update|create)\s*:\s*(?:req|request)\.body\b/.test(line)) {
        findings.push({
          severity: 'high',
          title: 'Mass assignment — request body spread into database operation',
          file: path,
          line: i + 1,
          code: trimmed.substring(0, 90),
          risk: 'Attacker can add unexpected fields like { isAdmin: true, credits: 99999 } to the request.',
          fix: 'Destructure only allowed fields: const { name, email } = req.body; use { name, email } as data.',
        });
      }

      // ── Prisma operator injection ─────────────────────────────
      if (/(?:findFirst|findMany|findUnique)\s*\(\s*\{[^}]*where\s*:\s*(?:req|request)\.body/.test(line)) {
        findings.push({
          severity: 'high',
          title: 'Prisma operator injection — raw body used as where clause',
          file: path,
          line: i + 1,
          code: trimmed.substring(0, 90),
          risk: 'Attacker can send { "email": { "contains": "" } } to match all records and bypass access control.',
          fix: 'Validate with Zod first: const { email } = z.object({ email: z.string().email() }).parse(req.body)',
        });
      }

      // ── console.log with sensitive data ──────────────────────
      if (
        /console\.log\s*\(/.test(line) &&
        /(?:password|passwd|token|secret|credential|private.?key|api.?key)/i.test(line)
      ) {
        findings.push({
          severity: 'low',
          title: 'console.log may expose sensitive data',
          file: path,
          line: i + 1,
          code: trimmed.substring(0, 90),
          risk: 'Passwords and tokens written to logs appear in log aggregation tools and can be accessed by anyone with log access.',
          fix: 'Remove or redact: console.log("user id:", user.id) instead of the full object.',
        });
      }
    });
  }

  return findings;
}
