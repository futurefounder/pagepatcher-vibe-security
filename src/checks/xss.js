const JS_EXT = /\.(js|ts|jsx|tsx|mjs|cjs)$/;

export function check(files) {
  const findings = [];

  for (const { path, lines } of files) {
    if (!JS_EXT.test(path)) continue;

    lines.forEach((line, i) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

      // Allow users to suppress false positives
      const prevLine = i > 0 ? lines[i - 1] : '';
      if (line.includes('vibe-security-ignore') || prevLine.includes('vibe-security-ignore')) return;

      // ── dangerouslySetInnerHTML with dynamic value ─────────
      if (/dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html\s*:/.test(line)) {
        // Flag if it's not a plain string literal (has a variable or expression)
        // Skip JSON.stringify which is the standard safe way to inject structured data (JSON-LD)
        if (!/:\s*['"`][^$\n]*['"`]\s*\}/.test(line) && !/JSON\.stringify\s*\(/.test(line)) {
          findings.push({
            severity: 'high',
            title: 'dangerouslySetInnerHTML with dynamic value — XSS risk',
            file: path,
            line: i + 1,
            code: trimmed.substring(0, 90),
            risk: 'If the value contains user-generated content, this is stored XSS — attackers can inject arbitrary JavaScript.',
            fix: "Sanitize with DOMPurify: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}",
          });
        }
      }

      // ── innerHTML with dynamic value ───────────────────────
      if (/\.innerHTML\s*=\s*/.test(line) && !/\.innerHTML\s*=\s*['"`][^$\n]*['"`]\s*;/.test(line)) {
        findings.push({
          severity: 'high',
          title: 'innerHTML assignment with dynamic value — XSS risk',
          file: path,
          line: i + 1,
          code: trimmed.substring(0, 90),
          risk: 'Setting innerHTML from a variable can execute attacker-controlled scripts if the value is derived from user input.',
          fix: 'Use textContent for plain text. For HTML, sanitize with DOMPurify.sanitize() first.',
        });
      }

      // ── eval() with non-literal argument ──────────────────
      if (/\beval\s*\(/.test(line) && !/\beval\s*\(\s*['"`][^$\n]*['"`]\s*\)/.test(line)) {
        findings.push({
          severity: 'critical',
          title: 'eval() with dynamic argument — code injection',
          file: path,
          line: i + 1,
          code: trimmed.substring(0, 90),
          risk: 'eval() with user-controlled input executes arbitrary JavaScript. An attacker can run any code in your app.',
          fix: 'Never use eval() with user input. Use JSON.parse() for data, or redesign to avoid dynamic execution.',
        });
      }

      // ── new Function() ─────────────────────────────────────
      if (/new\s+Function\s*\(/.test(line)) {
        findings.push({
          severity: 'high',
          title: 'new Function() — potential code injection',
          file: path,
          line: i + 1,
          code: trimmed.substring(0, 90),
          risk: 'new Function() is essentially eval(). If arguments include user input, attackers can execute arbitrary code.',
          fix: 'Avoid new Function() with dynamic arguments. Use safe, data-driven alternatives.',
        });
      }
    });
  }

  return findings;
}
