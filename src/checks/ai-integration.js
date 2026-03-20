const JS_EXT = /\.(js|ts|jsx|tsx|mjs|cjs)$/;
const AI_API_DOMAINS = /api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com/;
const PUBLIC_AI_KEY =
  /(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_)\w*(?:OPENAI|ANTHROPIC|GEMINI|CLAUDE|AI_API|LLM)\w*/i;

export function check(files, rootDir, stacks) {
  if (!stacks.has('ai')) return [];

  const findings = [];

  for (const { path, lines } of files) {
    if (!JS_EXT.test(path)) continue;

    const content = lines.join('\n');

    // ── AI key via public env prefix ─────────────────────────
    lines.forEach((line, i) => {
      if (PUBLIC_AI_KEY.test(line)) {
        findings.push({
          severity: 'critical',
          title: 'AI API key exposed via public env var prefix',
          file: path,
          line: i + 1,
          code: line.trim().substring(0, 90),
          risk: 'The API key is baked into the client bundle. Anyone can extract it and run up your API bill.',
          fix: 'Remove the NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_ prefix. Call the AI API from your backend only.',
        });
      }
    });

    // ── Direct client-side call to AI API ────────────────────
    const isServerFile =
      path.includes('/api/') ||
      path.includes('route.ts') ||
      path.includes('route.js') ||
      path.includes('server') ||
      path.includes('action');

    if (!isServerFile && AI_API_DOMAINS.test(content)) {
      const lineIdx = lines.findIndex((l) => AI_API_DOMAINS.test(l));
      findings.push({
        severity: 'high',
        title: 'Direct client-side call to AI API',
        file: path,
        line: lineIdx + 1,
        code: lines[lineIdx]?.trim().substring(0, 90),
        risk: 'Calling the AI API from client code requires embedding your API key in the browser bundle.',
        fix: 'Create a server-side API route (e.g. /api/chat) that proxies the request. The client calls your server.',
      });
    }

    // ── Prompt injection via string concatenation ─────────────
    lines.forEach((line, i) => {
      if (
        /`[^`]*(?:system|instructions|prompt|you are|persona)[^`]*\$\{[^}]*(?:user|input|message|body|query|param)/i.test(
          line
        )
      ) {
        findings.push({
          severity: 'medium',
          title: 'Potential prompt injection — user input in system prompt',
          file: path,
          line: i + 1,
          code: line.trim().substring(0, 90),
          risk: 'Raw user input concatenated into a system prompt lets attackers override your AI instructions.',
          fix: 'Use separate role messages: [{ role: "system", content: "..." }, { role: "user", content: userInput }]',
        });
      }
    });
  }

  return findings;
}
