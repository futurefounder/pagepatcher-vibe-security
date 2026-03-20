const JS_EXT = /\.(js|ts|jsx|tsx|mjs|cjs)$/;
const PUBLIC_MOBILE_SECRET =
  /EXPO_PUBLIC_\w*(?:SECRET|SERVICE|PRIVATE|OPENAI|ANTHROPIC|API_KEY|AI)\w*/i;

export function check(files, rootDir, stacks) {
  if (!stacks.has('mobile')) return [];

  const findings = [];

  for (const { path, lines } of files) {
    if (!JS_EXT.test(path)) continue;

    lines.forEach((line, i) => {
      // ── AsyncStorage with auth tokens ──────────────────────
      if (
        /AsyncStorage\.setItem\(/.test(line) &&
        /['"](?:[^'"]*(?:token|jwt|auth|session|refresh|access)[^'"]*)['"]/i.test(line)
      ) {
        findings.push({
          severity: 'high',
          title: 'Auth token stored in AsyncStorage (unencrypted plaintext)',
          file: path,
          line: i + 1,
          code: line.trim().substring(0, 90),
          risk: 'AsyncStorage writes to unencrypted plaintext on disk. On a rooted device, tokens are trivially readable.',
          fix: 'Use expo-secure-store (Expo) or react-native-keychain (bare React Native) for token storage.',
        });
      }

      // ── EXPO_PUBLIC_ with secret keys ──────────────────────
      if (PUBLIC_MOBILE_SECRET.test(line)) {
        findings.push({
          severity: 'critical',
          title: 'Secret API key exposed via EXPO_PUBLIC_ prefix',
          file: path,
          line: i + 1,
          code: line.trim().substring(0, 90),
          risk: 'EXPO_PUBLIC_ values are baked into the app bundle and extractable by anyone who downloads the app — even with Hermes bytecode.',
          fix: 'Use a backend proxy. The app calls your server; your server calls the third-party API with the secret key.',
        });
      }

      // ── Direct AI/external API calls from mobile ───────────
      if (
        /fetch\s*\(\s*['"]https:\/\/api\.openai\.com|fetch\s*\(\s*['"]https:\/\/api\.anthropic\.com/.test(
          line
        )
      ) {
        findings.push({
          severity: 'high',
          title: 'Direct AI API call from mobile app — key exposure risk',
          file: path,
          line: i + 1,
          code: line.trim().substring(0, 90),
          risk: 'Calling AI APIs directly requires an API key in the app bundle, which is extractable.',
          fix: 'Route AI calls through your backend: fetch("https://your-api.com/ai/chat", { ... })',
        });
      }
    });
  }

  return findings;
}
