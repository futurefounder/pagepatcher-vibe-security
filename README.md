# pagepatcher-vibe-security

> Security audit CLI for vibe-coded apps — by [PagePatcher.com](https://pagepatcher.com)

Scans your codebase for common security vulnerabilities that AI coding assistants introduce. Run it before every deploy.

```bash
npx pagepatcher-vibe-security
npx pagepatcher-vibe-security ./my-app
```

---

## What It Checks

| Category | What It Catches |
|---|---|
| **Secrets** | Hardcoded API keys, dangerous `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_` on secrets, missing `.gitignore`, hardcoded passwords |
| **Database** | Supabase `USING (true)` RLS policies, Firebase `allow: if true`, INSERT/UPDATE missing `WITH CHECK` |
| **Auth** | `jwt.decode()` without verify, tokens in `localStorage`, Server Actions without auth check, middleware-only auth |
| **Payments** | Client-submitted prices to Stripe, missing webhook signature verification, `request.json()` in webhook handler |
| **XSS** | `dangerouslySetInnerHTML` with dynamic value, `innerHTML =`, `eval()`, `new Function()` |
| **Path Traversal** | `fs.readFile` / `fs.writeFile` with user-controlled filenames |
| **Open Redirects** | `res.redirect(req.query…)`, `router.push(searchParams.get(…))` |
| **Rate Limiting** | Auth/AI/email endpoints without any rate limiting import |
| **AI / LLM** | AI keys via public env prefixes, direct client-side AI API calls, prompt injection patterns |
| **Data Access** | `$queryRawUnsafe`, SQL string concatenation, mass assignment, Prisma operator injection, `console.log` leaks |
| **Mobile** | `AsyncStorage` for auth tokens, `EXPO_PUBLIC_` secrets, direct AI API calls from mobile |
| **Deployment** | CORS wildcard `*`, source maps in production, missing security headers, full error objects sent to client |

---

## Output

```
╔══════════════════════════════════════════════════════════╗
║  PagePatcher.com — Vibe-Security — Audit                 ║
║  Scanning: /your/project                                 ║
╚══════════════════════════════════════════════════════════╝

Detected stack: Next.js · Supabase · Stripe

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋  SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🔴  CRITICAL   3    Fix before deploying
  🟠  HIGH       4    Fix this week
  🟡  MEDIUM     2    Schedule soon
  🔵  LOW        0    Nice to have

  Checked 143 files in 0.4s
```

Each finding includes: **file + line**, **the offending code**, **what an attacker can do**, and a **concrete fix**.

---

## Usage

```bash
# Scan current directory
npx pagepatcher-vibe-security

# Scan a specific path
npx pagepatcher-vibe-security ./my-app
npx pagepatcher-vibe-security --path ./my-app

# Install globally
npm install -g pagepatcher-vibe-security
pagepatcher-vibe-security

# In CI — exits with code 1 if critical/high issues exist
pagepatcher-vibe-security --path . && echo "Clean"
```

---

## Tech Stack Detection

Scans `package.json` to auto-detect which checks to run:

- **Next.js** → auth middleware, security headers, Server Actions
- **Supabase** → RLS policies, service_role exposure
- **Stripe** → webhook verification, client-side pricing
- **Firebase** → security rules
- **React Native / Expo** → AsyncStorage, bundle secrets
- **OpenAI / Anthropic / Google AI** → AI key exposure, client-side calls
- **Prisma** → operator injection, raw query safety

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No critical or high issues |
| `1` | Critical or high issues found |
| `2` | Could not read directory |

Useful in CI pipelines — block PRs if critical issues are found.

---

## Credits

This package is built on top of [vibe-security-skill](https://github.com/raroque/vibe-security-skill) by [Chris Raroque](https://twitter.com/raroque) — an agent skill that defines the security rules as AI-readable references. We translated those rules into runnable static analysis checks and packaged them as a standalone CLI.

Extended and maintained by [PagePatcher.com](https://pagepatcher.com).

---

## License

MIT License — see [LICENSE](./LICENSE) for full text.

Copyright (c) 2025 Chris Raroque  
Copyright (c) 2026 PagePatcher.com
