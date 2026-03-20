<p align="center">
    <img src="https://img.shields.io/badge/security-vibe--coded%20apps-DC2626.svg" alt="Security for vibe-coded apps" />
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" />
    <a href="https://pagepatcher.com">
        <img src="https://img.shields.io/badge/by-PagePatcher.com-0ea5e9.svg?style=flat" alt="PagePatcher.com" />
    </a>
    <a href="https://jessekhala.com">
        <img src="https://img.shields.io/badge/Contact-jessekhala.com-95a5a6.svg?style=flat" alt="jessekhala.com" />
    </a>
</p>

<h1 align="center">pagepatcher-vibe-security — CLI Security Audit for Vibe-Coded Apps</h1>

A CLI tool that scans your codebase for common security vulnerabilities that AI coding assistants introduce. Built by [Jesse](https://jessekhala.com) at [PagePatcher.com](https://pagepatcher.com).

AI assistants are great at building features fast but consistently get security wrong: hardcoding secrets, skipping row-level security, trusting client-submitted prices, storing tokens in localStorage. This tool catches those patterns before they ship.

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

# CI — exits with code 1 if critical/high issues exist
pagepatcher-vibe-security --path . && echo "Clean"
```

---

## Tech Stack Detection

Scans `package.json` to auto-detect which checks to run — no config needed:

- **Next.js** — auth middleware, security headers, Server Actions
- **Supabase** — RLS policies, service_role exposure
- **Stripe** — webhook verification, client-side pricing
- **Firebase** — security rules
- **React Native / Expo** — AsyncStorage, bundle secrets
- **OpenAI / Anthropic / Google AI** — key exposure, client-side calls
- **Prisma** — operator injection, raw query safety

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No critical or high issues |
| `1` | Critical or high issues found (useful for CI) |
| `2` | Could not read directory |

---

## Credits

The security rules in this tool are based on [vibe-security-skill](https://github.com/raroque/vibe-security-skill) by [Chris Raroque](https://twitter.com/raroque) — an agent skill that defines security audit rules as AI-readable references. We translated those rules into runnable static analysis checks and packaged them as a standalone CLI.

Extended and maintained by [PagePatcher.com](https://pagepatcher.com).

---

## License

MIT — see [LICENSE](./LICENSE).

Copyright (c) 2025 Chris Raroque  
Copyright (c) 2026 PagePatcher.com
